package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"reflect"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
)

const (
	maxCaptureEventDeletionClientRequestBytes = 128 << 10
	maxCaptureEventDeletionResponseBytes      = 256 << 10
)

type DeletionClient struct {
	endpoint *url.URL
	token    []byte
	client   *http.Client
}

func NewDeletionClient(baseURL string, token []byte, client *http.Client) (*DeletionClient, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" || !validDeletionClientToken(token) {
		return nil, errors.New("capture event deletion client configuration is invalid")
	}
	if client == nil {
		client = &http.Client{Timeout: 35 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	} else {
		clientCopy := *client
		clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		client = &clientCopy
	}
	return &DeletionClient{endpoint: parsed, token: append([]byte(nil), token...), client: client}, nil
}

func (c *DeletionClient) Preview(ctx context.Context, captureSessionID string) (CaptureEventDeletionPreview, error) {
	if c == nil || c.endpoint == nil || c.client == nil || !capture.ValidSessionID(captureSessionID) {
		return CaptureEventDeletionPreview{}, errors.New("capture event deletion preview request is invalid")
	}
	var preview CaptureEventDeletionPreview
	if err := c.request(ctx, "/v1/capture-event-deletions/"+captureSessionID+"/preview", nil, &preview); err != nil {
		return CaptureEventDeletionPreview{}, err
	}
	if err := preview.Validate(); err != nil || preview.CaptureSessionID != captureSessionID {
		return CaptureEventDeletionPreview{}, errors.New("capture event deletion service returned an invalid preview")
	}
	return preview, nil
}

func (c *DeletionClient) Delete(ctx context.Context, request CaptureEventDeletionRequest) (CaptureEventDeletionOutcome, error) {
	if c == nil || c.endpoint == nil || c.client == nil || request.Validate() != nil {
		return CaptureEventDeletionOutcome{}, errors.New("capture event deletion request is invalid")
	}
	var outcome CaptureEventDeletionOutcome
	path := "/v1/capture-event-deletions/" + request.Preview.CaptureSessionID + "/execute"
	if err := c.request(ctx, path, request, &outcome); err != nil {
		return CaptureEventDeletionOutcome{}, err
	}
	if err := outcome.Validate(); err != nil || outcome.CaptureSessionID != request.Preview.CaptureSessionID || outcome.PreviewSHA256 != request.Preview.PreviewSHA256 {
		return CaptureEventDeletionOutcome{}, errors.New("capture event deletion service returned an invalid outcome")
	}
	return outcome, nil
}

func (c *DeletionClient) PreviewEventSelection(ctx context.Context, request EventSelectionDeletionPreviewRequest) (EventSelectionDeletionBundle, error) {
	if c == nil || c.endpoint == nil || c.client == nil || request.Validate() != nil {
		return EventSelectionDeletionBundle{}, errors.New("event selection deletion preview request is invalid")
	}
	var preview EventSelectionDeletionBundle
	if err := c.requestSelection(ctx, "/v1/event-selection-deletions/preview", request, &preview); err != nil {
		return EventSelectionDeletionBundle{}, err
	}
	if preview.Validate() != nil || preview.Actor != request.Actor || !reflect.DeepEqual(preview.Selection, request.Selection) || !reflect.DeepEqual(preview.QuerySnapshot, request.QuerySnapshot) {
		return EventSelectionDeletionBundle{}, errors.New("event selection deletion service returned an invalid preview")
	}
	return preview, nil
}

func (c *DeletionClient) DeleteEventSelection(ctx context.Context, request EventSelectionDeletionRequest) (EventSelectionDeletionOutcome, error) {
	if c == nil || c.endpoint == nil || c.client == nil || request.Validate() != nil {
		return EventSelectionDeletionOutcome{}, errors.New("event selection deletion request is invalid")
	}
	var outcome EventSelectionDeletionOutcome
	if err := c.requestSelection(ctx, "/v1/event-selection-deletions/execute", request, &outcome); err != nil {
		return EventSelectionDeletionOutcome{}, err
	}
	if outcome.Validate() != nil || outcome.OperationID != request.OperationID || outcome.PreviewSHA256 != request.Preview.PreviewSHA256 {
		return EventSelectionDeletionOutcome{}, errors.New("event selection deletion service returned an invalid outcome")
	}
	return outcome, nil
}

func (c *DeletionClient) request(ctx context.Context, path string, body, destination any) error {
	return c.requestWithErrorScope(ctx, path, body, destination, false)
}

func (c *DeletionClient) requestSelection(ctx context.Context, path string, body, destination any) error {
	return c.requestWithErrorScope(ctx, path, body, destination, true)
}

func (c *DeletionClient) requestWithErrorScope(ctx context.Context, path string, body, destination any, selection bool) error {
	endpoint := *c.endpoint
	endpoint.Path = path
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil || len(encoded) > maxCaptureEventDeletionClientRequestBytes {
			return errors.New("capture event deletion request is invalid or oversized")
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), reader)
	if err != nil {
		return errors.New("create capture event deletion request")
	}
	request.Header.Set("Authorization", "Bearer "+string(c.token))
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("request capture event deletion service: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		var failure struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&failure)
		if selection {
			switch failure.Error.Code {
			case "deletion_preview_expired":
				return ErrEventSelectionDeletionPreviewExpired
			case "deletion_preview_stale":
				return ErrEventSelectionDeletionPreviewStale
			case "deletion_conflict":
				return ErrEventSelectionDeletionConflict
			case "deletion_barrier_missing":
				return ErrEventSelectionTombstoneMissing
			default:
				return fmt.Errorf("event selection deletion service returned HTTP %d", response.StatusCode)
			}
		}
		switch failure.Error.Code {
		case "deletion_preview_expired":
			return ErrCaptureEventDeletionPreviewExpired
		case "deletion_preview_stale":
			return ErrCaptureEventDeletionPreviewStale
		case "deletion_conflict":
			return ErrCaptureEventDeletionConflict
		default:
			return fmt.Errorf("capture event deletion service returned HTTP %d", response.StatusCode)
		}
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("capture event deletion service returned an invalid content type")
	}
	limited := &io.LimitedReader{R: response.Body, N: maxCaptureEventDeletionResponseBytes + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil || decoder.Decode(&struct{}{}) != io.EOF || limited.N <= 0 {
		return errors.New("capture event deletion service returned invalid or oversized JSON")
	}
	return nil
}

func validDeletionClientToken(token []byte) bool {
	if len(token) < 32 || len(token) > 128 {
		return false
	}
	for _, char := range token {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_') {
			return false
		}
	}
	return true
}
