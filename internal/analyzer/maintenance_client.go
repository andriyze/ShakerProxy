package analyzer

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
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
)

const (
	maxMaintenanceClientRequestBytes  = 32 << 10
	maxMaintenanceClientResponseBytes = 64 << 10
)

type MaintenanceClient struct {
	endpoint *url.URL
	token    []byte
	client   *http.Client
}

func NewMaintenanceClient(baseURL string, token []byte, client *http.Client) (*MaintenanceClient, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" || !validMaintenanceToken(token) {
		return nil, errors.New("analyzer maintenance client configuration is invalid")
	}
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	} else {
		copy := *client
		copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		client = &copy
	}
	return &MaintenanceClient{endpoint: parsed, token: append([]byte(nil), token...), client: client}, nil
}

func (c *MaintenanceClient) Preview(ctx context.Context, sessionID string) (CheckpointDeletionPreview, error) {
	if c == nil || c.endpoint == nil || c.client == nil || !capture.ValidSessionID(sessionID) {
		return CheckpointDeletionPreview{}, errors.New("analyzer checkpoint deletion preview request is invalid")
	}
	var preview CheckpointDeletionPreview
	if err := c.request(ctx, "/v1/checkpoints/"+sessionID+"/deletion-preview", nil, &preview); err != nil {
		return CheckpointDeletionPreview{}, err
	}
	if preview.Validate() != nil || preview.CaptureSessionID != sessionID {
		return CheckpointDeletionPreview{}, errors.New("analyzer maintenance service returned an invalid preview")
	}
	return preview, nil
}

func (c *MaintenanceClient) Status(ctx context.Context) (HealthSnapshot, error) {
	if c == nil || c.endpoint == nil || c.client == nil {
		return HealthSnapshot{}, errors.New("analyzer status client is invalid")
	}
	var snapshot HealthSnapshot
	if err := c.requestMethod(ctx, http.MethodGet, "/v1/status", nil, &snapshot); err != nil {
		return HealthSnapshot{}, err
	}
	if snapshot.Validate() != nil {
		return HealthSnapshot{}, errors.New("analyzer maintenance service returned invalid status")
	}
	return snapshot, nil
}

func (c *MaintenanceClient) Delete(ctx context.Context, request CheckpointDeletionRequest) (CheckpointDeletionOutcome, error) {
	if c == nil || c.endpoint == nil || c.client == nil || request.Validate() != nil {
		return CheckpointDeletionOutcome{}, errors.New("analyzer checkpoint deletion request is invalid")
	}
	var outcome CheckpointDeletionOutcome
	path := "/v1/checkpoints/" + request.Preview.CaptureSessionID + "/deletion"
	if err := c.request(ctx, path, request, &outcome); err != nil {
		return CheckpointDeletionOutcome{}, err
	}
	if outcome.Validate() != nil || outcome.Engine != request.Preview.Engine || outcome.CaptureSessionID != request.Preview.CaptureSessionID || outcome.OperationID != request.OperationID || outcome.Actor != request.Actor || outcome.PreviewSHA256 != request.Preview.PreviewSHA256 || outcome.CheckpointWasPresent != request.Preview.CheckpointPresent || outcome.DeletedCheckpointBytes != request.Preview.CheckpointBytes || outcome.ActiveProgressWasPresent != request.Preview.ActiveProgressPresent || outcome.DeletedActiveProgressBytes != request.Preview.ActiveProgressBytes {
		return CheckpointDeletionOutcome{}, errors.New("analyzer maintenance service returned an invalid outcome")
	}
	return outcome, nil
}

func (c *MaintenanceClient) AuthorizeReindex(ctx context.Context, request CheckpointReindexRequest) (CheckpointReindexOutcome, error) {
	if c == nil || c.endpoint == nil || c.client == nil || request.Validate() != nil {
		return CheckpointReindexOutcome{}, errors.New("analyzer checkpoint reindex request is invalid")
	}
	var outcome CheckpointReindexOutcome
	path := "/v1/checkpoints/" + request.CaptureSessionID + "/reindex"
	if err := c.request(ctx, path, request, &outcome); err != nil {
		return CheckpointReindexOutcome{}, err
	}
	if outcome.Validate() != nil || outcome.OperationID != request.OperationID || outcome.Actor != request.Actor || outcome.Engine != request.Engine || outcome.CaptureSessionID != request.CaptureSessionID || outcome.DeletionOperationID != request.DeletionOperationID || outcome.DeletionPreviewSHA256 != request.DeletionPreviewSHA256 || outcome.TargetManifestSHA256 != request.TargetManifestSHA256 {
		return CheckpointReindexOutcome{}, errors.New("analyzer maintenance service returned an invalid reindex outcome")
	}
	return outcome, nil
}

func (c *MaintenanceClient) request(ctx context.Context, path string, body, destination any) error {
	return c.requestMethod(ctx, http.MethodPost, path, body, destination)
}

func (c *MaintenanceClient) requestMethod(ctx context.Context, method, path string, body, destination any) error {
	endpoint := *c.endpoint
	endpoint.Path = path
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil || len(encoded) > maxMaintenanceClientRequestBytes {
			return errors.New("analyzer maintenance request is invalid or oversized")
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), reader)
	if err != nil {
		return errors.New("create analyzer maintenance request")
	}
	request.Header.Set("Authorization", "Bearer "+string(c.token))
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("request analyzer maintenance service: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		var failure struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&failure)
		switch failure.Error.Code {
		case "deletion_preview_expired":
			return ErrCheckpointDeletionPreviewExpired
		case "deletion_preview_stale":
			return ErrCheckpointDeletionPreviewStale
		case "deletion_conflict":
			return ErrCheckpointDeletionConflict
		case "reindex_conflict":
			return ErrCheckpointReindexConflict
		case "reindex_barrier_missing":
			return ErrCheckpointReindexBarrier
		default:
			return fmt.Errorf("analyzer maintenance service returned HTTP %d", response.StatusCode)
		}
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("analyzer maintenance service returned an invalid content type")
	}
	limited := &io.LimitedReader{R: response.Body, N: maxMaintenanceClientResponseBytes + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil || decoder.Decode(&struct{}{}) != io.EOF || limited.N <= 0 {
		return errors.New("analyzer maintenance service returned invalid or oversized JSON")
	}
	return nil
}
