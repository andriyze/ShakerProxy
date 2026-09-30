package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
)

const maxEventDetailResponseBytes = MaxEventBytes + (64 << 10)

func (c *QueryClient) GetEventDetail(ctx context.Context, recordID string) (EventDetail, error) {
	if c == nil || c.endpoint == nil || c.client == nil {
		return EventDetail{}, errors.New("event query client is unavailable")
	}
	if !validRecordID(recordID) {
		return EventDetail{}, errors.New("event record ID is invalid")
	}
	endpoint := *c.endpoint
	endpoint.Path = "/v1/events/" + recordID
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return EventDetail{}, errors.New("create event detail request")
	}
	request.Header.Set("Authorization", "Bearer "+string(c.token))
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return EventDetail{}, fmt.Errorf("request normalized event detail: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return EventDetail{}, ErrEventNotFound
	}
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return EventDetail{}, fmt.Errorf("event detail service returned HTTP %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return EventDetail{}, errors.New("event detail service returned an invalid content type")
	}
	limited := &io.LimitedReader{R: response.Body, N: maxEventDetailResponseBytes + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var detail EventDetail
	if err := decoder.Decode(&detail); err != nil || decoder.Decode(&struct{}{}) != io.EOF || limited.N <= 0 || detail.Event.DeviceFriendlyName != "" || detail.Event.DeviceFriendlyNameAtCapture != "" || detail.Event.DeviceFriendlyNameAtCaptureKnown || detail.Event.DeviceAliasRevision != 0 || detail.Event.DeviceFriendlyNameConflict || detail.Validate() != nil {
		return EventDetail{}, errors.New("event detail service returned an invalid or oversized response")
	}
	return detail, nil
}
