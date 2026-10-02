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

const maxDevicePlatformResponseBytes = 4 << 20

// QueryDevicePlatformHints fetches what each device most likely is. Callers
// treat it as best effort and bound it with their own context deadline.
func (c *QueryClient) QueryDevicePlatformHints(ctx context.Context) (DevicePlatformHints, error) {
	if c == nil || c.endpoint == nil || c.client == nil {
		return DevicePlatformHints{}, errors.New("event query client is unavailable")
	}
	endpoint := *c.endpoint
	endpoint.Path = "/v1/device-platform-hints"
	endpoint.RawQuery = ""
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return DevicePlatformHints{}, errors.New("create device platform request")
	}
	request.Header.Set("Authorization", "Bearer "+string(c.token))
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return DevicePlatformHints{}, fmt.Errorf("request device platform hints: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return DevicePlatformHints{}, fmt.Errorf("device platform service returned HTTP %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return DevicePlatformHints{}, errors.New("device platform service returned an invalid content type")
	}
	limited := &io.LimitedReader{R: response.Body, N: maxDevicePlatformResponseBytes + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var hints DevicePlatformHints
	if err := decoder.Decode(&hints); err != nil || decoder.Decode(&struct{}{}) != io.EOF || limited.N <= 0 {
		return DevicePlatformHints{}, errors.New("device platform service returned an invalid or oversized response")
	}
	if err := hints.Validate(); err != nil {
		return DevicePlatformHints{}, fmt.Errorf("device platform service returned invalid hints: %w", err)
	}
	return hints, nil
}
