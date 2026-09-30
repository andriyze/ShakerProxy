package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"
)

const (
	maxDeviceActivityResponseBytes = 2 << 20
	deviceActivityClientTimeout    = 10 * time.Second
)

// QueryDeviceActivity reads one bounded device aggregation from ingestd.
func (c *QueryClient) QueryDeviceActivity(ctx context.Context, query DeviceActivityQuery) (DeviceActivity, error) {
	if c == nil || c.endpoint == nil || c.client == nil {
		return DeviceActivity{}, errors.New("event query client is unavailable")
	}
	values, err := encodeDeviceActivityQuery(query)
	if err != nil {
		return DeviceActivity{}, err
	}
	endpoint := *c.endpoint
	endpoint.Path = "/v1/device-activity"
	endpoint.RawQuery = values.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return DeviceActivity{}, errors.New("create device activity request")
	}
	request.Header.Set("Authorization", "Bearer "+string(c.token))
	request.Header.Set("Accept", "application/json")
	// Aggregations over long windows can take longer than the default
	// short query timeout; ingestd bounds its own work to 8 seconds.
	client := *c.client
	if client.Timeout == 0 || client.Timeout < deviceActivityClientTimeout {
		client.Timeout = deviceActivityClientTimeout
	}
	response, err := client.Do(request)
	if err != nil {
		return DeviceActivity{}, fmt.Errorf("request device activity: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return DeviceActivity{}, fmt.Errorf("device activity service returned HTTP %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return DeviceActivity{}, errors.New("device activity service returned an invalid content type")
	}
	limited := &io.LimitedReader{R: response.Body, N: maxDeviceActivityResponseBytes + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var activity DeviceActivity
	if err := decoder.Decode(&activity); err != nil || decoder.Decode(&struct{}{}) != io.EOF || limited.N <= 0 {
		return DeviceActivity{}, errors.New("device activity service returned an invalid or oversized response")
	}
	if err := activity.Validate(query); err != nil {
		return DeviceActivity{}, fmt.Errorf("device activity service returned an invalid aggregation: %w", err)
	}
	return activity, nil
}
