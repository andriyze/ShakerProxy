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
	maxProtocolSummaryResponseBytes = 4 << 20
	protocolSummaryClientTimeout    = 12 * time.Second
)

// QueryProtocolSummary fetches the protocol discovery aggregate from ingestd.
// A 30-day aggregate can take longer than an event page, so this call uses
// its own bounded timeout on the shared transport.
func (c *QueryClient) QueryProtocolSummary(ctx context.Context, query ProtocolSummaryQuery) (ProtocolSummary, error) {
	if c == nil || c.endpoint == nil || c.client == nil {
		return ProtocolSummary{}, errors.New("event query client is unavailable")
	}
	values, err := encodeProtocolSummaryQuery(query)
	if err != nil {
		return ProtocolSummary{}, err
	}
	endpoint := *c.endpoint
	endpoint.Path = "/v1/protocol-summary"
	endpoint.RawQuery = values.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return ProtocolSummary{}, errors.New("create protocol summary request")
	}
	request.Header.Set("Authorization", "Bearer "+string(c.token))
	request.Header.Set("Accept", "application/json")
	client := *c.client
	if client.Timeout < protocolSummaryClientTimeout {
		client.Timeout = protocolSummaryClientTimeout
	}
	response, err := client.Do(request)
	if err != nil {
		return ProtocolSummary{}, fmt.Errorf("request protocol summary: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return ProtocolSummary{}, fmt.Errorf("protocol summary service returned HTTP %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return ProtocolSummary{}, errors.New("protocol summary service returned an invalid content type")
	}
	limited := &io.LimitedReader{R: response.Body, N: maxProtocolSummaryResponseBytes + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var summary ProtocolSummary
	if err := decoder.Decode(&summary); err != nil || decoder.Decode(&struct{}{}) != io.EOF || limited.N <= 0 {
		return ProtocolSummary{}, errors.New("protocol summary service returned an invalid or oversized response")
	}
	if err := summary.Validate(query); err != nil {
		return ProtocolSummary{}, fmt.Errorf("protocol summary service returned an invalid summary: %w", err)
	}
	for _, usage := range summary.Protocols {
		for _, device := range usage.Devices {
			if device.DeviceName != "" {
				return ProtocolSummary{}, errors.New("protocol summary service returned an unauthorized device name projection")
			}
		}
	}
	return summary, nil
}
