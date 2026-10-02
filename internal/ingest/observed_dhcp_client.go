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

const maxObservedDHCPResponseBytes = 8 << 20

// QueryObservedDHCP fetches the DHCP exchanges recorded on the lab, merged
// per client. Callers treat it as best effort and bound it with their own
// context deadline.
func (c *QueryClient) QueryObservedDHCP(ctx context.Context) (ObservedDHCP, error) {
	if c == nil || c.endpoint == nil || c.client == nil {
		return ObservedDHCP{}, errors.New("event query client is unavailable")
	}
	endpoint := *c.endpoint
	endpoint.Path = "/v1/observed-dhcp"
	endpoint.RawQuery = ""
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return ObservedDHCP{}, errors.New("create observed DHCP request")
	}
	request.Header.Set("Authorization", "Bearer "+string(c.token))
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return ObservedDHCP{}, fmt.Errorf("request observed DHCP: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return ObservedDHCP{}, fmt.Errorf("observed DHCP service returned HTTP %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return ObservedDHCP{}, errors.New("observed DHCP service returned an invalid content type")
	}
	limited := &io.LimitedReader{R: response.Body, N: maxObservedDHCPResponseBytes + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var observed ObservedDHCP
	if err := decoder.Decode(&observed); err != nil || decoder.Decode(&struct{}{}) != io.EOF || limited.N <= 0 {
		return ObservedDHCP{}, errors.New("observed DHCP service returned an invalid or oversized response")
	}
	if err := observed.Validate(); err != nil {
		return ObservedDHCP{}, fmt.Errorf("observed DHCP service returned invalid clients: %w", err)
	}
	return observed, nil
}
