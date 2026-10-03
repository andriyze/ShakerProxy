package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
)

const maxLabPresenceResponseBytes = 4 << 20

// QueryLabPresence fetches who was seen on the lab prefix recently and
// whether their traffic reached ShakerProxy. Best effort, like
// QueryObservedDHCP.
func (c *QueryClient) QueryLabPresence(ctx context.Context, prefix netip.Prefix) (LabPresence, error) {
	if c == nil || c.endpoint == nil || c.client == nil {
		return LabPresence{}, errors.New("event query client is unavailable")
	}
	if !ValidLabPresencePrefix(prefix) {
		return LabPresence{}, errors.New("lab prefix is invalid")
	}
	endpoint := *c.endpoint
	endpoint.Path = "/v1/lab-presence"
	endpoint.RawQuery = url.Values{"prefix": {prefix.String()}}.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return LabPresence{}, errors.New("create lab presence request")
	}
	request.Header.Set("Authorization", "Bearer "+string(c.token))
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return LabPresence{}, fmt.Errorf("request lab presence: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return LabPresence{}, fmt.Errorf("lab presence service returned HTTP %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return LabPresence{}, errors.New("lab presence service returned an invalid content type")
	}
	limited := &io.LimitedReader{R: response.Body, N: maxLabPresenceResponseBytes + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var presence LabPresence
	if err := decoder.Decode(&presence); err != nil || decoder.Decode(&struct{}{}) != io.EOF || limited.N <= 0 {
		return LabPresence{}, errors.New("lab presence service returned an invalid or oversized response")
	}
	if err := presence.Validate(); err != nil {
		return LabPresence{}, fmt.Errorf("lab presence service returned an invalid answer: %w", err)
	}
	if presence.Prefix != prefix.String() {
		return LabPresence{}, errors.New("lab presence service answered for another prefix")
	}
	return presence, nil
}
