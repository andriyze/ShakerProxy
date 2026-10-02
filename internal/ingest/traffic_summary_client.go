package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
)

const maxTrafficSummaryResponseBytes = 256 << 10

// QueryTrafficSummary fetches the events summary from ingestd. Device-name
// selectors travel as private references, like the event list's.
func (c *QueryClient) QueryTrafficSummary(ctx context.Context, query TrafficSummaryQuery) (TrafficSummary, error) {
	if c == nil || c.endpoint == nil || c.client == nil {
		return TrafficSummary{}, errors.New("event query client is unavailable")
	}
	if err := query.Validate(); err != nil {
		return TrafficSummary{}, err
	}
	publicCanonical := query.Events.Filter.Canonical
	query.Events.Limit = 1
	prepared, err := prepareStorageRecentQuery(query.Events)
	if err != nil {
		return TrafficSummary{}, err
	}
	query.Events = prepared
	values, err := encodeInternalTrafficSummaryQuery(query)
	if err != nil {
		return TrafficSummary{}, err
	}
	endpoint := *c.endpoint
	endpoint.Path = "/v1/events/summary"
	endpoint.RawQuery = values.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return TrafficSummary{}, errors.New("create events summary request")
	}
	request.Header.Set("Authorization", "Bearer "+string(c.token))
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return TrafficSummary{}, fmt.Errorf("request events summary: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return TrafficSummary{}, fmt.Errorf("events summary service returned HTTP %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return TrafficSummary{}, errors.New("events summary service returned an invalid content type")
	}
	limited := &io.LimitedReader{R: response.Body, N: maxTrafficSummaryResponseBytes + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var summary TrafficSummary
	if err := decoder.Decode(&summary); err != nil || decoder.Decode(&struct{}{}) != io.EOF || limited.N <= 0 {
		return TrafficSummary{}, errors.New("events summary service returned an invalid or oversized response")
	}
	if err := ValidateTrafficSummary(summary, query); err != nil {
		return TrafficSummary{}, fmt.Errorf("events summary service returned an invalid summary: %w", err)
	}
	// Device labels are the control plane's to add; ingestd only labels
	// unattributed addresses.
	for _, facet := range summary.Facets {
		for _, value := range facet.Values {
			if facet.Field == SummaryFacetDevice && value.Label != "" && "ip:"+value.Label != value.Value {
				return TrafficSummary{}, errors.New("events summary service returned an unauthorized device label")
			}
			if facet.Field != SummaryFacetDevice && value.Label != "" {
				return TrafficSummary{}, errors.New("events summary service returned an unexpected label")
			}
		}
	}
	summary.CanonicalQuery = publicCanonical
	if strings.TrimSpace(summary.CanonicalQuery) == "" {
		summary.CanonicalQuery = ""
	}
	return summary, nil
}
