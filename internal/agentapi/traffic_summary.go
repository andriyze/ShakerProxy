package agentapi

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

const maxTrafficSummaryBytes = 256 << 10

// TrafficSummaryRequest asks for counts by type over time, top devices,
// destinations and protocols, and byte totals for a query. Without a
// time:last_… term in Query the window is the last 15 minutes.
type TrafficSummaryRequest struct {
	Query   string
	Buckets int
}

func (c *Client) TrafficSummary(ctx context.Context, request TrafficSummaryRequest) (ingest.TrafficSummary, error) {
	if c == nil || c.base == nil || c.client == nil {
		return ingest.TrafficSummary{}, errors.New("agent API client is unavailable")
	}
	if request.Buckets == 0 {
		request.Buckets = ingest.DefaultTrafficSummaryBuckets
	}
	if request.Buckets < 1 || request.Buckets > ingest.MaxTrafficSummaryBuckets {
		return ingest.TrafficSummary{}, fmt.Errorf("traffic summary buckets must be between 1 and %d", ingest.MaxTrafficSummaryBuckets)
	}
	if len(request.Query) > 2048 {
		return ingest.TrafficSummary{}, errors.New("agent traffic query exceeds its bound")
	}
	values := url.Values{}
	values.Set("buckets", strconv.Itoa(request.Buckets))
	if request.Query != "" {
		values.Set("q", request.Query)
	}
	var summary ingest.TrafficSummary
	if _, err := c.getJSON(ctx, "/api/v1/events/summary", values, maxTrafficSummaryBytes, &summary); err != nil {
		return ingest.TrafficSummary{}, err
	}
	if err := ingest.ValidateTrafficSummary(summary, ingest.TrafficSummaryQuery{Buckets: request.Buckets}); err != nil {
		return ingest.TrafficSummary{}, fmt.Errorf("agent traffic API returned an invalid summary: %w", err)
	}
	return summary, nil
}
