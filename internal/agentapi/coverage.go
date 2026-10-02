package agentapi

import (
	"context"
	"errors"

	"shakerproxy.dev/shakerproxy/internal/coverage"
)

const maxCoverageOverviewBytes = 256 << 10

// VisibilityCoverage returns the last visibility coverage run and a fresh
// inspection of the ways devices could bypass ShakerProxy.
func (c *Client) VisibilityCoverage(ctx context.Context) (coverage.Overview, error) {
	if c == nil || c.base == nil || c.client == nil {
		return coverage.Overview{}, errors.New("agent API client is unavailable")
	}
	var overview coverage.Overview
	if _, err := c.getJSON(ctx, "/api/v1/coverage", nil, maxCoverageOverviewBytes, &overview); err != nil {
		return coverage.Overview{}, err
	}
	if overview.Schema != coverage.SchemaVersion || len(overview.Routing) > 32 || overview.LastRun != nil && len(overview.LastRun.Results) > 64 {
		return coverage.Overview{}, errors.New("coverage API returned an invalid bounded response")
	}
	return overview, nil
}
