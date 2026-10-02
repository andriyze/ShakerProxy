package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"shakerproxy.dev/shakerproxy/internal/coverage"
)

type VisibilityCoverageArgs struct{}

type visibilityCoverageResult struct {
	Summary  string            `json:"summary"`
	Overview coverage.Overview `json:"overview"`
}

func (s *Service) visibilityCoverage(ctx context.Context, _ *mcp.CallToolRequest, _ VisibilityCoverageArgs) (*mcp.CallToolResult, any, error) {
	overview, err := s.backend.VisibilityCoverage(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("read ShakerProxy visibility coverage: %w", err)
	}
	return textResult(visibilityCoverageResult{Summary: coverageSummary(overview), Overview: overview})
}

// coverageSummary says in one paragraph what ShakerProxy can and cannot see.
func coverageSummary(overview coverage.Overview) string {
	parts := []string{}
	if run := overview.LastRun; run == nil {
		parts = append(parts, "The visibility coverage check has not run yet (an administrator runs it from System or with `shakerproxy coverage run`)")
	} else {
		switch run.State {
		case coverage.StateRunning:
			parts = append(parts, "A visibility coverage check is running")
		case coverage.StateFailed:
			parts = append(parts, "The last visibility coverage check failed: "+run.Error)
		default:
			parts = append(parts, fmt.Sprintf("The last check (%s) saw %d of %d traffic types", run.StartedAt.Format("2006-01-02 15:04 MST"), run.PassCount, run.PassCount+run.FailCount))
			missing := []string{}
			for _, result := range run.Results {
				if result.Status == coverage.StatusFail {
					missing = append(missing, result.Name)
				}
			}
			if len(missing) > 0 {
				parts = append(parts, "not seen or not identified: "+strings.Join(missing, ", "))
			}
		}
	}
	gaps := []string{}
	for _, finding := range overview.Routing {
		if finding.Status == coverage.FindingGap {
			gaps = append(gaps, finding.Title)
		}
	}
	if len(gaps) > 0 {
		parts = append(parts, fmt.Sprintf("%d ways devices can bypass ShakerProxy: %s", len(gaps), strings.Join(gaps, "; ")))
	} else {
		parts = append(parts, "no way around ShakerProxy was found in the lab configuration")
	}
	return strings.Join(parts, "; ") + "."
}
