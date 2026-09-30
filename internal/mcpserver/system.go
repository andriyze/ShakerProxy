package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"shakerproxy.dev/shakerproxy/internal/agentapi"
)

type SystemStatusArgs struct{}

type systemStatusResult struct {
	Summary  string                  `json:"summary"`
	Overview agentapi.SystemOverview `json:"overview"`
}

func (s *Service) systemStatus(ctx context.Context, _ *mcp.CallToolRequest, _ SystemStatusArgs) (*mcp.CallToolResult, any, error) {
	overview, err := s.backend.SystemOverview(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("read ShakerProxy system status: %w", err)
	}
	return textResult(systemStatusResult{Summary: systemSummary(overview), Overview: overview})
}

func systemSummary(overview agentapi.SystemOverview) string {
	parts := []string{}
	switch overview.Overall {
	case "READY":
		parts = append(parts, "ShakerProxy is ready to collect evidence")
	case "DEGRADED":
		parts = append(parts, "ShakerProxy is running with reduced evidence")
	default:
		parts = append(parts, "ShakerProxy cannot collect evidence right now")
	}
	if overview.Gateway.Available {
		mode := strings.ToLower(strings.ReplaceAll(overview.Gateway.OperatingMode, "_", " "))
		parts = append(parts, "gateway in "+mode+" mode")
		if overview.Gateway.ActiveCapture {
			parts = append(parts, "a packet capture is running")
		}
	} else {
		parts = append(parts, "gateway unavailable")
	}
	healthy := []string{}
	for _, item := range overview.Analyzers {
		if item.Healthy {
			healthy = append(healthy, engineLabel(item.Engine))
		}
	}
	if len(healthy) > 0 {
		parts = append(parts, strings.Join(healthy, " and ")+" healthy")
	}
	if overview.Ingest.Available && overview.Ingest.DatabaseConnected {
		parts = append(parts, "event storage connected")
	} else {
		parts = append(parts, "event storage unavailable")
	}
	summary := strings.Join(parts, "; ") + "."
	if len(overview.Limitations) > 0 {
		summary += " Limitations: " + strings.Join(overview.Limitations, " ")
	}
	return boundText(summary, 600)
}

func boundText(value string, maximum int) string {
	if len(value) <= maximum {
		return value
	}
	return truncateText(value, maximum)
}

func engineLabel(engine string) string {
	switch engine {
	case "ZEEK":
		return "Zeek"
	case "SURICATA":
		return "Suricata"
	default:
		return engine
	}
}
