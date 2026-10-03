package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type SyslogCollectorArgs struct{}

type syslogCollectorResult struct {
	Summary        string   `json:"summary"`
	Available      bool     `json:"available"`
	Enabled        bool     `json:"enabled"`
	BindAddress    string   `json:"bind_address,omitempty"`
	AllowedSources []string `json:"allowed_sources"`
	Received       uint64   `json:"received"`
	Parsed         uint64   `json:"parsed"`
	Unparsed       uint64   `json:"unparsed"`
	Delivered      uint64   `json:"delivered"`
	Dropped        uint64   `json:"dropped_rate_limited"`
	Rejected       uint64   `json:"rejected_not_allowed"`
	Listening      bool     `json:"listening"`
	Error          string   `json:"error,omitempty"`
}

// syslogCollector reports the read-only status of the network-gear log
// collector. It is read-only: there is no MCP action to enable or disable it.
func (s *Service) syslogCollector(ctx context.Context, _ *mcp.CallToolRequest, _ SyslogCollectorArgs) (*mcp.CallToolResult, any, error) {
	status, err := s.backend.SyslogCollector(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("read syslog collector status: %w", err)
	}
	result := syslogCollectorResult{
		Available: status.Available, Enabled: status.Enabled, BindAddress: status.BindAddress,
		AllowedSources: status.AllowedSources,
	}
	if result.AllowedSources == nil {
		result.AllowedSources = []string{}
	}
	if status.Status != nil {
		result.Received, result.Parsed, result.Unparsed = status.Status.Received, status.Status.Parsed, status.Status.Unparsed
		result.Delivered, result.Dropped, result.Rejected = status.Status.Delivered, status.Status.Dropped, status.Status.Rejected
		result.Listening, result.Error = status.Status.Listening, boundText(status.Status.Error, 300)
	}
	switch {
	case !status.Available:
		result.Summary = "The network-gear log collector is not configured on this appliance."
	case !status.Enabled:
		result.Summary = "The network-gear log collector is off. Enable it (with the router's IP as an allowed source) to turn the router's DHCP, Wi-Fi and firewall logs into events."
	case status.Status != nil && !status.Status.Listening:
		reason := "it is starting"
		if result.Error != "" {
			reason = result.Error
		}
		result.Summary = boundText("The network-gear log collector is on but not listening on "+status.BindAddress+": "+reason+". It retries every few seconds.", 900)
	default:
		sources := "no sources"
		if len(status.AllowedSources) > 0 {
			sources = strings.Join(status.AllowedSources, ", ")
		}
		result.Summary = boundText(fmt.Sprintf("The network-gear log collector is on, listening on %s, accepting logs from %s; %d messages received, %d parsed into events, %d delivered.",
			status.BindAddress, sources, result.Received, result.Parsed, result.Delivered), 900)
	}
	return textResult(result)
}
