package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"shakerproxy.dev/shakerproxy/internal/agentapi"
)

type DNSVisibilityArgs struct{}

type dnsVisibilityResult struct {
	Summary    string                 `json:"summary"`
	Visibility agentapi.DNSVisibility `json:"visibility"`
}

func (s *Service) dnsVisibility(ctx context.Context, _ *mcp.CallToolRequest, _ DNSVisibilityArgs) (*mcp.CallToolResult, any, error) {
	view, err := s.backend.DNSVisibility(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("read ShakerProxy DNS visibility: %w", err)
	}
	return textResult(dnsVisibilityResult{Summary: dnsVisibilitySummary(view), Visibility: view})
}

func dnsVisibilitySummary(view agentapi.DNSVisibility) string {
	parts := []string{}
	if view.ForcePlainDNS {
		parts = append(parts, "every lab device's plain DNS is answered by ShakerProxy, so lookups are recorded")
	} else {
		parts = append(parts, "plain DNS sent to other resolvers is only seen in packet captures")
	}
	if view.BlockEncryptedDNS {
		parts = append(parts, fmt.Sprintf("encrypted DNS is blocked (DNS over TLS/QUIC, %d known DNS-over-HTTPS resolver addresses, %d resolver names), so devices fall back to plain DNS and blocked attempts appear as shakerproxy.blocked events", view.BlockedAddresses, len(view.BlockedNames)))
	} else {
		parts = append(parts, "encrypted DNS is allowed, so lookups over DoH/DoT are hidden")
	}
	return boundText(strings.Join(parts, "; ")+".", 600)
}
