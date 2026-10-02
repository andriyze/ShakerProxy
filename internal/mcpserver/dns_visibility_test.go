package mcpserver

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestDNSVisibilityToolSaysWhetherEveryLookupIsVisible(t *testing.T) {
	service := &Service{backend: newFakeBackend()}
	result, _, err := service.dnsVisibility(context.Background(), nil, DNSVisibilityArgs{})
	if err != nil {
		t.Fatal(err)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	for _, want := range []string{"plain DNS is answered by ShakerProxy", "encrypted DNS is blocked", "shakerproxy.blocked", "force_plain_dns"} {
		if !strings.Contains(text, want) {
			t.Fatalf("dns_visibility lacks %q:\n%s", want, text)
		}
	}
}
