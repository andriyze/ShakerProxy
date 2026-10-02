package mcpserver

import (
	"strings"
	"testing"

	"shakerproxy.dev/shakerproxy/internal/agentapi"
	"shakerproxy.dev/shakerproxy/internal/ingest"
)

// An agent reads who the destination is and how much went each way, as a
// SOC analyst would: "TLS … — Google (advertising)", from and to endpoints.
func TestEventLinesSayWhoTheDestinationIs(t *testing.T) {
	sent, received := int64(900), int64(4000)
	event := agentapi.Event{RecentEvent: ingest.RecentEvent{
		RecordID: strings.Repeat("a", 64), Kind: "zeek.conn", SourceIP: "10.77.0.50", SourcePort: 40001, DestinationIP: "142.250.1.2", DestinationPort: 443,
		Protocol: "tcp", TLSServerName: "googleads.g.doubleclick.net", BytesSent: &sent, BytesReceived: &received,
		DestinationOrganization: "Google", DestinationCategory: "advertising",
	}, Summary: "TLS to googleads.g.doubleclick.net"}
	line := newEventLine(event)
	if line.Owner != "Google (advertising)" || line.From != "10.77.0.50:40001" || line.To != "142.250.1.2:443" || line.BytesSent == nil || *line.BytesSent != 900 || *line.BytesReceived != 4000 {
		t.Fatalf("event line = %+v", line)
	}
	if line.Summary != "TLS to googleads.g.doubleclick.net — Google (advertising)" {
		t.Fatalf("summary = %q", line.Summary)
	}
	unknown := newEventLine(agentapi.Event{RecentEvent: ingest.RecentEvent{RecordID: strings.Repeat("b", 64), Kind: "zeek.conn", DestinationIP: "2001:db8::1", DestinationPort: 8883}})
	if unknown.Owner != "" || strings.Contains(unknown.Summary, " — ") || unknown.To != "[2001:db8::1]:8883" {
		t.Fatalf("unknown destination line = %+v", unknown)
	}
}
