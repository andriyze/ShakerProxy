package ingest

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/querylang"
)

// A technician or SOC analyst reads, on every row, who the destination is and
// how much went each way. Both come from what is already stored: the curated
// domain table and the analyzer payload.
func TestEventRowsSayWhoTheDestinationIsAndBytesEachWay(t *testing.T) {
	database, sink, ctx := openProtocolTestDatabase(t)
	_ = database
	now := time.Now().UTC().Truncate(time.Second)
	envelopes := []Envelope{
		zeekTestEnvelope(t, protocolTestZeekCapture, protocolTestTV, now.Add(-3*time.Minute), map[string]any{"_path": "conn", "uid": "CownerGoogle0001", "id.orig_h": "10.77.0.50", "id.orig_p": 40000, "id.resp_h": "142.250.1.1", "id.resp_p": 443, "proto": "tcp", "service": "ssl", "server_name": "maps.googleapis.com", "orig_bytes": 3389, "resp_bytes": 165943, "orig_ip_bytes": 3977, "resp_ip_bytes": 169835}),
		zeekTestEnvelope(t, protocolTestZeekCapture, protocolTestTV, now.Add(-2*time.Minute), map[string]any{"_path": "conn", "uid": "CownerAds0000001", "id.orig_h": "10.77.0.50", "id.orig_p": 40001, "id.resp_h": "142.250.1.2", "id.resp_p": 443, "proto": "tcp", "service": "ssl", "server_name": "googleads.g.doubleclick.net", "orig_ip_bytes": 900, "resp_ip_bytes": 4000}),
		suricataTestEnvelope(t, protocolTestSuriCapture, protocolTestCamera, now.Add(-time.Minute), map[string]any{"event_type": "flow", "src_ip": "10.77.0.40", "src_port": 50000, "dest_ip": "192.0.2.9", "dest_port": 8883, "proto": "TCP", "flow": map[string]any{"bytes_toserver": 73, "bytes_toclient": 247, "pkts_toserver": 1, "pkts_toclient": 1}}),
	}
	writeTestEnvelopes(t, ctx, sink, now, envelopes)

	type row struct {
		owner, category string
		sent, received  int64
	}
	want := map[int]row{
		40000: {"Google", "cloud-platform", 3389, 165943},
		40001: {"Google", "advertising", 900, 4000},
		50000: {"", "", 73, 247},
	}
	check := func(label string, events []RecentEvent) {
		t.Helper()
		seen := 0
		for _, event := range events {
			expected, ok := want[event.SourcePort]
			if !ok || event.Kind == "suricata.flow" && event.SourcePort != 50000 {
				continue
			}
			seen++
			if event.DestinationOrganization != expected.owner || event.DestinationCategory != expected.category || event.BytesSent == nil || *event.BytesSent != expected.sent || event.BytesReceived == nil || *event.BytesReceived != expected.received {
				t.Fatalf("%s: port %d = owner %q/%q bytes %v/%v, want %+v", label, event.SourcePort, event.DestinationOrganization, event.DestinationCategory, event.BytesSent, event.BytesReceived, expected)
			}
			if !validEventByteCounts(event) || !validEventDestinationOwner(event) {
				t.Fatalf("%s: row fails its own validation: %+v", label, event)
			}
		}
		if seen != len(want) {
			t.Fatalf("%s: saw %d of %d rows", label, seen, len(want))
		}
	}
	page, err := sink.QueryRecent(ctx, RecentEventQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	check("recent page", page.Events)
	encoded, err := json.Marshal(page.Events)
	if err != nil || !strings.Contains(string(encoded), `"destination_organization":"Google"`) || !strings.Contains(string(encoded), `"bytes_received":165943`) {
		t.Fatalf("encoded events lack the new fields: %s err=%v", encoded, err)
	}
	live, err := sink.QueryAfter(ctx, LiveEventQuery{RecentEventQuery: RecentEventQuery{Limit: 100}, AfterReceivedAt: now.Add(-time.Hour), AfterRecordID: strings.Repeat("0", 64)})
	if err != nil {
		t.Fatal(err)
	}
	check("live batch", live.Events)
	for _, event := range page.Events {
		if event.SourcePort != 40000 {
			continue
		}
		detail, err := sink.GetEventDetail(ctx, event.RecordID)
		if err != nil || detail.Event.DestinationOrganization != "Google" || detail.Event.BytesSent == nil || *detail.Event.BytesSent != 3389 {
			t.Fatalf("event detail = %+v err=%v", detail.Event, err)
		}
	}

	filtered := func(input string) map[int]bool {
		t.Helper()
		filter, err := querylang.Parse(input)
		if err != nil {
			t.Fatalf("%s: %v", input, err)
		}
		result, err := sink.QueryRecent(ctx, RecentEventQuery{Limit: 100, Filter: filter})
		if err != nil {
			t.Fatalf("%s: %v", input, err)
		}
		ports := map[int]bool{}
		for _, event := range result.Events {
			if _, known := want[event.SourcePort]; known {
				ports[event.SourcePort] = true
			}
		}
		return ports
	}
	if got := filtered("owner:google"); !got[40000] || !got[40001] || got[50000] {
		t.Fatalf("owner:google = %v", got)
	}
	if got := filtered("category:advertising"); got[40000] || !got[40001] {
		t.Fatalf("category:advertising = %v", got)
	}
	if got := filtered("owner!=google"); got[40000] || got[40001] || !got[50000] {
		t.Fatalf("owner!=google = %v", got)
	}
	if got := filtered("owner:amazon AND dst.port:443"); len(got) != 0 {
		t.Fatalf("owner:amazon = %v", got)
	}
}
