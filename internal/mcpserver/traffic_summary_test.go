package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"shakerproxy.dev/shakerproxy/internal/ingest"
	"shakerproxy.dev/shakerproxy/internal/querylang"
)

func fakeTrafficSummary() ingest.TrafficSummary {
	from := time.Date(2026, 10, 2, 11, 0, 0, 0, time.UTC)
	summary := ingest.TrafficSummary{Schema: 1, GeneratedAt: from.Add(time.Hour), From: from, To: from.Add(time.Hour), BucketSeconds: 1800, Buckets: []ingest.TrafficSummaryBucket{
		{Start: from, Counts: ingest.StreamTypeCounts{DNS: 1200, TLS: 30}},
		{Start: from.Add(30 * time.Minute), Counts: ingest.StreamTypeCounts{DNS: 40, QUIC: 5, Blocked: 2}},
	}}
	summary.Totals = ingest.TrafficSummaryTotals{Events: 1277, BytesSent: 2_100_000, BytesReceived: 48_000_000, Types: ingest.StreamTypeCounts{DNS: 1240, TLS: 30, QUIC: 5, Blocked: 2}}
	summary.Facets = []ingest.TrafficSummaryFacet{
		{Field: ingest.SummaryFacetDevice, Values: []ingest.TrafficSummaryFacetValue{{Value: tvID, Label: "Living room TV", Count: 1270}, {Value: "ip:10.77.0.9", Label: "10.77.0.9", Count: 7}}, Exact: true},
		{Field: ingest.SummaryFacetType, Values: []ingest.TrafficSummaryFacetValue{{Value: "dns", Count: 1240}, {Value: "tls", Count: 30}, {Value: "quic", Count: 5}, {Value: "blocked", Count: 2}}, Exact: true},
		{Field: ingest.SummaryFacetOrganization, Values: []ingest.TrafficSummaryFacetValue{{Value: "Samsung", Count: 900}}, OtherCount: 100, SampledEvents: 1000},
		{Field: ingest.SummaryFacetCategory, Values: []ingest.TrafficSummaryFacetValue{{Value: "Advertising & tracking", Count: 900}}, OtherCount: 100, SampledEvents: 1000},
		{Field: ingest.SummaryFacetDestinationPort, Values: []ingest.TrafficSummaryFacetValue{{Value: "53", Count: 1240}}, OtherCount: 37, Exact: true},
		{Field: ingest.SummaryFacetAppProtocol, Values: []ingest.TrafficSummaryFacetValue{}, OtherCount: 1277, Exact: true},
	}
	return summary
}

func TestTrafficSummaryToolScopesTheQueryAndSummarizes(t *testing.T) {
	backend := newFakeBackend()
	backend.summary = fakeTrafficSummary()
	session := connect(t, backend)
	called, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: toolTrafficSummary, Arguments: json.RawMessage(`{"device":"tv","window":"1h","query":"NOT service:ntp","buckets":2}`)})
	if err != nil || called.IsError {
		t.Fatalf("traffic_summary failed: %v %#v", err, called)
	}
	request := backend.summaries[len(backend.summaries)-1]
	if request.Query != "time:last_1h AND device.id:"+tvID+" AND (NOT service:ntp)" || request.Buckets != 2 {
		t.Fatalf("summary request: %#v", request)
	}
	if _, err := querylang.Parse(request.Query); err != nil {
		t.Fatalf("built-in summary query does not parse: %v", err)
	}
	var result trafficSummaryResult
	decodeToolResult(t, called, &result)
	for _, fragment := range []string{
		"1,277 events in the last hour for Living room TV matching NOT service:ntp: 1,240 DNS, 30 TLS, 5 QUIC, 2 blocked; sent 2.1 MB, received 48 MB.",
		"Top devices: Living room TV 1,270, 10.77.0.9 7.",
		"Top destinations: Samsung 900 (of the newest 1,000 events).",
	} {
		if !strings.Contains(result.Summary, fragment) {
			t.Errorf("summary lacks %q: %s", fragment, result.Summary)
		}
	}
	if result.Totals.Types["dns"] != 1240 || len(result.Timeline) != 2 || result.Timeline[1].Events != 47 || result.Timeline[1].Types["blocked"] != 2 {
		t.Fatalf("structured result: %+v", result)
	}
	if _, ok := result.Facets["type"]; ok || result.Facets["organization"].SampledEvents != 1000 || result.Facets["device"].Values[0].Label != "Living room TV" {
		t.Fatalf("facets: %+v", result.Facets)
	}

	for _, arguments := range []string{`{"buckets":61}`, `{"window":"2h"}`, `{"device":"toaster"}`, `{"query":"` + strings.Repeat("a", 1537) + `"}`} {
		failed, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: toolTrafficSummary, Arguments: json.RawMessage(arguments)})
		if err != nil || !failed.IsError {
			t.Errorf("%s was accepted: %v %#v", arguments, err, failed)
		}
	}
}

func TestTrafficSummaryToolDefaultsToTheLab(t *testing.T) {
	backend := newFakeBackend()
	backend.summary = fakeTrafficSummary()
	service := &Service{backend: backend}
	if _, _, err := service.trafficSummary(context.Background(), nil, TrafficSummaryArgs{}); err != nil {
		t.Fatal(err)
	}
	if request := backend.summaries[0]; request.Query != "time:last_24h" || request.Buckets != defaultSummaryBuckets {
		t.Fatalf("default request: %#v", request)
	}
	if line := trafficSummaryLine(ingest.TrafficSummary{}, "in the last hour"); line != "0 events in the last hour." {
		t.Fatalf("empty summary line: %q", line)
	}
	for value, want := range map[int64]string{0: "0 B", 999: "999 B", 1500: "1.5 kB", 48_000_000: "48 MB", 3_200_000_000: "3.2 GB"} {
		if got := formatBytes(value); got != want {
			t.Errorf("formatBytes(%d) = %q, want %q", value, got, want)
		}
	}
	for value, want := range map[int64]string{7: "7", 1277: "1,277", 1234567: "1,234,567", 100000: "100,000"} {
		if got := formatCount(value); got != want {
			t.Errorf("formatCount(%d) = %q, want %q", value, got, want)
		}
	}
}
