package ingest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const summaryTestDevice = "device-0123456789abcdef0123456789abcdef"

func TestParseInternalProtocolSummaryQueryIsBounded(t *testing.T) {
	query, err := ParseInternalProtocolSummaryQuery(url.Values{"window_seconds": {"604800"}, "device_id": {summaryTestDevice}, "category": {"iot-messaging"}, "exotic": {"true"}})
	if err != nil || query.WindowSeconds != 604800 || query.DeviceID != summaryTestDevice || query.Category != "iot-messaging" || query.Exotic == nil || !*query.Exotic {
		t.Fatalf("unexpected query: %#v %v", query, err)
	}
	if query, err := ParseInternalProtocolSummaryQuery(url.Values{}); err != nil || query.WindowSeconds != 86400 {
		t.Fatalf("default window is not 24h: %#v %v", query, err)
	}
	for _, values := range []url.Values{
		{"window_seconds": {"60"}}, {"device_id": {"tv"}}, {"category": {"gaming"}}, {"exotic": {"maybe"}},
		{"limit": {"5"}}, {"window_seconds": {"3600", "86400"}},
	} {
		if _, err := ParseInternalProtocolSummaryQuery(values); err == nil {
			t.Fatalf("invalid query was accepted: %v", values)
		}
	}
}

func summaryBuilderFixture(query ProtocolSummaryQuery) ProtocolSummary {
	end := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	start := end.Add(-time.Duration(query.WindowSeconds) * time.Second)
	builder := newProtocolSummaryBuilder(query, end, start)
	rows := []protocolSummaryRow{
		{kind: "flow", protocol: "mqtt", visibility: "CLEARTEXT", firstCount: 12, secondCount: 2, bytes: 3456},
		{kind: "event", protocol: "mqtt", visibility: "CLEARTEXT", firstCount: 20, secondCount: 1, firstAt: end.Add(-time.Hour), lastAt: end.Add(-time.Minute), firstFlag: true},
		{kind: "device", protocol: "mqtt", deviceID: summaryTestDevice, firstCount: 10, bytes: 3000, lastAt: end.Add(-time.Minute), rank: 1},
		{kind: "port", protocol: "mqtt", label: "tcp", port: 1883, firstCount: 12, rank: 1},
		{kind: "first_ever", protocol: "mqtt", firstAt: end.Add(-time.Hour)},
		{kind: "flow", protocol: "tls", visibility: "DECRYPTED", firstCount: 3, bytes: 9000},
		{kind: "event", protocol: "tls", visibility: "ENCRYPTED_METADATA", firstCount: 5, firstAt: end.Add(-2 * time.Hour), lastAt: end.Add(-time.Hour), firstFlag: true},
		{kind: "first_ever", protocol: "tls", firstAt: end.Add(-40 * 24 * time.Hour)},
		{kind: "event", protocol: "doh", visibility: "DECRYPTED", firstCount: 2, firstAt: end.Add(-time.Hour), lastAt: end.Add(-time.Hour)},
		{kind: "first_ever", protocol: "doh", firstAt: end.Add(-time.Hour)},
		{kind: "flow", protocol: "unknown-udp", visibility: "OPAQUE", firstCount: 1, bytes: 1544},
		{kind: "event", protocol: "unknown-udp", visibility: "OPAQUE", firstCount: 1, firstAt: end.Add(-time.Minute), lastAt: end.Add(-time.Minute)},
		{kind: "coverage", visibility: "CLEARTEXT", bytes: 3456},
		{kind: "coverage", visibility: "DECRYPTED", bytes: 9000},
		{kind: "coverage", visibility: "OPAQUE", bytes: 1544},
		{kind: "source", label: "ZEEK"},
		{kind: "source", label: "MITMPROXY"},
		{kind: "scanned", firstCount: 44},
	}
	for _, row := range rows {
		builder.add(row)
	}
	return builder.build()
}

func TestProtocolSummaryBuilderAppliesContractSemantics(t *testing.T) {
	query := ProtocolSummaryQuery{WindowSeconds: 86400}
	summary := summaryBuilderFixture(query)
	if err := summary.Validate(query); err != nil {
		t.Fatal(err)
	}
	if len(summary.Protocols) != 4 || summary.Protocols[0].Protocol != "tls" || summary.Protocols[1].Protocol != "mqtt" {
		t.Fatalf("protocols are not ordered by bytes: %#v", summary.Protocols)
	}
	tls, mqtt := summary.Protocols[0], summary.Protocols[1]
	if tls.Visibility != "DECRYPTED" || tls.Novel || !mqtt.Novel || !mqtt.Exotic || mqtt.Label != "MQTT" || mqtt.Category != "iot-messaging" || mqtt.Evidence != "ANALYZER" || mqtt.Flows != 12 || mqtt.UnattributedFlows != 2 || mqtt.Events != 20 {
		t.Fatalf("protocol usage lost contract fields: tls=%#v mqtt=%#v", tls, mqtt)
	}
	doh := summary.Protocols[3]
	if doh.Protocol != "doh" || doh.Flows != 0 || doh.Events != 2 || doh.Evidence != "UNCLASSIFIED" || doh.Visibility != "DECRYPTED" || len(doh.Ports) != 0 || doh.Devices == nil {
		t.Fatalf("evidence-only protocol is wrong: %#v", doh)
	}
	if summary.Coverage.TotalBytes != 14000 || summary.Coverage.OpaquePercent != 11 || summary.Coverage.DecryptedBytes != 9000 {
		t.Fatalf("coverage is wrong: %#v", summary.Coverage)
	}
	if len(summary.Sources) != 2 || summary.Sources[0] != SourceZeek || summary.Sources[1] != SourceMitmproxy || summary.Truncated {
		t.Fatalf("sources or truncation are wrong: %#v %v", summary.Sources, summary.Truncated)
	}
	encoded, _ := json.Marshal(summary)
	for _, field := range []string{`"schema":1`, `"window":"24h"`, `"window_start":`, `"coverage":{"total_bytes":14000`, `"truncated":false`, `"novel":true`} {
		if !strings.Contains(string(encoded), field) {
			t.Fatalf("encoded summary missing %s: %s", field, encoded)
		}
	}
	if strings.Contains(string(encoded), `"device_id":""`) {
		t.Fatalf("unfiltered summary must omit device_id: %s", encoded)
	}
}

func TestProtocolSummaryBuilderFiltersAndBounds(t *testing.T) {
	exotic := true
	query := ProtocolSummaryQuery{WindowSeconds: 86400, Exotic: &exotic}
	summary := summaryBuilderFixture(query)
	for _, usage := range summary.Protocols {
		if !usage.Exotic {
			t.Fatalf("exotic filter kept %s", usage.Protocol)
		}
	}
	if summary.Coverage.TotalBytes != 14000 {
		t.Fatalf("coverage must describe every protocol in scope: %#v", summary.Coverage)
	}
	end := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	builder := newProtocolSummaryBuilder(ProtocolSummaryQuery{WindowSeconds: 3600}, end, end.Add(-time.Hour))
	builder.add(protocolSummaryRow{kind: "event", protocol: "mqtt", firstCount: 1, firstAt: end.Add(-time.Minute), lastAt: end.Add(-time.Minute)})
	builder.add(protocolSummaryRow{kind: "device", protocol: "mqtt", deviceID: summaryTestDevice, rank: MaxSummaryDevicesPerProtocol + 1, lastAt: end})
	if !builder.build().Truncated {
		t.Fatal("device bound overflow was not reported as truncated")
	}
}

func TestProtocolSummaryValidateRejectsOutOfScopeResponses(t *testing.T) {
	query := ProtocolSummaryQuery{WindowSeconds: 86400, DeviceID: summaryTestDevice}
	summary := summaryBuilderFixture(ProtocolSummaryQuery{WindowSeconds: 86400})
	if err := summary.Validate(query); err == nil {
		t.Fatal("summary without the requested device scope was accepted")
	}
	forged := summaryBuilderFixture(ProtocolSummaryQuery{WindowSeconds: 86400})
	forged.Protocols[0].Label = "Not TLS"
	if err := forged.Validate(ProtocolSummaryQuery{WindowSeconds: 86400}); err == nil {
		t.Fatal("summary with a forged catalog label was accepted")
	}
	forged = summaryBuilderFixture(ProtocolSummaryQuery{WindowSeconds: 86400})
	forged.Coverage.OpaqueBytes++
	if err := forged.Validate(ProtocolSummaryQuery{WindowSeconds: 86400}); err == nil {
		t.Fatal("summary with inconsistent coverage was accepted")
	}
}

func TestProtocolSummaryClientValidatesAndRejectsNames(t *testing.T) {
	query := ProtocolSummaryQuery{WindowSeconds: 86400, Category: "iot-messaging"}
	summary := summaryBuilderFixture(query)
	var body []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/protocol-summary" || r.URL.Query().Get("window_seconds") != "86400" || r.URL.Query().Get("category") != "iot-messaging" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("t", 32) {
			t.Fatalf("unexpected protocol summary request: %s %v", r.URL, r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer server.Close()
	client, err := NewQueryClient(server.URL, []byte(strings.Repeat("t", 32)), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	body, _ = json.Marshal(summary)
	result, err := client.QueryProtocolSummary(context.Background(), query)
	if err != nil || len(result.Protocols) != 1 || result.Protocols[0].Protocol != "mqtt" {
		t.Fatalf("client rejected a valid summary: %#v %v", result, err)
	}
	summary.Protocols[0].Devices[0].DeviceName = "Bench camera"
	body, _ = json.Marshal(summary)
	if _, err := client.QueryProtocolSummary(context.Background(), query); err == nil {
		t.Fatal("client accepted device names from storage")
	}
	body = []byte(`{"schema":1,"extra":true}`)
	if _, err := client.QueryProtocolSummary(context.Background(), query); err == nil {
		t.Fatal("client accepted an unknown field")
	}
}
