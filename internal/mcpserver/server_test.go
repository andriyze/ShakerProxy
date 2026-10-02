package mcpserver

import (
	"context"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/agentapi"
	"shakerproxy.dev/shakerproxy/internal/devicereport"
	"shakerproxy.dev/shakerproxy/internal/ingest"
	"shakerproxy.dev/shakerproxy/internal/querylang"
	"shakerproxy.dev/shakerproxy/internal/testsession"
)

func TestBuiltInQueriesParseWithTheQueryLanguage(t *testing.T) {
	backend := newFakeBackend()
	service := &Service{backend: backend}
	ctx := context.Background()
	if _, _, err := service.deviceActivity(ctx, nil, DeviceActivityArgs{Device: "tv", Window: "7d"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.dnsLookups(ctx, nil, DNSLookupsArgs{Device: "tv", Name: "samsungacr.com"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.dnsLookups(ctx, nil, DNSLookupsArgs{Name: "samsung"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.tlsIssues(ctx, nil, TLSIssuesArgs{Device: "10.77.0.23", Window: "1h"}); err != nil {
		t.Fatal(err)
	}
	for _, search := range backend.searches {
		parsed, err := querylang.Parse(search.Query)
		if err != nil || parsed.Root == nil {
			t.Fatalf("built-in query does not parse: %q: %v", search.Query, err)
		}
	}
	if query := backend.searches[0].Query; query != "time:last_7d AND device.id:"+tvID {
		t.Fatalf("device activity query: %q", query)
	}
}

func TestDNSLookupsCoverAnalyzerLogsAndEncryptedDNS(t *testing.T) {
	backend := newFakeBackend()
	answers := 2
	backend.page.Events = []agentapi.Event{
		{RecentEvent: ingest.RecentEvent{RecordID: strings.Repeat("a", 64), Kind: "zeek.dns", OccurredAt: fakeNow, DNSQuery: "log.samsungacr.com", DNSRecordType: "A", DNSResponseCode: "NOERROR", DNSAnswerCount: &answers}},
		{RecentEvent: ingest.RecentEvent{RecordID: strings.Repeat("b", 64), Kind: "encrypted_dns_detected", Service: "doh", OccurredAt: fakeNow, DestinationIP: "8.8.8.8", DestinationPort: 443}},
	}
	service := &Service{backend: backend}
	result, _, err := service.dnsLookups(context.Background(), nil, DNSLookupsArgs{Device: "tv", Name: "samsungacr.com", Window: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	query := backend.lastSearch().Query
	for _, fragment := range []string{"(kind:shakerproxy.dns OR kind:zeek.dns OR kind:suricata.dns OR kind:encrypted_dns_detected OR service:doh)", "device.id:" + tvID, "(dns.query:samsungacr.com OR dns.query:*.samsungacr.com)", "time:last_1h"} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("DNS query %q lacks %q", query, fragment)
		}
	}
	if strings.Contains(query, "service:dns ") || strings.HasSuffix(query, "service:dns") {
		t.Fatalf("DNS query still relies on service:dns: %q", query)
	}
	var data struct {
		Summary string `json:"summary"`
		Lookups []struct {
			Query     string `json:"query"`
			Answers   *int   `json:"answers"`
			Encrypted bool   `json:"encrypted"`
			Summary   string `json:"summary"`
		} `json:"lookups"`
	}
	decodeToolResult(t, result, &data)
	if len(data.Lookups) != 2 || data.Lookups[0].Summary != "DNS lookup log.samsungacr.com (A) → 2 answers" || !data.Lookups[1].Encrypted || !strings.Contains(data.Summary, "1 used encrypted DNS") {
		t.Fatalf("DNS result: %#v", data)
	}
	for _, name := range []string{"bad name", "x) OR (kind:*", "a**b"} {
		if _, _, err := service.dnsLookups(context.Background(), nil, DNSLookupsArgs{Name: name}); err == nil {
			t.Fatalf("unsafe DNS name %q was accepted", name)
		}
	}
}

func TestTLSIssuesUseExactPinningReasons(t *testing.T) {
	backend := newFakeBackend()
	event := func(id byte, state, reason string, suspected bool) agentapi.Event {
		return agentapi.Event{RecentEvent: ingest.RecentEvent{RecordID: strings.Repeat(string(id), 64), Kind: "tls_interception_failed", OccurredAt: fakeNow, TLSServerName: "host-" + string(id) + ".example.com", TLSInterceptionState: state, TLSFailureReason: reason, TLSPinningSuspected: suspected}}
	}
	backend.page.Events = []agentapi.Event{
		event('a', "FAILED", "ca_not_trusted_or_pinning", false),
		event('b', "FAILED", "probable_certificate_pinning_or_custom_trust_store", true),
		event('c', "FAILED", "dynamic_probable_pinning_bypass", false),
		event('d', "BYPASSED", "", false),
	}
	backend.page.NextCursor = "cursor-2"
	service := &Service{backend: backend}
	result, _, err := service.tlsIssues(context.Background(), nil, TLSIssuesArgs{Device: "tv"})
	if err != nil {
		t.Fatal(err)
	}
	if query := backend.lastSearch().Query; !strings.Contains(query, "(source:MITMPROXY AND (tls.state:FAILED OR tls.state:BYPASSED))") || !strings.HasPrefix(query, "time:last_24h") {
		t.Fatalf("TLS query: %q", query)
	}
	var data struct {
		Summary string `json:"summary"`
		Scanned int    `json:"scanned"`
		Issues  []struct {
			Host          string `json:"host"`
			PinningLikely bool   `json:"pinning_likely"`
			Summary       string `json:"summary"`
		} `json:"issues"`
		NextCursor string `json:"next_cursor"`
	}
	decodeToolResult(t, result, &data)
	likely := map[string]bool{}
	for _, issue := range data.Issues {
		likely[issue.Host] = issue.PinningLikely
	}
	if likely["host-a.example.com"] || !likely["host-b.example.com"] || !likely["host-c.example.com"] || likely["host-d.example.com"] || data.NextCursor != "cursor-2" || !strings.Contains(data.Summary, "2 look like certificate pinning") {
		t.Fatalf("pinning classification: %#v", data)
	}
	result, _, err = service.tlsIssues(context.Background(), nil, TLSIssuesArgs{PinningOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	decodeToolResult(t, result, &data)
	if len(data.Issues) != 2 || data.Scanned != 4 || !strings.Contains(data.Summary, "Scanned 4 events") {
		t.Fatalf("pinning-only: %#v", data)
	}
}

func TestDeviceReportResolvesReferenceAndCompactsOutput(t *testing.T) {
	backend := newFakeBackend()
	report := devicereport.Report{
		Schema: 1, GeneratedAt: fakeNow, WindowStart: fakeNow.Add(-24 * time.Hour), WindowEnd: fakeNow, CATrust: devicereport.CATrustUnknown,
		Device:  devicereport.Device{DeviceID: tvID, FriendlyName: "Living room TV", Addresses: []string{"10.77.0.23"}, HardwareAddresses: []string{"52:54:00:aa:bb:23"}},
		Summary: "Living room TV contacted 70 domains.", Totals: devicereport.Totals{Events: 100},
		TLS:      devicereport.TLS{Intercepted: 2, Failed: 1, FailedHosts: []string{"a.example.com"}, InterceptedHosts: []string{}, OldVersions: []devicereport.OldTLSVersion{}},
		HTTP:     devicereport.HTTP{CleartextRequests: 3},
		Findings: []devicereport.Finding{{ID: "cleartext-http", Severity: devicereport.SeverityMedium, Title: "Device sends unencrypted HTTP", Evidence: []string{"x"}}},
	}
	for index := 0; index < 70; index++ {
		category := "telemetry"
		if index%2 == 0 {
			category = "advertising"
		}
		report.Domains = append(report.Domains, devicereport.Domain{Domain: strings.Repeat("d", index%5+1) + ".example.com", Category: category, Sources: []string{"dns"}, Events: 1})
	}
	backend.report = report
	service := &Service{backend: backend}
	result, _, err := service.deviceReport(context.Background(), nil, DeviceReportArgs{Device: "tv", Window: "24h"})
	if err != nil {
		t.Fatal(err)
	}
	if backend.reportRequest.DeviceID != tvID || backend.reportRequest.Window != "24h" || backend.resolved[0] != "tv" {
		t.Fatalf("report request: %#v resolved=%v", backend.reportRequest, backend.resolved)
	}
	var data reportResult
	decodeToolResult(t, result, &data)
	if len(data.Domains) != maxReportDomains || data.OmittedDomains != 10 || data.DomainsByCategory["advertising"] != 35 || data.DomainsByCategory["telemetry"] != 35 || len(data.Findings) != 1 {
		t.Fatalf("compact report: %#v", data)
	}
	steps := strings.Join(data.NextSteps, " ")
	for _, fragment := range []string{"CA is installed", "http_requests", "tls_issues"} {
		if !strings.Contains(steps, fragment) {
			t.Fatalf("next steps lack %q: %v", fragment, data.NextSteps)
		}
	}
	if strings.Contains(rawToolText(t, result), "52:54:00") {
		t.Fatal("report output leaked a hardware address to the agent")
	}
	if _, _, err := service.deviceReport(context.Background(), nil, DeviceReportArgs{Device: "tv", Window: "24h", Session: "ts-000000000000000000000001"}); err == nil {
		t.Fatal("window and session together were accepted")
	}
	if _, _, err := service.deviceReport(context.Background(), nil, DeviceReportArgs{Device: "toaster"}); err == nil || !strings.Contains(err.Error(), "list_devices") {
		t.Fatalf("unknown device error: %v", err)
	}
}

func TestCompareRunsDerivesDeviceFromBaseSession(t *testing.T) {
	backend := newFakeBackend()
	backend.session = testsession.Session{Schema: 1, ID: "ts-000000000000000000000001", DeviceID: tvID, Name: "Firmware 1.2", State: testsession.StateRunning, StartedAt: fakeNow, CreatedBy: "admin"}
	backend.comparison = devicereport.Comparison{Schema: 1, DeviceID: tvID, Summary: "Compared with Firmware 1.2, Firmware 1.3: new protocols: mqtt."}
	service := &Service{backend: backend}
	result, _, err := service.compareRuns(context.Background(), nil, CompareRunsArgs{Base: "ts-000000000000000000000001", Compare: "ts-000000000000000000000002"})
	if err != nil {
		t.Fatal(err)
	}
	if backend.compareRequest != (agentapi.CompareRequest{DeviceID: tvID, Base: "ts-000000000000000000000001", Compare: "ts-000000000000000000000002"}) {
		t.Fatalf("compare request: %#v", backend.compareRequest)
	}
	var data devicereport.Comparison
	decodeToolResult(t, result, &data)
	if !strings.Contains(data.Summary, "mqtt") {
		t.Fatalf("comparison: %#v", data)
	}
	if _, _, err := service.compareRuns(context.Background(), nil, CompareRunsArgs{Base: "ts-000000000000000000000001", Compare: "ts-000000000000000000000002", Device: "camera"}); err != nil || backend.compareRequest.DeviceID != cameraID {
		t.Fatalf("explicit device: %#v err=%v", backend.compareRequest, err)
	}
	if _, _, err := service.compareRuns(context.Background(), nil, CompareRunsArgs{Base: "ts-000000000000000000000009", Compare: "ts-000000000000000000000002"}); err == nil || !strings.Contains(err.Error(), "No test session") {
		t.Fatalf("unknown base session: %v", err)
	}
	if _, _, err := service.compareRuns(context.Background(), nil, CompareRunsArgs{Base: "ts-000000000000000000000001"}); err == nil {
		t.Fatal("missing compare session was accepted")
	}
}

func TestTestSessionsAndDevicesSummaries(t *testing.T) {
	backend := newFakeBackend()
	ended := fakeNow.Add(35 * time.Minute)
	backend.sessions = agentapi.TestSessionList{Schema: 1, Total: 1, Sessions: []testsession.Session{{Schema: 1, ID: "ts-000000000000000000000001", DeviceID: tvID, DeviceName: "Living room TV", Name: "Firmware 2.1 first boot", State: testsession.StateStopped, StartedAt: fakeNow, EndedAt: &ended, CreatedBy: "admin"}}}
	backend.devicePage = agentapi.DevicePage{Schema: 1, GeneratedAt: fakeNow, Matched: 2, Returned: 2, Devices: []agentapi.Device{
		{Schema: 1, ID: tvID, DisplayName: "Living room TV", Vendor: "Samsung", Online: true, Addresses: []agentapi.DeviceAddress{{Address: "10.77.0.23", Active: true}, {Address: "10.77.0.99", Active: false}}},
		{Schema: 1, ID: cameraID, DisplayName: "Bench camera", Addresses: []agentapi.DeviceAddress{}},
	}}
	service := &Service{backend: backend}
	result, _, err := service.testSessions(context.Background(), nil, TestSessionsArgs{Device: "tv", State: "stopped"})
	if err != nil {
		t.Fatal(err)
	}
	if backend.sessionsRequest.DeviceID != tvID || backend.sessionsRequest.State != "STOPPED" {
		t.Fatalf("sessions request: %#v", backend.sessionsRequest)
	}
	var sessions sessionList
	decodeToolResult(t, result, &sessions)
	if sessions.Summary != "1 test session for Living room TV, newest first." || sessions.Sessions[0].Summary != `"Firmware 2.1 first boot" on Living room TV, 2026-09-29 12:00 to 12:35 UTC (35 min)` {
		t.Fatalf("sessions: %#v", sessions)
	}
	if _, _, err := service.testSessions(context.Background(), nil, TestSessionsArgs{State: "paused"}); err == nil {
		t.Fatal("invalid state accepted")
	}

	result, _, err = service.listDevices(context.Background(), nil, ListDevicesArgs{Query: " tv ", OnlineOnly: true})
	if err != nil || backend.deviceRequest.Query != "tv" || !backend.deviceRequest.OnlineOnly || backend.deviceRequest.Limit != defaultToolResultLimit {
		t.Fatalf("list devices request: %#v err=%v", backend.deviceRequest, err)
	}
	var devices deviceList
	decodeToolResult(t, result, &devices)
	if devices.Summary != "2 devices (1 online)." || strings.Join(devices.Devices[0].Addresses, ",") != "10.77.0.23" || devices.Devices[0].Summary != "Living room TV (Samsung, 10.77.0.23, online)" {
		t.Fatalf("devices: %#v", devices)
	}

	result, _, err = service.findDevice(context.Background(), nil, FindDeviceArgs{Device: "10.77.0.23"})
	if err != nil {
		t.Fatal(err)
	}
	var found findDeviceResult
	decodeToolResult(t, result, &found)
	if !found.Unique || found.Summary != `"10.77.0.23" is Living room TV (Samsung, 10.77.0.23, online) (matched by name).` || strings.Contains(rawToolText(t, result), "52:54:00") {
		t.Fatalf("find device: %#v %s", found, rawToolText(t, result))
	}
}

func TestSearchTrafficSummarizesEventsAndReadsRecordDetail(t *testing.T) {
	backend := newFakeBackend()
	backend.page.Events = []agentapi.Event{
		{RecentEvent: ingest.RecentEvent{RecordID: strings.Repeat("a", 64), Kind: "zeek.conn", OccurredAt: fakeNow, Protocol: "tcp", Service: "mqtt", DestinationIP: "3.4.5.6", DestinationPort: 1883, NetworkBytes: 12 << 10}},
		{RecentEvent: ingest.RecentEvent{RecordID: strings.Repeat("b", 64), Kind: "zeek.conn", OccurredAt: fakeNow}, Summary: "Server-built summary line"},
		{RecentEvent: ingest.RecentEvent{RecordID: strings.Repeat("c", 64), Kind: "zeek.conn", OccurredAt: fakeNow, Protocol: "udp", DestinationIP: "5.6.7.8", DestinationPort: 34567, NetworkBytes: 2048}},
		{RecentEvent: ingest.RecentEvent{RecordID: strings.Repeat("d", 64), Kind: "tls_intercepted", OccurredAt: fakeNow, TLSServerName: "api.example.com", TLSInterceptionState: "INTERCEPTED"}},
	}
	service := &Service{backend: backend}
	result, _, err := service.searchTraffic(context.Background(), nil, SearchTrafficArgs{Query: "time:last_1h AND dst.port:1883", Limit: 10})
	if err != nil || backend.lastSearch().Query != "time:last_1h AND dst.port:1883" || backend.lastSearch().Limit != 10 {
		t.Fatalf("search request: %#v err=%v", backend.lastSearch(), err)
	}
	var data eventList
	decodeToolResult(t, result, &data)
	want := []string{"MQTT to 3.4.5.6:1883 · 12 KB", "Server-built summary line", "Unidentified UDP to 5.6.7.8:34567 · 2 KB", "HTTPS api.example.com — decrypted"}
	for index, line := range data.Events {
		if line.Summary != want[index] {
			t.Errorf("summary %d = %q, want %q", index, line.Summary, want[index])
		}
	}
	backend.detail = ingest.EventDetail{Schema: 1, Event: backend.page.Events[0].RecentEvent}
	result, _, err = service.searchTraffic(context.Background(), nil, SearchTrafficArgs{RecordID: strings.Repeat("a", 64)})
	if err != nil || !strings.Contains(rawToolText(t, result), "MQTT to 3.4.5.6:1883") {
		t.Fatalf("record detail: %v", err)
	}
	if _, _, err := service.searchTraffic(context.Background(), nil, SearchTrafficArgs{RecordID: "not-a-record"}); err == nil {
		t.Fatal("invalid record ID accepted")
	}
	if _, _, err := service.searchTraffic(context.Background(), nil, SearchTrafficArgs{Limit: 101}); err == nil {
		t.Fatal("unbounded limit accepted")
	}
}

func TestHTTPRequestsAndProtocols(t *testing.T) {
	backend := newFakeBackend()
	decrypted := true
	backend.httpPage.Events = []ingest.HTTPActivityEvent{{RecordID: strings.Repeat("a", 64), OccurredAt: fakeNow, Method: "GET", Scheme: "https", Host: "api.example.com", Path: "/v1/status", Status: 200, Decrypted: &decrypted}}
	service := &Service{backend: backend}
	result, _, err := service.httpRequests(context.Background(), nil, HTTPRequestsArgs{Device: "camera", Host: "api.example.com"})
	if err != nil || backend.httpRequest.DeviceID != cameraID || backend.httpRequest.Window != "24h" || backend.httpRequest.Host != "api.example.com" {
		t.Fatalf("HTTP request: %#v err=%v", backend.httpRequest, err)
	}
	if !strings.Contains(rawToolText(t, result), "GET api.example.com/v1/status → 200 (decrypted HTTPS)") {
		t.Fatalf("HTTP summary: %s", rawToolText(t, result))
	}
	if _, _, err := service.httpRequests(context.Background(), nil, HTTPRequestsArgs{Window: "7d"}); err == nil {
		t.Fatal("HTTP window beyond 24h accepted")
	}

	backend.protocols = agentapi.ProtocolsPage{Schema: 1, Window: "7d", Protocols: []agentapi.ProtocolSummary{{Protocol: "mqtt", Label: "MQTT", Category: "iot-messaging", Visibility: "CLEARTEXT", Exotic: true, Novel: true, Flows: 12}}, Coverage: agentapi.ProtocolCoverage{TotalBytes: 100, OpaqueBytes: 10, OpaquePercent: 10}}
	result, _, err = service.protocols(context.Background(), nil, ProtocolsArgs{Device: "tv", Window: "7d", ExoticOnly: true})
	if err != nil || backend.protocolRequest != (agentapi.ProtocolsRequest{Window: "7d", DeviceID: tvID, Exotic: true}) {
		t.Fatalf("protocols request: %#v err=%v", backend.protocolRequest, err)
	}
	if text := rawToolText(t, result); !strings.Contains(text, "Unusual: MQTT") || !strings.Contains(text, "First seen in this window: MQTT") || !strings.Contains(text, "10% of bytes are opaque") {
		t.Fatalf("protocols summary: %s", text)
	}
	backend.protocolsErr = &agentapi.APIError{Status: 404, Code: "not_found"}
	if _, _, err := service.protocols(context.Background(), nil, ProtocolsArgs{}); err == nil || !strings.Contains(err.Error(), "device_report") {
		t.Fatalf("missing protocol discovery: %v", err)
	}
}

func TestSystemSummaryExplainsLimitations(t *testing.T) {
	overview := readyOverview()
	overview.Overall, overview.EvidenceReady = "DEGRADED", false
	overview.Analyzers[1].Healthy = false
	overview.Limitations = []string{"Suricata is not reporting."}
	summary := systemSummary(overview)
	if !strings.Contains(summary, "reduced evidence") || !strings.Contains(summary, "Zeek healthy") || !strings.Contains(summary, "Limitations: Suricata is not reporting.") {
		t.Fatalf("summary: %q", summary)
	}
}

func TestHumanDuration(t *testing.T) {
	for value, want := range map[time.Duration]string{20 * time.Second: "under a minute", 35 * time.Minute: "35 min", 2 * time.Hour: "2 h", 125 * time.Minute: "2 h 5 min"} {
		if got := humanDuration(value); got != want {
			t.Errorf("humanDuration(%s) = %q, want %q", value, got, want)
		}
	}
}

func TestSummariesAreBounded(t *testing.T) {
	long := agentapi.Event{Summary: strings.Repeat("é", 200)}
	if got := recentEventSummary(long); len(got) > maxSummaryBytes || !strings.HasSuffix(got, "…") {
		t.Fatalf("summary bound: %d %q", len(got), got)
	}
}

func TestNewRejectsMissingBackend(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("nil MCP backend was accepted")
	}
}

func TestToolsRejectOversizedBackendPagesAndInvalidLimits(t *testing.T) {
	backend := newFakeBackend()
	for index := 0; index < 3; index++ {
		backend.page.Events = append(backend.page.Events, agentapi.Event{RecentEvent: ingest.RecentEvent{RecordID: strings.Repeat(string(rune('a'+index)), 64), Kind: "tls_passthrough", TLSInterceptionState: "BYPASSED"}})
		backend.httpPage.Events = append(backend.httpPage.Events, ingest.HTTPActivityEvent{RecordID: strings.Repeat(string(rune('a'+index)), 64)})
	}
	service := &Service{backend: backend}
	ctx := context.Background()
	checks := map[string]func() error{
		"search": func() error { _, _, err := service.searchTraffic(ctx, nil, SearchTrafficArgs{Limit: 2}); return err },
		"activity": func() error {
			_, _, err := service.deviceActivity(ctx, nil, DeviceActivityArgs{Device: "tv", Limit: 2})
			return err
		},
		"dns":  func() error { _, _, err := service.dnsLookups(ctx, nil, DNSLookupsArgs{Limit: 2}); return err },
		"tls":  func() error { _, _, err := service.tlsIssues(ctx, nil, TLSIssuesArgs{Limit: 2}); return err },
		"http": func() error { _, _, err := service.httpRequests(ctx, nil, HTTPRequestsArgs{Limit: 2}); return err },
	}
	for name, check := range checks {
		if err := check(); err == nil || !strings.Contains(err.Error(), "more events than requested") {
			t.Errorf("%s accepted an oversized page: %v", name, err)
		}
	}
	searches := len(backend.searches)
	if _, _, err := service.httpRequests(ctx, nil, HTTPRequestsArgs{Limit: 101}); err == nil {
		t.Fatal("unbounded HTTP limit accepted")
	}
	if _, _, err := service.deviceActivity(ctx, nil, DeviceActivityArgs{Device: "tv", Limit: -1}); err == nil {
		t.Fatal("negative limit accepted")
	}
	if len(backend.searches) != searches {
		t.Fatal("backend was called for an invalid limit")
	}
}

func TestHTTPRequestsNeverExposePlaintextFields(t *testing.T) {
	backend := newFakeBackend()
	decrypted := true
	requestBytes := int64(128)
	backend.httpPage.Events = []ingest.HTTPActivityEvent{{RecordID: strings.Repeat("a", 64), OccurredAt: fakeNow, Method: "POST", Scheme: "https", Host: "api.example.test", Port: 443, Path: "/v1/orders", Status: 201, RequestBytes: &requestBytes, Decrypted: &decrypted, ContentLocalOnly: true}}
	service := &Service{backend: backend}
	result, _, err := service.httpRequests(context.Background(), nil, HTTPRequestsArgs{Host: " API.Example.Test. ", Method: " post ", Window: " 1h "})
	if err != nil || backend.httpRequest.Window != "1h" || backend.httpRequest.Host != "API.Example.Test." || backend.httpRequest.Method != "post" {
		t.Fatalf("HTTP request: %#v err=%v", backend.httpRequest, err)
	}
	encoded := strings.ToLower(rawToolText(t, result))
	for _, forbidden := range []string{"request_headers", "response_headers", "request_body", "response_body", "authorization", "cookie", "?token="} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("MCP HTTP output leaked %q: %s", forbidden, encoded)
		}
	}
}
