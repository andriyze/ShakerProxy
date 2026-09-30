package ingest

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestEventSummaryUsesPlainLanguage(t *testing.T) {
	three := 3
	zero := 0
	cases := []struct {
		event RecentEvent
		want  string
	}{
		{RecentEvent{Source: SourceZeek, Kind: "zeek.dns", DNSQuery: "api.example.com", DNSRecordType: "A", DNSResponseCode: "NOERROR", DNSAnswerCount: &three}, "DNS lookup api.example.com (A) → 3 answers"},
		{RecentEvent{Source: SourceSuricata, Kind: "suricata.dns", DNSQuery: "missing.example", DNSRecordType: "AAAA", DNSResponseCode: "NXDOMAIN", DNSAnswerCount: &zero}, "DNS lookup missing.example (AAAA) → NXDOMAIN"},
		{RecentEvent{Source: SourceMitmproxy, Kind: "encrypted_dns_detected", DNSQuery: "tracker.example", DNSRecordType: "A"}, "Encrypted DNS (DoH) lookup tracker.example (A)"},
		{RecentEvent{Source: SourceMitmproxy, Kind: "tls_intercepted", TLSServerName: "api.example.com", TLSInterceptionState: "INTERCEPTED"}, "HTTPS api.example.com — decrypted"},
		{RecentEvent{Source: SourceMitmproxy, Kind: "tls_interception_failed", TLSServerName: "api.example.com", TLSInterceptionState: "FAILED", TLSPinningSuspected: true, TLSFailureReason: "probable_certificate_pinning_or_custom_trust_store"}, "HTTPS api.example.com — not decrypted (pinned?)"},
		{RecentEvent{Source: SourceMitmproxy, Kind: "tls_passthrough", TLSServerName: "bank.example", TLSInterceptionState: "BYPASSED"}, "HTTPS bank.example — not decrypted (bypassed)"},
		{RecentEvent{Source: SourceMitmproxy, Kind: "http_response", HTTPMethod: "GET", HTTPHost: "api.example.com", HTTPPath: "/v1/status", HTTPStatus: 200}, "GET api.example.com/v1/status → 200"},
		{RecentEvent{Source: SourceZeek, Kind: "zeek.conn", AppProtocol: "mqtt", DestinationIP: "3.4.5.6", DestinationPort: 1883, NetworkBytes: 12 * 1024}, "MQTT to 3.4.5.6:1883 · 12 KB"},
		{RecentEvent{Source: SourceSuricata, Kind: "suricata.flow", AppProtocol: "unknown-udp", DestinationIP: "5.6.7.8", DestinationPort: 34567, NetworkBytes: 2048}, "Unidentified UDP to 5.6.7.8:34567 · 2 KB"},
		{RecentEvent{Source: SourceZeek, Kind: "zeek.conn", AppProtocol: "tls", DestinationIP: "2001:db8::1", DestinationPort: 443}, "TLS to [2001:db8::1]:443"},
		{RecentEvent{Source: SourceSuricata, Kind: "suricata.alert", AlertSignature: "ET POLICY Telnet login", AlertSeverity: 1}, "Alert (HIGH): ET POLICY Telnet login"},
		{RecentEvent{Source: SourceHost, Kind: "shakerproxy.detection.rogue_dhcp", DetectionSeverity: "HIGH", DetectionSummary: "Unexpected DHCP server 10.77.0.9"}, "ShakerProxy detection (HIGH): Unexpected DHCP server 10.77.0.9"},
		{RecentEvent{Source: SourceZeek, Kind: "zeek.weird", SourceIP: "10.77.0.2", DestinationIP: "1.2.3.4", DestinationPort: 80}, "Zeek weird event: 10.77.0.2 → 1.2.3.4:80"},
	}
	for _, testCase := range cases {
		if got := EventSummary(testCase.event); got != testCase.want {
			t.Fatalf("EventSummary(%s) = %q, want %q", testCase.event.Kind, got, testCase.want)
		}
	}
}

func TestEventSummaryIsBoundedAndSingleLine(t *testing.T) {
	event := RecentEvent{Source: SourceSuricata, Kind: "suricata.alert", AlertSignature: strings.Repeat("é", 250), AlertSeverity: 2}
	summary := EventSummary(event)
	if utf8.RuneCountInString(summary) != MaxEventSummaryRunes || !strings.HasSuffix(summary, "…") || !validEventSummary(summary) {
		t.Fatalf("summary was not bounded: %d %q", utf8.RuneCountInString(summary), summary)
	}
	if summary := EventSummary(RecentEvent{Source: SourceMitmproxy, Kind: "http_request", HTTPMethod: "GET", HTTPHost: "a.example", HTTPPath: "/x"}); strings.ContainsAny(summary, "?#\n") {
		t.Fatalf("summary leaked a query string or newline: %q", summary)
	}
}
