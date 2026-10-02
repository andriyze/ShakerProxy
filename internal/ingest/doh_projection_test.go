package ingest

import (
	"encoding/json"
	"testing"
	"time"
)

func dohEnvelope(source Source, kind, payload string) Envelope {
	return Envelope{Schema: SchemaVersion, EventID: "doh-classification-0001", Source: source, Kind: kind, OccurredAt: time.Now(), SourceVersion: "test", ParserVersion: "test", Confidence: 90, Payload: json.RawMessage(payload)}
}

// The visibility coverage check found DoH recorded as plain TLS. It is
// classified from the resolver catalog by server name or resolver address.
func TestDNSOverHTTPSIsClassifiedFromTheResolverCatalog(t *testing.T) {
	for name, testCase := range map[string]struct {
		envelope Envelope
		want     string
	}{
		"server name":                      {dohEnvelope(SourceZeek, "zeek.conn", `{"id.orig_h":"192.168.10.201","id.orig_p":40000,"id.resp_h":"203.0.113.9","id.resp_p":443,"proto":"tcp","service":"ssl","server_name":"mozilla.cloudflare-dns.com"}`), "doh"},
		"resolver address over TCP":        {dohEnvelope(SourceZeek, "zeek.conn", `{"id.orig_h":"192.168.10.201","id.orig_p":40001,"id.resp_h":"8.8.8.8","id.resp_p":443,"proto":"tcp","service":"ssl"}`), "doh"},
		"resolver address over QUIC":       {dohEnvelope(SourceZeek, "zeek.conn", `{"id.orig_h":"192.168.10.201","id.orig_p":40002,"id.resp_h":"2606:4700:4700::1111","id.resp_p":443,"proto":"udp","service":"quic,ssl"}`), "doh"},
		"gateway connection to a resolver": {dohEnvelope(SourceHost, HostConnKind, `{"source_ip":"192.168.10.201","source_port":40003,"destination_ip":"9.9.9.9","destination_port":443,"protocol":"tcp"}`), "doh"},
		"ordinary HTTPS":                   {dohEnvelope(SourceZeek, "zeek.conn", `{"id.orig_h":"192.168.10.201","id.orig_p":40004,"id.resp_h":"140.82.121.4","id.resp_p":443,"proto":"tcp","service":"ssl","server_name":"github.com"}`), "tls"},
		"plain DNS to a resolver":          {dohEnvelope(SourceZeek, "zeek.conn", `{"id.orig_h":"192.168.10.201","id.orig_p":40005,"id.resp_h":"8.8.8.8","id.resp_p":53,"proto":"udp","service":"dns"}`), "dns"},
		"google.com is not dns.google":     {dohEnvelope(SourceZeek, "zeek.conn", `{"id.orig_h":"192.168.10.201","id.orig_p":40006,"id.resp_h":"142.250.1.1","id.resp_p":443,"proto":"tcp","service":"ssl","server_name":"www.google.com"}`), "tls"},
	} {
		projection := ProjectEvent(testCase.envelope)
		if projection.Protocol.AppProtocol != testCase.want {
			t.Fatalf("%s: app protocol = %q, want %q", name, projection.Protocol.AppProtocol, testCase.want)
		}
		if testCase.want == "doh" && (projection.Protocol.Category != "encrypted-dns" || projection.Protocol.Visibility == "") {
			t.Fatalf("%s: projection = %+v", name, projection.Protocol)
		}
	}
	// A refused attempt stays a block, not a DoH connection.
	blocked := ProjectEvent(dohEnvelope(SourceHost, HostBlockedKind, `{"source_ip":"192.168.10.201","destination_ip":"8.8.8.8","destination_port":443,"protocol":"tcp","service":"dns","blocked":true,"reason":"doh-ip"}`))
	if blocked.Protocol.AppProtocol != "" {
		t.Fatalf("a blocked attempt was classified as %q", blocked.Protocol.AppProtocol)
	}
}
