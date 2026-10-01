package ingest

import (
	"encoding/json"
	"testing"
)

func TestProjectNetworkFieldsNormalizesZeekAndSuricata(t *testing.T) {
	zeek := Envelope{Source: SourceZeek, Payload: json.RawMessage(`{"id.orig_h":"10.77.0.111","id.resp_h":"2001:db8::1","id.orig_p":54321,"id.resp_p":443,"proto":"TCP","service":"ssl","orig_ip_bytes":120,"resp_ip_bytes":340,"orig_bytes":20,"resp_bytes":40}`)}
	projection := ProjectNetworkFields(zeek)
	if projection.SourceIP != "10.77.0.111" || projection.DestinationIP != "2001:db8::1" || projection.SourcePort != 54321 || projection.DestinationPort != 443 || projection.Protocol != "tcp" || projection.Service != "ssl" || projection.NetworkBytes != 460 {
		t.Fatalf("unexpected Zeek projection: %#v", projection)
	}
	suricata := Envelope{Source: SourceSuricata, Payload: json.RawMessage(`{"src_ip":"10.77.0.112","dest_ip":"1.1.1.1","src_port":53000,"dest_port":53,"proto":"UDP","app_proto":"dns","flow":{"bytes_toserver":72,"bytes_toclient":144}}`)}
	projection = ProjectNetworkFields(suricata)
	if projection.SourceIP != "10.77.0.112" || projection.DestinationIP != "1.1.1.1" || projection.Protocol != "udp" || projection.Service != "dns" || projection.NetworkBytes != 216 {
		t.Fatalf("unexpected Suricata projection: %#v", projection)
	}
}

func TestProjectNetworkFieldsOmitsInvalidAndUntrustedValues(t *testing.T) {
	event := Envelope{Source: SourceSuricata, Payload: json.RawMessage(`{"src_ip":"not-an-ip","dest_ip":123,"src_port":-1,"dest_port":70000,"proto":"tcp\nheader","app_proto":{"bad":true},"flow":{"bytes_toserver":-1,"bytes_toclient":"huge"}}`)}
	if projection := ProjectNetworkFields(event); projection != (NetworkProjection{}) {
		t.Fatalf("invalid fields were projected: %#v", projection)
	}
}

func TestProjectNetworkFieldsRejectsPartialOverflowAndUsesSafeZeekFallback(t *testing.T) {
	overflow := Envelope{Source: SourceZeek, Payload: json.RawMessage(`{"orig_ip_bytes":9223372036854775807,"resp_ip_bytes":1}`)}
	if projection := ProjectNetworkFields(overflow); projection.NetworkBytes != 0 {
		t.Fatalf("overflow produced a partial byte total: %#v", projection)
	}
	fallback := Envelope{Source: SourceZeek, Payload: json.RawMessage(`{"orig_bytes":12,"resp_bytes":34}`)}
	if projection := ProjectNetworkFields(fallback); projection.NetworkBytes != 46 {
		t.Fatalf("safe Zeek byte fallback was not projected: %#v", projection)
	}
}

func TestProjectNetworkFieldsIncludesSafeMitmproxyEndpoints(t *testing.T) {
	event := Envelope{Source: SourceMitmproxy, Payload: json.RawMessage(`{"source_ip":"10.77.0.50","destination_ip":"2001:db8::50","source_port":52100,"destination_port":443,"protocol":"TCP","service":"TLS","network_bytes":999}`)}
	projection := ProjectNetworkFields(event)
	if projection.SourceIP != "10.77.0.50" || projection.DestinationIP != "2001:db8::50" || projection.SourcePort != 52100 || projection.DestinationPort != 443 || projection.Protocol != "tcp" || projection.Service != "tls" || projection.NetworkBytes != 0 {
		t.Fatalf("unexpected mitmproxy network projection: %#v", projection)
	}
}

func TestPassiveAnalyzerProjectionsUseRealSchemas(t *testing.T) {
	zeekSSL, err := NormalizeZeekJSON([]byte(`{"_path":"ssl","ts":1790000000.15,"uid":"CNBUD125J84HhWBWMf","id.orig_h":"10.77.0.23","id.orig_p":50001,"id.resp_h":"93.184.216.34","id.resp_p":443,"server_name":"API.Example.com.","established":false}`), "zeek-8.2.1", "")
	if err != nil {
		t.Fatal(err)
	}
	if projection := ProjectTLSFields(zeekSSL); projection != (TLSProjection{ServerName: "api.example.com"}) {
		t.Fatalf("Zeek ssl.log SNI was not projected: %#v", projection)
	}
	zeekConn, err := NormalizeZeekJSON([]byte(`{"_path":"conn","ts":1790000000.15,"uid":"CkwEze28Lpdsqx4AU1","server_name":"api.example.com","service":"ssl,http"}`), "zeek-8.2.1", "")
	if err != nil {
		t.Fatal(err)
	}
	// ShakerProxy's Zeek policy copies the server name onto conn.log.
	if projection := ProjectTLSFields(zeekConn); projection.ServerName != "api.example.com" {
		t.Fatalf("conn.log server name was not projected: %#v", projection)
	}
	if service := ProjectNetworkFields(zeekConn).Service; service != "ssl" {
		t.Fatalf("multi-service Zeek connection lost its service: %q", service)
	}
	suricataTLS, err := NormalizeSuricataEVE([]byte(`{"timestamp":"2026-09-21T14:13:20.160000+0000","flow_id":1,"event_type":"tls","src_ip":"10.77.0.23","src_port":50001,"dest_ip":"93.184.216.34","dest_port":443,"proto":"TCP","tls":{"sni":"api.example.com","version":"TLS 1.3"}}`), "suricata-8.0.6", "")
	if err != nil {
		t.Fatal(err)
	}
	if projection := ProjectTLSFields(suricataTLS); projection != (TLSProjection{ServerName: "api.example.com"}) {
		t.Fatalf("Suricata tls.sni was not projected: %#v", projection)
	}
	passive := RecentEvent{Source: SourceSuricata, Kind: "suricata.tls", TLSServerName: "api.example.com"}
	if !validTLSProjection(passive) {
		t.Fatal("passive SNI projection was rejected by the query client")
	}
	passive.TLSInterceptionState = "INTERCEPTED"
	if validTLSProjection(passive) {
		t.Fatal("passive analyzer claimed a MITM interception outcome")
	}
}

func TestSuricataDNSRequestDoesNotClaimAResponseCode(t *testing.T) {
	request, _ := NormalizeSuricataEVE([]byte(`{"timestamp":"2026-09-21T14:13:20.000000+0000","flow_id":3419338362,"event_type":"dns","src_ip":"10.77.0.23","src_port":40000,"dest_ip":"10.77.0.1","dest_port":53,"proto":"UDP","dns":{"version":3,"type":"request","id":4660,"rcode":"NOERROR","queries":[{"rrname":"_googlecast._tcp.example.com","rrtype":"A"}]}}`), "suricata-8.0.6", "")
	projection := ProjectDNSFields(request)
	if projection.Query != "_googlecast._tcp.example.com" || projection.RecordType != "A" || projection.ResponseCode != "" {
		t.Fatalf("unexpected Suricata request projection: %#v", projection)
	}
	response, _ := NormalizeSuricataEVE([]byte(`{"timestamp":"2026-09-21T14:13:20.010000+0000","flow_id":3419338362,"event_type":"dns","src_ip":"10.77.0.1","src_port":53,"dest_ip":"10.77.0.23","dest_port":40000,"proto":"UDP","dns":{"version":3,"type":"response","id":4660,"rcode":"NXDOMAIN","queries":[{"rrname":"_googlecast._tcp.example.com","rrtype":"A"}]}}`), "suricata-8.0.6", "")
	if projection := ProjectDNSFields(response); projection.ResponseCode != "NXDOMAIN" {
		t.Fatalf("Suricata response code was not projected: %#v", projection)
	}
}
