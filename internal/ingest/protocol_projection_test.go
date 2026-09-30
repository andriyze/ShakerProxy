package ingest

import (
	"encoding/json"
	"strings"
	"testing"
)

func projectFixture(source Source, kind, payload string) EventProjection {
	return ProjectEvent(Envelope{Source: source, Kind: kind, Payload: json.RawMessage(payload)})
}

func TestProjectEventClassifiesAnalyzerFlows(t *testing.T) {
	quic := projectFixture(SourceZeek, "zeek.conn", `{"id.orig_h":"10.77.0.20","id.resp_h":"142.250.1.1","id.orig_p":50000,"id.resp_p":443,"proto":"udp","service":"quic,ssl","orig_ip_bytes":1000,"resp_ip_bytes":9000}`)
	if quic.Network.Service != "quic" || quic.Protocol.AppProtocol != "quic" || quic.Protocol.Evidence != "ANALYZER" || quic.Protocol.Visibility != "ENCRYPTED_METADATA" || quic.Protocol.Exotic {
		t.Fatalf("comma-separated Zeek service was not classified: %#v", quic)
	}
	websocket := projectFixture(SourceZeek, "zeek.conn", `{"id.orig_h":"10.77.0.20","id.resp_h":"1.2.3.4","id.orig_p":50001,"id.resp_p":80,"proto":"tcp","service":"http,websocket"}`)
	if websocket.Network.Service != "http" || websocket.Protocol.AppProtocol != "websocket" {
		t.Fatalf("classification did not see the full Zeek analyzer list: %#v", websocket)
	}
	mqtt := projectFixture(SourceZeek, "zeek.conn", `{"id.orig_h":"10.77.0.21","id.resp_h":"3.4.5.6","id.orig_p":40000,"id.resp_p":1883,"proto":"tcp","orig_bytes":100,"resp_bytes":200}`)
	if mqtt.Protocol.AppProtocol != "mqtt" || mqtt.Protocol.Evidence != "PORT_HEURISTIC" || !mqtt.Protocol.Exotic || mqtt.Protocol.Category != "iot-messaging" || mqtt.Protocol.Visibility != "CLEARTEXT" {
		t.Fatalf("MQTT port heuristic was not classified: %#v", mqtt.Protocol)
	}
	unknown := projectFixture(SourceSuricata, "suricata.flow", `{"src_ip":"10.77.0.22","dest_ip":"5.6.7.8","src_port":40000,"dest_port":34567,"proto":"UDP","app_proto":"failed","flow":{"bytes_toserver":1024,"bytes_toclient":1024}}`)
	if unknown.Protocol.AppProtocol != "unknown-udp" || unknown.Protocol.Visibility != "OPAQUE" || unknown.Protocol.Evidence != "UNCLASSIFIED" {
		t.Fatalf("unidentified UDP was not reported as a coverage gap: %#v", unknown.Protocol)
	}
}

func TestProjectEventMakesDNSRecordsFindableByService(t *testing.T) {
	zeek := projectFixture(SourceZeek, "zeek.dns", `{"id.orig_h":"10.77.0.20","id.resp_h":"10.77.0.1","id.orig_p":5353,"id.resp_p":53,"proto":"udp","query":"api.example.com","qtype_name":"A","rcode_name":"NOERROR","answers":["1.2.3.4","1.2.3.5"]}`)
	if zeek.Network.Service != "dns" || zeek.Protocol.AppProtocol != "dns" || zeek.DNS.Query != "api.example.com" {
		t.Fatalf("Zeek dns.log record is not service:dns: %#v", zeek)
	}
	request := projectFixture(SourceSuricata, "suricata.dns", `{"src_ip":"10.77.0.20","dest_ip":"10.77.0.1","src_port":5353,"dest_port":53,"proto":"UDP","dns":{"version":3,"type":"request","rrname":"api.example.com","rrtype":"A","rcode":"NOERROR"}}`)
	if request.Network.Service != "dns" || request.Protocol.AppProtocol != "dns" || request.DNS.ResponseCode != "" {
		t.Fatalf("Suricata DNS request was mis-projected: %#v", request)
	}
	doh := projectFixture(SourceMitmproxy, "encrypted_dns_detected", `{"source_ip":"10.77.0.20","source_port":51000,"destination_ip":"8.8.8.8","destination_port":443,"protocol":"tcp","service":"doh","hostname":"dns.google","decrypted":true,"query_name":"Tracker.Example.","query_type":"aaaa"}`)
	if doh.DNS.Query != "tracker.example" || doh.DNS.RecordType != "AAAA" || doh.Protocol.AppProtocol != "doh" || doh.Protocol.Visibility != "DECRYPTED" || doh.Protocol.Category != "encrypted-dns" {
		t.Fatalf("DoH query name was not projected: %#v", doh)
	}
	undecoded := projectFixture(SourceMitmproxy, "encrypted_dns_detected", `{"service":"doh","query_name":"","query_type":""}`)
	if undecoded.DNS.Query != "" {
		t.Fatalf("undecodable DoH question was projected as a name: %#v", undecoded.DNS)
	}
}

func TestProjectEventUsesInterceptionStateForVisibility(t *testing.T) {
	intercepted := projectFixture(SourceMitmproxy, "tls_intercepted", `{"source_ip":"10.77.0.30","source_port":51000,"destination_ip":"1.2.3.4","destination_port":443,"protocol":"tcp","service":"tls","sni":"api.example.com","decrypted":true}`)
	if intercepted.Protocol.AppProtocol != "tls" || intercepted.Protocol.Visibility != "DECRYPTED" || intercepted.TLS.InterceptionState != "INTERCEPTED" {
		t.Fatalf("intercepted TLS was not DECRYPTED: %#v", intercepted)
	}
	bypassed := projectFixture(SourceMitmproxy, "tls_passthrough", `{"source_ip":"10.77.0.30","source_port":51001,"destination_ip":"1.2.3.4","destination_port":443,"protocol":"tcp","service":"tls","sni":"bank.example.com","reason":"policy_bypass"}`)
	if bypassed.Protocol.Visibility != "ENCRYPTED_METADATA" {
		t.Fatalf("bypassed TLS was reported as decrypted: %#v", bypassed.Protocol)
	}
	plainHTTP := projectFixture(SourceMitmproxy, "http_request", `{"source_ip":"10.77.0.30","source_port":51002,"destination_ip":"1.2.3.4","destination_port":80,"protocol":"tcp","service":"http","http_method":"get","http_scheme":"http","http_host":"Example.COM","http_port":80,"http_path":"/status?token=secret","http_version":"HTTP/1.1","decrypted":false}`)
	if plainHTTP.Protocol.AppProtocol != "http" || plainHTTP.Protocol.Visibility != "CLEARTEXT" || plainHTTP.HTTP.Method != "GET" || plainHTTP.HTTP.Host != "example.com" || plainHTTP.HTTP.Path != "/status" {
		t.Fatalf("plain HTTP was mis-projected: %#v", plainHTTP)
	}
}

func TestProjectEventProjectsPassiveHTTPTLSAndAlerts(t *testing.T) {
	zeekHTTP := projectFixture(SourceZeek, "zeek.http", `{"id.orig_h":"10.77.0.40","id.resp_h":"1.2.3.4","id.orig_p":40000,"id.resp_p":8080,"method":"POST","host":"api.example.com:8080","uri":"/v1/upload?key=secret#frag","status_code":201}`)
	if zeekHTTP.HTTP != (HTTPColumns{Method: "POST", Host: "api.example.com", Path: "/v1/upload", Status: 201}) || zeekHTTP.Network.Service != "http" {
		t.Fatalf("Zeek http.log was not projected: %#v", zeekHTTP)
	}
	suricataHTTP := projectFixture(SourceSuricata, "suricata.http", `{"src_ip":"10.77.0.40","dest_ip":"1.2.3.4","src_port":40001,"dest_port":80,"proto":"TCP","app_proto":"http","http":{"hostname":"CDN.Example.com","url":"http://cdn.example.com/a/b.js?x=1","http_method":"GET","status":304}}`)
	if suricataHTTP.HTTP != (HTTPColumns{Method: "GET", Host: "cdn.example.com", Path: "/a/b.js", Status: 304}) {
		t.Fatalf("Suricata http was not projected: %#v", suricataHTTP.HTTP)
	}
	longPath := projectFixture(SourceZeek, "zeek.http", `{"method":"GET","host":"x.example","uri":"/`+strings.Repeat("a", 600)+`"}`)
	if len(longPath.HTTP.Path) != MaxEventHTTPPathBytes {
		t.Fatalf("HTTP path was not bounded: %d", len(longPath.HTTP.Path))
	}
	zeekTLS := projectFixture(SourceZeek, "zeek.ssl", `{"id.orig_h":"10.77.0.40","id.resp_h":"1.2.3.4","id.orig_p":40002,"id.resp_p":443,"server_name":"Video.Example.com"}`)
	if zeekTLS.TLS.ServerName != "video.example.com" || zeekTLS.TLS.InterceptionState != "" || zeekTLS.Protocol.AppProtocol != "tls" {
		t.Fatalf("Zeek ssl.log SNI was not projected: %#v", zeekTLS)
	}
	suricataTLS := projectFixture(SourceSuricata, "suricata.tls", `{"src_ip":"10.77.0.40","dest_ip":"1.2.3.4","src_port":40003,"dest_port":443,"proto":"TCP","app_proto":"tls","tls":{"sni":"telemetry.example.com","version":"TLS 1.3"}}`)
	if suricataTLS.TLS.ServerName != "telemetry.example.com" {
		t.Fatalf("Suricata TLS SNI was not projected: %#v", suricataTLS.TLS)
	}
	alert := projectFixture(SourceSuricata, "suricata.alert", `{"src_ip":"10.77.0.40","dest_ip":"1.2.3.4","src_port":40004,"dest_port":23,"proto":"TCP","alert":{"signature":"ET POLICY Telnet\nlogin","severity":1,"category":"Potential Corporate Privacy Violation"}}`)
	if alert.Alert.Signature != "ET POLICY Telnet login" || alert.Alert.Severity != 1 || alert.Protocol.AppProtocol != "telnet" {
		t.Fatalf("Suricata alert was not projected: %#v", alert)
	}
}

func TestProjectEventLeavesNonTrafficRecordsUnclassified(t *testing.T) {
	for _, fixture := range []struct {
		source  Source
		kind    string
		payload string
	}{
		{SourceZeek, "zeek.weird", `{"id.orig_h":"10.77.0.40","id.resp_h":"1.2.3.4","name":"bad_TCP_checksum"}`},
		{SourceZeek, "zeek.files", `{"fuid":"F1","mime_type":"text/plain"}`},
		{SourceSuricata, "suricata.stats", `{"stats":{"uptime":1}}`},
		{SourceHost, "shakerproxy.detection.rogue_dhcp", `{"schema":1}`},
	} {
		if projection := projectFixture(fixture.source, fixture.kind, fixture.payload); projection.Protocol.Present() {
			t.Fatalf("%s was classified as traffic: %#v", fixture.kind, projection.Protocol)
		}
	}
}
