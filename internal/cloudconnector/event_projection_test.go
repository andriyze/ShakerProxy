package cloudconnector

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

func TestProjectNormalizedAlertAsPayloadFreeFlowMetadata(t *testing.T) {
	now := time.Now().UTC()
	raw := []byte(fmt.Sprintf(`{"timestamp":%q,"flow_id":123456,"event_type":"alert","src_ip":"10.77.0.20","src_port":53000,"dest_ip":"198.51.100.10","dest_port":443,"proto":"TCP","app_proto":"tls","flow":{"bytes_toserver":120,"bytes_toclient":340,"age":2},"alert":{"signature_id":9900001,"signature":"Cleartext policy alert","category":"Policy","severity":2},"http":{"request_body":"NEVER_UPLOAD"},"password":"NEVER_UPLOAD"}`, now.Format(time.RFC3339Nano)))
	envelope, err := ingest.NormalizeSuricataEVE(raw, "8.0.6", "")
	if err != nil {
		t.Fatalf("normalize alert: %v", err)
	}
	events := ProjectNormalizedEvents(envelope, now)
	if len(events) != 1 || events[0].Type != MetadataFlowSummary {
		t.Fatalf("unexpected alert projections: %#v", events)
	}
	var payload map[string]any
	if err := json.Unmarshal(events[0].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	attributes, _ := payload["attributes"].(map[string]any)
	if payload["bytes_sent"] != float64(120) || payload["bytes_received"] != float64(340) || payload["duration_ms"] != float64(2000) || attributes["alert"] != true || attributes["alert_signature"] != "Cleartext policy alert" {
		t.Fatalf("alert metadata is incomplete: %#v", payload)
	}
	if encoded := string(events[0].Payload); strings.Contains(encoded, "NEVER_UPLOAD") || strings.Contains(encoded, "request_body") || strings.Contains(encoded, "password") {
		t.Fatalf("cloud projection leaked raw or credential data: %s", encoded)
	}
}

func TestProjectNormalizedDNSAndTLSMetadata(t *testing.T) {
	now := time.Now().UTC()
	dnsRaw := []byte(fmt.Sprintf(`{"timestamp":%q,"flow_id":987,"event_type":"dns","src_ip":"10.77.0.21","src_port":54000,"dest_ip":"1.1.1.1","dest_port":53,"proto":"UDP","dns":{"rrname":"Example.TEST.","rrtype":"A","rcode":"NOERROR","answers":[{"rdata":"198.51.100.20"}]}}`, now.Format(time.RFC3339Nano)))
	dnsEnvelope, err := ingest.NormalizeSuricataEVE(dnsRaw, "8.0.6", "")
	if err != nil {
		t.Fatal(err)
	}
	dnsEvents := ProjectNormalizedEvents(dnsEnvelope, now)
	if len(dnsEvents) != 2 || dnsEvents[0].Type != MetadataFlowSummary || dnsEvents[1].Type != MetadataDNSEvent {
		t.Fatalf("unexpected DNS projections: %#v", dnsEvents)
	}
	var dnsPayload map[string]any
	_ = json.Unmarshal(dnsEvents[1].Payload, &dnsPayload)
	if dnsPayload["query_name"] != "example.test" || dnsPayload["transport"] != "dns-udp" || dnsPayload["encrypted"] != false {
		t.Fatalf("unexpected DNS metadata: %#v", dnsPayload)
	}

	tlsRaw := []byte(fmt.Sprintf(`{"ts":%f,"uid":"Ctls123","_path":"ssl","id.orig_h":"10.77.0.22","id.orig_p":55000,"id.resp_h":"203.0.113.20","id.resp_p":443,"proto":"tcp","service":"ssl","server_name":"api.example.test","next_protocol":"h2","version":"TLSv13","orig_bytes":50,"resp_bytes":75,"duration":0.25}`, float64(now.UnixNano())/1e9))
	tlsEnvelope, err := ingest.NormalizeZeekJSON(tlsRaw, "8.2.1", "")
	if err != nil {
		t.Fatal(err)
	}
	tlsEvents := ProjectNormalizedEvents(tlsEnvelope, now)
	if len(tlsEvents) != 2 || tlsEvents[1].Type != MetadataTLSEvent {
		t.Fatalf("unexpected TLS projections: %#v", tlsEvents)
	}
	var tlsPayload map[string]any
	_ = json.Unmarshal(tlsEvents[1].Payload, &tlsPayload)
	if tlsPayload["server_name"] != "api.example.test" || tlsPayload["alpn"] != "h2" || tlsPayload["interception_state"] != "encrypted-only" {
		t.Fatalf("unexpected TLS metadata: %#v", tlsPayload)
	}
}

func TestProjectNormalizedQUICAndHTTP3AsEncryptedMetadata(t *testing.T) {
	now := time.Now().UTC()
	raw := []byte(fmt.Sprintf(`{"timestamp":%q,"flow_id":321,"event_type":"quic","src_ip":"10.77.0.23","src_port":56000,"dest_ip":"203.0.113.30","dest_port":443,"proto":"UDP","app_proto":"quic","flow":{"bytes_toserver":240,"bytes_toclient":480,"age":1.5},"quic":{"sni":"media.example.test","alpn":"h3","version":"1","token":"NEVER_UPLOAD"}}`, now.Format(time.RFC3339Nano)))
	envelope, err := ingest.NormalizeSuricataEVE(raw, "8.0.6", "")
	if err != nil {
		t.Fatal(err)
	}
	events := ProjectNormalizedEvents(envelope, now)
	if len(events) != 2 || events[0].Type != MetadataFlowSummary || events[1].Type != MetadataTLSEvent {
		t.Fatalf("unexpected QUIC projections: %#v", events)
	}
	var flowPayload map[string]any
	if err := json.Unmarshal(events[0].Payload, &flowPayload); err != nil {
		t.Fatal(err)
	}
	if flowPayload["transport"] != "udp" || flowPayload["application_protocol"] != "quic" {
		t.Fatalf("QUIC flow metadata is incomplete: %#v", flowPayload)
	}
	var handshakePayload map[string]any
	if err := json.Unmarshal(events[1].Payload, &handshakePayload); err != nil {
		t.Fatal(err)
	}
	attributes, _ := handshakePayload["attributes"].(map[string]any)
	if handshakePayload["server_name"] != "media.example.test" || handshakePayload["alpn"] != "h3" || handshakePayload["interception_state"] != "encrypted-only" || attributes["encrypted_transport"] != "quic" || attributes["transport_version"] != "1" || attributes["application_protocol"] != "http3" {
		t.Fatalf("QUIC handshake metadata is incomplete: %#v", handshakePayload)
	}
	if encoded := string(events[1].Payload); strings.Contains(encoded, "NEVER_UPLOAD") || strings.Contains(encoded, "token") {
		t.Fatalf("QUIC projection leaked raw fields: %s", encoded)
	}
}

func TestProjectNormalizedEventsHonorsQueueAgeAndMITMBoundary(t *testing.T) {
	now := time.Now().UTC()
	envelope := ingest.Envelope{Schema: 1, EventID: "host-event-0000000001", Source: ingest.SourceHost, Kind: "host.health", OccurredAt: now.Add(-MaxMetadataQueueAge - time.Second), SourceVersion: "host-v1", ParserVersion: "host-v1", Payload: json.RawMessage(`{}`)}
	if events := ProjectNormalizedEvents(envelope, now); len(events) != 0 {
		t.Fatalf("expired event was projected: %#v", events)
	}
	envelope.Source = ingest.SourceMitmproxy
	envelope.OccurredAt = now
	envelope.Kind = "tls_intercepted"
	if events := ProjectNormalizedEvents(envelope, now); len(events) != 0 {
		t.Fatalf("MITM event bypassed its dedicated projection path: %#v", events)
	}
}

func TestFlowSummaryCarriesProtocolClassification(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name       string
		raw        string
		protocol   string
		category   string
		visibility string
		evidence   string
		exotic     bool
		analyzer   string
	}{
		{
			name:     "zeek analyzer",
			raw:      `{"ts":%f,"uid":"Cproto01","_path":"conn","id.orig_h":"10.77.0.30","id.orig_p":50000,"id.resp_h":"198.51.100.40","id.resp_p":1883,"proto":"tcp","service":"mqtt","orig_ip_bytes":30,"resp_ip_bytes":20}`,
			protocol: "mqtt", category: "iot-messaging", visibility: "CLEARTEXT", evidence: "ANALYZER", exotic: true,
		},
		{
			name:     "analyzer alias",
			raw:      `{"ts":%f,"uid":"Cproto02","_path":"conn","id.orig_h":"10.77.0.30","id.orig_p":50001,"id.resp_h":"198.51.100.41","id.resp_p":443,"proto":"tcp","service":"ssl"}`,
			protocol: "tls", category: "web", visibility: "ENCRYPTED_METADATA", evidence: "ANALYZER", exotic: false, analyzer: "ssl",
		},
		{
			name:     "port heuristic",
			raw:      `{"ts":%f,"uid":"Cproto03","_path":"conn","id.orig_h":"10.77.0.31","id.orig_p":50002,"id.resp_h":"198.51.100.42","id.resp_p":6668,"proto":"tcp"}`,
			protocol: "tuya", category: "smart-home", visibility: "OPAQUE", evidence: "PORT_HEURISTIC", exotic: true,
		},
		{
			name:     "unidentified",
			raw:      `{"ts":%f,"uid":"Cproto04","_path":"conn","id.orig_h":"10.77.0.31","id.orig_p":50003,"id.resp_h":"198.51.100.43","id.resp_p":34567,"proto":"udp"}`,
			protocol: "unknown-udp", category: "unknown", visibility: "OPAQUE", evidence: "UNCLASSIFIED", exotic: true,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			envelope, err := ingest.NormalizeZeekJSON([]byte(fmt.Sprintf(testCase.raw, float64(now.UnixNano())/1e9)), "8.2.1", "")
			if err != nil {
				t.Fatal(err)
			}
			events := ProjectNormalizedEvents(envelope, now)
			if len(events) != 1 || events[0].Type != MetadataFlowSummary {
				t.Fatalf("unexpected projections: %#v", events)
			}
			var payload map[string]any
			if err := json.Unmarshal(events[0].Payload, &payload); err != nil {
				t.Fatal(err)
			}
			attributes, _ := payload["attributes"].(map[string]any)
			if payload["application_protocol"] != testCase.protocol || attributes["protocol_category"] != testCase.category || attributes["protocol_visibility"] != testCase.visibility || attributes["protocol_evidence"] != testCase.evidence || attributes["protocol_exotic"] != testCase.exotic {
				t.Fatalf("classification = %v %#v", payload["application_protocol"], attributes)
			}
			analyzer, present := attributes["analyzer_service"]
			if testCase.analyzer == "" && present || testCase.analyzer != "" && analyzer != testCase.analyzer {
				t.Fatalf("analyzer_service = %v (present %v), want %q", analyzer, present, testCase.analyzer)
			}
		})
	}
}
