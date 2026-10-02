package ingest

import (
	"encoding/json"
	"testing"

	"shakerproxy.dev/shakerproxy/internal/inventory"
)

// hostDNSEvent is a lookup exactly as shakerproxy-dnsd spools it.
const hostDNSEvent = `{"schema":1,"event_id":"evt_01790899277000000000_00000001_abcdefabcdef","source":"HOST","kind":"shakerproxy.dns","occurred_at":"2026-10-01T12:00:00Z","source_version":"shakerproxy-dnsd-1","parser_version":"shakerproxy-dns-v1","confidence":100,"payload":{"source_ip":"192.168.10.201","source_port":40000,"destination_port":53,"protocol":"udp","service":"dns","query":"connectivitycheck.grapheneos.network","query_type":"A","response_code":"NOERROR","answer_count":2,"answers":[{"name":"connectivitycheck.grapheneos.network","type":"A","ttl":60,"data":"121.127.40.19"},{"name":"connectivitycheck.grapheneos.network","type":"A","ttl":60,"data":"121.127.40.20"}],"blocked":false}}`

func TestHostDNSLookupsProjectAsDNSFromTheClient(t *testing.T) {
	envelope, err := DecodeEnvelope([]byte(hostDNSEvent))
	if err != nil {
		t.Fatal(err)
	}
	network := ProjectNetworkFields(envelope)
	if network != (NetworkProjection{SourceIP: "192.168.10.201", SourcePort: 40000, DestinationPort: 53, Protocol: "udp", Service: "dns"}) {
		t.Fatalf("network projection = %+v", network)
	}
	dns := ProjectDNSFields(envelope)
	if dns.Query != "connectivitycheck.grapheneos.network" || dns.RecordType != "A" || dns.ResponseCode != "NOERROR" || dns.AnswerCount == nil || *dns.AnswerCount != 2 {
		t.Fatalf("DNS projection = %+v", dns)
	}
	summary := EventSummary(RecentEvent{Source: envelope.Source, Kind: envelope.Kind, DNSQuery: dns.Query, DNSRecordType: dns.RecordType, DNSResponseCode: dns.ResponseCode, DNSAnswerCount: dns.AnswerCount})
	if summary != "DNS lookup connectivitycheck.grapheneos.network (A) → 2 answers" {
		t.Fatalf("summary = %q", summary)
	}
}

// Other HOST events (ShakerProxy detections) carry no device traffic, so the
// new projection must not give them network or DNS fields.
func TestOnlyForwarderLookupsGetHostNetworkFields(t *testing.T) {
	var event map[string]any
	if err := json.Unmarshal([]byte(hostDNSEvent), &event); err != nil {
		t.Fatal(err)
	}
	event["kind"] = "shakerproxy.detection.beaconing"
	raw, _ := json.Marshal(event)
	envelope, err := DecodeEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	if network := ProjectNetworkFields(envelope); network != (NetworkProjection{}) {
		t.Fatalf("detection got network fields: %+v", network)
	}
	if dns := ProjectDNSFields(envelope); dns.Query != "" {
		t.Fatalf("detection got DNS fields: %+v", dns)
	}
}

func TestHostDNSLookupsAreAttributedToTheAskingDevice(t *testing.T) {
	deviceID := "device-0123456789abcdef0123456789abcdef"
	envelope, err := DecodeEnvelope([]byte(hostDNSEvent))
	if err != nil {
		t.Fatal(err)
	}
	resolver := fakeDeviceAttributor{results: map[string]inventory.AddressAttribution{"192.168.10.201": testAddressAttribution(deviceID, "192.168.10.201")}}
	attributed, evidence, err := AttributeAnalyzerEvent(envelope, resolver)
	if err != nil || attributed.DeviceID != deviceID || attributed.Confidence != 70 || evidence == nil || evidence.Endpoint != AttributionEndpointSource || evidence.Address != "192.168.10.201" {
		t.Fatalf("lookup was not attributed: %#v evidence=%#v err=%v", attributed, evidence, err)
	}
	projected := RecentEvent{Source: attributed.Source, Kind: attributed.Kind, OccurredAt: attributed.OccurredAt, DeviceID: attributed.DeviceID, Confidence: attributed.Confidence, SourceIP: "192.168.10.201"}
	if err := evidence.Validate(projected); err != nil {
		t.Fatalf("stored evidence does not validate on read: %v", err)
	}
	// Evidence for a destination endpoint, or for another HOST kind, is
	// never valid for a lookup.
	destination := *evidence
	destination.Endpoint = AttributionEndpointDestination
	if destination.Validate(projected) == nil {
		t.Fatal("destination evidence was accepted for a lookup")
	}
	detection := projected
	detection.Kind = "shakerproxy.detection.beaconing"
	if evidence.Validate(detection) == nil {
		t.Fatal("attribution evidence was accepted for a HOST detection")
	}
	if unknown, evidence, err := AttributeAnalyzerEvent(envelope, fakeDeviceAttributor{}); err != nil || unknown.DeviceID != "" || evidence != nil {
		t.Fatalf("an unknown client was attributed: %#v err=%v", unknown, err)
	}
}
