package ingest

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/inventory"
)

type fakeDeviceAttributor struct {
	results map[string]inventory.AddressAttribution
	err     error
}

func (f fakeDeviceAttributor) ResolveAddress(address netip.Addr, _ time.Time) (inventory.AddressAttribution, error) {
	if f.err != nil {
		return inventory.AddressAttribution{}, f.err
	}
	return f.results[address.String()], nil
}

func testAddressAttribution(deviceID, address string) inventory.AddressAttribution {
	return inventory.AddressAttribution{
		DeviceID: deviceID, Address: address, Confidence: 70, Source: inventory.SourceDHCP4Lease,
		ValidFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), ValidUntil: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), Matched: true,
	}
}

func TestAttributeAnalyzerEventUsesSourceThenDestination(t *testing.T) {
	deviceID := "device-0123456789abcdef0123456789abcdef"
	zeek, err := NormalizeZeekJSON([]byte(`{"ts":1788278400,"uid":"Cabc123","id.orig_h":"10.77.0.111","id.resp_h":"1.1.1.1","_path":"conn"}`), "8.2.1", "")
	if err != nil {
		t.Fatal(err)
	}
	resolver := fakeDeviceAttributor{results: map[string]inventory.AddressAttribution{"10.77.0.111": testAddressAttribution(deviceID, "10.77.0.111")}}
	attributed, evidence, err := AttributeAnalyzerEvent(zeek, resolver)
	if err != nil || attributed.DeviceID != deviceID || attributed.Confidence != 70 || attributed.EventID != zeek.EventID || evidence == nil || evidence.Endpoint != AttributionEndpointSource || evidence.Address != "10.77.0.111" || evidence.Source != inventory.SourceDHCP4Lease {
		t.Fatalf("Zeek source attribution failed: %#v err=%v", attributed, err)
	}

	suricata, err := NormalizeSuricataEVE([]byte(`{"timestamp":"2026-09-01T12:00:00Z","flow_id":123456789,"event_type":"flow","src_ip":"1.1.1.1","dest_ip":"10.77.0.111"}`), "8.0.6", "")
	if err != nil {
		t.Fatal(err)
	}
	attributed, evidence, err = AttributeAnalyzerEvent(suricata, resolver)
	if err != nil || attributed.DeviceID != deviceID || attributed.Confidence != 70 || evidence == nil || evidence.Endpoint != AttributionEndpointDestination {
		t.Fatalf("Suricata destination fallback failed: %#v err=%v", attributed, err)
	}
}

func TestAttributeAnalyzerEventLeavesAmbiguousEventsUnattributedAndPropagatesFailure(t *testing.T) {
	event, err := NormalizeSuricataEVE([]byte(`{"timestamp":"2026-09-01T12:00:00Z","event_type":"flow","src_ip":"10.77.0.111","dest_ip":"10.77.0.112"}`), "8.0.6", "")
	if err != nil {
		t.Fatal(err)
	}
	ambiguous := fakeDeviceAttributor{results: map[string]inventory.AddressAttribution{
		"10.77.0.111": {Ambiguous: true},
		"10.77.0.112": testAddressAttribution("device-0123456789abcdef0123456789abcdef", "10.77.0.112"),
	}}
	result, evidence, err := AttributeAnalyzerEvent(event, ambiguous)
	if err != nil || result.DeviceID != "" || evidence != nil {
		t.Fatalf("ambiguous source was attributed: %#v err=%v", result, err)
	}
	if _, _, err := AttributeAnalyzerEvent(event, fakeDeviceAttributor{err: errors.New("inventory unavailable")}); err == nil {
		t.Fatal("attribution backend failure was ignored")
	}
}
