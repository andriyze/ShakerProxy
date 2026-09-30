package ingest

import (
	"path/filepath"
	"testing"
	"time"

	"net/netip"
	"shakerproxy.dev/shakerproxy/internal/inventory"
)

func testNDPAttribution(deviceID, address string) inventory.AddressAttribution {
	return inventory.AddressAttribution{
		DeviceID: deviceID, Address: address, Confidence: inventory.NDPConfidence, Source: inventory.SourceNDP,
		ValidFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), ValidUntil: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), Matched: true,
	}
}

func TestAttributeAnalyzerEventAttributesIPv6Endpoints(t *testing.T) {
	deviceID := "device-0123456789abcdef0123456789abcdef"
	lab := "fd12:3456:789a:1:5054:ff:fe12:3456"
	zeek, err := NormalizeZeekJSON([]byte(`{"ts":1788278400,"uid":"Cabc124","id.orig_h":"fd12:3456:789a:1:5054:ff:fe12:3456","id.resp_h":"2606:4700:4700::1111","_path":"conn"}`), "8.2.1", "")
	if err != nil {
		t.Fatal(err)
	}
	resolver := fakeDeviceAttributor{results: map[string]inventory.AddressAttribution{lab: testNDPAttribution(deviceID, lab)}}
	attributed, evidence, err := AttributeAnalyzerEvent(zeek, resolver)
	if err != nil || attributed.DeviceID != deviceID || attributed.Confidence != inventory.NDPConfidence || evidence == nil || evidence.Endpoint != AttributionEndpointSource || evidence.Address != lab || evidence.Source != inventory.SourceNDP {
		t.Fatalf("IPv6 source attribution failed: %#v evidence=%#v err=%v", attributed, evidence, err)
	}

	suricata, err := NormalizeSuricataEVE([]byte(`{"timestamp":"2026-09-01T12:00:00Z","flow_id":987,"event_type":"flow","src_ip":"2606:4700:4700::1111","dest_ip":"fd12:3456:789a:1:5054:ff:fe12:3456"}`), "8.0.6", "")
	if err != nil {
		t.Fatal(err)
	}
	attributed, evidence, err = AttributeAnalyzerEvent(suricata, resolver)
	if err != nil || attributed.DeviceID != deviceID || evidence == nil || evidence.Endpoint != AttributionEndpointDestination {
		t.Fatalf("IPv6 destination fallback failed: %#v err=%v", attributed, err)
	}
}

func TestAttributionEvidenceBindsSourceToAddressFamily(t *testing.T) {
	deviceID := "device-0123456789abcdef0123456789abcdef"
	occurred := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	event := RecentEvent{Source: SourceZeek, OccurredAt: occurred, DeviceID: deviceID, Confidence: 70, SourceIP: "fd12::50"}
	evidence := AttributionEvidence{Schema: AttributionEvidenceSchema, DeviceID: deviceID, Address: "fd12::50", Endpoint: AttributionEndpointSource, Source: inventory.SourceNDP, Confidence: 80, ValidFrom: occurred.Add(-time.Minute), ValidUntil: occurred.Add(time.Minute)}
	if err := evidence.Validate(event); err != nil {
		t.Fatalf("valid NDP evidence was rejected: %v", err)
	}
	wrongFamily := evidence
	wrongFamily.Source = inventory.SourceDHCP4Lease
	if err := wrongFamily.Validate(event); err == nil {
		t.Fatal("DHCPv4 evidence was accepted for an IPv6 address")
	}
	ipv4 := evidence
	ipv4.Address, event.SourceIP = "10.77.0.5", "10.77.0.5"
	if err := ipv4.Validate(event); err == nil {
		t.Fatal("NDP evidence was accepted for an IPv4 address")
	}
	nonCanonical := evidence
	nonCanonical.Address, event.SourceIP = "FD12::50", "FD12::50"
	if err := nonCanonical.Validate(event); err == nil {
		t.Fatal("non-canonical IPv6 evidence was accepted")
	}
}

func TestAnalyzerAddressSkipsUnattributableEndpoints(t *testing.T) {
	for _, value := range []string{`"ff02::fb"`, `"::"`, `"::1"`, `"fe80::1%eth0"`, `"not-an-ip"`, `5`} {
		if _, ok := analyzerAddress([]byte(value)); ok {
			t.Fatalf("unattributable endpoint %s was accepted", value)
		}
	}
	for value, expected := range map[string]string{`"fe80::1"`: "fe80::1", `"::ffff:10.77.0.5"`: "10.77.0.5", `"10.77.0.5"`: "10.77.0.5"} {
		address, ok := analyzerAddress([]byte(value))
		if !ok || address.String() != expected {
			t.Fatalf("endpoint %s parsed as %s ok=%v", value, address, ok)
		}
	}
}

func TestInventoryAttributorResolvesIPv6ForIngest(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	store := &inventory.Store{Path: filepath.Join(t.TempDir(), "inventory.json"), Now: func() time.Time { return now }}
	lab := "fd12:3456:789a:1:5054:ff:fe12:3456"
	if _, err := store.ReconcileNeighbors([]inventory.NeighborObservation{{Address: netip.MustParseAddr(lab), HardwareAddr: "52:54:00:12:34:56", SeenAt: now.Add(-time.Minute)}}); err != nil {
		t.Fatal(err)
	}
	zeek, err := NormalizeZeekJSON([]byte(`{"ts":1788264000,"uid":"Cabc125","id.orig_h":"fd12:3456:789a:1:5054:ff:fe12:3456","id.resp_h":"2606:4700:4700::1111","_path":"conn"}`), "8.2.1", "")
	if err != nil {
		t.Fatal(err)
	}
	var attributor DeviceAttributor = &inventory.Attributor{Store: store, Now: func() time.Time { return now }}
	attributed, evidence, err := AttributeAnalyzerEvent(zeek, attributor)
	if err != nil || attributed.DeviceID == "" || evidence == nil || evidence.Source != inventory.SourceNDP {
		t.Fatalf("inventory NDP evidence did not attribute the IPv6 event: %#v evidence=%#v err=%v", attributed, evidence, err)
	}
}

// Single-arm and static-IP lab devices are known only from the gateway's ARP
// table; their IPv4 traffic must still be attributed.
func TestAttributeAnalyzerEventAttributesIPv4FromARP(t *testing.T) {
	deviceID := "device-0123456789abcdef0123456789abcdef"
	lab := "172.31.47.197"
	zeek, err := NormalizeZeekJSON([]byte(`{"ts":1788278400,"uid":"Cabc125","id.orig_h":"172.31.47.197","id.resp_h":"1.1.1.1","_path":"conn"}`), "8.2.1", "")
	if err != nil {
		t.Fatal(err)
	}
	attribution := testNDPAttribution(deviceID, lab)
	attribution.Source, attribution.Confidence = inventory.SourceARP, inventory.ARPConfidence
	resolver := fakeDeviceAttributor{results: map[string]inventory.AddressAttribution{lab: attribution}}
	attributed, evidence, err := AttributeAnalyzerEvent(zeek, resolver)
	if err != nil || attributed.DeviceID != deviceID || evidence == nil || evidence.Source != inventory.SourceARP || evidence.Address != lab {
		t.Fatalf("IPv4 ARP attribution failed: %#v evidence=%#v err=%v", attributed, evidence, err)
	}
	if err := evidence.Validate(RecentEvent{Source: SourceZeek, OccurredAt: time.Unix(1788278400, 0).UTC(), DeviceID: deviceID, Confidence: attributed.Confidence, SourceIP: lab}); err != nil {
		t.Fatalf("ARP evidence for an IPv4 address must validate: %v", err)
	}
}
