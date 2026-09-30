package inventory

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func neighborObservation(address, mac string, seenAt time.Time) NeighborObservation {
	return NeighborObservation{Address: netip.MustParseAddr(address), HardwareAddr: mac, SeenAt: seenAt, Interface: "enp2s0", ScopePlanSHA256: strings.Repeat("e", 64)}
}

func TestReconcileNeighborsAttachesSLAACAddressesToTheDHCPDevice(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	if _, err := store.ReconcileDHCP4([]DHCP4Lease{{Address: netip.MustParseAddr("10.77.0.111"), HardwareAddr: "52:54:00:00:00:01", ClientID: "01:01", Hostname: "tv", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.ReconcileNeighbors([]NeighborObservation{
		neighborObservation("fd12:3456:789a:1:5054:ff:fe00:1", "52:54:00:00:00:01", now.Add(-time.Minute)),
		neighborObservation("fe80::5054:ff:fe00:1", "52:54:00:00:00:01", now.Add(-time.Minute)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Devices) != 1 {
		t.Fatalf("NDP evidence created a duplicate device: %+v", snapshot.Devices)
	}
	device := snapshot.Devices[0]
	ipv6 := []AddressObservation{}
	for _, address := range device.Addresses {
		if address.Family == "IPv6" {
			ipv6 = append(ipv6, address)
		}
	}
	if len(ipv6) != 2 || device.AttributionConfidence != 95 || !device.Online {
		t.Fatalf("unexpected device after NDP evidence: %+v", device)
	}
	for _, address := range ipv6 {
		if address.Source != SourceNDP || address.Confidence != NDPConfidence || address.Confidence >= 95 || !address.ValidFrom.Equal(now.Add(-time.Minute)) || !address.ValidUntil.Equal(now.Add(-time.Minute).Add(NDPValidity)) || !address.Active || address.Interface != "enp2s0" {
			t.Fatalf("unexpected NDP address window: %+v", address)
		}
	}
	for _, identity := range device.Identities {
		if identity.Kind == IdentityMAC && identity.Source != SourceDHCP4Lease {
			t.Fatalf("NDP evidence downgraded the DHCP MAC identity: %+v", identity)
		}
	}
	reloaded, err := store.Snapshot()
	if err != nil || len(reloaded.Devices) != 1 || len(reloaded.Devices[0].Addresses) != 3 {
		t.Fatalf("NDP evidence did not survive strict reload: %+v err=%v", reloaded, err)
	}
}

func TestReconcileNeighborsExtendsWindowsAndOpensNewOnesAfterGaps(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	clock := now
	store := deterministicMutationStore(t, now)
	store.Now = func() time.Time { return clock }
	address := "fd12:3456:789a:1::50"
	if _, err := store.ReconcileNeighbors([]NeighborObservation{neighborObservation(address, "52:54:00:00:00:50", now)}); err != nil {
		t.Fatal(err)
	}
	clock = now.Add(5 * time.Minute)
	snapshot, err := store.ReconcileNeighbors([]NeighborObservation{neighborObservation(address, "52:54:00:00:00:50", clock.Add(-time.Second))})
	if err != nil {
		t.Fatal(err)
	}
	device := snapshot.Devices[0]
	if len(device.Addresses) != 1 || !device.Addresses[0].ValidFrom.Equal(now) || !device.Addresses[0].ValidUntil.Equal(clock.Add(-time.Second).Add(NDPValidity)) {
		t.Fatalf("contiguous NDP evidence did not extend the window: %+v", device.Addresses)
	}
	if device.Identities[0].Source != SourceNDP || device.Identities[0].Confidence != NDPConfidence || device.AttributionConfidence != NDPConfidence || !device.Online {
		t.Fatalf("IPv6-only device identity is wrong: %+v", device)
	}
	clock = now.Add(2 * time.Hour)
	snapshot, err = store.ReconcileNeighbors(nil)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Devices[0].Online || snapshot.Devices[0].Addresses[0].Active {
		t.Fatalf("expired NDP window kept the device online: %+v", snapshot.Devices[0])
	}
	snapshot, err = store.ReconcileNeighbors([]NeighborObservation{neighborObservation(address, "52:54:00:00:00:50", clock)})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Devices[0].Addresses) != 2 || !snapshot.Devices[0].Online {
		t.Fatalf("returning device did not open a new window: %+v", snapshot.Devices[0].Addresses)
	}
	// A lingering STALE entry keeps its old confirmation time and must not
	// extend the window or keep the device online.
	clock = clock.Add(time.Hour)
	snapshot, err = store.ReconcileNeighbors([]NeighborObservation{neighborObservation(address, "52:54:00:00:00:50", now.Add(2*time.Hour))})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Devices[0].Online || len(snapshot.Devices[0].Addresses) != 2 {
		t.Fatalf("stale neighbor evidence kept the device online: %+v", snapshot.Devices[0])
	}
	// The DHCP reconcile must not flip NDP-only devices offline while their
	// window is open.
	clock = now.Add(2 * time.Hour)
	snapshot, err = store.ReconcileDHCP4(nil)
	if err != nil || !snapshot.Devices[0].Online {
		t.Fatalf("DHCP reconcile ignored active NDP evidence: %+v err=%v", snapshot.Devices, err)
	}
}

func TestReconcileNeighborsRejectsMalformedEvidence(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	cases := map[string]NeighborObservation{
		"broadcast":     neighborObservation("255.255.255.255", "52:54:00:00:00:50", now),
		"multicast":     neighborObservation("ff02::1", "52:54:00:00:00:50", now),
		"mapped":        neighborObservation("::ffff:10.77.0.5", "52:54:00:00:00:50", now),
		"zone":          {Address: netip.MustParseAddr("fe80::1%eth1"), HardwareAddr: "52:54:00:00:00:50", SeenAt: now},
		"multicast MAC": neighborObservation("fe80::1", "01:00:5e:00:00:50", now),
		"zero MAC":      neighborObservation("fe80::1", "00:00:00:00:00:00", now),
		"no time":       neighborObservation("fe80::1", "52:54:00:00:00:50", time.Time{}),
		"bad scope":     {Address: netip.MustParseAddr("fe80::1"), HardwareAddr: "52:54:00:00:00:50", SeenAt: now, Interface: "enp2s0"},
	}
	for name, observation := range cases {
		store := deterministicMutationStore(t, now)
		if _, err := store.ReconcileNeighbors([]NeighborObservation{observation}); err == nil {
			t.Fatalf("%s neighbor evidence was accepted", name)
		}
	}
	store := deterministicMutationStore(t, now)
	if _, err := store.ReconcileNeighbors(make([]NeighborObservation, MaxNeighborObservations+1)); err == nil {
		t.Fatal("unbounded neighbor batch was accepted")
	}
	future := neighborObservation("fe80::1", "52:54:00:00:00:50", now.Add(time.Hour))
	snapshot, err := store.ReconcileNeighbors([]NeighborObservation{future})
	if err != nil || !snapshot.Devices[0].Addresses[0].ValidFrom.Equal(now) {
		t.Fatalf("future observation time was not clamped: %+v err=%v", snapshot.Devices, err)
	}
}

// Single-arm labs have no ShakerProxy DHCP and static-IP devices never
// lease, so the gateway's ARP table is the only IPv4 evidence for them.
func TestReconcileNeighborsCreatesDevicesFromIPv4ARP(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	snapshot, err := store.ReconcileNeighbors([]NeighborObservation{neighborObservation("10.77.0.40", "52:54:00:00:00:40", now)})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Devices) != 1 || !snapshot.Devices[0].Online {
		t.Fatalf("an ARP neighbor must appear as an online device: %+v", snapshot.Devices)
	}
	device := snapshot.Devices[0]
	address := device.Addresses[0]
	if address.Source != SourceARP || address.Family != "IPv4" || address.Confidence != ARPConfidence || address.Address != "10.77.0.40" || !address.Active {
		t.Fatalf("unexpected ARP address evidence: %+v", address)
	}
	if identity := device.Identities[0]; identity.Kind != IdentityMAC || identity.Source != SourceARP || identity.Value != "52:54:00:00:00:40" {
		t.Fatalf("unexpected ARP identity: %+v", identity)
	}
	if device.AttributionConfidence != ARPConfidence {
		t.Fatalf("ARP-only device confidence = %d, want %d", device.AttributionConfidence, ARPConfidence)
	}
	later := now.Add(NDPValidity + time.Minute)
	store.Now = func() time.Time { return later }
	snapshot, err = store.ReconcileNeighbors(nil)
	if err != nil || snapshot.Devices[0].Online {
		t.Fatalf("an ARP window must expire without fresh evidence: %+v err=%v", snapshot.Devices, err)
	}
}

func TestAttributorResolvesIPv6FromNDPWindows(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	address := netip.MustParseAddr("fd12:3456:789a:1:5054:ff:fe00:1")
	if _, err := store.ReconcileNeighbors([]NeighborObservation{neighborObservation(address.String(), "52:54:00:00:00:01", now.Add(-time.Minute))}); err != nil {
		t.Fatal(err)
	}
	attributor := &Attributor{Store: store, Now: func() time.Time { return now }}
	match, err := attributor.ResolveAddress(address, now)
	if err != nil || !match.Matched || match.Source != SourceNDP || match.Confidence != NDPConfidence || match.Address != address.String() || match.Interface != "enp2s0" {
		t.Fatalf("IPv6 address was not attributed: %+v err=%v", match, err)
	}
	for _, outside := range []time.Time{now.Add(-2 * time.Minute), now.Add(-time.Minute).Add(NDPValidity)} {
		if result, err := attributor.ResolveAddress(address, outside); err != nil || result.Matched {
			t.Fatalf("IPv6 attribution outside the NDP window: %+v err=%v", result, err)
		}
	}
	if _, err := attributor.ResolveIPv4(address, now); err == nil {
		t.Fatal("IPv4-only resolver accepted an IPv6 address")
	}
	if _, err := attributor.ResolveAddress(netip.MustParseAddr("ff02::1"), now); err == nil {
		t.Fatal("multicast IPv6 attribution was accepted")
	}
	if _, err := store.ReconcileNeighbors([]NeighborObservation{neighborObservation(address.String(), "52:54:00:00:00:02", now)}); err != nil {
		t.Fatal(err)
	}
	ambiguous, err := (&Attributor{Store: store, Now: func() time.Time { return now.Add(time.Hour) }}).ResolveAddress(address, now)
	if err != nil || ambiguous.Matched || !ambiguous.Ambiguous {
		t.Fatalf("conflicting NDP owners were attributed: %+v err=%v", ambiguous, err)
	}
}

func TestSplitDeviceMovesNDPEvidence(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	if _, err := store.ReconcileDHCP4([]DHCP4Lease{{Address: netip.MustParseAddr("10.77.0.111"), HardwareAddr: "52:54:00:00:00:01", ClientID: "01:01", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.ReconcileNeighbors([]NeighborObservation{neighborObservation("fe80::1", "52:54:00:00:00:01", now)})
	if err != nil {
		t.Fatal(err)
	}
	device := snapshot.Devices[0]
	var moved AddressObservation
	for _, address := range device.Addresses {
		if address.Source == SourceNDP {
			moved = address
		}
	}
	result, err := store.SplitDevice(device.ID, "admin", "split-ndp-000000000001", SplitSelection{
		Identities: []IdentitySelector{{Kind: IdentityDHCPClientID, Value: "01:01", Source: SourceDHCP4Lease}},
		Addresses:  []AddressSelector{{Address: moved.Address, Source: SourceNDP, ValidFrom: moved.ValidFrom, ValidUntil: moved.ValidUntil, Interface: moved.Interface, ScopePlanSHA256: moved.ScopePlanSHA256}},
	})
	if err != nil || len(result.Devices) != 2 {
		t.Fatalf("NDP evidence could not be split: %+v err=%v", result, err)
	}
	for _, split := range result.Devices {
		if split.ID != device.ID && (len(split.Addresses) != 1 || split.Addresses[0].Source != SourceNDP) {
			t.Fatalf("NDP address did not move with the split: %+v", split)
		}
	}
}
