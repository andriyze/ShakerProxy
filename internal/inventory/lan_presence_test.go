package inventory

import (
	"net/netip"
	"testing"
	"time"
)

// The iPhone on the test VM's lab Wi-Fi took 192.168.10.130 from the router;
// ShakerProxy saw its DHCP request and its mDNS, nothing else. It must still
// appear as a device, named by itself, with its traffic attributed to it.
func TestLANPresenceMakesABypassingPhoneADevice(t *testing.T) {
	now := time.Date(2026, 10, 2, 23, 52, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	iphone := LANPresence{HardwareAddr: "62:bc:f1:bc:1d:8d", Address: netip.MustParseAddr("192.168.10.130"), HostName: "iPhone", FirstSeen: now.Add(-4 * time.Minute), LastSeen: now.Add(-time.Minute)}
	snapshot, err := store.ReconcileLANPresence([]LANPresence{iphone}, observedScope)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Devices) != 1 {
		t.Fatalf("devices = %+v", snapshot.Devices)
	}
	device := snapshot.Devices[0]
	if !device.Online || device.AttributionConfidence != ObservedLANConfidence || len(device.Identities) != 1 || device.Identities[0].Source != SourceObservedLAN || device.FriendlyName != "" {
		t.Fatalf("device = %+v", device)
	}
	address := device.Addresses[0]
	if address.Source != SourceObservedLAN || address.Address != "192.168.10.130" || !address.ValidUntil.Equal(iphone.LastSeen.Add(ObservedLANValidity)) || !address.Active || address.Interface != "ens18" {
		t.Fatalf("address = %+v", address)
	}
	if len(device.Hostnames) != 1 || device.Hostnames[0].Hostname != "iphone" {
		t.Fatalf("hostnames = %+v", device.Hostnames)
	}
	attributor := &Attributor{Store: store, Now: func() time.Time { return now }}
	match, err := attributor.ResolveAddress(netip.MustParseAddr("192.168.10.130"), now)
	if err != nil || !match.Matched || match.DeviceID != device.ID || match.Source != SourceObservedLAN || match.Confidence != ObservedLANConfidence {
		t.Fatalf("attribution = %+v err=%v", match, err)
	}
	if _, err := store.Snapshot(); err != nil {
		t.Fatalf("the evidence did not survive a strict reload: %v", err)
	}
	// The same frames again change nothing.
	again, err := store.ReconcileLANPresence([]LANPresence{iphone}, observedScope)
	if err != nil || len(again.Devices) != 1 || len(again.Devices[0].Addresses) != 1 {
		t.Fatalf("again = %+v err=%v", again.Devices, err)
	}
}

// Weaker evidence never renames a device or lowers its confidence, and a
// phone's next private MAC at the same address stays the same device.
func TestLANPresenceKeepsNamesAndFollowsRotation(t *testing.T) {
	now := time.Date(2026, 10, 2, 23, 52, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	snapshot, err := store.ReconcileObservedDHCP([]ObservedDHCPClient{acknowledged("b6:53:83:65:54:a2", "192.168.10.201", "android-7f3a", now.Add(-2*time.Hour))}, observedScope)
	if err != nil {
		t.Fatal(err)
	}
	id := snapshot.Devices[0].ID
	if _, err := store.UpdateAlias(id, "admin", "lan-presence-alias-0001", AliasUpdate{FriendlyName: "Pixel", Reason: "Phone in hand", ExpectedRevision: 0}); err != nil {
		t.Fatal(err)
	}
	rotated := LANPresence{HardwareAddr: "fa:16:3e:22:11:00", Address: netip.MustParseAddr("192.168.10.201"), HostName: "Pixel-7", FirstSeen: now.Add(-time.Minute), LastSeen: now}
	snapshot, err = store.ReconcileLANPresence([]LANPresence{rotated}, observedScope)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Devices) != 1 {
		t.Fatalf("the rotated MAC became another device: %+v", snapshot.Devices)
	}
	device := snapshot.Devices[0]
	if device.ID != id || device.FriendlyName != "Pixel" || device.AttributionConfidence != ObservedDHCPConfidence || len(device.Identities) != 2 {
		t.Fatalf("device = %+v", device)
	}
}

func TestLANPresenceRejectsInvalidObservations(t *testing.T) {
	now := time.Date(2026, 10, 2, 23, 52, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	for name, observation := range map[string]LANPresence{
		"multicast MAC":   {HardwareAddr: "01:00:5e:00:00:fb", Address: netip.MustParseAddr("192.168.10.130"), FirstSeen: now, LastSeen: now},
		"multicast IP":    {HardwareAddr: "62:bc:f1:bc:1d:8d", Address: netip.MustParseAddr("224.0.0.251"), FirstSeen: now, LastSeen: now},
		"IPv6":            {HardwareAddr: "62:bc:f1:bc:1d:8d", Address: netip.MustParseAddr("fe80::1"), FirstSeen: now, LastSeen: now},
		"times backwards": {HardwareAddr: "62:bc:f1:bc:1d:8d", Address: netip.MustParseAddr("192.168.10.130"), FirstSeen: now, LastSeen: now.Add(-time.Minute)},
		"bad host name":   {HardwareAddr: "62:bc:f1:bc:1d:8d", Address: netip.MustParseAddr("192.168.10.130"), HostName: "two\nlines", FirstSeen: now, LastSeen: now},
	} {
		if _, err := store.ReconcileLANPresence([]LANPresence{observation}, observedScope); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
