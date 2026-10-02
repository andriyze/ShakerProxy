package inventory

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

var observedScope = ObservedDHCPScope{Interface: "ens18", ScopePlanSHA256: strings.Repeat("e", 64)}

func acknowledged(mac, address, hostname string, at time.Time) ObservedDHCPClient {
	return ObservedDHCPClient{
		HardwareAddr: mac, HostName: hostname, VendorClass: "android-dhcp-14", ParameterList: "1,3,6,15,26,28,51,58,59,43,114,108",
		AssignedAddr: netip.MustParseAddr(address), AssignedAt: at, LeaseTime: 24 * time.Hour,
		Server: netip.MustParseAddr("192.168.10.1"), Router: netip.MustParseAddr("192.168.10.1"), FirstSeen: at, LastSeen: at,
	}
}

// In a single-arm lab the router serves DHCP: the phone's acknowledged lease
// names it, binds its address for the lease and suggests its own name.
func TestObservedDHCPNamesAndAttributesTheRoutersClient(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	snapshot, err := store.ReconcileObservedDHCP([]ObservedDHCPClient{acknowledged("b6:53:83:65:54:a2", "192.168.10.201", "Pixel-7", now.Add(-time.Hour))}, observedScope)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Devices) != 1 {
		t.Fatalf("devices = %+v", snapshot.Devices)
	}
	device := snapshot.Devices[0]
	if !device.Online || device.AttributionConfidence != ObservedDHCPConfidence || len(device.Identities) != 1 || device.Identities[0].Source != SourceObservedDHCP {
		t.Fatalf("device = %+v", device)
	}
	address := device.Addresses[0]
	if address.Source != SourceObservedDHCP || address.Address != "192.168.10.201" || !address.ValidFrom.Equal(now.Add(-time.Hour)) || !address.ValidUntil.Equal(now.Add(23*time.Hour)) || !address.Active || address.Interface != "ens18" {
		t.Fatalf("address = %+v", address)
	}
	if len(device.Hostnames) != 1 || device.Hostnames[0].Hostname != "pixel-7" || device.Hostnames[0].Source != SourceObservedDHCP || device.Hostnames[0].Confidence != ObservedDHCPHostnameConfidence {
		t.Fatalf("hostnames = %+v", device.Hostnames)
	}
	observed := device.ObservedDHCP
	if observed == nil || observed.HostName != "Pixel-7" || observed.VendorClass != "android-dhcp-14" || observed.Server != "192.168.10.1" || observed.Router != "192.168.10.1" || observed.HardwareAddr != "b6:53:83:65:54:a2" {
		t.Fatalf("observed = %+v", observed)
	}
	got, err := store.Get(device.ID)
	if err != nil || len(got.SuggestedNames) != 1 || got.SuggestedNames[0].Name != "pixel-7" || got.SuggestedNames[0].Source != SourceObservedDHCP {
		t.Fatalf("suggested names = %+v err=%v", got.SuggestedNames, err)
	}
	attributor := &Attributor{Store: store, Now: func() time.Time { return now }}
	match, err := attributor.ResolveAddress(netip.MustParseAddr("192.168.10.201"), now)
	if err != nil || !match.Matched || match.DeviceID != device.ID || match.Source != SourceObservedDHCP || match.Confidence != ObservedDHCPConfidence {
		t.Fatalf("attribution = %+v err=%v", match, err)
	}
	reloaded, err := store.Snapshot()
	if err != nil || reloaded.Devices[0].ObservedDHCP == nil || reloaded.Devices[0].ObservedDHCP.HostName != "Pixel-7" {
		t.Fatalf("observed DHCP did not survive a strict reload: %+v err=%v", reloaded.Devices, err)
	}
}

// A client seen only asking (a neighbouring network's iPad) adds nothing on
// its own, but enriches a device the lab already knows.
func TestObservedDHCPRequestsOnlyEnrichKnownDevices(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	asking := ObservedDHCPClient{HardwareAddr: "0e:47:eb:9f:1b:6a", HostName: "iPad", ParameterList: "1,121,3,6,15,108,114,119,252,95,44,46", FirstSeen: now, LastSeen: now}
	snapshot, err := store.ReconcileObservedDHCP([]ObservedDHCPClient{asking}, observedScope)
	if err != nil || len(snapshot.Devices) != 0 {
		t.Fatalf("a request alone created a device: %+v err=%v", snapshot.Devices, err)
	}
	if _, err := store.ReconcileNeighbors([]NeighborObservation{{Address: netip.MustParseAddr("192.168.10.40"), HardwareAddr: "0e:47:eb:9f:1b:6a", SeenAt: now, Interface: "ens18", ScopePlanSHA256: strings.Repeat("e", 64)}}); err != nil {
		t.Fatal(err)
	}
	snapshot, err = store.ReconcileObservedDHCP([]ObservedDHCPClient{asking}, observedScope)
	if err != nil || len(snapshot.Devices) != 1 {
		t.Fatalf("devices = %+v err=%v", snapshot.Devices, err)
	}
	device := snapshot.Devices[0]
	if len(device.Hostnames) != 1 || device.Hostnames[0].Hostname != "ipad" || device.ObservedDHCP == nil || device.ObservedDHCP.HostName != "iPad" || device.ObservedDHCP.Server != "" {
		t.Fatalf("device = %+v", device)
	}
	if device.Identities[0].Source != SourceARP {
		t.Fatalf("a request alone upgraded the ARP identity: %+v", device.Identities)
	}
	for _, address := range device.Addresses {
		if address.Source == SourceObservedDHCP {
			t.Fatalf("a request alone added an address window: %+v", address)
		}
	}
}

// The name an administrator chose stays; the observed name is only a
// suggestion, and ShakerProxy's own lease name outranks it.
func TestObservedDHCPNeverReplacesTheAdministratorsName(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	snapshot, err := store.ReconcileObservedDHCP([]ObservedDHCPClient{acknowledged("b6:53:83:65:54:a2", "192.168.10.201", "android-7f3a", now)}, observedScope)
	if err != nil {
		t.Fatal(err)
	}
	id := snapshot.Devices[0].ID
	if _, err := store.UpdateAlias(id, "admin", "observed-dhcp-alias-0001", AliasUpdate{FriendlyName: "Pixel", Reason: "Phone in hand", ExpectedRevision: 0}); err != nil {
		t.Fatal(err)
	}
	later := acknowledged("b6:53:83:65:54:a2", "192.168.10.201", "Pixel-7", now.Add(time.Hour))
	store.Now = func() time.Time { return now.Add(time.Hour) }
	snapshot, err = store.ReconcileObservedDHCP([]ObservedDHCPClient{later}, observedScope)
	if err != nil {
		t.Fatal(err)
	}
	device := snapshot.Devices[0]
	if device.FriendlyName != "Pixel" || device.ObservedDHCP.HostName != "Pixel-7" || len(device.Hostnames) != 2 {
		t.Fatalf("device = %+v", device)
	}
}

// A phone that rotates its private MAC asks the router again with a new MAC
// and gets the same address: the same device, its old lease ended.
func TestObservedDHCPFollowsARotatedPrivateMAC(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	first, err := store.ReconcileObservedDHCP([]ObservedDHCPClient{acknowledged("b6:53:83:65:54:a2", "192.168.10.201", "Pixel-7", now.Add(-2*time.Hour))}, observedScope)
	if err != nil {
		t.Fatal(err)
	}
	id := first.Devices[0].ID
	snapshot, err := store.ReconcileObservedDHCP([]ObservedDHCPClient{acknowledged("fa:16:3e:22:11:00", "192.168.10.201", "Pixel-7", now.Add(-time.Hour))}, observedScope)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Devices) != 1 || snapshot.Devices[0].ID != id || len(snapshot.Devices[0].Identities) != 2 {
		t.Fatalf("the rotated MAC was not the same device: %+v", snapshot.Devices)
	}
	attributor := &Attributor{Store: store, Now: func() time.Time { return now }}
	if match, err := attributor.ResolveAddress(netip.MustParseAddr("192.168.10.201"), now); err != nil || !match.Matched || match.Ambiguous || match.DeviceID != id {
		t.Fatalf("attribution = %+v err=%v", match, err)
	}
}

// A newer acknowledgement of an address to another device ends the older
// device's observed lease, so traffic from it is not ambiguous.
func TestObservedDHCPReassignmentEndsTheOldLease(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	tv := acknowledged("3c:28:6d:00:00:01", "192.168.10.50", "living-room-tv", now.Add(-3*time.Hour))
	tv.VendorClass, tv.ParameterList = "", ""
	console := acknowledged("f8:4d:89:00:00:02", "192.168.10.50", "console", now.Add(-time.Hour))
	snapshot, err := store.ReconcileObservedDHCP([]ObservedDHCPClient{console, tv}, observedScope)
	if err != nil || len(snapshot.Devices) != 2 {
		t.Fatalf("devices = %+v err=%v", snapshot.Devices, err)
	}
	attributor := &Attributor{Store: store, Now: func() time.Time { return now }}
	byName := map[string]string{}
	for _, device := range snapshot.Devices {
		byName[device.ObservedDHCP.HostName] = device.ID
		for _, address := range device.Addresses {
			if device.ObservedDHCP.HostName == "living-room-tv" && !address.ValidUntil.Equal(now.Add(-time.Hour)) {
				t.Fatalf("the TV's lease was not ended at the reassignment: %+v", address)
			}
		}
	}
	if match, _ := attributor.ResolveAddress(netip.MustParseAddr("192.168.10.50"), now); match.DeviceID != byName["console"] || match.Ambiguous {
		t.Fatalf("now = %+v", match)
	}
	if match, _ := attributor.ResolveAddress(netip.MustParseAddr("192.168.10.50"), now.Add(-2*time.Hour)); match.DeviceID != byName["living-room-tv"] {
		t.Fatalf("before the reassignment = %+v", match)
	}
}

func TestObservedDHCPRejectsInvalidClientsAndBoundsTheLease(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	for _, client := range []ObservedDHCPClient{
		{HardwareAddr: "ff:ff:ff:ff:ff:ff", FirstSeen: now, LastSeen: now},
		{HardwareAddr: "B6:53:83:65:54:A2", FirstSeen: now, LastSeen: now},
		{HardwareAddr: "b6:53:83:65:54:a2", HostName: "bad\nname", FirstSeen: now, LastSeen: now},
		{HardwareAddr: "b6:53:83:65:54:a2", ParameterList: "1,3,x", FirstSeen: now, LastSeen: now},
		{HardwareAddr: "b6:53:83:65:54:a2", Server: netip.MustParseAddr("192.168.10.1"), FirstSeen: now, LastSeen: now},
		{HardwareAddr: "b6:53:83:65:54:a2", AssignedAddr: netip.MustParseAddr("224.0.0.1"), AssignedAt: now, FirstSeen: now, LastSeen: now},
	} {
		if _, err := store.ReconcileObservedDHCP([]ObservedDHCPClient{client}, observedScope); err == nil {
			t.Fatalf("accepted %+v", client)
		}
	}
	if _, err := store.ReconcileObservedDHCP(nil, ObservedDHCPScope{Interface: "ens18"}); err == nil {
		t.Fatal("a scope without its plan was accepted")
	}
	forever := acknowledged("b6:53:83:65:54:a2", "192.168.10.201", "", now)
	forever.LeaseTime = 100 * 365 * 24 * time.Hour
	snapshot, err := store.ReconcileObservedDHCP([]ObservedDHCPClient{forever}, ObservedDHCPScope{})
	if err != nil || !snapshot.Devices[0].Addresses[0].ValidUntil.Equal(now.Add(MaxObservedDHCPLease)) || len(snapshot.Devices[0].Hostnames) != 0 {
		t.Fatalf("snapshot = %+v err=%v", snapshot, err)
	}
}
