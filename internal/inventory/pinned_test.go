package inventory

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestNamingAnAddressBeforeTheDeviceIsSeen(t *testing.T) {
	now := time.Date(2026, 10, 1, 21, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	result, err := store.NameAddress("admin", "name-address-000001", AddressName{Name: "Pixel 9", Address: " 192.168.10.201 "})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Devices) != 1 || result.Devices[0].FriendlyName != "Pixel 9" || result.Devices[0].PinnedAddress != "192.168.10.201" || result.Devices[0].Online {
		t.Fatalf("named device = %+v", result.Devices)
	}
	id := result.Devices[0].ID
	// The phone connects with one private MAC, then another; a manufacturer
	// MAC at the named address is the same device too (the tester said so).
	for index, mac := range []string{"e2:4f:7b:ef:5c:30", "72:58:49:e8:e4:00", "00:1a:2b:3c:4d:5e"} {
		if _, err := store.ReconcileNeighbors([]NeighborObservation{neighborObservation("192.168.10.201", mac, now.Add(time.Duration(index)*time.Minute))}); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Devices) != 1 || snapshot.Devices[0].ID != id || len(snapshot.Devices[0].Identities) != 3 || !snapshot.Devices[0].Online {
		t.Fatalf("MACs at the named address did not join it: %+v", snapshot.Devices)
	}
}

func TestNamingTheAddressOfASeenDeviceNamesItAndFoldsEarlierRecords(t *testing.T) {
	now := time.Date(2026, 10, 1, 21, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	recordSeparately(t, store, "192.168.10.201", []string{"8a:23:46:10:cf:33", "00:1a:2b:3c:4d:5e"}, now.Add(-time.Hour))
	// Another device at another address stays out of it.
	if _, err := store.ReconcileNeighbors([]NeighborObservation{neighborObservation("192.168.10.50", "00:aa:bb:cc:dd:ee", now.Add(-time.Minute))}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReconcileNeighbors([]NeighborObservation{neighborObservation("192.168.10.201", "72:58:49:e8:e4:00", now.Add(-time.Minute))}); err != nil {
		t.Fatal(err)
	}
	before, _ := store.Snapshot()
	result, err := store.NameAddress("admin", "name-address-000002", AddressName{Name: "Pixel 9", Address: "192.168.10.201"})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Devices) != 2 {
		t.Fatalf("devices = %d (before %d), want the named phone and the other device", len(snapshot.Devices), len(before.Devices))
	}
	phone := result.Devices[0]
	if phone.FriendlyName != "Pixel 9" || phone.PinnedAddress != "192.168.10.201" || len(phone.Identities) != 3 || !phone.Online || len(phone.FormerIDs) != 1 {
		t.Fatalf("named phone = %+v", phone)
	}
}

func TestNamingAnAddressRejectsConflictsAndBadInput(t *testing.T) {
	now := time.Date(2026, 10, 1, 21, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	first, err := store.NameAddress("admin", "name-address-000003", AddressName{Name: "Pixel 9", Address: "192.168.10.201"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.NameAddress("admin", "name-address-000004", AddressName{Name: "TV", Address: "192.168.10.50"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.NameAddress("admin", "name-address-000005", AddressName{Name: "TV", Address: "192.168.10.201", DeviceID: second.Devices[0].ID}); !errors.Is(err, ErrAddressAlreadyNamed) {
		t.Fatalf("taking another device's address: %v", err)
	}
	// Renaming by the same address updates the same device.
	renamed, err := store.NameAddress("admin", "name-address-000006", AddressName{Name: "Pixel 9 Pro", Address: "192.168.10.201"})
	if err != nil || renamed.Devices[0].ID != first.Devices[0].ID || renamed.Devices[0].FriendlyName != "Pixel 9 Pro" {
		t.Fatalf("rename by address = %+v err=%v", renamed.Devices, err)
	}
	for _, address := range []string{"", "phone", "127.0.0.1", "224.0.0.251", "fe80::1", "0.0.0.0", "192.168.10.0/24"} {
		if _, err := store.NameAddress("admin", "name-address-bad-"+operationSuffix(address), AddressName{Name: "X", Address: address}); !errors.Is(err, ErrMutationRejected) {
			t.Fatalf("address %q was accepted: %v", address, err)
		}
	}
	if _, err := store.NameAddress("admin", "name-address-000007", AddressName{Name: "", Address: "192.168.10.9"}); !errors.Is(err, ErrMutationRejected) {
		t.Fatalf("empty name was accepted: %v", err)
	}
}

func TestUnpinningAnAddress(t *testing.T) {
	now := time.Date(2026, 10, 1, 21, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	unseen, err := store.NameAddress("admin", "name-address-000008", AddressName{Name: "Printer", Address: "192.168.10.60"})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := store.UnpinAddress(unseen.Devices[0].ID, "admin", "unpin-address-000001"); err != nil || len(result.Devices) != 0 {
		t.Fatalf("unpinning a never-seen device should remove it: %+v err=%v", result, err)
	}
	seen, err := store.NameAddress("admin", "name-address-000009", AddressName{Name: "Pixel 9", Address: "192.168.10.201"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReconcileNeighbors([]NeighborObservation{neighborObservation("192.168.10.201", "72:58:49:e8:e4:00", now)}); err != nil {
		t.Fatal(err)
	}
	result, err := store.UnpinAddress(seen.Devices[0].ID, "admin", "unpin-address-000002")
	if err != nil || len(result.Devices) != 1 || result.Devices[0].PinnedAddress != "" || result.Devices[0].FriendlyName != "Pixel 9" {
		t.Fatalf("unpinning a seen device should keep it and its name: %+v err=%v", result, err)
	}
	snapshot, _ := store.Snapshot()
	if len(snapshot.Devices) != 1 {
		t.Fatalf("devices after unpinning = %d", len(snapshot.Devices))
	}
}

func TestADHCPClientAtANamedAddressJoinsIt(t *testing.T) {
	now := time.Date(2026, 10, 1, 21, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	named, err := store.NameAddress("admin", "name-address-000010", AddressName{Name: "Smart TV", Address: "10.77.0.50"})
	if err != nil {
		t.Fatal(err)
	}
	lease := DHCP4Lease{Address: netip.MustParseAddr("10.77.0.50"), HardwareAddr: "52:54:00:00:00:09", Hostname: "tv", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)}
	snapshot, err := store.ReconcileDHCP4([]DHCP4Lease{lease})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Devices) != 1 || snapshot.Devices[0].ID != named.Devices[0].ID || snapshot.Devices[0].FriendlyName != "Smart TV" {
		t.Fatalf("the DHCP client did not join the named device: %+v", snapshot.Devices)
	}
}

func operationSuffix(value string) string {
	out := []byte{}
	for _, c := range []byte(value) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			out = append(out, c)
		} else {
			out = append(out, '-')
		}
	}
	return string(out) + "-op"
}
