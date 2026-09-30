package inventory

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEmptySnapshotSerializesDevicesAsArray(t *testing.T) {
	snapshot, err := (&Store{Path: filepath.Join(t.TempDir(), "inventory.json")}).Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"devices":[]`) {
		t.Fatalf("empty device inventory must serialize as an array: %s", payload)
	}
}

func TestReconcileDHCP4UsesIdentityNotReusedAddress(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	sequence := byte(0)
	store := &Store{Path: filepath.Join(t.TempDir(), "inventory.json"), Now: func() time.Time { return now }, Random: func(dst []byte) (int, error) {
		sequence++
		for index := range dst {
			dst[index] = sequence
		}
		return len(dst), nil
	}}
	address := netip.MustParseAddr("10.77.0.111")
	oldLease := DHCP4Lease{Address: address, HardwareAddr: "52:54:00:00:00:01", ClientID: "01:0d", Hostname: "old-device", ValidLifetime: 10 * time.Minute, ExpiresAt: now.Add(-time.Hour)}
	newLease := DHCP4Lease{Address: address, HardwareAddr: "52:54:00:00:00:02", ClientID: "01:0e", Hostname: "new-device", ValidLifetime: 10 * time.Minute, ExpiresAt: now.Add(10 * time.Minute)}
	snapshot, err := store.ReconcileDHCP4([]DHCP4Lease{oldLease, newLease})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Devices) != 2 {
		t.Fatalf("IP reuse merged devices: %#v", snapshot.Devices)
	}
	if !snapshot.Devices[0].Online || snapshot.Devices[1].Online {
		t.Fatalf("unexpected online attribution: %#v", snapshot.Devices)
	}
	if snapshot.Devices[0].Addresses[0].Address != snapshot.Devices[1].Addresses[0].Address {
		t.Fatal("test did not preserve time-bounded address reuse")
	}

	persisted, err := store.Snapshot()
	if err != nil || len(persisted.Devices) != 2 {
		t.Fatalf("inventory did not persist: snapshot=%#v err=%v", persisted, err)
	}
}

func TestReconcileDHCP4CorrelatesAddressHistoryByMAC(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	store := &Store{Path: filepath.Join(t.TempDir(), "inventory.json"), Now: func() time.Time { return now }, Random: func(dst []byte) (int, error) {
		for index := range dst {
			dst[index] = 7
		}
		return len(dst), nil
	}}
	leases := []DHCP4Lease{
		{Address: netip.MustParseAddr("10.77.0.110"), HardwareAddr: "52:54:00:00:00:01", ClientID: "01:aa", ValidLifetime: 10 * time.Minute, ExpiresAt: now.Add(-time.Hour)},
		{Address: netip.MustParseAddr("10.77.0.120"), HardwareAddr: "52:54:00:00:00:01", ClientID: "01:aa", ValidLifetime: 10 * time.Minute, ExpiresAt: now.Add(10 * time.Minute)},
	}
	snapshot, err := store.ReconcileDHCP4(leases)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Devices) != 1 || len(snapshot.Devices[0].Addresses) != 2 || !snapshot.Devices[0].Online || snapshot.Devices[0].AttributionConfidence != 95 {
		t.Fatalf("unexpected correlated device: %#v", snapshot.Devices)
	}
}

func TestReconcileDHCP4PreservesConfirmedNetworkScope(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	store := &Store{Path: filepath.Join(t.TempDir(), "inventory.json"), Now: func() time.Time { return now }}
	vlan20, vlan30 := 20, 30
	planHash := strings.Repeat("a", 64)
	base := DHCP4Lease{
		Address:         netip.MustParseAddr("10.77.0.110"),
		HardwareAddr:    "52:54:00:00:00:01",
		ClientID:        "01:aa",
		ValidLifetime:   10 * time.Minute,
		ExpiresAt:       now.Add(10 * time.Minute),
		Interface:       "enp2s0.20",
		VLANID:          &vlan20,
		ScopePlanSHA256: planHash,
	}
	otherScope := base
	otherScope.Interface, otherScope.VLANID = "enp3s0.30", &vlan30
	snapshot, err := store.ReconcileDHCP4([]DHCP4Lease{base, otherScope})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Devices) != 1 || len(snapshot.Devices[0].Addresses) != 2 {
		t.Fatalf("network scopes were collapsed: %#v", snapshot.Devices)
	}
	observed := make(map[string]AddressObservation, 2)
	for _, address := range snapshot.Devices[0].Addresses {
		observed[address.Interface] = address
	}
	if observed["enp2s0.20"].VLANID == nil || *observed["enp2s0.20"].VLANID != 20 || observed["enp2s0.20"].ScopePlanSHA256 != planHash || observed["enp3s0.30"].VLANID == nil || *observed["enp3s0.30"].VLANID != 30 {
		t.Fatalf("confirmed scope provenance was not preserved: %#v", snapshot.Devices[0].Addresses)
	}
	vlan20 = 99
	persisted, err := store.Snapshot()
	if err != nil || persisted.Devices[0].Addresses[0].VLANID == nil || *persisted.Devices[0].Addresses[0].VLANID == 99 {
		t.Fatalf("lease scope pointer leaked into durable state: %#v err=%v", persisted, err)
	}
}

func TestReconcileDHCP4RejectsPartialOrInvalidNetworkScopeAtomically(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	store := &Store{Path: filepath.Join(t.TempDir(), "inventory.json"), Now: func() time.Time { return now }}
	base := DHCP4Lease{Address: netip.MustParseAddr("10.77.0.110"), HardwareAddr: "52:54:00:00:00:01", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)}
	if _, err := store.ReconcileDHCP4([]DHCP4Lease{base}); err != nil {
		t.Fatal(err)
	}
	invalid := base
	invalid.Interface = "enp2s0"
	invalid.ScopePlanSHA256 = "not-a-plan-hash"
	if _, err := store.ReconcileDHCP4([]DHCP4Lease{invalid}); err == nil {
		t.Fatal("invalid network scope was accepted")
	}
	after, err := store.Snapshot()
	if err != nil || len(after.Devices) != 1 || len(after.Devices[0].Addresses) != 1 || after.Devices[0].Addresses[0].Interface != "" {
		t.Fatalf("rejected scope changed durable inventory: %#v err=%v", after, err)
	}
	partial := base
	partial.Interface = "enp2s0"
	if _, err := store.ReconcileDHCP4([]DHCP4Lease{partial}); err == nil {
		t.Fatal("partial network scope without plan provenance was accepted")
	}
}

func TestReconcileDHCP4DoesNotSilentlyMergeConflictingIdentities(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	sequence := byte(0)
	store := &Store{Path: filepath.Join(t.TempDir(), "inventory.json"), Now: func() time.Time { return now }, Random: func(dst []byte) (int, error) {
		sequence++
		for index := range dst {
			dst[index] = sequence
		}
		return len(dst), nil
	}}
	base := []DHCP4Lease{
		{Address: netip.MustParseAddr("10.77.0.110"), HardwareAddr: "52:54:00:00:00:01", ClientID: "01:01", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)},
		{Address: netip.MustParseAddr("10.77.0.120"), HardwareAddr: "52:54:00:00:00:02", ClientID: "01:02", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)},
	}
	if _, err := store.ReconcileDHCP4(base); err != nil {
		t.Fatal(err)
	}
	conflict := DHCP4Lease{Address: netip.MustParseAddr("10.77.0.121"), HardwareAddr: "52:54:00:00:00:02", ClientID: "01:01", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)}
	snapshot, err := store.ReconcileDHCP4(append(base, conflict))
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Devices) != 2 || len(snapshot.Devices[0].AttributionWarnings)+len(snapshot.Devices[1].AttributionWarnings) == 0 {
		t.Fatalf("identity conflict was merged or hidden: %#v", snapshot.Devices)
	}
}

func TestInventoryReadRejectsSymlinkAndDeviceIDCollisionFailsClosed(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	directory := t.TempDir()
	store := &Store{Path: filepath.Join(directory, "inventory.json"), Now: func() time.Time { return now }, Random: func(destination []byte) (int, error) {
		for index := range destination {
			destination[index] = 7
		}
		return len(destination), nil
	}}
	first := DHCP4Lease{Address: netip.MustParseAddr("10.77.0.110"), HardwareAddr: "52:54:00:00:00:01", ClientID: "01:01", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)}
	if _, err := store.ReconcileDHCP4([]DHCP4Lease{first}); err != nil {
		t.Fatal(err)
	}
	second := DHCP4Lease{Address: netip.MustParseAddr("10.77.0.120"), HardwareAddr: "52:54:00:00:00:02", ClientID: "01:02", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)}
	if _, err := store.ReconcileDHCP4([]DHCP4Lease{first, second}); err == nil {
		t.Fatal("duplicate generated device ID was published")
	}
	persisted, err := store.Snapshot()
	if err != nil || len(persisted.Devices) != 1 {
		t.Fatalf("failed collision changed durable inventory: %#v err=%v", persisted, err)
	}
	link := filepath.Join(directory, "inventory-link.json")
	if err := os.Symlink(store.Path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Store{Path: link}).Snapshot(); err == nil {
		t.Fatal("symlinked inventory state was accepted")
	}
}
