package inventory

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAttributorUsesHistoricalValidityWindowsAndRejectsAmbiguity(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	address := netip.MustParseAddr("10.77.0.111")
	vlan := 20
	planHash := strings.Repeat("d", 64)
	snapshot, err := store.ReconcileDHCP4([]DHCP4Lease{
		{Address: address, HardwareAddr: "52:54:00:00:00:01", ClientID: "01:01", ValidLifetime: time.Hour, ExpiresAt: now.Add(-time.Hour)},
		{Address: address, HardwareAddr: "52:54:00:00:00:02", ClientID: "01:02", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour), Interface: "enp2s0.20", VLANID: &vlan, ScopePlanSHA256: planHash},
	})
	if err != nil || len(snapshot.Devices) != 2 {
		t.Fatalf("seed inventory failed: %#v err=%v", snapshot, err)
	}
	attributor := &Attributor{Store: store, Now: func() time.Time { return now }}
	old, err := attributor.ResolveIPv4(address, now.Add(-90*time.Minute))
	if err != nil || !old.Matched || old.Ambiguous || old.DeviceID == "" || old.Address != address.String() || old.Confidence != 95 || !old.ValidFrom.Equal(now.Add(-2*time.Hour)) || !old.ValidUntil.Equal(now.Add(-time.Hour)) {
		t.Fatalf("historical address was not attributed: %#v err=%v", old, err)
	}
	current, err := attributor.ResolveIPv4(address, now)
	if err != nil || !current.Matched || current.DeviceID == old.DeviceID || current.Interface != "enp2s0.20" || current.VLANID == nil || *current.VLANID != 20 || current.ScopePlanSHA256 != planHash {
		t.Fatalf("reused address was not attributed by time: %#v err=%v", current, err)
	}
	boundary, err := attributor.ResolveIPv4(address, now.Add(-time.Hour))
	if err != nil || boundary.Matched || boundary.Ambiguous {
		t.Fatalf("expiry boundary was not treated as an exclusive end: %#v err=%v", boundary, err)
	}

	overlapStore := &Store{Path: filepath.Join(t.TempDir(), "inventory.json"), Now: func() time.Time { return now }}
	overlapStore.Random = store.Random
	_, err = overlapStore.ReconcileDHCP4([]DHCP4Lease{
		{Address: address, HardwareAddr: "52:54:00:00:00:03", ClientID: "01:03", ValidLifetime: 2 * time.Hour, ExpiresAt: now.Add(time.Hour)},
		{Address: address, HardwareAddr: "52:54:00:00:00:04", ClientID: "01:04", ValidLifetime: 2 * time.Hour, ExpiresAt: now.Add(time.Hour)},
	})
	if err != nil {
		t.Fatal(err)
	}
	ambiguous, err := (&Attributor{Store: overlapStore, Now: func() time.Time { return now }}).ResolveIPv4(address, now)
	if err != nil || ambiguous.Matched || !ambiguous.Ambiguous || ambiguous.DeviceID != "" {
		t.Fatalf("overlapping devices were attributed: %#v err=%v", ambiguous, err)
	}
}

func TestAttributorCacheRefreshesAndFailsClosed(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	address := netip.MustParseAddr("10.77.0.111")
	if _, err := store.ReconcileDHCP4([]DHCP4Lease{{Address: address, HardwareAddr: "52:54:00:00:00:01", ClientID: "01:01", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	clock := now
	attributor := &Attributor{Store: store, RefreshInterval: time.Second, Now: func() time.Time { return clock }}
	if result, err := attributor.ResolveIPv4(address, now); err != nil || !result.Matched {
		t.Fatalf("initial attribution failed: %#v err=%v", result, err)
	}
	if err := osWriteInvalidInventory(store.Path); err != nil {
		t.Fatal(err)
	}
	if result, err := attributor.ResolveIPv4(address, now); err != nil || !result.Matched {
		t.Fatalf("unexpired cache was not used: %#v err=%v", result, err)
	}
	clock = clock.Add(2 * time.Second)
	if _, err := attributor.ResolveIPv4(address, now); err == nil {
		t.Fatal("invalid inventory was accepted after cache expiry")
	}
}

func osWriteInvalidInventory(path string) error {
	return os.WriteFile(path, []byte("not-json\n"), 0o600)
}
