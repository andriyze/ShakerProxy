package inventory

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCATrustIsAuditedIdempotentAndPersisted(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	snapshot, err := store.ReconcileDHCP4([]DHCP4Lease{
		{Address: netip.MustParseAddr("10.77.0.23"), HardwareAddr: "52:54:00:00:00:23", ClientID: "01:23", Hostname: "tv", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)},
	})
	if err != nil || len(snapshot.Devices) != 1 {
		t.Fatalf("seed inventory: %#v err=%v", snapshot, err)
	}
	device := snapshot.Devices[0]
	if device.CATrustState() != CATrustUnknown {
		t.Fatalf("new device CA trust: %q", device.CATrustState())
	}
	encoded, _ := json.Marshal(device)
	if strings.Contains(string(encoded), "ca_trust") {
		t.Fatalf("unset CA trust must be omitted for compatibility: %s", encoded)
	}

	result, err := store.SetCATrust(device.ID, "admin", "ca-trust-operation-0001", CATrustNotInstalled)
	if err != nil || result.Replayed || len(result.Devices) != 1 || result.Devices[0].CATrust != CATrustNotInstalled {
		t.Fatalf("set CA trust: %#v err=%v", result, err)
	}
	if result.Audit.Action != AuditCATrustUpdated || len(result.Audit.Changes) != 1 || result.Audit.Changes[0] != "CA trust changed from UNKNOWN to NOT_INSTALLED" || result.Audit.Actor != "admin" {
		t.Fatalf("CA trust audit: %#v", result.Audit)
	}
	replay, err := store.SetCATrust(device.ID, "admin", "ca-trust-operation-0001", CATrustNotInstalled)
	if err != nil || !replay.Replayed || replay.Audit.ID != result.Audit.ID {
		t.Fatalf("replay was not idempotent: %#v err=%v", replay, err)
	}
	if _, err := store.SetCATrust(device.ID, "admin", "ca-trust-operation-0001", CATrustInstalled); !errors.Is(err, ErrOperationConflict) {
		t.Fatalf("operation reuse with a different state: %v", err)
	}
	if unchanged, err := store.SetCATrust(device.ID, "admin", "ca-trust-operation-0002", CATrustNotInstalled); err != nil || !unchanged.Unchanged || unchanged.Audit.ID != "" || unchanged.Devices[0].CATrust != CATrustNotInstalled {
		t.Fatalf("no-op change: %#v err=%v", unchanged, err)
	}
	for _, invalid := range []string{"", "installed", "MAYBE"} {
		if _, err := store.SetCATrust(device.ID, "admin", "ca-trust-operation-0003", invalid); !errors.Is(err, ErrMutationRejected) {
			t.Fatalf("invalid state %q: %v", invalid, err)
		}
	}
	if _, err := store.SetCATrust("device-00000000000000000000000000000000", "admin", "ca-trust-operation-0004", CATrustInstalled); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unknown device: %v", err)
	}

	reloaded, err := store.Get(device.ID)
	if err != nil || reloaded.CATrustState() != CATrustNotInstalled {
		t.Fatalf("persisted state: %#v err=%v", reloaded, err)
	}
	cleared, err := store.SetCATrust(device.ID, "admin", "ca-trust-operation-0005", CATrustUnknown)
	if err != nil || cleared.Devices[0].CATrust != "" || cleared.Devices[0].CATrustState() != CATrustUnknown {
		t.Fatalf("clearing CA trust: %#v err=%v", cleared, err)
	}
	events, err := store.AuditLog(10)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, event := range events {
		if event.Action == AuditCATrustUpdated {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("audit log holds %d CA trust events: %#v", count, events)
	}
}

func TestInventoryRejectsInvalidStoredCATrust(t *testing.T) {
	device := Device{CATrust: "SOMETIMES"}
	if validCATrust(device.CATrust) {
		t.Fatal("invalid stored CA trust was accepted")
	}
	for _, value := range []string{"", CATrustInstalled, CATrustNotInstalled} {
		if !validCATrust(value) {
			t.Fatalf("valid stored CA trust %q was rejected", value)
		}
	}
}

func TestMergeKeepsRecordedCATrust(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	snapshot, err := store.ReconcileDHCP4([]DHCP4Lease{
		{Address: netip.MustParseAddr("10.77.0.41"), HardwareAddr: "52:54:00:00:00:41", ClientID: "01:41", Hostname: "phone-a", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)},
		{Address: netip.MustParseAddr("10.77.0.42"), HardwareAddr: "52:54:00:00:00:42", ClientID: "01:42", Hostname: "phone-b", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)},
	})
	if err != nil {
		t.Fatal(err)
	}
	source := deviceWithMAC(t, snapshot.Devices, "52:54:00:00:00:41")
	target := deviceWithMAC(t, snapshot.Devices, "52:54:00:00:00:42")
	if _, err := store.SetCATrust(source.ID, "admin", "ca-trust-merge-op-0001", CATrustNotInstalled); err != nil {
		t.Fatal(err)
	}
	merged, err := store.MergeDevices(target.ID, source.ID, "admin", "ca-trust-merge-op-0002")
	if err != nil || len(merged.Devices) != 1 || merged.Devices[0].CATrustState() != CATrustNotInstalled {
		t.Fatalf("merge lost CA trust: %#v err=%v", merged, err)
	}

	conflictTarget := Device{CATrust: CATrustInstalled}
	mergeCATrust(&conflictTarget, Device{CATrust: CATrustNotInstalled})
	if conflictTarget.CATrust != CATrustInstalled || len(conflictTarget.AttributionWarnings) != 1 {
		t.Fatalf("conflicting CA trust merge: %#v", conflictTarget)
	}
}
