package inventory

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMetadataAndMergeAreAuditedAndIdempotent(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	snapshot, err := store.ReconcileDHCP4([]DHCP4Lease{
		{Address: netip.MustParseAddr("10.77.0.110"), HardwareAddr: "52:54:00:00:00:01", ClientID: "01:01", Hostname: "camera", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)},
		{Address: netip.MustParseAddr("10.77.0.120"), HardwareAddr: "52:54:00:00:00:02", ClientID: "01:02", Hostname: "sensor", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)},
	})
	if err != nil || len(snapshot.Devices) != 2 {
		t.Fatalf("seed inventory failed: %#v err=%v", snapshot, err)
	}
	target := deviceWithMAC(t, snapshot.Devices, "52:54:00:00:00:01")
	source := deviceWithMAC(t, snapshot.Devices, "52:54:00:00:00:02")
	metadata := DeviceMetadata{FriendlyName: "Bench Camera", Owner: "Lab Team", Location: "North bench", Category: "Camera", Icon: "camera", Tags: []string{"Camera", "bench"}, Notes: "Authorized fixture"}
	updated, err := store.UpdateMetadata(target.ID, "admin", "device-meta-op-0001", metadata)
	if err != nil || updated.Replayed || len(updated.Devices) != 1 || updated.Devices[0].FriendlyName != "Bench Camera" || updated.Devices[0].Location != "North bench" || updated.Devices[0].Category != "camera" || updated.Devices[0].Icon != "camera" || len(updated.Devices[0].Tags) != 2 || updated.Devices[0].Tags[0] != "bench" {
		t.Fatalf("metadata mutation failed: %#v err=%v", updated, err)
	}
	replay, err := store.UpdateMetadata(target.ID, "admin", "device-meta-op-0001", metadata)
	if err != nil || !replay.Replayed || replay.Audit.ID != updated.Audit.ID {
		t.Fatalf("metadata replay was not idempotent: %#v err=%v", replay, err)
	}
	if _, err := store.UpdateMetadata(target.ID, "admin", "device-meta-op-0001", DeviceMetadata{FriendlyName: "Different"}); !errors.Is(err, ErrOperationConflict) {
		t.Fatalf("metadata operation ID reuse with a different request was accepted: %v", err)
	}
	if _, err := store.UpdateMetadata(target.ID, "admin", "device-meta-invalid-1", DeviceMetadata{Icon: "https://example.test/icon.svg"}); !errors.Is(err, ErrMutationRejected) {
		t.Fatalf("unsafe device icon was accepted: %v", err)
	}
	if _, err := store.UpdateMetadata(target.ID, "admin", "device-meta-invalid-2", DeviceMetadata{Category: "Camera / Lab"}); !errors.Is(err, ErrMutationRejected) {
		t.Fatalf("noncanonical device category was accepted: %v", err)
	}
	merged, err := store.MergeDevices(target.ID, source.ID, "admin", "device-merge-op-001")
	if err != nil || len(merged.Devices) != 1 || len(merged.Devices[0].Identities) != 4 || merged.Devices[0].FriendlyName != "Bench Camera" {
		t.Fatalf("device merge failed: %#v err=%v", merged, err)
	}
	persisted, err := store.Snapshot()
	if err != nil || len(persisted.Devices) != 1 {
		t.Fatalf("merged inventory did not persist: %#v err=%v", persisted, err)
	}
	audit, err := store.AuditLog(10)
	if err != nil || len(audit) != 2 || audit[0].Action != AuditDevicesMerged || audit[1].Action != AuditMetadataUpdated || audit[0].PreviousSHA256 != audit[1].EntrySHA256 || audit[1].PreviousSHA256 != "" {
		t.Fatalf("unexpected audit trail: %#v err=%v", audit, err)
	}
	if _, err := store.MergeDevices(target.ID, source.ID, "admin", "device-meta-op-0001"); !errors.Is(err, ErrOperationConflict) {
		t.Fatalf("operation ID reuse with different semantics was accepted: %v", err)
	}
	contents, err := os.ReadFile(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	auditOffset := strings.Index(text, `"audit_events"`)
	if auditOffset < 0 {
		t.Fatal("audit fixture did not contain an audit ledger")
	}
	tampered := text[:auditOffset] + strings.Replace(text[auditOffset:], `"actor": "admin"`, `"actor": "admon"`, 1)
	if tampered == string(contents) {
		t.Fatal("audit fixture did not contain the expected actor")
	}
	if err := os.WriteFile(store.Path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Snapshot(); err == nil {
		t.Fatal("tampered device audit hash chain was accepted")
	}
}

func TestAliasUpdatesAreRevisionedIdempotentAndConflictAware(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	snapshot, err := store.ReconcileDHCP4([]DHCP4Lease{
		{Address: netip.MustParseAddr("10.77.0.110"), HardwareAddr: "52:54:00:00:00:01", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)},
		{Address: netip.MustParseAddr("10.77.0.120"), HardwareAddr: "52:54:00:00:00:02", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)},
	})
	if err != nil || len(snapshot.Devices) != 2 {
		t.Fatalf("seed inventory failed: %#v err=%v", snapshot, err)
	}
	first := deviceWithMAC(t, snapshot.Devices, "52:54:00:00:00:01")
	second := deviceWithMAC(t, snapshot.Devices, "52:54:00:00:00:02")
	result, err := store.UpdateAlias(first.ID, "admin", "device-alias-op-1001", AliasUpdate{FriendlyName: "  Bench Camera  ", Reason: "  Matched chassis label  ", ExpectedRevision: 0})
	if err != nil || result.Replayed || result.Devices[0].AliasRevision != 1 || result.Devices[0].FriendlyName != "Bench Camera" || len(result.Devices[0].AliasHistory) != 1 || result.Devices[0].AliasHistory[0].Reason != "Matched chassis label" || result.Audit.Action != AuditAliasUpdated {
		t.Fatalf("unexpected alias update: %#v err=%v", result, err)
	}
	replay, err := store.UpdateAlias(first.ID, "admin", "device-alias-op-1001", AliasUpdate{FriendlyName: "  Bench Camera  ", Reason: "  Matched chassis label  ", ExpectedRevision: 0})
	if err != nil || !replay.Replayed || replay.Audit.ID != result.Audit.ID {
		t.Fatalf("alias replay was not idempotent: %#v err=%v", replay, err)
	}
	if _, err := store.UpdateAlias(first.ID, "admin", "device-alias-op-1002", AliasUpdate{FriendlyName: "North Camera", Reason: "Moved", ExpectedRevision: 0}); !errors.Is(err, ErrAliasRevisionConflict) {
		t.Fatalf("stale alias revision was accepted: %v", err)
	}
	if _, err := store.UpdateAlias(second.ID, "admin", "device-alias-op-1003", AliasUpdate{FriendlyName: "bench camera", Reason: "Duplicate is intentional", ExpectedRevision: 0}); err != nil {
		t.Fatal(err)
	}
	persisted, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range persisted.Devices {
		if !device.FriendlyNameConflict {
			t.Fatalf("case-insensitive duplicate name was not flagged: %#v", persisted.Devices)
		}
	}
}

func TestMetadataPatchReplaysLegacyDigestWithoutClearingAdditiveFields(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	snapshot, err := store.ReconcileDHCP4([]DHCP4Lease{{Address: netip.MustParseAddr("10.77.0.110"), HardwareAddr: "52:54:00:00:00:01", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	deviceID := snapshot.Devices[0].ID
	legacy := DeviceMetadata{FriendlyName: "Bench Camera", Owner: "Lab", Tags: []string{"camera"}, Notes: "Legacy"}
	result, err := store.UpdateMetadata(deviceID, "admin", "legacy-metadata-op-1", legacy)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := store.load()
	if err != nil {
		t.Fatal(err)
	}
	legacyDigest, err := mutationRequestDigest(AuditMetadataUpdated, []string{deviceID}, legacy)
	if err != nil {
		t.Fatal(err)
	}
	doc.AuditEvents[0].RequestSHA256 = legacyDigest
	doc.AuditEvents[0].EntrySHA256, err = auditEventDigest(doc.AuditEvents[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := store.save(doc); err != nil {
		t.Fatalf("seed legacy audit: %v", err)
	}
	replay, err := store.PatchMetadata(deviceID, "admin", "legacy-metadata-op-1", DeviceMetadataPatch{FriendlyName: &legacy.FriendlyName, Owner: &legacy.Owner, Tags: &legacy.Tags, Notes: &legacy.Notes})
	if err != nil || !replay.Replayed || replay.Audit.ID != result.Audit.ID {
		t.Fatalf("legacy metadata digest did not replay: %#v err=%v", replay, err)
	}
	location, category, icon := "North bench", "camera", "camera"
	patched, err := store.PatchMetadata(deviceID, "admin", "additive-metadata-op-1", DeviceMetadataPatch{Location: &location, Category: &category, Icon: &icon})
	if err != nil || patched.Devices[0].FriendlyName != legacy.FriendlyName || patched.Devices[0].Location != location || patched.Devices[0].Category != category || patched.Devices[0].Icon != icon {
		t.Fatalf("additive patch cleared legacy metadata: %#v err=%v", patched, err)
	}
}

func TestAliasHistoryIsBoundedAndMarksItsBoundary(t *testing.T) {
	device := Device{}
	start := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	for revision := 1; revision <= MaxAliasHistory+1; revision++ {
		if err := appendAliasChange(&device, fmt.Sprintf("Name %d", revision), "admin", "Bounded history test", start.Add(time.Duration(revision)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if len(device.AliasHistory) != MaxAliasHistory || !device.AliasHistoryTruncated || device.AliasHistory[0].Revision != 2 || device.AliasRevision != MaxAliasHistory+1 {
		t.Fatalf("alias history was not bounded correctly: revision=%d first=%d length=%d truncated=%v", device.AliasRevision, device.AliasHistory[0].Revision, len(device.AliasHistory), device.AliasHistoryTruncated)
	}
}

func TestSplitMovesOnlyExactSelectedEvidenceAndPersistsAudit(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	vlan := 20
	planHash := strings.Repeat("b", 64)
	snapshot, err := store.ReconcileDHCP4([]DHCP4Lease{
		{Address: netip.MustParseAddr("10.77.0.110"), HardwareAddr: "52:54:00:00:00:01", ClientID: "01:01", Hostname: "first", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour), Interface: "enp2s0.20", VLANID: &vlan, ScopePlanSHA256: planHash},
		{Address: netip.MustParseAddr("10.77.0.120"), HardwareAddr: "52:54:00:00:00:01", ClientID: "01:02", Hostname: "second", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour), Interface: "enp2s0.20", VLANID: &vlan, ScopePlanSHA256: planHash},
	})
	if err != nil || len(snapshot.Devices) != 1 {
		t.Fatalf("seed inventory failed: %#v err=%v", snapshot, err)
	}
	source := snapshot.Devices[0]
	var selectedAddress AddressObservation
	for _, address := range source.Addresses {
		if address.Address == "10.77.0.120" {
			selectedAddress = address
		}
	}
	selection := SplitSelection{
		Identities: []IdentitySelector{{Kind: IdentityDHCPClientID, Value: "01:02", Source: SourceDHCP4Lease}},
		Addresses:  []AddressSelector{{Address: selectedAddress.Address, Source: selectedAddress.Source, ValidFrom: selectedAddress.ValidFrom, ValidUntil: selectedAddress.ValidUntil, Interface: selectedAddress.Interface, VLANID: selectedAddress.VLANID, ScopePlanSHA256: selectedAddress.ScopePlanSHA256}},
		Hostnames:  []HostnameSelector{{Hostname: "second", Source: SourceDHCP4Lease}},
		Metadata:   DeviceMetadata{FriendlyName: "Separated Sensor", Tags: []string{"reviewed"}},
	}
	inexact := selection
	inexact.Addresses = append([]AddressSelector(nil), selection.Addresses...)
	inexact.Addresses[0].Interface, inexact.Addresses[0].VLANID, inexact.Addresses[0].ScopePlanSHA256 = "", nil, ""
	if _, err := store.SplitDevice(source.ID, "admin", "device-split-scope-00", inexact); err == nil {
		t.Fatal("split selector without the observed network scope was accepted")
	}
	result, err := store.SplitDevice(source.ID, "admin", "device-split-op-001", selection)
	if err != nil || len(result.Devices) != 2 {
		t.Fatalf("device split failed: %#v err=%v", result, err)
	}
	var original, created Device
	for _, device := range result.Devices {
		if device.ID == source.ID {
			original = device
		} else {
			created = device
		}
	}
	if len(original.Identities) != 2 || len(original.Addresses) != 1 || len(created.Identities) != 1 || len(created.Addresses) != 1 || created.Addresses[0].Address != "10.77.0.120" || created.FriendlyName != "Separated Sensor" || !created.Online {
		t.Fatalf("split did not preserve exact evidence boundaries: original=%#v created=%#v", original, created)
	}
	replay, err := store.SplitDevice(source.ID, "admin", "device-split-op-001", selection)
	if err != nil || !replay.Replayed || replay.Audit.ID != result.Audit.ID {
		t.Fatalf("split replay was not idempotent: %#v err=%v", replay, err)
	}
	conflictingSelection := selection
	conflictingSelection.Metadata.FriendlyName = "Different"
	if _, err := store.SplitDevice(source.ID, "admin", "device-split-op-001", conflictingSelection); !errors.Is(err, ErrOperationConflict) {
		t.Fatalf("split operation ID reuse with a different request was accepted: %v", err)
	}
	audit, err := store.AuditLog(1)
	if err != nil || len(audit) != 1 || audit[0].Action != AuditDeviceSplit || len(audit[0].ResultDeviceIDs) != 2 {
		t.Fatalf("split audit is missing: %#v err=%v", audit, err)
	}
}

func TestSplitRejectsInexactEvidenceWithoutChangingInventory(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	snapshot, err := store.ReconcileDHCP4([]DHCP4Lease{{Address: netip.MustParseAddr("10.77.0.110"), HardwareAddr: "52:54:00:00:00:01", ClientID: "01:01", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.SplitDevice(snapshot.Devices[0].ID, "admin", "device-split-op-002", SplitSelection{Identities: []IdentitySelector{{Kind: IdentityDHCPClientID, Value: "01:ff", Source: SourceDHCP4Lease}}})
	if err == nil {
		t.Fatal("inexact split evidence was accepted")
	}
	after, snapshotErr := store.Snapshot()
	audit, auditErr := store.AuditLog(10)
	if snapshotErr != nil || auditErr != nil || len(after.Devices) != 1 || len(audit) != 0 {
		t.Fatalf("rejected split changed durable state: snapshot=%#v audit=%#v errors=%v/%v", after, audit, snapshotErr, auditErr)
	}
}

func deterministicMutationStore(t *testing.T, now time.Time) *Store {
	t.Helper()
	sequence := byte(0)
	return &Store{Path: filepath.Join(t.TempDir(), "inventory.json"), Now: func() time.Time { return now }, Random: func(destination []byte) (int, error) {
		sequence++
		for index := range destination {
			destination[index] = sequence
		}
		return len(destination), nil
	}}
}

func deviceWithMAC(t *testing.T, devices []Device, mac string) Device {
	t.Helper()
	for _, device := range devices {
		for _, identity := range device.Identities {
			if identity.Kind == IdentityMAC && identity.Value == mac {
				return device
			}
		}
	}
	t.Fatalf("device with MAC %s was not found", mac)
	return Device{}
}
