package inventory

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFullDeviceAuditRollsIntoVerifiedArchive(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	snapshot, err := store.ReconcileDHCP4([]DHCP4Lease{{Address: netip.MustParseAddr("10.77.0.110"), HardwareAddr: "52:54:00:00:00:01", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	deviceID := snapshot.Devices[0].ID
	doc, err := store.load()
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < MaxAuditEvents; index++ {
		event := newAuditEvent(fmt.Sprintf("seed-operation-%06d", index), sha256Hex(index), AuditMetadataUpdated, "admin", now, []string{deviceID}, []string{deviceID}, []string{"notes changed"})
		if err := appendAudit(&doc, &event); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.save(doc); err != nil {
		t.Fatal(err)
	}
	// The ledger is full; the next mutation archives the oldest batch instead of failing.
	result, err := store.PatchMetadata(deviceID, "admin", "archive-trigger-op-0001", DeviceMetadataPatch{Notes: ptr("after rollover")})
	if err != nil {
		t.Fatalf("mutation on a full audit ledger failed: %v", err)
	}
	reloaded, err := store.load()
	if err != nil {
		t.Fatalf("archived ledger does not verify: %v", err)
	}
	if len(reloaded.AuditEvents) != MaxAuditEvents-AuditArchiveBatch+1 || reloaded.AuditArchivedCount != AuditArchiveBatch || reloaded.AuditEvents[0].PreviousSHA256 != reloaded.AuditAnchorSHA256 || reloaded.AuditEvents[len(reloaded.AuditEvents)-1].ID != result.Audit.ID {
		t.Fatalf("unexpected retained ledger: len=%d archived=%d", len(reloaded.AuditEvents), reloaded.AuditArchivedCount)
	}
	archive, err := os.Open(filepath.Join(filepath.Dir(store.Path), auditArchiveName))
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	previous := ""
	count := 0
	scanner := bufio.NewScanner(archive)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		var event AuditEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil || validateAuditEvent(event) != nil || event.PreviousSHA256 != previous {
			t.Fatalf("archived event %d does not chain: %v", count, err)
		}
		previous = event.EntrySHA256
		count++
	}
	if count != AuditArchiveBatch || previous != reloaded.AuditAnchorSHA256 {
		t.Fatalf("archive has %d events ending at %s, anchor %s", count, previous, reloaded.AuditAnchorSHA256)
	}
	// Tampering with the anchor is detected.
	reloaded.AuditAnchorSHA256 = sha256Hex(99)
	if err := store.save(reloaded); err != nil {
		t.Fatal(err)
	}
	if _, err := store.load(); err == nil {
		t.Fatal("a broken archive anchor was accepted")
	}
}

func TestReconcileSkipsRewritingUnchangedEvidence(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	current := now
	store := deterministicMutationStore(t, now)
	store.Now = func() time.Time { return current }
	leases := []DHCP4Lease{{Address: netip.MustParseAddr("10.77.0.110"), HardwareAddr: "52:54:00:00:00:01", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)}}
	if _, err := store.ReconcileDHCP4(leases); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	current = now.Add(10 * time.Second)
	snapshot, err := store.ReconcileDHCP4(leases)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("an unchanged reconciliation rewrote the inventory file")
	}
	if !snapshot.EvidenceAsOf.Equal(current) {
		t.Fatalf("reconcile snapshot evidence time = %s, want %s", snapshot.EvidenceAsOf, current)
	}
	listed, err := store.Snapshot()
	if err != nil || !listed.EvidenceAsOf.Equal(current) || !listed.Devices[0].LastReconciled.Equal(current) {
		t.Fatalf("snapshot did not report the in-memory reconciliation time: %#v %v", listed.EvidenceAsOf, err)
	}
	// A changed lease is written immediately.
	current = now.Add(20 * time.Second)
	changed := append(leases, DHCP4Lease{Address: netip.MustParseAddr("10.77.0.120"), HardwareAddr: "52:54:00:00:00:02", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)})
	if _, err := store.ReconcileDHCP4(changed); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(store.Path)
	if err != nil || bytes.Equal(written, after) {
		t.Fatalf("changed evidence was not saved: %v", err)
	}
	// The heartbeat persists timestamps periodically even without changes.
	current = now.Add(reconcileHeartbeat + 30*time.Second)
	if _, err := store.ReconcileDHCP4(changed); err != nil {
		t.Fatal(err)
	}
	heartbeat, err := os.ReadFile(store.Path)
	if err != nil || bytes.Equal(heartbeat, written) {
		t.Fatalf("heartbeat reconciliation was not saved: %v", err)
	}
}

func TestNoOpEditsAreUnchangedAndAddressAliasesCanBeDeleted(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	store := deterministicMutationStore(t, now)
	snapshot, err := store.ReconcileDHCP4([]DHCP4Lease{{Address: netip.MustParseAddr("10.77.0.110"), HardwareAddr: "52:54:00:00:00:01", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	deviceID := snapshot.Devices[0].ID
	if _, err := store.PatchMetadata(deviceID, "admin", "noop-meta-op-000001", DeviceMetadataPatch{Owner: ptr("Lab")}); err != nil {
		t.Fatal(err)
	}
	same, err := store.PatchMetadata(deviceID, "admin", "noop-meta-op-000002", DeviceMetadataPatch{Owner: ptr("Lab")})
	if err != nil || !same.Unchanged || same.Audit.ID != "" || len(same.Devices) != 1 {
		t.Fatalf("no-op metadata patch = %#v err=%v", same, err)
	}
	page, err := store.AuditPage(10, "")
	if err != nil || len(page.Events) != 1 {
		t.Fatalf("no-op patch recorded audit: %#v err=%v", page, err)
	}
	created, err := store.CreateAddressAlias("admin", "alias-create-op-00001", AddressAliasInput{Name: "Switch", Prefix: "10.77.0.2", Interface: "lab0", ValidFrom: now.Add(-time.Hour), Priority: 1, Confidence: 90, Reason: "static"})
	if err != nil {
		t.Fatal(err)
	}
	sameAlias, err := store.UpdateAddressAlias(created.Alias.ID, "admin", "alias-update-op-00001", AddressAliasUpdate{AddressAliasInput: AddressAliasInput{Name: "Switch", Prefix: "10.77.0.2", Interface: "lab0", ValidFrom: now.Add(-time.Hour), Priority: 1, Confidence: 90, Reason: "static"}, ExpectedRevision: 1})
	if err != nil || !sameAlias.Unchanged || sameAlias.Alias.Revision != 1 {
		t.Fatalf("no-op alias update = %#v err=%v", sameAlias, err)
	}
	if _, err := store.DeleteAddressAlias(created.Alias.ID, "admin", "alias-delete-op-00001", 2, ""); !errors.Is(err, ErrAddressAliasRevisionConflict) {
		t.Fatalf("stale delete returned %v", err)
	}
	deleted, err := store.DeleteAddressAlias(created.Alias.ID, "admin", "alias-delete-op-00002", 1, "decommissioned")
	if err != nil || !deleted.Deleted || deleted.Audit.Action != AuditAddressAliasDeleted {
		t.Fatalf("delete = %#v err=%v", deleted, err)
	}
	replay, err := store.DeleteAddressAlias(created.Alias.ID, "admin", "alias-delete-op-00002", 1, "decommissioned")
	if err != nil || !replay.Replayed || replay.Audit.ID != deleted.Audit.ID {
		t.Fatalf("delete replay = %#v err=%v", replay, err)
	}
	aliases, err := store.ListAddressAliases()
	if err != nil || len(aliases) != 0 {
		t.Fatalf("alias still listed: %#v err=%v", aliases, err)
	}
	if _, err := store.DeleteAddressAlias(created.Alias.ID, "admin", "alias-delete-op-00003", 0, ""); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("delete of missing alias returned %v", err)
	}
	if _, err := store.load(); err != nil {
		t.Fatalf("inventory with a deletion audit does not verify: %v", err)
	}
}

func TestAddressAliasCapacityIsACapacityError(t *testing.T) {
	err := newCapacityError("full")
	if !errors.Is(err, ErrCapacity) || !errors.Is(err, ErrMutationRejected) || err.Error() != "full" {
		t.Fatalf("capacity error does not classify: %v", err)
	}
}

func ptr(value string) *string { return &value }

func sha256Hex(index int) string { return fmt.Sprintf("%064x", index+1) }
