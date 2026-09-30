package ingest

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const selectionDeviceID = "device-0123456789abcdef0123456789abcdef"

func TestEventSelectionUsesExplicitDeviceBeforeAddressFallback(t *testing.T) {
	start := time.Date(2026, 9, 1, 11, 0, 0, 0, time.UTC)
	end := start.Add(2 * time.Hour)
	selection, err := CanonicalEventSelection(selectionDeviceID, start, end, []EventSelectionAddress{
		{Address: "10.77.0.111", StartAt: start, EndAt: start.Add(time.Hour)},
		{Address: "10.77.0.111", StartAt: start.Add(time.Hour), EndAt: end},
	})
	if err != nil || len(selection.Addresses) != 1 || selection.Addresses[0].StartAt != start || selection.Addresses[0].EndAt != end {
		t.Fatalf("selection evidence was not canonicalized: %#v err=%v", selection, err)
	}
	target := selectionEnvelope(t, selectionDeviceID, "10.77.0.111", start.Add(time.Hour))
	if !selection.Matches(target) {
		t.Fatal("explicit target device did not match")
	}
	other := target
	other.DeviceID = "device-ffeeddccbbaa99887766554433221100"
	if selection.Matches(other) {
		t.Fatal("address fallback overrode a different explicit device identity")
	}
	unattributed := target
	unattributed.DeviceID = ""
	if !selection.Matches(unattributed) {
		t.Fatal("time-bounded address evidence did not match an unattributed analyzer event")
	}
	unattributed.OccurredAt = end
	if selection.Matches(unattributed) {
		t.Fatal("exclusive selection end was treated as included")
	}
}

func TestSpoolSelectionTombstonePurgesAndBlocksReplay(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 5, 0, 0, time.UTC)
	start, end := now.Add(-time.Hour), now.Add(time.Hour)
	selection, err := CanonicalEventSelection(selectionDeviceID, start, end, []EventSelectionAddress{{Address: "10.77.0.111", StartAt: start, EndAt: end}})
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "spool")
	spool := &Spool{Root: root, MaxBytes: 8 << 20, ReserveBytes: 1, Now: func() time.Time { return now }}
	targetRaw := selectionEventJSON("selection-event-0001", selectionDeviceID, "10.77.0.111", now)
	target, err := spool.Accept([]byte(targetRaw))
	if err != nil {
		t.Fatal(err)
	}
	pendingPath := filepath.Join(root, "pending", target.RecordID+".json")
	delayedRecord, err := os.ReadFile(pendingPath)
	if err != nil {
		t.Fatal(err)
	}
	unrelatedRaw := selectionEventJSON("selection-event-0002", "device-ffeeddccbbaa99887766554433221100", "10.77.0.222", now)
	if _, err := spool.Accept([]byte(unrelatedRaw)); err != nil {
		t.Fatal(err)
	}
	footprint, err := spool.ReadEventSelectionSpoolFootprint(selection)
	if err != nil || footprint.PendingRecords != 1 || footprint.PendingFileBytes != int64(len(delayedRecord)) {
		t.Fatalf("selection footprint is not exact: %#v err=%v", footprint, err)
	}
	selectionSHA, _ := selection.SHA256()
	tombstone := EventSelectionTombstone{
		Schema: EventSelectionSchemaVersion, OperationID: "device-event-delete-0001", Actor: "admin", Selection: selection, SelectionSHA256: selectionSHA,
		QuerySnapshotID: "qsnap-0123456789abcdef0123456789abcdef", QuerySnapshotSHA256: strings.Repeat("a", 64), CreatedAt: now,
	}
	result, err := spool.PutEventSelectionTombstoneForPreview(tombstone, footprint)
	if err != nil || result.Existing || result.PurgedRecords != 1 || result.PurgedBytes != int64(len(delayedRecord)) {
		t.Fatalf("selection tombstone was not installed exactly: %#v err=%v", result, err)
	}
	if _, err := spool.Accept([]byte(targetRaw)); !errors.Is(err, ErrEventSelectionTombstoned) {
		t.Fatalf("future matching event crossed the selection tombstone: %v", err)
	}
	if result, err := spool.Accept([]byte(unrelatedRaw)); err != nil || !result.Duplicate {
		t.Fatalf("unrelated event was blocked: %#v err=%v", result, err)
	}
	if err := os.WriteFile(pendingPath, delayedRecord, 0o600); err != nil {
		t.Fatal(err)
	}
	restarted := &Spool{Root: root, MaxBytes: 8 << 20, ReserveBytes: 1}
	batch, err := restarted.PendingBatch(10)
	if err != nil || len(batch) != 1 || batch[0].Record.Envelope.DeviceID == selectionDeviceID {
		t.Fatalf("restart replay barrier did not retain only unrelated data: %#v err=%v", batch, err)
	}
	if _, err := os.Stat(pendingPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("delayed matching record survived restart purge: %v", err)
	}
	replayed, err := restarted.PutEventSelectionTombstoneForPreview(tombstone, EventSelectionSpoolFootprint{})
	if err != nil || !replayed.Existing || replayed.Tombstone.OperationID != tombstone.OperationID {
		t.Fatalf("selection tombstone replay was not stable: %#v err=%v", replayed, err)
	}
	conflicting := tombstone
	conflicting.Actor = "another-admin"
	if _, err := restarted.PutEventSelectionTombstoneForPreview(conflicting, EventSelectionSpoolFootprint{}); !errors.Is(err, ErrEventSelectionConflict) {
		t.Fatalf("operation identity was rebound to different evidence: %v", err)
	}
}

func TestSpoolSelectionTombstoneRejectsChangedPendingPopulationBeforeMutation(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 5, 0, 0, time.UTC)
	selection, err := CanonicalEventSelection(selectionDeviceID, now.Add(-time.Hour), now.Add(time.Hour), nil)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "spool")
	spool := &Spool{Root: root, MaxBytes: 8 << 20, ReserveBytes: 1}
	if _, err := spool.Accept([]byte(selectionEventJSON("selection-event-stale-0001", selectionDeviceID, "10.77.0.111", now))); err != nil {
		t.Fatal(err)
	}
	footprint, err := spool.ReadEventSelectionSpoolFootprint(selection)
	if err != nil || footprint.PendingRecords != 1 {
		t.Fatalf("could not freeze selection footprint: %#v err=%v", footprint, err)
	}
	if _, err := spool.Accept([]byte(selectionEventJSON("selection-event-stale-0002", selectionDeviceID, "10.77.0.111", now))); err != nil {
		t.Fatal(err)
	}
	selectionSHA, _ := selection.SHA256()
	tombstone := EventSelectionTombstone{Schema: 1, OperationID: "device-event-delete-stale-0001", Actor: "admin", Selection: selection, SelectionSHA256: selectionSHA, QuerySnapshotID: "qsnap-0123456789abcdef0123456789abcdef", QuerySnapshotSHA256: strings.Repeat("c", 64), CreatedAt: now}
	if _, err := spool.PutEventSelectionTombstoneForPreview(tombstone, footprint); !errors.Is(err, ErrCaptureEventDeletionPreviewStale) {
		t.Fatalf("changed pending population did not stale the preview: %v", err)
	}
	current, err := spool.ReadEventSelectionSpoolFootprint(selection)
	if err != nil || current.PendingRecords != 2 {
		t.Fatalf("stale preview partially purged pending data: %#v err=%v", current, err)
	}
	if _, err := os.Stat(filepath.Join(root, "selection-tombstones", tombstone.OperationID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale preview installed a durable barrier: %v", err)
	}
}

func TestSpoolSelectionTombstoneFailsClosedOnTamperAfterRestart(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	selection, err := CanonicalEventSelection(selectionDeviceID, now.Add(-time.Hour), now.Add(time.Hour), nil)
	if err != nil {
		t.Fatal(err)
	}
	selectionSHA, _ := selection.SHA256()
	root := filepath.Join(t.TempDir(), "spool")
	spool := &Spool{Root: root, MaxBytes: 8 << 20, ReserveBytes: 1}
	tombstone := EventSelectionTombstone{Schema: 1, OperationID: "device-event-delete-0002", Actor: "admin", Selection: selection, SelectionSHA256: selectionSHA, QuerySnapshotID: "qsnap-0123456789abcdef0123456789abcdef", QuerySnapshotSHA256: strings.Repeat("b", 64), CreatedAt: now}
	if _, err := spool.PutEventSelectionTombstoneForPreview(tombstone, EventSelectionSpoolFootprint{}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "selection-tombstones", tombstone.OperationID+".json")
	if err := os.WriteFile(path, []byte(`{"schema":999}`), 0o600); err != nil {
		t.Fatal(err)
	}
	restarted := &Spool{Root: root, MaxBytes: 8 << 20, ReserveBytes: 1}
	if _, err := restarted.Accept([]byte(selectionEventJSON("selection-event-0003", selectionDeviceID, "10.77.0.111", now))); err == nil || errors.Is(err, ErrEventSelectionTombstoned) {
		t.Fatalf("tampered selection tombstone did not fail closed: %v", err)
	}
}

func selectionEnvelope(t *testing.T, deviceID, address string, occurredAt time.Time) Envelope {
	t.Helper()
	envelope, err := DecodeEnvelope([]byte(selectionEventJSON("selection-event-model", deviceID, address, occurredAt)))
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func selectionEventJSON(eventID, deviceID, address string, occurredAt time.Time) string {
	device := ""
	if deviceID != "" {
		device = `,"device_id":"` + deviceID + `"`
	}
	return `{"schema":1,"event_id":"` + eventID + `","source":"ZEEK","kind":"connection","occurred_at":"` + occurredAt.UTC().Format(time.RFC3339Nano) + `","source_version":"8.2.1","parser_version":"shakerproxy-zeek-v1","capture_session_id":"capture-0123456789abcdef0123456789abcdef"` + device + `,"confidence":90,"payload":{"id.orig_h":"` + address + `","id.resp_h":"10.77.0.1","proto":"tcp"}}`
}
