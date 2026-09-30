package ingest

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSpoolAcceptsDeduplicatesAndQuarantinesConflicts(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 1, 0, 0, time.UTC)
	spool := &Spool{Root: filepath.Join(t.TempDir(), "spool"), MaxBytes: 8 << 20, ReserveBytes: 1, Now: func() time.Time { return now }}
	accepted, err := spool.Accept([]byte(validEvent))
	if err != nil || !accepted.Accepted || accepted.Duplicate || len(accepted.RecordID) != 64 {
		t.Fatalf("event was not accepted: result=%#v err=%v", accepted, err)
	}
	duplicate, err := spool.Accept([]byte(validEvent))
	if err != nil || !duplicate.Accepted || !duplicate.Duplicate || duplicate.RecordID != accepted.RecordID {
		t.Fatalf("event was not deduplicated: result=%#v err=%v", duplicate, err)
	}
	conflict := strings.Replace(validEvent, `"proto":"tcp"`, `"proto":"udp"`, 1)
	quarantined, err := spool.Accept([]byte(conflict))
	if err != nil || !quarantined.Quarantined || quarantined.Accepted {
		t.Fatalf("event identity conflict was not quarantined: result=%#v err=%v", quarantined, err)
	}
	stats, err := spool.Stats()
	if err != nil || stats.PendingRecords != 1 || stats.QuarantinedRecords != 1 || stats.IngestLagSeconds != 0 {
		t.Fatalf("unexpected spool stats: %#v err=%v", stats, err)
	}
}

func TestSpoolTombstonePurgesPendingAndRejectsDelayedReplay(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 5, 0, 0, time.UTC)
	root := filepath.Join(t.TempDir(), "spool")
	spool := &Spool{Root: root, MaxBytes: 8 << 20, ReserveBytes: 1, Now: func() time.Time { return now }}
	accepted, err := spool.Accept([]byte(validEvent))
	if err != nil {
		t.Fatal(err)
	}
	pendingPath := filepath.Join(root, "pending", accepted.RecordID+".json")
	delayedRecord, err := os.ReadFile(pendingPath)
	if err != nil {
		t.Fatal(err)
	}
	tombstone := CaptureTombstone{Schema: CaptureTombstoneSchemaVersion, CaptureSessionID: "capture-0123456789abcdef0123456789abcdef", OperationID: "capture-delete-operation-0001", Actor: "admin", CreatedAt: now}
	result, err := spool.PutCaptureTombstone(tombstone)
	if err != nil || result.Existing || result.PurgedRecords != 1 || result.PurgedBytes != int64(len(delayedRecord)) {
		t.Fatalf("pending capture was not durably tombstoned: %#v err=%v", result, err)
	}
	if _, err := os.Stat(pendingPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending capture record survived purge: %v", err)
	}
	if _, err := spool.Accept([]byte(validEvent)); !errors.Is(err, ErrCaptureTombstoned) {
		t.Fatalf("future capture event was not rejected: %v", err)
	}

	// Simulate an analyzer record that was already in flight when the deletion
	// barrier was created. PendingBatch must discard it instead of replaying it.
	if err := os.WriteFile(pendingPath, delayedRecord, 0o600); err != nil {
		t.Fatal(err)
	}
	restarted := &Spool{Root: root, MaxBytes: 8 << 20, ReserveBytes: 1}
	batch, err := restarted.PendingBatch(10)
	if err != nil || len(batch) != 0 {
		t.Fatalf("delayed replay crossed the durable tombstone: %#v err=%v", batch, err)
	}
	if _, err := os.Stat(pendingPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("delayed tombstoned record was not purged: %v", err)
	}
	replayed, err := restarted.PutCaptureTombstone(CaptureTombstone{Schema: CaptureTombstoneSchemaVersion, CaptureSessionID: tombstone.CaptureSessionID, OperationID: "capture-delete-operation-0002", Actor: "another-admin", CreatedAt: now.Add(time.Hour)})
	if err != nil || !replayed.Existing || replayed.Tombstone != tombstone {
		t.Fatalf("tombstone replay did not preserve original evidence: %#v err=%v", replayed, err)
	}

	otherCapture := strings.Replace(validEvent, tombstone.CaptureSessionID, "capture-fedcba9876543210fedcba9876543210", 1)
	if result, err := restarted.Accept([]byte(otherCapture)); err != nil || !result.Accepted {
		t.Fatalf("unrelated capture was rejected: %#v err=%v", result, err)
	}
}

func TestSpoolFailsClosedOnTamperedCaptureTombstone(t *testing.T) {
	root := filepath.Join(t.TempDir(), "spool")
	spool := &Spool{Root: root, MaxBytes: 8 << 20, ReserveBytes: 1}
	if _, err := spool.PutCaptureTombstone(CaptureTombstone{Schema: CaptureTombstoneSchemaVersion, CaptureSessionID: "capture-0123456789abcdef0123456789abcdef", OperationID: "capture-delete-operation-0001", Actor: "admin", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "tombstones", "capture-0123456789abcdef0123456789abcdef.json")
	if err := os.WriteFile(path, []byte(`{"schema":999}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Accept([]byte(validEvent)); err == nil || errors.Is(err, ErrCaptureTombstoned) {
		t.Fatalf("tampered tombstone did not fail closed: %v", err)
	}
}

func TestSpoolQuarantinesMalformedEventWithBoundedPrefix(t *testing.T) {
	spool := &Spool{Root: filepath.Join(t.TempDir(), "spool"), MaxBytes: 8 << 20, ReserveBytes: 1}
	result, err := spool.Accept([]byte(`{"schema":1,"source":"SURICATA","payload":` + strings.Repeat("x", MaxQuarantineBytes*2)))
	if err != nil || !result.Quarantined {
		t.Fatalf("malformed event was not quarantined: %#v err=%v", result, err)
	}
	entries, err := os.ReadDir(filepath.Join(spool.Root, "quarantine"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("unexpected quarantine: entries=%d err=%v", len(entries), err)
	}
	info, err := entries[0].Info()
	if err != nil || info.Size() > MaxQuarantineBytes*2 {
		t.Fatalf("quarantine record was not bounded: info=%#v err=%v", info, err)
	}
}

func TestSpoolRejectsSymlinkedRootChildren(t *testing.T) {
	root := filepath.Join(t.TempDir(), "spool")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "pending")); err != nil {
		t.Fatal(err)
	}
	spool := &Spool{Root: root, MaxBytes: 8 << 20, ReserveBytes: 1}
	if _, err := spool.Accept([]byte(validEvent)); err == nil {
		t.Fatal("symlinked pending directory was accepted")
	}
}

func TestSpoolAppliesBackpressureBeforeWriting(t *testing.T) {
	spool := &Spool{Root: filepath.Join(t.TempDir(), "spool"), MaxBytes: 1, ReserveBytes: 1}
	if _, err := spool.Accept([]byte(validEvent)); err == nil || !strings.Contains(err.Error(), "backpressure") {
		t.Fatalf("spool byte limit did not apply backpressure: %v", err)
	}
}

func TestSpoolFailsClosedOnTamperedPendingRecord(t *testing.T) {
	spool := &Spool{Root: filepath.Join(t.TempDir(), "spool"), MaxBytes: 8 << 20, ReserveBytes: 1}
	result, err := spool.Accept([]byte(validEvent))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(spool.Root, "pending", result.RecordID+".json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b = []byte(strings.Replace(string(b), `"proto": "tcp"`, `"proto": "udp"`, 1))
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Stats(); err == nil {
		t.Fatal("tampered pending record was accepted")
	}
}

func TestSpoolFailsClosedWhenFilenameDoesNotBindEventIdentity(t *testing.T) {
	spool := &Spool{Root: filepath.Join(t.TempDir(), "spool"), MaxBytes: 8 << 20, ReserveBytes: 1}
	result, err := spool.Accept([]byte(validEvent))
	if err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(spool.Root, "pending", result.RecordID+".json")
	wrongID := strings.Repeat("a", 64)
	if wrongID == result.RecordID {
		wrongID = strings.Repeat("b", 64)
	}
	if err := os.Rename(original, filepath.Join(spool.Root, "pending", wrongID+".json")); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.PendingBatch(10); err == nil {
		t.Fatal("drain accepted a record whose filename did not bind its event identity")
	}
}

func TestSpoolAcknowledgementRejectsUntrustedIdentities(t *testing.T) {
	spool := &Spool{Root: filepath.Join(t.TempDir(), "spool"), MaxBytes: 8 << 20, ReserveBytes: 1}
	if err := spool.Acknowledge([]string{"../quarantine/event"}); err == nil {
		t.Fatal("acknowledgement accepted a caller-controlled path")
	}
	if err := spool.Acknowledge([]string{strings.Repeat("a", 64), strings.Repeat("a", 64)}); err == nil {
		t.Fatal("acknowledgement accepted duplicate identities")
	}
}

func TestSpoolQuickStatsTracksAcceptsAndAcknowledgementsWithoutRescanning(t *testing.T) {
	spool := &Spool{Root: filepath.Join(t.TempDir(), "spool"), MaxBytes: 8 << 20, ReserveBytes: 1}
	first, err := spool.Accept([]byte(validEvent))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Accept([]byte(strings.Replace(validEvent, "zeek-event-00000001", "zeek-event-00000002", 1))); err != nil {
		t.Fatal(err)
	}
	stats, err := spool.QuickStats()
	if err != nil || stats.PendingRecords != 2 || stats.PendingBytes <= 0 {
		t.Fatalf("unexpected cached usage: %#v err=%v", stats, err)
	}
	full, err := spool.Stats()
	if err != nil || full.PendingRecords != stats.PendingRecords || full.PendingBytes != stats.PendingBytes {
		t.Fatalf("cached usage diverged from a verified scan: quick=%#v full=%#v err=%v", stats, full, err)
	}
	if err := spool.Acknowledge([]string{first.RecordID}); err != nil {
		t.Fatal(err)
	}
	after, err := spool.QuickStats()
	if err != nil || after.PendingRecords != 1 || after.PendingBytes >= stats.PendingBytes {
		t.Fatalf("acknowledgement did not update cached usage: %#v err=%v", after, err)
	}
}

func TestCaptureDeletionAlsoPurgesRejectedRecords(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 5, 0, 0, time.UTC)
	root := filepath.Join(t.TempDir(), "spool")
	spool := &Spool{Root: root, MaxBytes: 8 << 20, ReserveBytes: 1, Now: func() time.Time { return now }}
	accepted, err := spool.Accept([]byte(validEvent))
	if err != nil {
		t.Fatal(err)
	}
	if moved, err := spool.SetAside([]string{accepted.RecordID}, false); err != nil || moved != 1 {
		t.Fatalf("record was not set aside: moved=%d err=%v", moved, err)
	}
	rejectedPath := filepath.Join(root, "rejected", accepted.RecordID+".json")
	if _, err := os.Stat(rejectedPath); err != nil {
		t.Fatalf("rejected record was not retained: %v", err)
	}
	tombstone := CaptureTombstone{Schema: CaptureTombstoneSchemaVersion, CaptureSessionID: "capture-0123456789abcdef0123456789abcdef", OperationID: "capture-delete-operation-0002", Actor: "admin", CreatedAt: now}
	if _, err := spool.PutCaptureTombstone(tombstone); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(rejectedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted capture survived in the rejected set: %v", err)
	}
}
