package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/analyzer"
	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/ingest"
)

type coordinatorFootprintReader struct {
	footprint ingest.CaptureEventDatabaseFootprint
}

func (r coordinatorFootprintReader) ReadCaptureEventFootprint(context.Context, string) (ingest.CaptureEventDatabaseFootprint, error) {
	return r.footprint, nil
}

func coordinatorDeletionPreview(t *testing.T, exportRecords int) coordinatedCaptureDeletionPreview {
	t.Helper()
	return coordinatorDeletionPreviewAt(t, exportRecords, time.Now().UTC().Truncate(time.Microsecond))
}

func coordinatorDeletionPreviewAt(t *testing.T, exportRecords int, now time.Time) coordinatedCaptureDeletionPreview {
	t.Helper()
	host := capture.DeletionPreview{
		Schema: 1, SessionID: captureTestID, PreviewSHA256: strings.Repeat("a", 64),
		GeneratedAt: now, ExpiresAt: now.Add(capture.DeletionPreviewLifetime), State: capture.StateCompleted,
		Footprint:                 capture.DeletionFootprint{CaptureFiles: 2, CaptureBytes: 4096, MetadataFiles: 3, MetadataBytes: 512},
		EstimatedRecoverableBytes: 4608, DeletedDataClasses: []string{"capture_session_metadata", "pcap_artifacts"},
		RetainedDataClasses: []string{"normalized_event_metadata", "analyzer_checkpoints", "capture_export_audit", "external_exported_copies"}, Confirmation: captureTestID,
	}
	events, err := (ingest.CaptureEventDeletionPlanner{
		Spool: &ingest.Spool{Root: filepath.Join(t.TempDir(), "spool"), MaxBytes: 8 << 20, ReserveBytes: 1},
		Database: coordinatorFootprintReader{footprint: ingest.CaptureEventDatabaseFootprint{
			EventRows: 3, ExclusiveIdentityRows: 2, EventLogicalBytes: 768, IdentityLogicalBytes: 128, MaxIngestSequence: 7,
		}},
		Now: func() time.Time { return now },
	}).Preview(t.Context(), captureTestID)
	if err != nil {
		t.Fatal(err)
	}
	zeekService, err := analyzer.NewCheckpointDeletionService(analyzer.NewStateStore(filepath.Join(t.TempDir(), "zeek")), analyzer.EngineZeek)
	if err != nil {
		t.Fatal(err)
	}
	zeekService.Now = func() time.Time { return now }
	zeek, err := zeekService.Preview(captureTestID)
	if err != nil {
		t.Fatal(err)
	}
	suricataService, err := analyzer.NewCheckpointDeletionService(analyzer.NewStateStore(filepath.Join(t.TempDir(), "suricata")), analyzer.EngineSuricata)
	if err != nil {
		t.Fatal(err)
	}
	suricataService.Now = func() time.Time { return now }
	suricata, err := suricataService.Preview(captureTestID)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := newCoordinatedCaptureDeletionPreview(host, events, zeek, suricata, exportRecords)
	if err != nil {
		t.Fatal(err)
	}
	return preview
}

func TestCoordinatedCaptureDeletionRejectsExpiredNewIntent(t *testing.T) {
	dataDirectory := filepath.Join(t.TempDir(), "data")
	store := NewStore(dataDirectory, filepath.Join(dataDirectory, "unused-token"))
	preview := coordinatorDeletionPreviewAt(t, 0, time.Now().UTC().Add(-ingest.DefaultEventDeletionPreviewTTL-time.Minute))
	if _, _, err := store.beginCoordinatedCaptureDeletion(preview, "admin", "coordinated-expired-0001"); !errors.Is(err, errCoordinatedCaptureDeletionExpired) {
		t.Fatalf("expired preview was not rejected before intent creation: %v", err)
	}
	jobs, err := store.listCoordinatedCaptureDeletionJobs()
	if err != nil || len(jobs) != 0 {
		t.Fatalf("expired preview created a durable operation: %#v err=%v", jobs, err)
	}
}

func TestCoordinatedCaptureDeletionPreviewBindsEveryBackendAndBoundary(t *testing.T) {
	preview := coordinatorDeletionPreview(t, 2)
	if preview.SessionID != captureTestID || preview.HostArtifacts.Footprint.TotalBytes() != 4608 || preview.NormalizedEvents.Database.EventRows != 3 || preview.ZeekCheckpoint == nil || preview.ZeekCheckpoint.Engine != analyzer.EngineZeek || preview.SuricataCheckpoint == nil || preview.SuricataCheckpoint.Engine != analyzer.EngineSuricata || preview.ExistingExportRecords != 2 || len(preview.CopyBoundaries) != 6 || preview.CopyBoundaries[0].ObjectCount != 2 || preview.CopyBoundaries[5].CountExact || preview.Confirmation != captureTestID || len(preview.PreviewSHA256) != 64 {
		t.Fatalf("unexpected coordinated deletion preview: %#v", preview)
	}
	if !containsString(preview.DeletedDataClasses, "normalized_event_metadata") || !containsString(preview.DeletedDataClasses, "analyzer_checkpoints") || containsString(preview.RetainedDataClasses, "analyzer_checkpoints") || !containsString(preview.RetainedDataClasses, "external_exported_copies") || !containsString(preview.RetainedDataClasses, "existing_backups") {
		t.Fatalf("deletion boundaries are incomplete: %#v", preview)
	}
	tampered := preview
	tampered.NormalizedEvents.Database.EventRows++
	if err := tampered.validate(); err == nil {
		t.Fatal("tampered backend evidence retained a valid combined preview")
	}
	tampered = preview
	tampered.CopyBoundaries[0].ObjectCount++
	if err := tampered.validate(); err == nil {
		t.Fatal("tampered export boundary retained a valid combined preview")
	}
}

func TestCoordinatedCaptureDeletionSchemaTwoPreviewWithoutCopyBoundariesRemainsValid(t *testing.T) {
	preview := coordinatorDeletionPreview(t, 2)
	preview.CopyBoundaries = nil
	var err error
	preview.PreviewSHA256, err = coordinatedCaptureDeletionPreviewHash(preview)
	if err != nil || preview.validate() != nil {
		t.Fatalf("pre-boundary schema-2 preview compatibility was lost: %#v err=%v", preview, err)
	}
}

func TestCoordinatedCaptureDeletionLedgerIsDurableAndIdempotent(t *testing.T) {
	dataDirectory := filepath.Join(t.TempDir(), "data")
	store := NewStore(dataDirectory, filepath.Join(dataDirectory, "unused-token"))
	preview := coordinatorDeletionPreview(t, 1)
	record, replayed, err := store.beginCoordinatedCaptureDeletion(preview, "admin", "coordinated-delete-0001")
	if err != nil || replayed {
		t.Fatalf("begin deletion: replayed=%t err=%v", replayed, err)
	}
	if record.Job.State != coordinatedDeletionPending || len(record.Job.Backends) != 4 || !allBackendsState(record.Job.Backends, deletionBackendNotStarted) {
		t.Fatalf("unexpected durable job: %#v", record.Job)
	}
	info, err := os.Stat(filepath.Join(dataDirectory, "capture-deletion-operations.json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("unsafe ledger mode: info=%v err=%v", info, err)
	}

	restarted := NewStore(dataDirectory, filepath.Join(dataDirectory, "unused-token"))
	replayedRecord, replayed, err := restarted.beginCoordinatedCaptureDeletion(preview, "admin", "coordinated-delete-0001")
	if err != nil || !replayed || replayedRecord.Job.ID != record.Job.ID {
		t.Fatalf("durable replay mismatch: replayed=%t record=%#v err=%v", replayed, replayedRecord, err)
	}
	jobs, err := restarted.listCoordinatedCaptureDeletionJobs()
	if err != nil || len(jobs) != 1 || jobs[0].ID != record.Job.ID {
		t.Fatalf("unexpected persisted jobs: %#v err=%v", jobs, err)
	}

	conflictingPreview := coordinatorDeletionPreview(t, 2)
	if _, _, err := restarted.beginCoordinatedCaptureDeletion(conflictingPreview, "admin", "coordinated-delete-0001"); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("idempotency conflict was not rejected: %v", err)
	}
}

func TestLegacyTwoBackendDeletionLedgerRemainsReadable(t *testing.T) {
	dataDirectory := filepath.Join(t.TempDir(), "data")
	store := NewStore(dataDirectory, filepath.Join(dataDirectory, "unused-token"))
	legacy := coordinatorDeletionPreview(t, 0)
	legacy.Schema = legacyCoordinatedCaptureDeletionSchema
	legacy.ZeekCheckpoint = nil
	legacy.SuricataCheckpoint = nil
	legacy.CopyBoundaries = nil
	legacy.DeletedDataClasses = append([]string(nil), legacyCoordinatedCaptureDeletedDataClasses...)
	legacy.RetainedDataClasses = append([]string(nil), legacyCoordinatedCaptureRetainedDataClasses...)
	digest, err := coordinatedCaptureDeletionPreviewHash(legacy)
	if err != nil {
		t.Fatal(err)
	}
	legacy.PreviewSHA256 = digest
	if err := legacy.validate(); err != nil {
		t.Fatal(err)
	}
	record, _, err := store.beginCoordinatedCaptureDeletion(legacy, "admin", "legacy-coordinated-delete-0001")
	if err != nil || record.Schema != legacyCoordinatedCaptureDeletionSchema || len(record.Job.Backends) != 2 {
		t.Fatalf("legacy deletion intent was not preserved: %#v err=%v", record, err)
	}
	reopened := NewStore(dataDirectory, filepath.Join(dataDirectory, "unused-token"))
	loaded, err := reopened.getCoordinatedCaptureDeletionRecord(record.Job.ID)
	if err != nil || loaded.Schema != legacyCoordinatedCaptureDeletionSchema || loaded.Preview.ZeekCheckpoint != nil || loaded.Preview.SuricataCheckpoint != nil || len(loaded.Job.Backends) != 2 {
		t.Fatalf("legacy deletion ledger did not survive restart: %#v err=%v", loaded, err)
	}
}

func TestCoordinatedCaptureDeletionUpdatePreservesImmutableEvidence(t *testing.T) {
	dataDirectory := filepath.Join(t.TempDir(), "data")
	store := NewStore(dataDirectory, filepath.Join(dataDirectory, "unused-token"))
	record, _, err := store.beginCoordinatedCaptureDeletion(coordinatorDeletionPreview(t, 0), "admin", "coordinated-delete-0002")
	if err != nil {
		t.Fatal(err)
	}
	updatedAt := record.Job.CreatedAt.Add(time.Second)
	updated, err := store.updateCoordinatedCaptureDeletion(record.Job.ID, func(candidate *coordinatedCaptureDeletionRecord) error {
		candidate.Job.State = coordinatedDeletionRunning
		candidate.Job.Phase = "TOMBSTONES_WRITING"
		candidate.Job.ProgressPercent = 15
		candidate.Job.UpdatedAt = updatedAt
		candidate.Job.Backends[0].State = deletionBackendRunning
		candidate.Job.Backends[0].UpdatedAt = updatedAt
		return nil
	})
	if err != nil || updated.Job.State != coordinatedDeletionRunning || updated.Job.Backends[0].State != deletionBackendRunning {
		t.Fatalf("valid progress update failed: %#v err=%v", updated, err)
	}
	if _, err := store.updateCoordinatedCaptureDeletion(record.Job.ID, func(candidate *coordinatedCaptureDeletionRecord) error {
		candidate.Job.State = coordinatedDeletionCompleted
		candidate.Job.Phase = "COMPLETED"
		candidate.Job.ProgressPercent = 100
		candidate.Job.UpdatedAt = updatedAt.Add(time.Second)
		candidate.Job.CompletedAt = &candidate.Job.UpdatedAt
		return nil
	}); err == nil {
		t.Fatal("job completed without authoritative backend acknowledgements")
	}
	if _, err := store.updateCoordinatedCaptureDeletion(record.Job.ID, func(candidate *coordinatedCaptureDeletionRecord) error {
		candidate.Preview.ExistingExportRecords++
		return nil
	}); err == nil {
		t.Fatal("immutable preview evidence was changed")
	}
	jobs, err := store.listCoordinatedCaptureDeletionJobs()
	if err != nil || len(jobs) != 1 || jobs[0].State != coordinatedDeletionRunning {
		t.Fatalf("rejected update corrupted durable job: %#v err=%v", jobs, err)
	}
}

func TestCoordinatedCaptureDeletionRecordBindsAnalyzerAcknowledgement(t *testing.T) {
	dataDirectory := filepath.Join(t.TempDir(), "data")
	store := NewStore(dataDirectory, filepath.Join(dataDirectory, "unused-token"))
	record, _, err := store.beginCoordinatedCaptureDeletion(coordinatorDeletionPreview(t, 0), "admin", "coordinated-delete-analyzer-binding-0001")
	if err != nil {
		t.Fatal(err)
	}
	now := record.Job.CreatedAt.Add(time.Second)
	preview := *record.Preview.ZeekCheckpoint
	outcome := analyzer.CheckpointDeletionOutcome{
		Schema: analyzer.CheckpointDeletionSchema, Engine: preview.Engine, CaptureSessionID: record.Job.SessionID,
		OperationID: record.Job.ID, Actor: record.Job.Administrator, PreviewSHA256: preview.PreviewSHA256,
		CheckpointWasPresent: preview.CheckpointPresent, DeletedCheckpointBytes: preview.CheckpointBytes,
		ActiveProgressWasPresent: preview.ActiveProgressPresent, DeletedActiveProgressBytes: preview.ActiveProgressBytes,
		VerifiedAbsent: true, CreatedAt: now, CompletedAt: now,
	}
	record.Job.State = coordinatedDeletionRunning
	record.Job.Phase = "ZEEK_CHECKPOINT_VERIFIED"
	record.Job.ProgressPercent = 70
	record.Job.UpdatedAt = now
	record.Job.Backends[1] = captureDeletionBackendResult{Backend: "zeek_checkpoint", State: deletionBackendCompleted, UpdatedAt: now, AnalyzerCheckpoint: &outcome}
	if err := record.validate(); err != nil {
		t.Fatalf("valid analyzer acknowledgement was rejected: %v", err)
	}
	record.Job.Backends[1].AnalyzerCheckpoint.Actor = "different-admin"
	if err := record.validate(); err == nil {
		t.Fatal("analyzer acknowledgement from a different actor was accepted")
	}
}

func TestCoordinatedCaptureDeletionRetryLedgerIsDurableAndImmutable(t *testing.T) {
	dataDirectory := filepath.Join(t.TempDir(), "data")
	store := NewStore(dataDirectory, filepath.Join(dataDirectory, "unused-token"))
	record, _, err := store.beginCoordinatedCaptureDeletion(coordinatorDeletionPreview(t, 0), "admin", "coordinated-delete-retry-0001")
	if err != nil {
		t.Fatal(err)
	}
	failedAt := time.Now().UTC().Truncate(time.Microsecond)
	record, err = store.updateCoordinatedCaptureDeletion(record.Job.ID, func(candidate *coordinatedCaptureDeletionRecord) error {
		candidate.Job.State = coordinatedDeletionFailed
		candidate.Job.Phase = "NORMALIZED_EVENTS_FAILED"
		candidate.Job.UpdatedAt = failedAt
		candidate.Job.CompletedAt = &failedAt
		candidate.Job.Failure = "injected failure"
		candidate.Job.Backends[0] = captureDeletionBackendResult{Backend: "normalized_events", State: deletionBackendFailed, UpdatedAt: failedAt, Failure: "injected failure"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	record, replayed, err := store.beginCoordinatedCaptureDeletionRetry(record.Job.ID, "coordinated-retry-0001", "admin")
	if err != nil || replayed || len(record.Retries) != 1 || record.Retries[0].CompletedAt != nil {
		t.Fatalf("retry intent was not durably started: replayed=%t record=%#v err=%v", replayed, record, err)
	}
	if _, _, err := store.beginCoordinatedCaptureDeletionRetry(record.Job.ID, "coordinated-retry-0002", "admin"); !errors.Is(err, errCaptureDeletionRetryConflict) {
		t.Fatalf("a second retry started while durable retry work was unfinished: %v", err)
	}

	restarted := NewStore(dataDirectory, filepath.Join(dataDirectory, "unused-token"))
	recoverable, err := restarted.listRecoverableCoordinatedCaptureDeletions()
	if err != nil || len(recoverable) != 1 || recoverable[0].Job.ID != record.Job.ID {
		t.Fatalf("unfinished retry was not recoverable after restart: %#v err=%v", recoverable, err)
	}
	finished, err := restarted.finishCoordinatedCaptureDeletionRetry(record.Job.ID, "coordinated-retry-0001")
	if err != nil || finished.Retries[0].CompletedAt == nil || finished.Retries[0].ResultState != coordinatedDeletionFailed {
		t.Fatalf("retry completion was not persisted: %#v err=%v", finished.Retries, err)
	}
	if _, replayed, err := restarted.beginCoordinatedCaptureDeletionRetry(record.Job.ID, "coordinated-retry-0001", "admin"); err != nil || !replayed {
		t.Fatalf("completed retry was not idempotent: replayed=%t err=%v", replayed, err)
	}
	if _, err := restarted.updateCoordinatedCaptureDeletion(record.Job.ID, func(candidate *coordinatedCaptureDeletionRecord) error {
		changed := candidate.Retries[0].CompletedAt.Add(time.Second)
		candidate.Retries[0].CompletedAt = &changed
		return nil
	}); err == nil || !strings.Contains(err.Error(), "immutable retry evidence") {
		t.Fatalf("completed retry evidence was mutable: %v", err)
	}

	second, _, err := restarted.beginCoordinatedCaptureDeletion(coordinatorDeletionPreview(t, 0), "admin", "coordinated-delete-retry-0002")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := restarted.beginCoordinatedCaptureDeletionRetry(second.Job.ID, "coordinated-retry-0001", "admin"); !errors.Is(err, errCaptureDeletionRetryConflict) {
		t.Fatalf("retry idempotency key was reusable across operations: %v", err)
	}
	if _, _, err := restarted.beginCoordinatedCaptureDeletion(coordinatorDeletionPreview(t, 0), "admin", "coordinated-retry-0001"); !errors.Is(err, errCoordinatedCaptureDeletionConflict) {
		t.Fatalf("retry idempotency key was reusable as an initial request: %v", err)
	}
}

func TestCoordinatedCaptureDeletionSupersessionPreservesCompletedBackends(t *testing.T) {
	dataDirectory := filepath.Join(t.TempDir(), "data")
	store := NewStore(dataDirectory, filepath.Join(dataDirectory, "unused-token"))
	record, _, err := store.beginCoordinatedCaptureDeletion(coordinatorDeletionPreview(t, 0), "admin", "coordinated-delete-supersede-0001")
	if err != nil {
		t.Fatal(err)
	}
	failedAt := record.Job.CreatedAt.Add(time.Second)
	zeekPreview := *record.Preview.ZeekCheckpoint
	zeekOutcome := analyzer.CheckpointDeletionOutcome{
		Schema: analyzer.CheckpointDeletionSchema, Engine: zeekPreview.Engine, CaptureSessionID: record.Job.SessionID,
		OperationID: record.Job.ID, Actor: record.Job.Administrator, PreviewSHA256: zeekPreview.PreviewSHA256,
		CheckpointWasPresent: zeekPreview.CheckpointPresent, DeletedCheckpointBytes: zeekPreview.CheckpointBytes,
		VerifiedAbsent: true, CreatedAt: failedAt, CompletedAt: failedAt,
	}
	record, err = store.updateCoordinatedCaptureDeletion(record.Job.ID, func(candidate *coordinatedCaptureDeletionRecord) error {
		candidate.Job.State, candidate.Job.Phase, candidate.Job.ProgressPercent = coordinatedDeletionPartial, "SURICATA_CHECKPOINT_FAILED", 75
		candidate.Job.UpdatedAt, candidate.Job.CompletedAt, candidate.Job.Failure = failedAt, &failedAt, "injected stale evidence"
		candidate.Job.Backends[1] = captureDeletionBackendResult{Backend: "zeek_checkpoint", State: deletionBackendCompleted, UpdatedAt: failedAt, AnalyzerCheckpoint: &zeekOutcome}
		candidate.Job.Backends[2] = captureDeletionBackendResult{Backend: "suricata_checkpoint", State: deletionBackendFailed, UpdatedAt: failedAt, Failure: "injected stale evidence"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	fresh := coordinatorDeletionPreviewAt(t, 0, time.Now().UTC().Truncate(time.Microsecond))
	superseded, replayed, err := store.supersedeCoordinatedCaptureDeletion(record.Job.ID, fresh, "coordinated-supersede-0001", "admin")
	if err != nil || replayed || superseded.Job.State != coordinatedDeletionPending || superseded.Job.PreviewSHA256 != fresh.PreviewSHA256 || len(superseded.Supersessions) != 1 || superseded.Job.Backends[1].State != deletionBackendCompleted || superseded.Job.Backends[2].State != deletionBackendNotStarted {
		t.Fatalf("fresh preview did not supersede only unfinished evidence: replayed=%t record=%#v err=%v", replayed, superseded, err)
	}
	if superseded.Job.Backends[1].AnalyzerCheckpoint.PreviewSHA256 != zeekPreview.PreviewSHA256 {
		t.Fatal("supersession replaced a completed analyzer acknowledgement")
	}
	restarted := NewStore(dataDirectory, filepath.Join(dataDirectory, "unused-token"))
	loaded, err := restarted.getCoordinatedCaptureDeletionRecord(record.Job.ID)
	if err != nil || loaded.validate() != nil || len(loaded.Supersessions) != 1 {
		t.Fatalf("supersession was not durable: %#v err=%v", loaded, err)
	}
	tampered := loaded
	tampered.Supersessions = append([]captureDeletionSupersession(nil), loaded.Supersessions...)
	tampered.Supersessions[0].ReplacementPreviewSHA256 = strings.Repeat("f", 64)
	if tampered.validate() == nil {
		t.Fatal("tampered supersession lineage remained valid")
	}
	if _, err := restarted.updateCoordinatedCaptureDeletion(record.Job.ID, func(candidate *coordinatedCaptureDeletionRecord) error {
		candidate.Supersessions[0].Administrator = "different-admin"
		return nil
	}); err == nil {
		t.Fatal("ordinary job update mutated supersession evidence")
	}
	if replay, wasReplayed, err := restarted.supersedeCoordinatedCaptureDeletion(record.Job.ID, fresh, "coordinated-supersede-0001", "admin"); err != nil || !wasReplayed || replay.Job.PreviewSHA256 != fresh.PreviewSHA256 {
		t.Fatalf("supersession replay was not stable: replayed=%t err=%v", wasReplayed, err)
	}
}

func TestCoordinatedCaptureDeletionLedgerRejectsUnsafeOrCorruptFiles(t *testing.T) {
	for name, prepare := range map[string]func(*testing.T, string){
		"symlink": func(t *testing.T, path string) {
			target := filepath.Join(t.TempDir(), "target")
			if err := os.WriteFile(target, []byte(`{"schema":1,"records":[]}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		},
		"trailing data": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("{\"schema\":1,\"records\":[]} false\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dataDirectory := t.TempDir()
			path := filepath.Join(dataDirectory, "capture-deletion-operations.json")
			prepare(t, path)
			store := NewStore(dataDirectory, filepath.Join(dataDirectory, "unused-token"))
			if _, err := store.listCoordinatedCaptureDeletionJobs(); err == nil {
				t.Fatal("unsafe or corrupt deletion ledger was accepted")
			}
		})
	}
}

func TestBoundedCoordinatorFailure(t *testing.T) {
	if got := boundedCoordinatorFailure(errors.New(strings.Repeat("x", 600))); len(got) != 512 {
		t.Fatalf("failure text was not bounded: %d", len(got))
	}
}
