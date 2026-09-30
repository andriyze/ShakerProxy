package capture

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func finalizedDeletionManager(t *testing.T, retentionLock bool) (*Manager, Session, *time.Time) {
	t.Helper()
	now := time.Date(2026, 9, 1, 14, 0, 0, 0, time.UTC)
	store := Store{Root: filepath.Join(t.TempDir(), "pcap")}
	session := validSession(t, store.Root)
	session.Request.RetentionLock = retentionLock
	if err := store.Create(session); err != nil {
		t.Fatal(err)
	}
	artifactDirectory, _ := store.ArtifactDirectory(session.ID)
	if err := os.WriteFile(filepath.Join(artifactDirectory, "capture.pcapng"), []byte("bounded pcap fixture"), 0o640); err != nil {
		t.Fatal(err)
	}
	status := WorkerStatus{Schema: SchemaVersion, SessionID: session.ID, State: StateCompleted, StartedAt: session.StartedAt, EndedAt: now, UpdatedAt: now}
	if err := store.WriteWorkerStatus(status); err != nil {
		t.Fatal(err)
	}
	manifest, err := store.CollectFiles(session.ID, now)
	if err != nil || store.WriteManifest(manifest) != nil {
		t.Fatalf("finalize capture: %v", err)
	}
	manager := &Manager{Store: store, Now: func() time.Time { return now }, Random: func(value []byte) (int, error) {
		copy(value, []byte("delete-job-id-01"))
		return len(value), nil
	}}
	return manager, session, &now
}

func TestCaptureDeletionPreviewAndVerifiedJob(t *testing.T) {
	manager, session, _ := finalizedDeletionManager(t, false)
	preview, err := manager.PreviewDeletion(t.Context(), session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if preview.SessionID != session.ID || preview.Footprint.CaptureFiles != 1 || preview.Footprint.CaptureBytes != int64(len("bounded pcap fixture")) || preview.Footprint.MetadataFiles != 3 || preview.EstimatedRecoverableBytes != preview.Footprint.TotalBytes() || preview.SharedPCAPCollateralKnown || preview.Confirmation != session.ID {
		t.Fatalf("unexpected deletion preview: %#v", preview)
	}
	request := DeleteRequest{SessionID: session.ID, PreviewSHA256: preview.PreviewSHA256, PreviewExpiresAt: preview.ExpiresAt, Confirmation: session.ID, Administrator: "admin", IdempotencyKey: "capture-delete-request-0001"}
	job, err := manager.Delete(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if job.State != DeletionCompleted || job.Phase != "VERIFIED" || job.ProgressPercent != 100 || job.RemainingFiles != 0 || job.RemainingBytes != 0 || job.CompletedAt == nil || job.CompletedAt.IsZero() {
		t.Fatalf("unexpected deletion job: %#v", job)
	}
	if _, err := manager.Store.ReadSession(session.ID); !os.IsNotExist(err) {
		t.Fatalf("deleted capture session remains readable: %v", err)
	}
	jobs, err := manager.ListDeletionJobs()
	if err != nil || len(jobs) != 1 || jobs[0].ID != job.ID {
		t.Fatalf("deletion job was not durable: %#v %v", jobs, err)
	}
	replayed, err := manager.Delete(t.Context(), request)
	if err != nil || replayed.ID != job.ID || replayed.State != DeletionCompleted {
		t.Fatalf("idempotent deletion replay failed: %#v %v", replayed, err)
	}
	if err := manager.Store.Create(session); err == nil {
		t.Fatal("deletion receipt allowed the capture session ID to be recreated")
	}
}

func TestCaptureDeletionIncludesClosedRotationFeedMetadata(t *testing.T) {
	manager, session, now := finalizedDeletionManager(t, false)
	status, err := manager.Store.ReadWorkerStatus(session.ID)
	if err != nil {
		t.Fatal(err)
	}
	status.State = StateRunning
	if err := manager.Store.WriteWorkerStatus(status); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Store.PublishClosedSegment(session.ID, "capture.pcapng", now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	status.State = StateCompleted
	if err := manager.Store.WriteWorkerStatus(status); err != nil {
		t.Fatal(err)
	}
	preview, err := manager.PreviewDeletion(t.Context(), session.ID)
	if err != nil || preview.Footprint.MetadataFiles != 4 {
		t.Fatalf("active rotation feed was not included in deletion evidence: %#v err=%v", preview, err)
	}
}

func TestCaptureDeletionRejectsRetentionLockAndStalePreview(t *testing.T) {
	lockedManager, lockedSession, _ := finalizedDeletionManager(t, true)
	lockedPreview, err := lockedManager.PreviewDeletion(t.Context(), lockedSession.ID)
	if err != nil || !lockedPreview.RetentionLock {
		t.Fatalf("retention lock was not shown in preview: %#v %v", lockedPreview, err)
	}
	_, err = lockedManager.Delete(t.Context(), DeleteRequest{SessionID: lockedSession.ID, PreviewSHA256: lockedPreview.PreviewSHA256, PreviewExpiresAt: lockedPreview.ExpiresAt, Confirmation: lockedSession.ID, Administrator: "admin", IdempotencyKey: "capture-delete-request-0002"})
	if err == nil {
		t.Fatal("retention-locked capture was deleted")
	}
	if _, err := lockedManager.Store.ReadSession(lockedSession.ID); err != nil {
		t.Fatalf("retention-locked capture changed: %v", err)
	}

	manager, session, _ := finalizedDeletionManager(t, false)
	preview, err := manager.PreviewDeletion(t.Context(), session.ID)
	if err != nil {
		t.Fatal(err)
	}
	artifactDirectory, _ := manager.Store.ArtifactDirectory(session.ID)
	if err := os.WriteFile(filepath.Join(artifactDirectory, "unexpected.txt"), []byte("drift"), 0o640); err != nil {
		t.Fatal(err)
	}
	_, err = manager.Delete(t.Context(), DeleteRequest{SessionID: session.ID, PreviewSHA256: preview.PreviewSHA256, PreviewExpiresAt: preview.ExpiresAt, Confirmation: session.ID, Administrator: "admin", IdempotencyKey: "capture-delete-request-0003"})
	if err == nil {
		t.Fatal("stale capture deletion preview was accepted")
	}
}

func TestCaptureDeletionPreviewExpiresAndRequiresExactConfirmation(t *testing.T) {
	manager, session, now := finalizedDeletionManager(t, false)
	preview, err := manager.PreviewDeletion(t.Context(), session.ID)
	if err != nil {
		t.Fatal(err)
	}
	*now = preview.ExpiresAt.Add(time.Nanosecond)
	_, err = manager.Delete(t.Context(), DeleteRequest{SessionID: session.ID, PreviewSHA256: preview.PreviewSHA256, PreviewExpiresAt: preview.ExpiresAt, Confirmation: session.ID, Administrator: "admin", IdempotencyKey: "capture-delete-request-0004"})
	if err == nil {
		t.Fatal("expired capture deletion preview was accepted")
	}
	*now = preview.GeneratedAt
	_, err = manager.Delete(t.Context(), DeleteRequest{SessionID: session.ID, PreviewSHA256: preview.PreviewSHA256, PreviewExpiresAt: preview.ExpiresAt, Confirmation: "DELETE", Administrator: "admin", IdempotencyKey: "capture-delete-request-0005"})
	if err == nil {
		t.Fatal("capture deletion accepted an inexact confirmation")
	}
}

func TestCaptureDeletionFailurePersistsExactRemainder(t *testing.T) {
	manager, session, _ := finalizedDeletionManager(t, false)
	preview, err := manager.PreviewDeletion(t.Context(), session.ID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	job, err := manager.Delete(ctx, DeleteRequest{SessionID: session.ID, PreviewSHA256: preview.PreviewSHA256, PreviewExpiresAt: preview.ExpiresAt, Confirmation: session.ID, Administrator: "admin", IdempotencyKey: "capture-delete-request-0006"})
	if err == nil || job.State != DeletionFailed || job.Phase != "VERIFYING_PREVIEW" || job.RemainingFiles != preview.Footprint.TotalFiles() || job.RemainingBytes != preview.Footprint.TotalBytes() {
		t.Fatalf("unexpected failed deletion evidence: %#v %v", job, err)
	}
	if _, err := manager.Store.ReadSession(session.ID); err != nil {
		t.Fatalf("failed deletion removed the capture: %v", err)
	}
	jobs, listErr := manager.ListDeletionJobs()
	if listErr != nil || len(jobs) != 1 || jobs[0].State != DeletionFailed || jobs[0].RemainingFiles != preview.Footprint.TotalFiles() {
		t.Fatalf("failed deletion was not durable: %#v %v", jobs, listErr)
	}
}

func TestCaptureDeletionRejectsSymlinkWithoutTouchingTarget(t *testing.T) {
	manager, session, _ := finalizedDeletionManager(t, false)
	preview, err := manager.PreviewDeletion(t.Context(), session.ID)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.pcapng")
	if err := os.WriteFile(outside, []byte("do not delete"), 0o640); err != nil {
		t.Fatal(err)
	}
	artifactDirectory, err := manager.Store.ArtifactDirectory(session.ID)
	if err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(artifactDirectory, "capture.pcapng")
	if err := os.Remove(artifact); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, artifact); err != nil {
		t.Fatal(err)
	}
	_, err = manager.Delete(t.Context(), DeleteRequest{SessionID: session.ID, PreviewSHA256: preview.PreviewSHA256, PreviewExpiresAt: preview.ExpiresAt, Confirmation: session.ID, Administrator: "admin", IdempotencyKey: "capture-delete-request-0007"})
	if err == nil {
		t.Fatal("capture deletion accepted a symlink artifact")
	}
	if contents, readErr := os.ReadFile(outside); readErr != nil || string(contents) != "do not delete" {
		t.Fatalf("capture deletion changed the symlink target: %q %v", contents, readErr)
	}
}
