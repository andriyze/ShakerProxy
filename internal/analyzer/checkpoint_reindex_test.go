package analyzer

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCheckpointReindexAuthorizesOneManifestAndArchivesBarrier(t *testing.T) {
	store := NewStateStore(t.TempDir())
	if err := store.Prepare(); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	oldManifest := strings.Repeat("a", 64)
	newManifest := strings.Repeat("b", 64)
	checkpoint := Checkpoint{Schema: SchemaVersion, Engine: EngineZeek, CaptureSessionID: testSessionID, ManifestSHA256: oldManifest, CaptureFiles: 1, EventsDelivered: 4, OutputBytes: 512, AnalysisCompletedAt: now}
	if err := store.WriteCheckpoint(checkpoint); err != nil {
		t.Fatal(err)
	}
	service, err := NewCheckpointDeletionService(store, EngineZeek)
	if err != nil {
		t.Fatal(err)
	}
	service.Now = func() time.Time { return now.Add(time.Minute) }
	preview, err := service.Preview(testSessionID)
	if err != nil {
		t.Fatal(err)
	}
	deletion := CheckpointDeletionRequest{Schema: CheckpointDeletionSchema, OperationID: "checkpoint-delete-reindex-0001", Actor: "admin", Preview: preview}
	if _, err := service.Delete(deletion); err != nil {
		t.Fatal(err)
	}
	reindex := CheckpointReindexRequest{
		Schema: CheckpointReindexSchema, OperationID: "checkpoint-reindex-operation-0001", Actor: "admin", Engine: EngineZeek,
		CaptureSessionID: testSessionID, DeletionOperationID: deletion.OperationID,
		DeletionPreviewSHA256: preview.PreviewSHA256, TargetManifestSHA256: newManifest,
	}
	authorized, err := service.AuthorizeReindex(reindex)
	if err != nil || authorized.State != "AUTHORIZED" || authorized.Replayed {
		t.Fatalf("reindex was not authorized: %#v err=%v", authorized, err)
	}
	wrong := checkpoint
	wrong.ManifestSHA256 = strings.Repeat("c", 64)
	wrong.AnalysisCompletedAt = now.Add(2 * time.Minute)
	if err := store.WriteCheckpoint(wrong); !errors.Is(err, ErrCheckpointDeletionBarrier) {
		t.Fatalf("unreviewed manifest crossed deletion barrier: %v", err)
	}
	replacement := checkpoint
	replacement.ManifestSHA256 = newManifest
	replacement.EventsDelivered = 3
	replacement.AnalysisCompletedAt = now.Add(3 * time.Minute)
	if err := store.WriteCheckpoint(replacement); err != nil {
		t.Fatal(err)
	}
	if barrier, err := store.HasCheckpointDeletionBarrier(EngineZeek, testSessionID); err != nil || barrier {
		t.Fatalf("completed reindex did not retire the active barrier: barrier=%v err=%v", barrier, err)
	}
	completed, err := service.AuthorizeReindex(reindex)
	if err != nil || completed.State != "COMPLETED" || !completed.Replayed || completed.CompletedAt == nil {
		t.Fatalf("completed reindex receipt did not replay: %#v err=%v", completed, err)
	}
	deletedReplay, err := service.Delete(deletion)
	if err != nil || !deletedReplay.Replayed {
		t.Fatalf("archived deletion receipt did not replay: %#v err=%v", deletedReplay, err)
	}
	service.Now = func() time.Time { return now.Add(4 * time.Minute) }
	nextPreview, err := service.Preview(testSessionID)
	if err != nil || !nextPreview.CheckpointPresent || nextPreview.ManifestSHA256 != newManifest {
		t.Fatalf("reindexed checkpoint is unavailable for a later deletion: %#v err=%v", nextPreview, err)
	}
	next := CheckpointDeletionRequest{Schema: CheckpointDeletionSchema, OperationID: "checkpoint-delete-reindex-0002", Actor: "admin", Preview: nextPreview}
	if _, err := service.Delete(next); err != nil {
		t.Fatalf("later checkpoint deletion could not start a new generation: %v", err)
	}
}

func TestCheckpointReindexRejectsSubstitutedDeletionEvidence(t *testing.T) {
	store := NewStateStore(t.TempDir())
	if err := store.Prepare(); err != nil {
		t.Fatal(err)
	}
	service, err := NewCheckpointDeletionService(store, EngineSuricata)
	if err != nil {
		t.Fatal(err)
	}
	request := CheckpointReindexRequest{
		Schema: CheckpointReindexSchema, OperationID: "checkpoint-reindex-operation-0002", Actor: "admin", Engine: EngineSuricata,
		CaptureSessionID: testSessionID, DeletionOperationID: "checkpoint-delete-reindex-0003",
		DeletionPreviewSHA256: strings.Repeat("d", 64), TargetManifestSHA256: strings.Repeat("e", 64),
	}
	if _, err := service.AuthorizeReindex(request); !errors.Is(err, ErrCheckpointReindexBarrier) {
		t.Fatalf("reindex without a matching deletion barrier was accepted: %v", err)
	}
}
