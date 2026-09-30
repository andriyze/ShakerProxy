package capture

import (
	"os"
	"testing"
)

func configuredRetentionManager(t *testing.T) (*Manager, RetentionPreview) {
	t.Helper()
	manager, _, _ := finalizedDeletionManager(t, false)
	preview, err := manager.PreviewRetention(t.Context(), RetentionPolicyInput{MaxPCAPBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.ApplyRetentionPolicy(t.Context(), ApplyRetentionPolicyRequest{ExpectedRevision: 0, Enabled: false, Rules: preview.Policy, RunEverySeconds: 1800, PreviewSHA256: preview.PreviewSHA256, PreviewExpiresAt: preview.ExpiresAt, Administrator: "admin", IdempotencyKey: "capture-retention-policy-run-0001"})
	if err != nil {
		t.Fatal(err)
	}
	return manager, preview
}

func TestRetentionRunDeletesExactPreviewAndReplays(t *testing.T) {
	manager, preview := configuredRetentionManager(t)
	request := StartRetentionRunRequest{PolicyRevision: 1, PreviewSHA256: preview.PreviewSHA256, PreviewExpiresAt: preview.ExpiresAt, Administrator: "admin", IdempotencyKey: "capture-retention-run-request-0001", Trigger: RetentionTriggerManual}
	run, err := manager.StartRetentionRun(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if run.State != RetentionRunCompleted || run.Phase != "VERIFIED" || run.SelectedSessions != 1 || run.DeletedSessions != 1 || run.FailedSessions != 0 || run.RemainingFiles != 0 || run.RemainingBytes != 0 || run.CompletedAt == nil || len(run.Items) != 1 || run.Items[0].State != RetentionItemDeleted || !deletionJobIDPattern.MatchString(run.Items[0].DeletionJobID) {
		t.Fatalf("unexpected retention run: %#v", run)
	}
	if _, err := manager.Store.ReadSession(run.Items[0].SessionID); !os.IsNotExist(err) {
		t.Fatalf("retention run left its selected capture: %v", err)
	}
	replayed, err := manager.StartRetentionRun(t.Context(), request)
	if err != nil || replayed.ID != run.ID || replayed.State != RetentionRunCompleted {
		t.Fatalf("retention run replay failed: %#v %v", replayed, err)
	}
	runs, err := manager.ListRetentionRuns()
	if err != nil || len(runs) != 1 || runs[0].ID != run.ID {
		t.Fatalf("retention run was not durable: %#v %v", runs, err)
	}
}

func TestRetentionRunRecordsExternallyCoordinatedDeletion(t *testing.T) {
	manager, preview := configuredRetentionManager(t)
	request := StartRetentionRunRequest{PolicyRevision: 1, PreviewSHA256: preview.PreviewSHA256, PreviewExpiresAt: preview.ExpiresAt, Administrator: "admin", IdempotencyKey: "capture-retention-run-plan-0001", Trigger: RetentionTriggerManual}
	run, err := manager.PlanRetentionRun(t.Context(), request)
	if err != nil || run.State != RetentionRunPending || len(run.Items) != 1 {
		t.Fatalf("retention plan was not persisted: %#v err=%v", run, err)
	}
	item := run.Items[0]
	if _, err := manager.Store.ReadSession(item.SessionID); err != nil {
		t.Fatalf("planning mutated capture artifacts: %v", err)
	}
	hostJob, err := manager.Delete(t.Context(), DeleteRequest{SessionID: item.SessionID, PreviewSHA256: item.DeletionPreviewSHA256, PreviewExpiresAt: item.DeletionPreviewExpiresAt, Confirmation: item.SessionID, Administrator: run.Administrator, IdempotencyKey: item.DeletionIdempotencyKey})
	if err != nil || hostJob.State != DeletionCompleted {
		t.Fatalf("host acknowledgement setup failed: %#v err=%v", hostJob, err)
	}
	outcome := RecordRetentionItemOutcomeRequest{RunID: run.ID, SessionID: item.SessionID, State: RetentionItemDeleted, CoordinatedDeletionJobID: "capture-delete-operation-0123456789abcdef0123456789abcdef", DeletionJobID: hostJob.ID}
	completed, err := manager.RecordRetentionItemOutcome(outcome)
	if err != nil || completed.State != RetentionRunCompleted || completed.DeletedSessions != 1 || completed.Items[0].CoordinatedDeletionJobID != outcome.CoordinatedDeletionJobID || completed.Items[0].DeletionJobID != hostJob.ID {
		t.Fatalf("coordinated outcome was not recorded: %#v err=%v", completed, err)
	}
	replayed, err := manager.RecordRetentionItemOutcome(outcome)
	if err != nil || replayed.State != RetentionRunCompleted {
		t.Fatalf("coordinated outcome was not idempotent: %#v err=%v", replayed, err)
	}
	conflict := outcome
	conflict.State, conflict.CoordinatedDeletionJobID, conflict.DeletionJobID, conflict.Failure = RetentionItemFailed, "", "", "conflicting outcome"
	if _, err := manager.RecordRetentionItemOutcome(conflict); err == nil {
		t.Fatal("terminal coordinated retention evidence was mutable")
	}
}

func TestRetentionRunRejectsUnverifiedExternalCompletion(t *testing.T) {
	manager, preview := configuredRetentionManager(t)
	run, err := manager.PlanRetentionRun(t.Context(), StartRetentionRunRequest{PolicyRevision: 1, PreviewSHA256: preview.PreviewSHA256, PreviewExpiresAt: preview.ExpiresAt, Administrator: "admin", IdempotencyKey: "capture-retention-run-plan-0002", Trigger: RetentionTriggerManual})
	if err != nil {
		t.Fatal(err)
	}
	request := RecordRetentionItemOutcomeRequest{RunID: run.ID, SessionID: run.Items[0].SessionID, State: RetentionItemDeleted, CoordinatedDeletionJobID: "capture-delete-operation-1123456789abcdef0123456789abcdef", DeletionJobID: "capture-delete-1123456789abcdef0123456789abcdef"}
	if _, err := manager.RecordRetentionItemOutcome(request); err == nil {
		t.Fatal("retention accepted completion without a durable host acknowledgement")
	}
}

func TestRetentionRunRejectsPolicyRevisionAndPopulationDrift(t *testing.T) {
	manager, preview := configuredRetentionManager(t)
	request := StartRetentionRunRequest{PolicyRevision: 2, PreviewSHA256: preview.PreviewSHA256, PreviewExpiresAt: preview.ExpiresAt, Administrator: "admin", IdempotencyKey: "capture-retention-run-request-0002", Trigger: RetentionTriggerManual}
	if _, err := manager.StartRetentionRun(t.Context(), request); err == nil {
		t.Fatal("retention run accepted a stale policy revision")
	}
	request.PolicyRevision = 1
	request.IdempotencyKey = "capture-retention-run-request-0003"
	artifacts, _ := manager.Store.ArtifactDirectory(preview.Selected[0].SessionID)
	if err := os.WriteFile(artifacts+"/unexpected.txt", []byte("drift"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.StartRetentionRun(t.Context(), request); err == nil {
		t.Fatal("retention run accepted a drifted preview population")
	}
}

func TestRetentionRunResumesPersistedPendingItem(t *testing.T) {
	manager, preview := configuredRetentionManager(t)
	candidate := preview.Selected[0]
	deletionPreview, err := manager.previewDeletion(t.Context(), candidate.SessionID, preview.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	now := manager.now()
	run := RetentionRun{Schema: 1, ID: "retention-run-00000000000000000000000000000001", State: RetentionRunPending, Phase: "RECORDING_INTENT", PolicyRevision: 1, Policy: preview.Policy, PreviewSHA256: preview.PreviewSHA256, Administrator: "admin", Trigger: RetentionTriggerManual, SelectedSessions: 1, RemainingFiles: candidate.Footprint.TotalFiles(), RemainingBytes: candidate.Footprint.TotalBytes(), CreatedAt: now, UpdatedAt: now, Items: []RetentionRunItem{{SessionID: candidate.SessionID, Name: candidate.Name, Reasons: candidate.Reasons, Footprint: candidate.Footprint, State: RetentionItemPending, DeletionPreviewSHA256: deletionPreview.PreviewSHA256, DeletionPreviewExpiresAt: deletionPreview.ExpiresAt, DeletionIdempotencyKey: "retention-delete-resume-00000001", UpdatedAt: now}}}
	request := StartRetentionRunRequest{PolicyRevision: 1, PreviewSHA256: preview.PreviewSHA256, PreviewExpiresAt: preview.ExpiresAt, Administrator: "admin", IdempotencyKey: "capture-retention-run-request-0004", Trigger: RetentionTriggerManual}
	requestHash, _ := hashJSON(request)
	if err := manager.Store.WriteRetentionRunRecord(retentionRunRecord{Run: run, IdempotencyKey: request.IdempotencyKey, RequestSHA256: requestHash}); err != nil {
		t.Fatal(err)
	}
	resumed, err := manager.ResumeRetentionRuns(t.Context())
	if err != nil || len(resumed) != 1 || resumed[0].State != RetentionRunCompleted || resumed[0].DeletedSessions != 1 {
		t.Fatalf("pending retention run did not resume: %#v %v", resumed, err)
	}
}
