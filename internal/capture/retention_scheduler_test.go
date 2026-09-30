package capture

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRetentionSchedulerPlansOneDurableJobPerCadenceSlot(t *testing.T) {
	manager, session, now := finalizedDeletionManager(t, false)
	seed := byte(1)
	manager.Random = func(value []byte) (int, error) {
		for index := range value {
			value[index] = seed
		}
		seed++
		return len(value), nil
	}
	preview, err := manager.PreviewRetention(t.Context(), RetentionPolicyInput{MaxPCAPBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := manager.ApplyRetentionPolicy(t.Context(), ApplyRetentionPolicyRequest{ExpectedRevision: 0, Enabled: true, Rules: preview.Policy, RunEverySeconds: 300, PreviewSHA256: preview.PreviewSHA256, PreviewExpiresAt: preview.ExpiresAt, Administrator: "admin", IdempotencyKey: "capture-retention-scheduler-policy-0001"})
	if err != nil {
		t.Fatal(err)
	}
	*now = policy.UpdatedAt.Add(299 * time.Second)
	status, run, err := manager.RunRetentionSchedulerOnce(t.Context())
	if err != nil || run != nil || !status.Enabled || status.NextRunAt == nil || !status.NextRunAt.Equal(policy.UpdatedAt.Add(300*time.Second)) {
		t.Fatalf("scheduler ran before cadence: %#v %#v %v", status, run, err)
	}
	*now = policy.UpdatedAt.Add(300 * time.Second)
	status, run, err = manager.RunRetentionSchedulerOnce(t.Context())
	if err != nil || run == nil || run.Trigger != RetentionTriggerAutomatic || run.ScheduledFor == nil || !run.ScheduledFor.Equal(*now) || run.State != RetentionRunPending || run.DeletedSessions != 0 || status.LastRunID != run.ID {
		t.Fatalf("scheduler did not plan due slot: %#v %#v %v", status, run, err)
	}
	if _, err := manager.Store.ReadSession(session.ID); err != nil {
		t.Fatalf("host scheduler deleted a capture before coordinated acknowledgement: %v", err)
	}
	_, duplicate, err := manager.RunRetentionSchedulerOnce(t.Context())
	if err != nil || duplicate != nil {
		t.Fatalf("scheduler duplicated a cadence slot: %#v %v", duplicate, err)
	}
	runs, err := manager.ListRetentionRuns()
	if err != nil || len(runs) != 1 {
		t.Fatalf("unexpected automatic run history: %#v %v", runs, err)
	}
}

func TestRetentionSchedulerPersistsGenericFailureEvidence(t *testing.T) {
	manager, session, now := finalizedDeletionManager(t, false)
	preview, err := manager.PreviewRetention(t.Context(), RetentionPolicyInput{MaxPCAPBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := manager.ApplyRetentionPolicy(t.Context(), ApplyRetentionPolicyRequest{ExpectedRevision: 0, Enabled: true, Rules: preview.Policy, RunEverySeconds: 300, PreviewSHA256: preview.PreviewSHA256, PreviewExpiresAt: preview.ExpiresAt, Administrator: "admin", IdempotencyKey: "capture-retention-scheduler-policy-0004"})
	if err != nil {
		t.Fatal(err)
	}
	artifacts, _ := manager.Store.ArtifactDirectory(session.ID)
	if err := os.WriteFile(filepath.Join(artifacts, "unexpected.txt"), []byte("drift"), 0o640); err != nil {
		t.Fatal(err)
	}
	*now = policy.UpdatedAt.Add(300 * time.Second)
	if _, run, err := manager.RunRetentionSchedulerOnce(t.Context()); err == nil || run != nil {
		t.Fatalf("drifted scheduler check did not fail: %#v %v", run, err)
	}
	status, err := manager.RetentionSchedulerStatus()
	if err != nil || status.LastFailure != "automatic retention check failed" || status.LastFailureAt == nil {
		t.Fatalf("scheduler failure evidence was not durable and generic: %#v %v", status, err)
	}
}

func TestRetentionSchedulerStopsAfterDisabledRevision(t *testing.T) {
	manager, _, now := finalizedDeletionManager(t, false)
	preview, err := manager.PreviewRetention(t.Context(), RetentionPolicyInput{MaxAgeSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := manager.ApplyRetentionPolicy(t.Context(), ApplyRetentionPolicyRequest{ExpectedRevision: 0, Enabled: true, Rules: preview.Policy, RunEverySeconds: 300, PreviewSHA256: preview.PreviewSHA256, PreviewExpiresAt: preview.ExpiresAt, Administrator: "admin", IdempotencyKey: "capture-retention-scheduler-policy-0002"})
	if err != nil {
		t.Fatal(err)
	}
	disablePreview, err := manager.PreviewRetention(t.Context(), enabled.Rules)
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := manager.ApplyRetentionPolicy(t.Context(), ApplyRetentionPolicyRequest{ExpectedRevision: enabled.Revision, Enabled: false, Rules: enabled.Rules, RunEverySeconds: enabled.RunEverySeconds, PreviewSHA256: disablePreview.PreviewSHA256, PreviewExpiresAt: disablePreview.ExpiresAt, Administrator: "admin", IdempotencyKey: "capture-retention-scheduler-policy-0003"})
	if err != nil {
		t.Fatal(err)
	}
	*now = disabled.UpdatedAt.Add(time.Hour)
	status, run, err := manager.RunRetentionSchedulerOnce(t.Context())
	if err != nil || run != nil || status.Enabled || status.NextRunAt != nil {
		t.Fatalf("disabled scheduler executed: %#v %#v %v", status, run, err)
	}
}
