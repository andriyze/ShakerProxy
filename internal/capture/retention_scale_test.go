package capture

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestRetentionPreviewHandlesMoreSessionsThanOneRunSelects(t *testing.T) {
	now := time.Date(2026, 9, 1, 18, 0, 0, 0, time.UTC)
	store := Store{Root: filepath.Join(t.TempDir(), "pcap")}
	total := MaxRetentionCandidates + 6
	for index := 0; index < total; index++ {
		addRetentionCapture(t, store, fmt.Sprintf("capture-%032x", index+1), now.Add(-time.Duration(total-index)*time.Minute-time.Hour), 16, false)
	}
	manager := &Manager{Store: store, Now: func() time.Time { return now }}
	preview, err := manager.PreviewRetention(t.Context(), RetentionPolicyInput{MaxAgeSeconds: 60})
	if err != nil {
		t.Fatalf("retention stopped working past %d sessions: %v", MaxRetentionCandidates, err)
	}
	if preview.EvaluatedSessions != total || len(preview.Selected) != MaxRetentionCandidates || preview.Selected[0].SessionID != fmt.Sprintf("capture-%032x", 1) {
		t.Fatalf("unexpected bounded selection: evaluated=%d selected=%d first=%s", preview.EvaluatedSessions, len(preview.Selected), preview.Selected[0].SessionID)
	}
}

func TestRetentionSchedulerPrunesFinishedRunHistory(t *testing.T) {
	manager, _, now := finalizedDeletionManager(t, false)
	seed := 0
	manager.Random = func(value []byte) (int, error) {
		seed++
		digest := sha256.Sum256([]byte(fmt.Sprint(seed)))
		copy(value, digest[:])
		return len(value), nil
	}
	rules := RetentionPolicyInput{MaxAgeSeconds: 10 * 365 * 24 * 60 * 60}
	preview, err := manager.PreviewRetention(t.Context(), rules)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := manager.ApplyRetentionPolicy(t.Context(), ApplyRetentionPolicyRequest{ExpectedRevision: 0, Enabled: true, Rules: preview.Policy, RunEverySeconds: 300, PreviewSHA256: preview.PreviewSHA256, PreviewExpiresAt: preview.ExpiresAt, Administrator: "admin", IdempotencyKey: "capture-retention-scheduler-policy-prune"})
	if err != nil {
		t.Fatal(err)
	}
	*now = policy.UpdatedAt.Add(300 * time.Second)
	_, run, err := manager.RunRetentionSchedulerOnce(t.Context())
	if err != nil || run == nil || len(run.Items) != 0 || run.State != RetentionRunCompleted {
		t.Fatalf("first empty automatic run was not recorded: %#v %v", run, err)
	}
	records, err := manager.Store.ListRetentionRunRecords()
	if err != nil || len(records) != 1 {
		t.Fatalf("unexpected run records: %d %v", len(records), err)
	}
	template := records[0]
	for index := 1; index < MaxRetentionRuns; index++ {
		clone := template
		id := sha256.Sum256([]byte(fmt.Sprint("history", index)))
		clone.Run.ID = "retention-run-" + hex.EncodeToString(id[:16])
		clone.IdempotencyKey = "capture-retention-history-" + hex.EncodeToString(id[:8])
		slot := template.Run.ScheduledFor.Add(-time.Duration(index) * 300 * time.Second)
		clone.Run.ScheduledFor = &slot
		clone.Run.CreatedAt, clone.Run.UpdatedAt = slot, slot
		completed := slot
		clone.Run.CompletedAt = &completed
		if err := manager.Store.WriteRetentionRunRecord(clone); err != nil {
			t.Fatal(err)
		}
	}
	*now = now.Add(300 * time.Second)
	_, next, err := manager.RunRetentionSchedulerOnce(t.Context())
	if err != nil || next == nil {
		t.Fatalf("automatic retention stopped at the run-history limit: %#v %v", next, err)
	}
	records, err = manager.Store.ListRetentionRunRecords()
	if err != nil || len(records) != MaxRetentionRuns-retentionRunPruneHeadroom+1 {
		t.Fatalf("run history was not pruned to its bound: %d %v", len(records), err)
	}
}
