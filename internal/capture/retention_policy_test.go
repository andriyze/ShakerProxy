package capture

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func retentionPolicyRequest(preview RetentionPreview, expected uint64, key string) ApplyRetentionPolicyRequest {
	return ApplyRetentionPolicyRequest{ExpectedRevision: expected, Enabled: false, Rules: preview.Policy, RunEverySeconds: 1800, PreviewSHA256: preview.PreviewSHA256, PreviewExpiresAt: preview.ExpiresAt, Administrator: "admin", IdempotencyKey: key}
}

func TestRetentionPolicyApplyIsRevisionedDurableAndIdempotent(t *testing.T) {
	manager, _, _ := finalizedDeletionManager(t, false)
	preview, err := manager.PreviewRetention(t.Context(), RetentionPolicyInput{MaxAgeSeconds: 3600, MaxPCAPBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	initial, err := manager.GetRetentionPolicy()
	if err != nil || initial.Revision != 0 || initial.Enabled {
		t.Fatalf("unexpected default retention policy: %#v %v", initial, err)
	}
	request := retentionPolicyRequest(preview, initial.Revision, "capture-retention-policy-0001")
	applied, err := manager.ApplyRetentionPolicy(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if applied.Revision != 1 || applied.Enabled || applied.Rules != preview.Policy || applied.UpdatedBy != "admin" || applied.UpdatedAt.IsZero() {
		t.Fatalf("unexpected applied policy: %#v", applied)
	}
	reloaded, err := manager.GetRetentionPolicy()
	if err != nil || reloaded != applied {
		t.Fatalf("retention policy was not durable: %#v %v", reloaded, err)
	}
	replayed, err := manager.ApplyRetentionPolicy(t.Context(), request)
	if err != nil || replayed != applied {
		t.Fatalf("idempotent policy replay failed: %#v %v", replayed, err)
	}
	conflict := request
	conflict.RunEverySeconds = 3600
	if _, err := manager.ApplyRetentionPolicy(t.Context(), conflict); err == nil {
		t.Fatal("idempotency key was reused for a different policy request")
	}
}

func TestRetentionPolicyRejectsStaleRevisionAndPreview(t *testing.T) {
	manager, session, _ := finalizedDeletionManager(t, false)
	preview, err := manager.PreviewRetention(t.Context(), RetentionPolicyInput{MaxAgeSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	request := retentionPolicyRequest(preview, 1, "capture-retention-policy-0002")
	if _, err := manager.ApplyRetentionPolicy(t.Context(), request); err == nil {
		t.Fatal("stale expected policy revision was accepted")
	}
	request.ExpectedRevision = 0
	artifacts, _ := manager.Store.ArtifactDirectory(session.ID)
	if err := os.WriteFile(filepath.Join(artifacts, "unexpected.txt"), []byte("drift"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ApplyRetentionPolicy(t.Context(), request); err == nil {
		t.Fatal("stale retention population preview was accepted")
	}
}

func TestRetentionPolicyConcurrentExpectedRevisionHasOneWinner(t *testing.T) {
	manager, _, _ := finalizedDeletionManager(t, false)
	preview, err := manager.PreviewRetention(t.Context(), RetentionPolicyInput{MaxPCAPBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	requests := []ApplyRetentionPolicyRequest{
		retentionPolicyRequest(preview, 0, "capture-retention-policy-0003"),
		retentionPolicyRequest(preview, 0, "capture-retention-policy-0004"),
	}
	requests[1].RunEverySeconds = 3600
	var wait sync.WaitGroup
	results := make(chan error, 2)
	for _, request := range requests {
		request := request
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := manager.ApplyRetentionPolicy(t.Context(), request)
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly one revision winner, got %d", successes)
	}
	policy, err := manager.GetRetentionPolicy()
	if err != nil || policy.Revision != 1 {
		t.Fatalf("concurrent update corrupted policy: %#v %v", policy, err)
	}
}

func TestRetentionPolicyRejectsExpiredPreview(t *testing.T) {
	manager, _, now := finalizedDeletionManager(t, false)
	preview, err := manager.PreviewRetention(t.Context(), RetentionPolicyInput{MaxAgeSeconds: int64((24 * time.Hour) / time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	*now = preview.ExpiresAt.Add(time.Nanosecond)
	if _, err := manager.ApplyRetentionPolicy(t.Context(), retentionPolicyRequest(preview, 0, "capture-retention-policy-0005")); err == nil {
		t.Fatal("expired retention policy preview was accepted")
	}
}

func TestRetentionPolicyCanEnableDurableExecutor(t *testing.T) {
	manager, _, _ := finalizedDeletionManager(t, false)
	preview, err := manager.PreviewRetention(t.Context(), RetentionPolicyInput{MaxAgeSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	request := retentionPolicyRequest(preview, 0, "capture-retention-policy-0006")
	request.Enabled = true
	policy, err := manager.ApplyRetentionPolicy(t.Context(), request)
	if err != nil || !policy.Enabled {
		t.Fatalf("durable retention executor could not be enabled: %#v %v", policy, err)
	}
}
