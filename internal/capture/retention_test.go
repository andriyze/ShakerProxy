package capture

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func addRetentionCapture(t *testing.T, store Store, id string, finalizedAt time.Time, size int, locked bool) {
	t.Helper()
	session := validSession(t, store.Root)
	session.ID = id
	session.Request.Name = "capture " + id[len(id)-4:]
	session.Request.RetentionLock = locked
	session.StartedAt = finalizedAt.Add(-time.Hour)
	session.StopAt = finalizedAt
	if err := store.Create(session); err != nil {
		t.Fatal(err)
	}
	artifacts, err := store.ArtifactDirectory(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artifacts, "capture.pcapng"), make([]byte, size), 0o640); err != nil {
		t.Fatal(err)
	}
	status := WorkerStatus{Schema: SchemaVersion, SessionID: id, State: StateCompleted, StartedAt: session.StartedAt, EndedAt: finalizedAt, UpdatedAt: finalizedAt}
	if err := store.WriteWorkerStatus(status); err != nil {
		t.Fatal(err)
	}
	manifest, err := store.CollectFiles(id, finalizedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteManifest(manifest); err != nil {
		t.Fatal(err)
	}
}

func TestRetentionPreviewSelectsOldestAndPreservesLocks(t *testing.T) {
	now := time.Date(2026, 9, 1, 18, 0, 0, 0, time.UTC)
	store := Store{Root: filepath.Join(t.TempDir(), "pcap")}
	addRetentionCapture(t, store, "capture-00000000000000000000000000000001", now.Add(-4*time.Hour), 40, true)
	addRetentionCapture(t, store, "capture-00000000000000000000000000000002", now.Add(-3*time.Hour), 30, false)
	addRetentionCapture(t, store, "capture-00000000000000000000000000000003", now.Add(-time.Hour), 50, false)
	unfinalized := validSession(t, store.Root)
	unfinalized.ID = "capture-00000000000000000000000000000006"
	if err := store.Create(unfinalized); err != nil {
		t.Fatal(err)
	}
	unfinalizedArtifacts, _ := store.ArtifactDirectory(unfinalized.ID)
	if err := os.WriteFile(filepath.Join(unfinalizedArtifacts, "capture.pcapng"), make([]byte, 10), 0o640); err != nil {
		t.Fatal(err)
	}
	manager := &Manager{Store: store, Now: func() time.Time { return now }}
	policy := RetentionPolicyInput{MaxAgeSeconds: int64((2 * time.Hour) / time.Second), MaxPCAPBytes: 60}
	preview, err := manager.PreviewRetention(t.Context(), policy)
	if err != nil {
		t.Fatal(err)
	}
	if preview.EvaluatedSessions != 3 || preview.EvaluatedPCAPBytes != 120 || preview.ExcludedSessions != 1 || preview.ExcludedPCAPBytes != 10 || preview.ProjectedPCAPBytes != 40 || !preview.PCAPByteTargetMet || len(preview.Selected) != 2 || len(preview.BlockedByRetentionLock) != 1 || !validSHA256String(preview.PreviewSHA256) {
		t.Fatalf("unexpected retention preview: %#v", preview)
	}
	if got := []string{preview.Selected[0].SessionID, preview.Selected[1].SessionID}; !reflect.DeepEqual(got, []string{"capture-00000000000000000000000000000002", "capture-00000000000000000000000000000003"}) {
		t.Fatalf("selection is not deterministic oldest-first: %#v", got)
	}
	if !reflect.DeepEqual(preview.Selected[0].Reasons, []string{"MAX_AGE"}) || !reflect.DeepEqual(preview.Selected[1].Reasons, []string{"MAX_PCAP_BYTES"}) || !reflect.DeepEqual(preview.BlockedByRetentionLock[0].Reasons, []string{"MAX_AGE", "MAX_PCAP_BYTES"}) {
		t.Fatalf("selection reasons are incomplete: selected=%#v blocked=%#v", preview.Selected, preview.BlockedByRetentionLock)
	}
	second, err := manager.PreviewRetention(t.Context(), policy)
	if err != nil || second.PreviewSHA256 != preview.PreviewSHA256 {
		t.Fatalf("same frozen population produced a different digest: %s %v", second.PreviewSHA256, err)
	}
}

func TestRetentionPreviewReportsUnachievableByteTarget(t *testing.T) {
	now := time.Date(2026, 9, 1, 18, 0, 0, 0, time.UTC)
	store := Store{Root: filepath.Join(t.TempDir(), "pcap")}
	addRetentionCapture(t, store, "capture-00000000000000000000000000000004", now.Add(-4*time.Hour), 40, true)
	addRetentionCapture(t, store, "capture-00000000000000000000000000000005", now.Add(-3*time.Hour), 30, false)
	manager := &Manager{Store: store, Now: func() time.Time { return now }}
	preview, err := manager.PreviewRetention(t.Context(), RetentionPolicyInput{MaxPCAPBytes: 10})
	if err != nil {
		t.Fatal(err)
	}
	if preview.PCAPByteTargetMet || preview.ProjectedPCAPBytes != 40 || len(preview.Selected) != 1 || len(preview.BlockedByRetentionLock) != 1 {
		t.Fatalf("locked target shortfall was hidden: %#v", preview)
	}
}

func TestRetentionPreviewRejectsUnboundedPolicy(t *testing.T) {
	manager := &Manager{Store: Store{Root: filepath.Join(t.TempDir(), "pcap")}}
	if _, err := manager.PreviewRetention(t.Context(), RetentionPolicyInput{}); err == nil {
		t.Fatal("unbounded retention policy was accepted")
	}
}
