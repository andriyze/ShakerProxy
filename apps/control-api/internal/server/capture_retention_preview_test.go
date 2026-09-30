package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
)

func coordinatorRetentionPreview(t *testing.T, exports int) coordinatedCaptureRetentionPreview {
	t.Helper()
	item := coordinatorDeletionPreview(t, exports)
	host := capture.RetentionPreview{
		Schema: 1, PreviewSHA256: strings.Repeat("b", 64), GeneratedAt: item.GeneratedAt, ExpiresAt: item.HostArtifacts.ExpiresAt,
		Policy: capture.RetentionPolicyInput{MaxPCAPBytes: 1}, EvaluatedSessions: 1, EvaluatedPCAPBytes: item.HostArtifacts.Footprint.CaptureBytes,
		Selected:               []capture.RetentionCandidate{{SessionID: item.SessionID, Name: "retention fixture", FinalizedAt: item.GeneratedAt.Add(-1), Footprint: item.HostArtifacts.Footprint, Reasons: []string{"MAX_PCAP_BYTES"}}},
		BlockedByRetentionLock: []capture.RetentionCandidate{}, DeleteFiles: item.HostArtifacts.Footprint.TotalFiles(), ImmediatelyRecoverableBytes: item.HostArtifacts.Footprint.TotalBytes(),
		ProjectedPCAPBytes: 0, PCAPByteTargetMet: true, DeletedDataClasses: []string{"capture_session_metadata", "pcap_artifacts"}, RetainedDataClasses: append([]string(nil), item.HostArtifacts.RetainedDataClasses...),
	}
	preview := coordinatedCaptureRetentionPreview{
		Schema: coordinatedCaptureRetentionPreviewSchema, GeneratedAt: item.GeneratedAt, ExpiresAt: item.ExpiresAt, HostRetention: host, Selected: []coordinatedCaptureDeletionPreview{item},
		NormalizedEventRows: item.NormalizedEvents.Database.EventRows, ExclusiveIdentityRows: item.NormalizedEvents.Database.ExclusiveIdentityRows,
		PendingSpoolRecords: item.NormalizedEvents.Spool.PendingRecords, PendingSpoolBytes: item.NormalizedEvents.Spool.PendingFileBytes, ExistingExportRecords: exports,
		ImmediatelyRecoverableBytes:             item.HostArtifacts.EstimatedRecoverableBytes + item.NormalizedEvents.EstimatedImmediatelyReclaimableBytes,
		LogicalBytesReclaimableAfterMaintenance: item.NormalizedEvents.LogicalBytesReclaimableAfterMaintenance,
		DeletedDataClasses:                      append([]string(nil), coordinatedCaptureDeletedDataClasses...), RetainedDataClasses: append([]string(nil), coordinatedCaptureRetainedDataClasses...),
	}
	digest, err := coordinatedCaptureRetentionPreviewHash(preview)
	if err != nil {
		t.Fatal(err)
	}
	preview.PreviewSHA256 = digest
	if err := preview.validate(); err != nil {
		t.Fatal(err)
	}
	return preview
}

func TestCoordinatedCaptureRetentionPreviewBindsEverySelectedBackend(t *testing.T) {
	preview := coordinatorRetentionPreview(t, 2)
	if preview.NormalizedEventRows != 3 || preview.ExclusiveIdentityRows != 2 || preview.ExistingExportRecords != 2 || preview.ImmediatelyRecoverableBytes != 4608 || preview.LogicalBytesReclaimableAfterMaintenance != 896 {
		t.Fatalf("unexpected combined retention totals: %#v", preview)
	}
	tampered := preview
	tampered.Selected = append([]coordinatedCaptureDeletionPreview(nil), preview.Selected...)
	tampered.Selected[0].NormalizedEvents.Database.EventRows++
	if err := tampered.validate(); err == nil {
		t.Fatal("tampered selected backend evidence retained a valid preview")
	}
}

func TestCoordinatedCaptureRetentionPreviewLedgerIsDurableAndPrivate(t *testing.T) {
	dataDirectory := filepath.Join(t.TempDir(), "data")
	store := NewStore(dataDirectory, filepath.Join(dataDirectory, "unused-token"))
	preview := coordinatorRetentionPreview(t, 1)
	record, err := store.recordCoordinatedCaptureRetentionPreview(preview, "admin")
	if err != nil || record.Preview.PreviewSHA256 != preview.PreviewSHA256 {
		t.Fatalf("record preview: %#v err=%v", record, err)
	}
	path := filepath.Join(dataDirectory, "capture-retention-previews.json")
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("preview ledger permissions: %v err=%v", info, err)
	}
	reopened := NewStore(dataDirectory, filepath.Join(dataDirectory, "unused-token"))
	loaded, err := reopened.getCoordinatedCaptureRetentionPreview(preview.PreviewSHA256, "admin")
	if err != nil || loaded.Preview.PreviewSHA256 != preview.PreviewSHA256 {
		t.Fatalf("reload preview: %#v err=%v", loaded, err)
	}
	byHost, err := reopened.getCoordinatedCaptureRetentionPreviewByHostDigest(preview.HostRetention.PreviewSHA256, "admin")
	if err != nil || byHost.Preview.PreviewSHA256 != preview.PreviewSHA256 {
		t.Fatalf("reload preview by host digest: %#v err=%v", byHost, err)
	}
	if _, err := reopened.getCoordinatedCaptureRetentionPreview(preview.PreviewSHA256, "another-admin"); !os.IsNotExist(err) {
		t.Fatalf("different administrator loaded preview: %v", err)
	}
}

func TestLegacyCombinedRetentionPreviewLedgerRemainsReadable(t *testing.T) {
	dataDirectory := filepath.Join(t.TempDir(), "data")
	store := NewStore(dataDirectory, filepath.Join(dataDirectory, "unused-token"))
	legacy := coordinatorRetentionPreview(t, 0)
	legacy.Schema = legacyCoordinatedCaptureRetentionPreviewSchema
	legacy.DeletedDataClasses = append([]string(nil), legacyCoordinatedCaptureDeletedDataClasses...)
	legacy.RetainedDataClasses = append([]string(nil), legacyCoordinatedCaptureRetainedDataClasses...)
	legacy.Selected = append([]coordinatedCaptureDeletionPreview(nil), legacy.Selected...)
	legacy.Selected[0].Schema = legacyCoordinatedCaptureDeletionSchema
	legacy.Selected[0].ZeekCheckpoint = nil
	legacy.Selected[0].SuricataCheckpoint = nil
	legacy.Selected[0].CopyBoundaries = nil
	legacy.Selected[0].DeletedDataClasses = append([]string(nil), legacyCoordinatedCaptureDeletedDataClasses...)
	legacy.Selected[0].RetainedDataClasses = append([]string(nil), legacyCoordinatedCaptureRetainedDataClasses...)
	itemDigest, err := coordinatedCaptureDeletionPreviewHash(legacy.Selected[0])
	if err != nil {
		t.Fatal(err)
	}
	legacy.Selected[0].PreviewSHA256 = itemDigest
	previewDigest, err := coordinatedCaptureRetentionPreviewHash(legacy)
	if err != nil {
		t.Fatal(err)
	}
	legacy.PreviewSHA256 = previewDigest
	if err := legacy.validate(); err != nil {
		t.Fatal(err)
	}
	recordedAt := legacy.GeneratedAt.Add(time.Second)
	ledger := coordinatedCaptureRetentionPreviewLedger{Schema: coordinatedCaptureRetentionLedgerSchema, Records: []coordinatedCaptureRetentionPreviewRecord{{Schema: legacyCoordinatedCaptureRetentionPreviewSchema, Preview: legacy, Administrator: "admin", RecordedAt: recordedAt}}}
	if err := store.writeCoordinatedCaptureRetentionPreviewsLocked(ledger); err != nil {
		t.Fatal(err)
	}
	reopened := NewStore(dataDirectory, filepath.Join(dataDirectory, "unused-token"))
	loaded, err := reopened.getCoordinatedCaptureRetentionPreview(legacy.PreviewSHA256, "admin")
	if err != nil || loaded.Preview.Schema != legacyCoordinatedCaptureRetentionPreviewSchema || loaded.Preview.Selected[0].ZeekCheckpoint != nil {
		t.Fatalf("legacy retention preview did not survive restart: %#v err=%v", loaded, err)
	}
}

func TestManualRetentionRestartUsesReviewedPreviewWithoutRefreshingBackends(t *testing.T) {
	dataDirectory := filepath.Join(t.TempDir(), "data")
	preview := coordinatorRetentionPreview(t, 0)
	store := NewStore(dataDirectory, filepath.Join(dataDirectory, "unused-token"))
	if _, err := store.recordCoordinatedCaptureRetentionPreview(preview, "admin"); err != nil {
		t.Fatal(err)
	}
	// Reopen the store to model a control-plane restart. The gateway socket is
	// intentionally absent: any attempt to refresh the host preview must fail.
	reopened := NewStore(dataDirectory, filepath.Join(dataDirectory, "unused-token"))
	selected := preview.Selected[0]
	config := Config{Store: reopened, GatewaySocket: filepath.Join(t.TempDir(), "absent.sock"), CaptureEventDeletions: &captureDeletionEventStub{preview: selected.NormalizedEvents}}
	configureAnalyzerDeletionPreviews(&config, selected)
	server := New(config)
	run := capture.RetentionRun{ID: "retention-run-4123456789abcdef0123456789abcdef", PreviewSHA256: preview.HostRetention.PreviewSHA256, Administrator: "admin", Trigger: capture.RetentionTriggerManual}
	item := capture.RetentionRunItem{SessionID: selected.SessionID, Footprint: selected.HostArtifacts.Footprint, DeletionPreviewSHA256: selected.HostArtifacts.PreviewSHA256, DeletionPreviewExpiresAt: selected.HostArtifacts.ExpiresAt}
	record, err := server.beginRetentionCaptureDeletion(t.Context(), run, item, "retention-restart-preview-0001")
	if err != nil {
		t.Fatal(err)
	}
	if record.Preview.PreviewSHA256 != selected.PreviewSHA256 || record.Preview.NormalizedEvents.PreviewSHA256 != selected.NormalizedEvents.PreviewSHA256 {
		t.Fatalf("restart did not reuse reviewed backend evidence: %#v", record.Preview)
	}
}
