package ingest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type captureEventFootprintReaderFunc func(context.Context, string) (CaptureEventDatabaseFootprint, error)

func (f captureEventFootprintReaderFunc) ReadCaptureEventFootprint(ctx context.Context, captureSessionID string) (CaptureEventDatabaseFootprint, error) {
	return f(ctx, captureSessionID)
}

func TestCaptureEventDeletionPreviewBindsExactObservedFootprints(t *testing.T) {
	now := time.Date(2026, 9, 1, 13, 0, 0, 0, time.UTC)
	target := "capture-0123456789abcdef0123456789abcdef"
	spool := &Spool{Root: filepath.Join(t.TempDir(), "spool"), MaxBytes: 8 << 20, ReserveBytes: 1, Now: func() time.Time { return now }}
	var expectedSpoolBytes int64
	for index, event := range []string{
		validEvent,
		strings.Replace(validEvent, "zeek-event-00000001", "zeek-event-00000002", 1),
		strings.Replace(strings.Replace(validEvent, "zeek-event-00000001", "zeek-event-00000003", 1), target, "capture-fedcba9876543210fedcba9876543210", 1),
	} {
		accepted, err := spool.Accept([]byte(event))
		if err != nil {
			t.Fatal(err)
		}
		if index < 2 {
			info, err := os.Stat(filepath.Join(spool.Root, "pending", accepted.RecordID+".json"))
			if err != nil {
				t.Fatal(err)
			}
			expectedSpoolBytes += info.Size()
		}
	}
	database := CaptureEventDatabaseFootprint{EventRows: 7, ExclusiveIdentityRows: 6, EventLogicalBytes: 4096, IdentityLogicalBytes: 512, MaxIngestSequence: 99}
	planner := CaptureEventDeletionPlanner{Spool: spool, Database: captureEventFootprintReaderFunc(func(_ context.Context, captureSessionID string) (CaptureEventDatabaseFootprint, error) {
		if captureSessionID != target {
			t.Fatalf("unexpected capture scope %q", captureSessionID)
		}
		return database, nil
	}), Now: func() time.Time { return now }}
	preview, err := planner.Preview(t.Context(), target)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Spool.PendingRecords != 2 || preview.Spool.PendingFileBytes != expectedSpoolBytes || preview.Database != database || preview.EstimatedImmediatelyReclaimableBytes != preview.Spool.PendingFileBytes || preview.LogicalBytesReclaimableAfterMaintenance != 4608 || preview.DatabaseReclaimMode != DatabaseReclaimDeferred || !preview.GeneratedAt.Equal(now) || !preview.ExpiresAt.Equal(now.Add(DefaultEventDeletionPreviewTTL)) || len(preview.PreviewSHA256) != 64 {
		t.Fatalf("unexpected exact event deletion preview: %#v", preview)
	}
	tampered := preview
	tampered.Database.EventRows++
	if err := tampered.Validate(); err == nil {
		t.Fatal("tampered event deletion preview retained a valid digest")
	}
}

func TestCaptureEventFootprintValidationRejectsImpossibleEvidence(t *testing.T) {
	invalidDatabase := []CaptureEventDatabaseFootprint{
		{EventRows: 1, EventLogicalBytes: 1},
		{EventRows: 1, EventLogicalBytes: 1, MaxIngestSequence: 1, ExclusiveIdentityRows: 2},
		{EventRows: 1, EventLogicalBytes: 1, MaxIngestSequence: 1, ExclusiveIdentityRows: 1},
		{EventLogicalBytes: 1},
	}
	for _, footprint := range invalidDatabase {
		if err := footprint.Validate(); err == nil {
			t.Fatalf("invalid database footprint was accepted: %#v", footprint)
		}
	}
	for _, footprint := range []CaptureEventSpoolFootprint{{PendingRecords: 1}, {PendingFileBytes: 1}, {PendingRecords: MaxPendingRecords + 1, PendingFileBytes: 1}} {
		if err := footprint.Validate(); err == nil {
			t.Fatalf("invalid spool footprint was accepted: %#v", footprint)
		}
	}
}

func TestCaptureEventDeletionReceiptRequiresVerifiedBoundedEvidence(t *testing.T) {
	receipt := CaptureEventDeletionReceipt{
		Schema: CaptureEventDeletionPreviewSchema, CaptureSessionID: "capture-0123456789abcdef0123456789abcdef",
		OperationID: "capture-delete-operation-0001", PreviewSHA256: strings.Repeat("a", 64),
		DeletedEventRows: 2, DeletedIdentityRows: 1, DeletedEventLogicalBytes: 512, DeletedIdentityLogicalBytes: 64,
		DatabaseReclaimMode: DatabaseReclaimDeferred, VerifiedAbsent: true, CompletedAt: time.Now().UTC(),
	}
	if err := receipt.Validate(); err != nil {
		t.Fatalf("valid deletion receipt was rejected: %v", err)
	}
	receipt.VerifiedAbsent = false
	if err := receipt.Validate(); err == nil {
		t.Fatal("unverified deletion receipt was accepted")
	}
}
