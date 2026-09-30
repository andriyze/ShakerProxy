package ingest

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type eventSelectionDeletionDatabaseStub struct {
	preview   EventSelectionDeletionPreview
	tombstone EventSelectionTombstone
	receipt   EventSelectionDeletionReceipt
}

func (d *eventSelectionDeletionDatabaseStub) PreviewEventSelectionDeletion(_ context.Context, actor string, selection EventSelection, snapshot EventQuerySnapshot) (EventSelectionDeletionPreview, error) {
	preview := d.preview
	preview.Actor = actor
	preview.Selection = selection
	preview.SelectionSHA256, _ = selection.SHA256()
	preview.QuerySnapshot = snapshot
	preview.ExpiresAt = snapshot.ExpiresAt
	preview.PreviewSHA256, _ = hashEventSelectionDeletionPreview(preview)
	return preview, preview.Validate()
}

func (d *eventSelectionDeletionDatabaseStub) PrepareEventSelectionDeletion(_ context.Context, preview EventSelectionDeletionPreview, tombstone EventSelectionTombstone) (EventSelectionTombstone, bool, error) {
	if preview.Validate() != nil || tombstone.Validate() != nil {
		return EventSelectionTombstone{}, false, errors.New("invalid preparation")
	}
	if d.tombstone.OperationID != "" {
		if !reflect.DeepEqual(d.tombstone, tombstone) {
			return EventSelectionTombstone{}, false, ErrEventSelectionDeletionConflict
		}
		return d.tombstone, true, nil
	}
	d.tombstone = tombstone
	return tombstone, false, nil
}

func (d *eventSelectionDeletionDatabaseStub) DeleteEventSelection(_ context.Context, preview EventSelectionDeletionPreview, operationID string) (EventSelectionDeletionReceipt, error) {
	if d.tombstone.OperationID != operationID || d.tombstone.DeletionPreviewSHA256 == "" {
		return EventSelectionDeletionReceipt{}, ErrEventSelectionTombstoneMissing
	}
	if d.receipt.OperationID != "" {
		if d.receipt.PreviewSHA256 != preview.PreviewSHA256 {
			return EventSelectionDeletionReceipt{}, ErrEventSelectionDeletionConflict
		}
		replayed := d.receipt
		replayed.Replayed = true
		return replayed, nil
	}
	d.receipt = EventSelectionDeletionReceipt{
		Schema: EventSelectionDeletionSchema, OperationID: operationID, PreviewSHA256: preview.PreviewSHA256,
		DeletedEventRows: preview.Database.EventRows, DeletedIdentityRows: preview.Database.ExclusiveIdentityRows,
		DeletedEventLogicalBytes: preview.Database.EventLogicalBytes, DeletedIdentityLogicalBytes: preview.Database.IdentityLogicalBytes,
		DatabaseReclaimMode: DatabaseReclaimDeferred, VerifiedAbsent: true, CompletedAt: preview.GeneratedAt.Add(time.Minute),
	}
	return d.receipt, d.receipt.Validate()
}

func eventSelectionDeletionServiceFixture(t *testing.T) (EventSelectionDeletionService, EventSelectionDeletionPreviewRequest) {
	t.Helper()
	start := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	selection, err := CanonicalEventSelection(selectionDeviceID, start, end, []EventSelectionAddress{{Address: "10.77.0.111", StartAt: start, EndAt: end}})
	if err != nil {
		t.Fatal(err)
	}
	canonical := "device.id:" + selectionDeviceID + " AND time>=" + start.Format(time.RFC3339Nano) + " AND time<" + end.Format(time.RFC3339Nano)
	snapshot := EventQuerySnapshot{
		Schema: 1, ID: "qsnap-0123456789abcdef0123456789abcdef", CanonicalQuery: canonical, Sort: DefaultEventQuerySort(),
		MatchedCount: 1, CountRelation: "eq", CreatedAt: start.Add(2 * time.Hour), ExpiresAt: start.Add(12 * time.Minute),
		DatasetWatermark: EventDatasetWatermark{IngestSequence: 9, ReceivedAt: start.Add(2 * time.Hour), RecordID: strings.Repeat("a", 64)},
		SnapshotSHA256:   strings.Repeat("b", 64), PolicyVersion: QuerySnapshotPolicyVersion,
	}
	// The snapshot interval must be positive; its clock is independent of the selected historical range.
	snapshot.CreatedAt = time.Date(2026, 9, 1, 15, 0, 0, 0, time.UTC)
	snapshot.ExpiresAt = snapshot.CreatedAt.Add(10 * time.Minute)
	database := &eventSelectionDeletionDatabaseStub{preview: EventSelectionDeletionPreview{
		Schema:                                  EventSelectionDeletionSchema,
		Database:                                EventSelectionDatabaseFootprint{EventRows: 1, ExclusiveIdentityRows: 1, EventLogicalBytes: 128, IdentityLogicalBytes: 64, MaxIngestSequence: 9},
		LogicalBytesReclaimableAfterMaintenance: 192, DatabaseReclaimMode: DatabaseReclaimDeferred,
		GeneratedAt: snapshot.CreatedAt.Add(time.Minute),
	}}
	spool := &Spool{Root: t.TempDir(), MaxBytes: 8 << 20, ReserveBytes: 1}
	if _, err := spool.Accept([]byte(selectionEventJSON("event-selection-service-0001", selectionDeviceID, "10.77.0.111", start.Add(30*time.Minute)))); err != nil {
		t.Fatal(err)
	}
	return EventSelectionDeletionService{Spool: spool, Database: database}, EventSelectionDeletionPreviewRequest{Actor: "admin", Selection: selection, QuerySnapshot: snapshot}
}

func TestEventSelectionDeletionServiceBindsSpoolAndDatabaseAndReplays(t *testing.T) {
	service, request := eventSelectionDeletionServiceFixture(t)
	preview, err := service.Preview(t.Context(), request)
	if err != nil || preview.Spool.PendingRecords != 1 || preview.Database.Database.EventRows != 1 || preview.EstimatedImmediatelyReclaimableBytes == 0 {
		t.Fatalf("combined selection preview is inaccurate: %#v err=%v", preview, err)
	}
	deletion := EventSelectionDeletionRequest{Schema: 1, Preview: preview, OperationID: "event-selection-coordinator-0001", Actor: "admin"}
	outcome, err := service.Delete(t.Context(), deletion)
	if err != nil || outcome.Replayed || outcome.Spool.PurgedRecords != 1 || outcome.Database.DeletedEventRows != 1 || outcome.Tombstone.DeletionPreviewSHA256 != preview.PreviewSHA256 {
		t.Fatalf("selection deletion was not coordinated: %#v err=%v", outcome, err)
	}
	replayed, err := service.Delete(t.Context(), deletion)
	if err != nil || !replayed.Replayed || !replayed.Database.Replayed || !replayed.Spool.Existing || replayed.CompletedAt != outcome.CompletedAt {
		t.Fatalf("selection deletion replay was not stable: %#v err=%v", replayed, err)
	}
}

func TestEventSelectionDeletionServiceRejectsChangedCombinedPreview(t *testing.T) {
	service, request := eventSelectionDeletionServiceFixture(t)
	preview, err := service.Preview(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	deletion := EventSelectionDeletionRequest{Schema: 1, Preview: preview, OperationID: "event-selection-coordinator-0002", Actor: "admin"}
	if _, err := service.Delete(t.Context(), deletion); err != nil {
		t.Fatal(err)
	}
	changed := preview
	changed.Spool.PendingRecords = 0
	changed.Spool.PendingFileBytes = 0
	changed.EstimatedImmediatelyReclaimableBytes = 0
	changed.PreviewSHA256, _ = eventSelectionDeletionBundleHash(changed)
	if err := changed.Validate(); err != nil {
		t.Fatal(err)
	}
	deletion.Preview = changed
	if _, err := service.Delete(t.Context(), deletion); !errors.Is(err, ErrEventSelectionDeletionConflict) {
		t.Fatalf("operation accepted changed combined evidence: %v", err)
	}
}
