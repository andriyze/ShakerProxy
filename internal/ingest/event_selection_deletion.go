package ingest

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/querylang"
)

const EventSelectionDeletionSchema = 1

var (
	ErrEventSelectionDeletionPreviewExpired = errors.New("event selection deletion preview has expired")
	ErrEventSelectionDeletionPreviewStale   = errors.New("event selection deletion preview is stale")
	ErrEventSelectionDeletionConflict       = errors.New("event selection deletion already used different preview evidence")
	ErrEventSelectionTombstoneMissing       = errors.New("event selection database tombstone is missing")
)

type EventSelectionDatabaseFootprint struct {
	EventRows             int64 `json:"event_rows"`
	ExclusiveIdentityRows int64 `json:"exclusive_identity_rows"`
	EventLogicalBytes     int64 `json:"event_logical_bytes"`
	IdentityLogicalBytes  int64 `json:"identity_logical_bytes"`
	MaxIngestSequence     int64 `json:"max_ingest_sequence"`
	TombstonePresent      bool  `json:"tombstone_present"`
}

type EventSelectionDeletionPreview struct {
	Schema                                  int                             `json:"schema"`
	Actor                                   string                          `json:"actor"`
	Selection                               EventSelection                  `json:"selection"`
	SelectionSHA256                         string                          `json:"selection_sha256"`
	QuerySnapshot                           EventQuerySnapshot              `json:"query_snapshot"`
	Database                                EventSelectionDatabaseFootprint `json:"database"`
	LogicalBytesReclaimableAfterMaintenance int64                           `json:"logical_bytes_reclaimable_after_maintenance"`
	DatabaseReclaimMode                     string                          `json:"database_reclaim_mode"`
	GeneratedAt                             time.Time                       `json:"generated_at"`
	ExpiresAt                               time.Time                       `json:"expires_at"`
	PreviewSHA256                           string                          `json:"preview_sha256"`
}

type EventSelectionDeletionReceipt struct {
	Schema                      int       `json:"schema"`
	OperationID                 string    `json:"operation_id"`
	PreviewSHA256               string    `json:"preview_sha256"`
	DeletedEventRows            int64     `json:"deleted_event_rows"`
	DeletedIdentityRows         int64     `json:"deleted_identity_rows"`
	DeletedEventLogicalBytes    int64     `json:"deleted_event_logical_bytes"`
	DeletedIdentityLogicalBytes int64     `json:"deleted_identity_logical_bytes"`
	DatabaseReclaimMode         string    `json:"database_reclaim_mode"`
	VerifiedAbsent              bool      `json:"verified_absent"`
	CompletedAt                 time.Time `json:"completed_at"`
	Replayed                    bool      `json:"replayed"`
}

func (f EventSelectionDatabaseFootprint) Validate() error {
	if f.EventRows < 0 || f.ExclusiveIdentityRows < 0 || f.ExclusiveIdentityRows > f.EventRows || f.EventLogicalBytes < 0 || f.IdentityLogicalBytes < 0 || f.MaxIngestSequence < 0 {
		return errors.New("event selection database footprint is invalid")
	}
	if f.EventRows == 0 && (f.EventLogicalBytes != 0 || f.ExclusiveIdentityRows != 0 || f.IdentityLogicalBytes != 0 || f.MaxIngestSequence != 0) {
		return errors.New("empty event selection footprint contains row evidence")
	}
	if f.EventRows > 0 && (f.EventLogicalBytes == 0 || f.MaxIngestSequence == 0) || f.ExclusiveIdentityRows > 0 && f.IdentityLogicalBytes == 0 {
		return errors.New("event selection footprint omits byte or sequence evidence")
	}
	return nil
}

func (p EventSelectionDeletionPreview) Validate() error {
	selectionSHA, err := p.Selection.SHA256()
	if p.Schema != EventSelectionDeletionSchema || !validSnapshotActor(p.Actor) || err != nil || p.SelectionSHA256 != selectionSHA || ValidateEventQuerySnapshot(p.QuerySnapshot) != nil || p.QuerySnapshot.CountRelation != "eq" || validateEventSelectionSnapshotScope(p.Selection, p.QuerySnapshot) != nil || p.Database.Validate() != nil || p.Database.EventRows != p.QuerySnapshot.MatchedCount || p.LogicalBytesReclaimableAfterMaintenance != p.Database.EventLogicalBytes+p.Database.IdentityLogicalBytes || p.DatabaseReclaimMode != DatabaseReclaimDeferred || p.GeneratedAt.IsZero() || !p.ExpiresAt.Equal(p.QuerySnapshot.ExpiresAt) || !p.GeneratedAt.Before(p.ExpiresAt) || len(p.PreviewSHA256) != sha256.Size*2 {
		return errors.New("event selection deletion preview is invalid")
	}
	if _, err := hex.DecodeString(p.PreviewSHA256); err != nil {
		return errors.New("event selection deletion preview digest is invalid")
	}
	expected, err := hashEventSelectionDeletionPreview(p)
	if err != nil || expected != p.PreviewSHA256 {
		return errors.New("event selection deletion preview digest does not match")
	}
	return nil
}

func (r EventSelectionDeletionReceipt) Validate() error {
	if r.Schema != EventSelectionDeletionSchema || !opaqueIDPattern.MatchString(r.OperationID) || !querySnapshotSHA256.MatchString(r.PreviewSHA256) || r.DeletedEventRows < 0 || r.DeletedIdentityRows < 0 || r.DeletedIdentityRows > r.DeletedEventRows || r.DeletedEventLogicalBytes < 0 || r.DeletedIdentityLogicalBytes < 0 || r.DatabaseReclaimMode != DatabaseReclaimDeferred || !r.VerifiedAbsent || r.CompletedAt.IsZero() {
		return errors.New("event selection deletion receipt is invalid")
	}
	return nil
}

func (s PostgresSink) PreviewEventSelectionDeletion(ctx context.Context, actor string, selection EventSelection, snapshot EventQuerySnapshot) (EventSelectionDeletionPreview, error) {
	if s.DB == nil || !validSnapshotActor(actor) || selection.Validate() != nil || ValidateEventQuerySnapshot(snapshot) != nil || snapshot.CountRelation != "eq" || validateEventSelectionSnapshotScope(selection, snapshot) != nil {
		return EventSelectionDeletionPreview{}, errors.New("event selection deletion preview request is invalid")
	}
	resolved, err := s.ResolveEventQuerySnapshot(ctx, actor, snapshot.ID)
	if err != nil || !reflect.DeepEqual(resolved.Snapshot, snapshot) {
		return EventSelectionDeletionPreview{}, ErrEventSelectionDeletionPreviewStale
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return EventSelectionDeletionPreview{}, fmt.Errorf("begin event selection deletion preview: %w", err)
	}
	defer tx.Rollback()
	var databaseNow time.Time
	if err := tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&databaseNow); err != nil {
		return EventSelectionDeletionPreview{}, fmt.Errorf("read event selection deletion preview time: %w", err)
	}
	databaseNow = databaseNow.UTC().Truncate(time.Microsecond)
	if !databaseNow.Before(snapshot.ExpiresAt) {
		return EventSelectionDeletionPreview{}, ErrEventSelectionDeletionPreviewExpired
	}
	if err := createEventSelectionTargetTable(ctx, tx, resolved.Query, snapshot.DatasetWatermark.IngestSequence, "event_selection_preview_targets"); err != nil {
		return EventSelectionDeletionPreview{}, err
	}
	if changed, err := eventSelectionRowsAfterWatermark(ctx, tx, resolved.Query, snapshot.DatasetWatermark.IngestSequence); err != nil {
		return EventSelectionDeletionPreview{}, err
	} else if changed > 0 {
		return EventSelectionDeletionPreview{}, ErrEventSelectionDeletionPreviewStale
	}
	selectionSHA, _ := selection.SHA256()
	footprint, err := readEventSelectionFootprintTx(ctx, tx, "event_selection_preview_targets", selectionSHA, snapshot)
	if err != nil {
		return EventSelectionDeletionPreview{}, err
	}
	if footprint.EventRows != snapshot.MatchedCount {
		return EventSelectionDeletionPreview{}, ErrEventSelectionDeletionPreviewStale
	}
	preview := EventSelectionDeletionPreview{
		Schema: EventSelectionDeletionSchema, Actor: actor, Selection: selection, SelectionSHA256: selectionSHA,
		QuerySnapshot: snapshot, Database: footprint, LogicalBytesReclaimableAfterMaintenance: footprint.EventLogicalBytes + footprint.IdentityLogicalBytes,
		DatabaseReclaimMode: DatabaseReclaimDeferred, GeneratedAt: databaseNow, ExpiresAt: snapshot.ExpiresAt,
	}
	preview.PreviewSHA256, err = hashEventSelectionDeletionPreview(preview)
	if err != nil || preview.Validate() != nil {
		return EventSelectionDeletionPreview{}, errors.New("event selection deletion preview could not be bound")
	}
	if err := tx.Commit(); err != nil {
		return EventSelectionDeletionPreview{}, fmt.Errorf("commit event selection deletion preview: %w", err)
	}
	return preview, nil
}

func (s PostgresSink) PrepareEventSelectionDeletion(ctx context.Context, preview EventSelectionDeletionPreview, tombstone EventSelectionTombstone) (EventSelectionTombstone, bool, error) {
	if s.DB == nil || preview.Validate() != nil || tombstone.Validate() != nil || tombstone.Actor != preview.Actor || tombstone.SelectionSHA256 != preview.SelectionSHA256 || !reflect.DeepEqual(tombstone.Selection, preview.Selection) || tombstone.QuerySnapshotID != preview.QuerySnapshot.ID || tombstone.QuerySnapshotSHA256 != preview.QuerySnapshot.SnapshotSHA256 {
		return EventSelectionTombstone{}, false, errors.New("event selection deletion preparation request is invalid")
	}
	tombstone.CreatedAt = tombstone.CreatedAt.UTC().Truncate(time.Microsecond)
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return EventSelectionTombstone{}, false, fmt.Errorf("begin event selection deletion preparation: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended('normalized-event-selection-tombstones', 7))"); err != nil {
		return EventSelectionTombstone{}, false, fmt.Errorf("lock event selection deletion population: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "LOCK TABLE normalized_event_selection_tombstones IN SHARE ROW EXCLUSIVE MODE"); err != nil {
		return EventSelectionTombstone{}, false, fmt.Errorf("lock event selection ingestion boundary: %w", err)
	}
	storedReceipt, completed, err := readEventSelectionDeletionReceipt(ctx, tx, tombstone.OperationID)
	if err != nil {
		return EventSelectionTombstone{}, false, err
	}
	stored, exists, err := readDatabaseEventSelectionTombstone(ctx, tx, tombstone.OperationID)
	if err != nil {
		return EventSelectionTombstone{}, false, err
	}
	preparedPreviewSHA, prepared, err := readEventSelectionDeletionPreparation(ctx, tx, tombstone.OperationID)
	if err != nil {
		return EventSelectionTombstone{}, false, err
	}
	if completed {
		if storedReceipt.PreviewSHA256 != preview.PreviewSHA256 || !exists || !reflect.DeepEqual(stored, tombstone) || !prepared || preparedPreviewSHA != preview.PreviewSHA256 {
			return EventSelectionTombstone{}, false, ErrEventSelectionDeletionConflict
		}
		if err := tx.Commit(); err != nil {
			return EventSelectionTombstone{}, false, err
		}
		return stored, true, nil
	}
	if exists && !reflect.DeepEqual(stored, tombstone) {
		return EventSelectionTombstone{}, false, ErrEventSelectionConflict
	}
	if prepared {
		if !exists || preparedPreviewSHA != preview.PreviewSHA256 {
			return EventSelectionTombstone{}, false, ErrEventSelectionDeletionConflict
		}
		if err := tx.Commit(); err != nil {
			return EventSelectionTombstone{}, false, err
		}
		return stored, true, nil
	}
	resolved, err := s.ResolveEventQuerySnapshot(ctx, preview.Actor, preview.QuerySnapshot.ID)
	if err != nil || !reflect.DeepEqual(resolved.Snapshot, preview.QuerySnapshot) {
		return EventSelectionTombstone{}, false, ErrEventSelectionDeletionPreviewStale
	}
	var databaseNow time.Time
	if err := tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&databaseNow); err != nil {
		return EventSelectionTombstone{}, false, err
	}
	if !databaseNow.UTC().Before(preview.ExpiresAt) {
		return EventSelectionTombstone{}, false, ErrEventSelectionDeletionPreviewExpired
	}
	if err := createEventSelectionTargetTable(ctx, tx, resolved.Query, preview.QuerySnapshot.DatasetWatermark.IngestSequence, "event_selection_prepare_targets"); err != nil {
		return EventSelectionTombstone{}, false, err
	}
	if changed, err := eventSelectionRowsAfterWatermark(ctx, tx, resolved.Query, preview.QuerySnapshot.DatasetWatermark.IngestSequence); err != nil {
		return EventSelectionTombstone{}, false, err
	} else if changed > 0 {
		return EventSelectionTombstone{}, false, ErrEventSelectionDeletionPreviewStale
	}
	actual, err := readEventSelectionFootprintTx(ctx, tx, "event_selection_prepare_targets", preview.SelectionSHA256, preview.QuerySnapshot)
	if err != nil {
		return EventSelectionTombstone{}, false, err
	}
	if !sameEventSelectionRows(actual, preview.Database) {
		return EventSelectionTombstone{}, false, ErrEventSelectionDeletionPreviewStale
	}
	if !exists {
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM normalized_event_selection_tombstones").Scan(&count); err != nil {
			return EventSelectionTombstone{}, false, err
		}
		if count >= MaxEventSelectionTombstones {
			return EventSelectionTombstone{}, false, errors.New("event selection tombstone limit reached")
		}
		selectionJSON, _ := json.Marshal(tombstone.Selection)
		if _, err := tx.ExecContext(ctx, `INSERT INTO normalized_event_selection_tombstones(
operation_id,actor_name,device_id,start_at,end_at,selection_sha256,selection_json,
query_snapshot_id,query_snapshot_sha256,deletion_preview_sha256,created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,NULLIF($10,''),$11)`, tombstone.OperationID, tombstone.Actor, tombstone.Selection.DeviceID, tombstone.Selection.StartAt, tombstone.Selection.EndAt, tombstone.SelectionSHA256, selectionJSON, tombstone.QuerySnapshotID, tombstone.QuerySnapshotSHA256, tombstone.DeletionPreviewSHA256, tombstone.CreatedAt); err != nil {
			return EventSelectionTombstone{}, false, fmt.Errorf("persist preview-bound event selection tombstone: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO normalized_event_selection_deletion_preparations(operation_id,preview_sha256,prepared_at)
VALUES ($1,$2,$3)`, tombstone.OperationID, preview.PreviewSHA256, tombstone.CreatedAt); err != nil {
		return EventSelectionTombstone{}, false, fmt.Errorf("persist event selection deletion preparation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return EventSelectionTombstone{}, false, fmt.Errorf("commit event selection deletion preparation: %w", err)
	}
	return tombstone, false, nil
}

func (s PostgresSink) DeleteEventSelection(ctx context.Context, preview EventSelectionDeletionPreview, operationID string) (EventSelectionDeletionReceipt, error) {
	if s.DB == nil || preview.Validate() != nil || !opaqueIDPattern.MatchString(operationID) {
		return EventSelectionDeletionReceipt{}, errors.New("event selection deletion request is invalid")
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return EventSelectionDeletionReceipt{}, fmt.Errorf("begin event selection deletion: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "LOCK TABLE normalized_event_selection_tombstones IN SHARE ROW EXCLUSIVE MODE"); err != nil {
		return EventSelectionDeletionReceipt{}, fmt.Errorf("lock event selection deletion boundary: %w", err)
	}
	receipt, exists, err := readEventSelectionDeletionReceipt(ctx, tx, operationID)
	if err != nil {
		return EventSelectionDeletionReceipt{}, err
	}
	if exists {
		if receipt.PreviewSHA256 != preview.PreviewSHA256 {
			return EventSelectionDeletionReceipt{}, ErrEventSelectionDeletionConflict
		}
		receipt.Replayed = true
		if err := tx.Commit(); err != nil {
			return EventSelectionDeletionReceipt{}, err
		}
		return receipt, nil
	}
	preparedPreviewSHA, prepared, err := readEventSelectionDeletionPreparation(ctx, tx, operationID)
	if err != nil {
		return EventSelectionDeletionReceipt{}, err
	}
	if !prepared {
		return EventSelectionDeletionReceipt{}, ErrEventSelectionTombstoneMissing
	}
	if preparedPreviewSHA != preview.PreviewSHA256 {
		return EventSelectionDeletionReceipt{}, ErrEventSelectionDeletionConflict
	}
	resolved, err := s.ResolveEventQuerySnapshot(ctx, preview.Actor, preview.QuerySnapshot.ID)
	if err != nil || !reflect.DeepEqual(resolved.Snapshot, preview.QuerySnapshot) {
		return EventSelectionDeletionReceipt{}, ErrEventSelectionDeletionPreviewStale
	}
	var databaseNow time.Time
	if err := tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&databaseNow); err != nil {
		return EventSelectionDeletionReceipt{}, err
	}
	databaseNow = databaseNow.UTC().Truncate(time.Microsecond)
	if !databaseNow.Before(preview.ExpiresAt) {
		return EventSelectionDeletionReceipt{}, ErrEventSelectionDeletionPreviewExpired
	}
	tombstone, tombstoned, err := readDatabaseEventSelectionTombstone(ctx, tx, operationID)
	if err != nil {
		return EventSelectionDeletionReceipt{}, err
	}
	if !tombstoned {
		return EventSelectionDeletionReceipt{}, ErrEventSelectionTombstoneMissing
	}
	if tombstone.Actor != preview.Actor || tombstone.SelectionSHA256 != preview.SelectionSHA256 || tombstone.QuerySnapshotID != preview.QuerySnapshot.ID || tombstone.QuerySnapshotSHA256 != preview.QuerySnapshot.SnapshotSHA256 || !reflect.DeepEqual(tombstone.Selection, preview.Selection) {
		return EventSelectionDeletionReceipt{}, ErrEventSelectionDeletionConflict
	}
	if err := createEventSelectionTargetTable(ctx, tx, resolved.Query, preview.QuerySnapshot.DatasetWatermark.IngestSequence, "event_selection_delete_targets"); err != nil {
		return EventSelectionDeletionReceipt{}, err
	}
	if changed, err := eventSelectionRowsAfterWatermark(ctx, tx, resolved.Query, preview.QuerySnapshot.DatasetWatermark.IngestSequence); err != nil {
		return EventSelectionDeletionReceipt{}, err
	} else if changed > 0 {
		return EventSelectionDeletionReceipt{}, ErrEventSelectionDeletionPreviewStale
	}
	actual, err := readEventSelectionFootprintTx(ctx, tx, "event_selection_delete_targets", preview.SelectionSHA256, preview.QuerySnapshot)
	if err != nil {
		return EventSelectionDeletionReceipt{}, err
	}
	if !sameEventSelectionRows(actual, preview.Database) {
		return EventSelectionDeletionReceipt{}, ErrEventSelectionDeletionPreviewStale
	}
	eventResult, err := tx.ExecContext(ctx, `DELETE FROM normalized_events event_row
USING event_selection_delete_targets target
WHERE event_row.occurred_at=target.occurred_at AND event_row.record_id=target.record_id`)
	if err != nil {
		return EventSelectionDeletionReceipt{}, fmt.Errorf("delete selected event rows: %w", err)
	}
	deletedEvents, err := eventResult.RowsAffected()
	if err != nil || deletedEvents != preview.Database.EventRows {
		return EventSelectionDeletionReceipt{}, errors.New("selected event deletion row count did not match preview")
	}
	identityResult, err := tx.ExecContext(ctx, `DELETE FROM normalized_event_identities identity_row
WHERE EXISTS (SELECT 1 FROM event_selection_delete_targets target WHERE target.record_id=identity_row.record_id)
  AND NOT EXISTS (SELECT 1 FROM normalized_events remaining WHERE remaining.record_id=identity_row.record_id)`)
	if err != nil {
		return EventSelectionDeletionReceipt{}, fmt.Errorf("delete selected event identity rows: %w", err)
	}
	deletedIdentities, err := identityResult.RowsAffected()
	if err != nil || deletedIdentities != preview.Database.ExclusiveIdentityRows {
		return EventSelectionDeletionReceipt{}, errors.New("selected event identity deletion count did not match preview")
	}
	var remaining, orphaned int64
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM normalized_events event_row
JOIN event_selection_delete_targets target ON target.occurred_at=event_row.occurred_at AND target.record_id=event_row.record_id`).Scan(&remaining); err != nil {
		return EventSelectionDeletionReceipt{}, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM normalized_event_identities identity_row
WHERE EXISTS (SELECT 1 FROM event_selection_delete_targets target WHERE target.record_id=identity_row.record_id)
  AND NOT EXISTS (SELECT 1 FROM normalized_events remaining WHERE remaining.record_id=identity_row.record_id)`).Scan(&orphaned); err != nil {
		return EventSelectionDeletionReceipt{}, err
	}
	if remaining != 0 || orphaned != 0 {
		return EventSelectionDeletionReceipt{}, errors.New("event selection deletion verification failed")
	}
	if err := tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&databaseNow); err != nil {
		return EventSelectionDeletionReceipt{}, err
	}
	receipt = EventSelectionDeletionReceipt{
		Schema: EventSelectionDeletionSchema, OperationID: operationID, PreviewSHA256: preview.PreviewSHA256,
		DeletedEventRows: preview.Database.EventRows, DeletedIdentityRows: preview.Database.ExclusiveIdentityRows,
		DeletedEventLogicalBytes: preview.Database.EventLogicalBytes, DeletedIdentityLogicalBytes: preview.Database.IdentityLogicalBytes,
		DatabaseReclaimMode: DatabaseReclaimDeferred, VerifiedAbsent: true, CompletedAt: databaseNow.UTC().Truncate(time.Microsecond),
	}
	if err := receipt.Validate(); err != nil {
		return EventSelectionDeletionReceipt{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO normalized_event_selection_deletion_receipts(
operation_id,preview_sha256,deleted_event_rows,deleted_identity_rows,deleted_event_logical_bytes,
deleted_identity_logical_bytes,completed_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`, receipt.OperationID, receipt.PreviewSHA256, receipt.DeletedEventRows, receipt.DeletedIdentityRows, receipt.DeletedEventLogicalBytes, receipt.DeletedIdentityLogicalBytes, receipt.CompletedAt); err != nil {
		return EventSelectionDeletionReceipt{}, fmt.Errorf("persist event selection deletion receipt: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return EventSelectionDeletionReceipt{}, fmt.Errorf("commit event selection deletion: %w", err)
	}
	return receipt, nil
}

func createEventSelectionTargetTable(ctx context.Context, tx *sql.Tx, query RecentEventQuery, watermark int64, table string) error {
	if table != "event_selection_preview_targets" && table != "event_selection_prepare_targets" && table != "event_selection_delete_targets" {
		return errors.New("event selection target table is invalid")
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`CREATE TEMP TABLE %s (
occurred_at timestamptz NOT NULL,
record_id text NOT NULL CHECK (record_id ~ '^[a-f0-9]{64}$'),
PRIMARY KEY (occurred_at,record_id)
) ON COMMIT DROP`, table)); err != nil {
		return fmt.Errorf("create event selection target set: %w", err)
	}
	clauses, args, err := buildEventWhere(query, true)
	if err != nil {
		return err
	}
	args = append(args, watermark)
	clauses = append(clauses, fmt.Sprintf("ingest_sequence <= $%d", len(args)))
	statement := fmt.Sprintf("INSERT INTO %s(occurred_at,record_id) SELECT occurred_at,record_id FROM normalized_events WHERE %s", table, strings.Join(clauses, " AND "))
	if _, err := tx.ExecContext(ctx, statement, args...); err != nil {
		return fmt.Errorf("freeze event selection target set: %w", err)
	}
	return nil
}

func eventSelectionRowsAfterWatermark(ctx context.Context, tx *sql.Tx, query RecentEventQuery, watermark int64) (int64, error) {
	clauses, args, err := buildEventWhere(query, true)
	if err != nil {
		return 0, err
	}
	args = append(args, watermark)
	clauses = append(clauses, fmt.Sprintf("ingest_sequence > $%d", len(args)))
	var count int64
	statement := fmt.Sprintf("SELECT count(*) FROM normalized_events WHERE %s", strings.Join(clauses, " AND "))
	if err := tx.QueryRowContext(ctx, statement, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("check event selection rows after snapshot watermark: %w", err)
	}
	return count, nil
}

func readEventSelectionFootprintTx(ctx context.Context, tx *sql.Tx, table, selectionSHA string, snapshot EventQuerySnapshot) (EventSelectionDatabaseFootprint, error) {
	if table != "event_selection_preview_targets" && table != "event_selection_prepare_targets" && table != "event_selection_delete_targets" {
		return EventSelectionDatabaseFootprint{}, errors.New("event selection target table is invalid")
	}
	var footprint EventSelectionDatabaseFootprint
	statement := fmt.Sprintf(`SELECT count(*),COALESCE(sum(pg_column_size(event_row)),0),COALESCE(max(event_row.ingest_sequence),0)
FROM normalized_events event_row JOIN %s target
ON target.occurred_at=event_row.occurred_at AND target.record_id=event_row.record_id`, table)
	if err := tx.QueryRowContext(ctx, statement).Scan(&footprint.EventRows, &footprint.EventLogicalBytes, &footprint.MaxIngestSequence); err != nil {
		return EventSelectionDatabaseFootprint{}, fmt.Errorf("read event selection row footprint: %w", err)
	}
	statement = fmt.Sprintf(`SELECT count(*),COALESCE(sum(pg_column_size(identity_row)),0)
FROM normalized_event_identities identity_row
WHERE EXISTS (SELECT 1 FROM %s target WHERE target.record_id=identity_row.record_id)
  AND NOT EXISTS (
    SELECT 1 FROM normalized_events remaining
    WHERE remaining.record_id=identity_row.record_id
      AND NOT EXISTS (SELECT 1 FROM %s target WHERE target.occurred_at=remaining.occurred_at AND target.record_id=remaining.record_id)
  )`, table, table)
	if err := tx.QueryRowContext(ctx, statement).Scan(&footprint.ExclusiveIdentityRows, &footprint.IdentityLogicalBytes); err != nil {
		return EventSelectionDatabaseFootprint{}, fmt.Errorf("read event selection identity footprint: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (
SELECT 1 FROM normalized_event_selection_tombstones
WHERE selection_sha256=$1 AND query_snapshot_id=$2 AND query_snapshot_sha256=$3)`, selectionSHA, snapshot.ID, snapshot.SnapshotSHA256).Scan(&footprint.TombstonePresent); err != nil {
		return EventSelectionDatabaseFootprint{}, fmt.Errorf("read event selection tombstone footprint: %w", err)
	}
	if err := footprint.Validate(); err != nil {
		return EventSelectionDatabaseFootprint{}, err
	}
	return footprint, nil
}

func readEventSelectionDeletionReceipt(ctx context.Context, tx *sql.Tx, operationID string) (EventSelectionDeletionReceipt, bool, error) {
	receipt := EventSelectionDeletionReceipt{Schema: EventSelectionDeletionSchema, DatabaseReclaimMode: DatabaseReclaimDeferred, VerifiedAbsent: true}
	err := tx.QueryRowContext(ctx, `SELECT operation_id,preview_sha256,deleted_event_rows,deleted_identity_rows,
deleted_event_logical_bytes,deleted_identity_logical_bytes,completed_at
FROM normalized_event_selection_deletion_receipts WHERE operation_id=$1`, operationID).Scan(&receipt.OperationID, &receipt.PreviewSHA256, &receipt.DeletedEventRows, &receipt.DeletedIdentityRows, &receipt.DeletedEventLogicalBytes, &receipt.DeletedIdentityLogicalBytes, &receipt.CompletedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return EventSelectionDeletionReceipt{}, false, nil
	}
	if err != nil {
		return EventSelectionDeletionReceipt{}, false, fmt.Errorf("read event selection deletion receipt: %w", err)
	}
	receipt.CompletedAt = receipt.CompletedAt.UTC().Truncate(time.Microsecond)
	if err := receipt.Validate(); err != nil {
		return EventSelectionDeletionReceipt{}, false, err
	}
	return receipt, true, nil
}

func readEventSelectionDeletionPreparation(ctx context.Context, tx *sql.Tx, operationID string) (string, bool, error) {
	var previewSHA string
	err := tx.QueryRowContext(ctx, `SELECT preview_sha256
FROM normalized_event_selection_deletion_preparations WHERE operation_id=$1`, operationID).Scan(&previewSHA)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read event selection deletion preparation: %w", err)
	}
	if !querySnapshotSHA256.MatchString(previewSHA) {
		return "", false, errors.New("stored event selection deletion preparation is invalid")
	}
	return previewSHA, true, nil
}

func validateEventSelectionSnapshotScope(selection EventSelection, snapshot EventQuerySnapshot) error {
	filter, err := querylang.Parse(fmt.Sprintf("device.id:%s AND time>=%s AND time<%s", selection.DeviceID, selection.StartAt.Format(time.RFC3339Nano), selection.EndAt.Format(time.RFC3339Nano)))
	if err != nil || snapshot.CanonicalQuery != filter.Canonical {
		return errors.New("event query snapshot does not match the event selection")
	}
	return nil
}

func hashEventSelectionDeletionPreview(preview EventSelectionDeletionPreview) (string, error) {
	preview.PreviewSHA256 = ""
	encoded, err := json.Marshal(preview)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func sameEventSelectionRows(left, right EventSelectionDatabaseFootprint) bool {
	return left.EventRows == right.EventRows && left.ExclusiveIdentityRows == right.ExclusiveIdentityRows && left.EventLogicalBytes == right.EventLogicalBytes && left.IdentityLogicalBytes == right.IdentityLogicalBytes && left.MaxIngestSequence == right.MaxIngestSequence
}
