package ingest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

func (s PostgresSink) PrepareCaptureEventDeletion(ctx context.Context, preview CaptureEventDeletionPreview, tombstone CaptureTombstone) (CaptureTombstone, bool, error) {
	if s.DB == nil {
		return CaptureTombstone{}, false, errors.New("PostgreSQL connection is required")
	}
	if err := preview.Validate(); err != nil {
		return CaptureTombstone{}, false, err
	}
	if err := tombstone.Validate(); err != nil {
		return CaptureTombstone{}, false, err
	}
	if tombstone.CaptureSessionID != preview.CaptureSessionID {
		return CaptureTombstone{}, false, errors.New("capture event deletion tombstone scope does not match preview")
	}
	tombstone.CreatedAt = tombstone.CreatedAt.UTC().Truncate(time.Microsecond)
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return CaptureTombstone{}, false, fmt.Errorf("begin capture event deletion preparation: %w", err)
	}
	defer tx.Rollback()
	if err := lockCaptureIngestion(ctx, tx, preview.CaptureSessionID); err != nil {
		return CaptureTombstone{}, false, err
	}
	receipt, completed, err := readCaptureEventDeletionReceipt(ctx, tx, preview.CaptureSessionID)
	if err != nil {
		return CaptureTombstone{}, false, err
	}
	stored, exists, err := readDatabaseCaptureTombstone(ctx, tx, preview.CaptureSessionID)
	if err != nil {
		return CaptureTombstone{}, false, err
	}
	if completed {
		if receipt.PreviewSHA256 != preview.PreviewSHA256 {
			return CaptureTombstone{}, false, ErrCaptureEventDeletionConflict
		}
		if !exists {
			return CaptureTombstone{}, false, ErrCaptureEventTombstoneMissing
		}
		if err := tx.Commit(); err != nil {
			return CaptureTombstone{}, false, fmt.Errorf("commit capture event deletion preparation replay: %w", err)
		}
		return stored, true, nil
	}
	var databaseNow time.Time
	if err := tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&databaseNow); err != nil {
		return CaptureTombstone{}, false, fmt.Errorf("read capture event deletion preparation time: %w", err)
	}
	if !databaseNow.UTC().Before(preview.ExpiresAt) {
		return CaptureTombstone{}, false, ErrCaptureEventDeletionPreviewExpired
	}
	actual, err := readCaptureEventFootprintTx(ctx, tx, preview.CaptureSessionID)
	if err != nil {
		return CaptureTombstone{}, false, err
	}
	if !sameCaptureEventRows(actual, preview.Database) {
		return CaptureTombstone{}, false, ErrCaptureEventDeletionPreviewStale
	}
	if exists {
		if err := tx.Commit(); err != nil {
			return CaptureTombstone{}, false, fmt.Errorf("commit existing capture event deletion preparation: %w", err)
		}
		return stored, true, nil
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO normalized_event_deletion_tombstones(capture_session_id,operation_id,actor_name,created_at)
VALUES ($1,$2,$3,$4)`, tombstone.CaptureSessionID, tombstone.OperationID, tombstone.Actor, tombstone.CreatedAt); err != nil {
		return CaptureTombstone{}, false, fmt.Errorf("persist preview-bound capture event tombstone: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return CaptureTombstone{}, false, fmt.Errorf("commit capture event deletion preparation: %w", err)
	}
	return tombstone, false, nil
}

func (s PostgresSink) DeleteCaptureEvents(ctx context.Context, preview CaptureEventDeletionPreview) (CaptureEventDeletionReceipt, error) {
	if s.DB == nil {
		return CaptureEventDeletionReceipt{}, errors.New("PostgreSQL connection is required")
	}
	if err := preview.Validate(); err != nil {
		return CaptureEventDeletionReceipt{}, err
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return CaptureEventDeletionReceipt{}, fmt.Errorf("begin capture event deletion transaction: %w", err)
	}
	defer tx.Rollback()
	if err := lockCaptureIngestion(ctx, tx, preview.CaptureSessionID); err != nil {
		return CaptureEventDeletionReceipt{}, err
	}
	stored, exists, err := readCaptureEventDeletionReceipt(ctx, tx, preview.CaptureSessionID)
	if err != nil {
		return CaptureEventDeletionReceipt{}, err
	}
	if exists {
		if stored.PreviewSHA256 != preview.PreviewSHA256 {
			return CaptureEventDeletionReceipt{}, ErrCaptureEventDeletionConflict
		}
		stored.Replayed = true
		if err := tx.Commit(); err != nil {
			return CaptureEventDeletionReceipt{}, fmt.Errorf("commit capture event deletion replay: %w", err)
		}
		return stored, nil
	}
	var databaseNow time.Time
	if err := tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&databaseNow); err != nil {
		return CaptureEventDeletionReceipt{}, fmt.Errorf("read capture event deletion time: %w", err)
	}
	databaseNow = databaseNow.UTC().Truncate(time.Microsecond)
	if !databaseNow.Before(preview.ExpiresAt) {
		return CaptureEventDeletionReceipt{}, ErrCaptureEventDeletionPreviewExpired
	}
	tombstone, exists, err := readDatabaseCaptureTombstone(ctx, tx, preview.CaptureSessionID)
	if err != nil {
		return CaptureEventDeletionReceipt{}, err
	}
	if !exists {
		return CaptureEventDeletionReceipt{}, ErrCaptureEventTombstoneMissing
	}
	actual, err := readCaptureEventFootprintTx(ctx, tx, preview.CaptureSessionID)
	if err != nil {
		return CaptureEventDeletionReceipt{}, err
	}
	if !sameCaptureEventRows(actual, preview.Database) {
		return CaptureEventDeletionReceipt{}, ErrCaptureEventDeletionPreviewStale
	}
	if _, err := tx.ExecContext(ctx, `CREATE TEMP TABLE capture_event_deletion_targets (
  record_id text PRIMARY KEY CHECK (record_id ~ '^[a-f0-9]{64}$')
) ON COMMIT DROP`); err != nil {
		return CaptureEventDeletionReceipt{}, fmt.Errorf("create capture event deletion target set: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO capture_event_deletion_targets(record_id)
SELECT DISTINCT record_id FROM normalized_events WHERE capture_session_id=$1`, preview.CaptureSessionID); err != nil {
		return CaptureEventDeletionReceipt{}, fmt.Errorf("freeze capture event deletion target set: %w", err)
	}
	eventResult, err := tx.ExecContext(ctx, "DELETE FROM normalized_events WHERE capture_session_id=$1", preview.CaptureSessionID)
	if err != nil {
		return CaptureEventDeletionReceipt{}, fmt.Errorf("delete capture event rows: %w", err)
	}
	deletedEvents, err := eventResult.RowsAffected()
	if err != nil || deletedEvents != preview.Database.EventRows {
		return CaptureEventDeletionReceipt{}, errors.New("capture event deletion row count did not match preview")
	}
	identityResult, err := tx.ExecContext(ctx, `DELETE FROM normalized_event_identities identity_row
USING capture_event_deletion_targets target
WHERE identity_row.record_id=target.record_id
  AND NOT EXISTS (SELECT 1 FROM normalized_events remaining WHERE remaining.record_id=identity_row.record_id)`)
	if err != nil {
		return CaptureEventDeletionReceipt{}, fmt.Errorf("delete capture event identity rows: %w", err)
	}
	deletedIdentities, err := identityResult.RowsAffected()
	if err != nil || deletedIdentities != preview.Database.ExclusiveIdentityRows {
		return CaptureEventDeletionReceipt{}, errors.New("capture event identity deletion row count did not match preview")
	}
	var remainingEvents, orphanedIdentities int64
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM normalized_events WHERE capture_session_id=$1", preview.CaptureSessionID).Scan(&remainingEvents); err != nil {
		return CaptureEventDeletionReceipt{}, fmt.Errorf("verify capture event absence: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM normalized_event_identities identity_row
JOIN capture_event_deletion_targets target ON target.record_id=identity_row.record_id
WHERE NOT EXISTS (SELECT 1 FROM normalized_events remaining WHERE remaining.record_id=identity_row.record_id)`).Scan(&orphanedIdentities); err != nil {
		return CaptureEventDeletionReceipt{}, fmt.Errorf("verify capture event identity absence: %w", err)
	}
	if remainingEvents != 0 || orphanedIdentities != 0 {
		return CaptureEventDeletionReceipt{}, errors.New("capture event deletion verification failed")
	}
	if err := tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&databaseNow); err != nil {
		return CaptureEventDeletionReceipt{}, fmt.Errorf("read capture event deletion completion time: %w", err)
	}
	databaseNow = databaseNow.UTC().Truncate(time.Microsecond)
	receipt := CaptureEventDeletionReceipt{
		Schema: CaptureEventDeletionPreviewSchema, CaptureSessionID: preview.CaptureSessionID,
		OperationID: tombstone.OperationID, PreviewSHA256: preview.PreviewSHA256,
		DeletedEventRows: preview.Database.EventRows, DeletedIdentityRows: preview.Database.ExclusiveIdentityRows,
		DeletedEventLogicalBytes: preview.Database.EventLogicalBytes, DeletedIdentityLogicalBytes: preview.Database.IdentityLogicalBytes,
		DatabaseReclaimMode: DatabaseReclaimDeferred, VerifiedAbsent: true, CompletedAt: databaseNow,
	}
	if err := receipt.Validate(); err != nil {
		return CaptureEventDeletionReceipt{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO normalized_event_deletion_receipts(
capture_session_id,operation_id,preview_sha256,deleted_event_rows,deleted_identity_rows,
deleted_event_logical_bytes,deleted_identity_logical_bytes,completed_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, receipt.CaptureSessionID, receipt.OperationID, receipt.PreviewSHA256, receipt.DeletedEventRows, receipt.DeletedIdentityRows, receipt.DeletedEventLogicalBytes, receipt.DeletedIdentityLogicalBytes, receipt.CompletedAt); err != nil {
		return CaptureEventDeletionReceipt{}, fmt.Errorf("persist capture event deletion receipt: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return CaptureEventDeletionReceipt{}, fmt.Errorf("commit capture event deletion: %w", err)
	}
	return receipt, nil
}

func readCaptureEventFootprintTx(ctx context.Context, tx *sql.Tx, captureSessionID string) (CaptureEventDatabaseFootprint, error) {
	var footprint CaptureEventDatabaseFootprint
	if err := tx.QueryRowContext(ctx, `SELECT count(*), COALESCE(sum(pg_column_size(e)),0), COALESCE(max(ingest_sequence),0)
FROM normalized_events e WHERE capture_session_id = $1`, captureSessionID).Scan(&footprint.EventRows, &footprint.EventLogicalBytes, &footprint.MaxIngestSequence); err != nil {
		return CaptureEventDatabaseFootprint{}, fmt.Errorf("read capture event row footprint: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*), COALESCE(sum(pg_column_size(i)),0)
FROM normalized_event_identities i
WHERE EXISTS (SELECT 1 FROM normalized_events target WHERE target.record_id=i.record_id AND target.capture_session_id=$1)
  AND NOT EXISTS (SELECT 1 FROM normalized_events shared WHERE shared.record_id=i.record_id AND shared.capture_session_id IS DISTINCT FROM $1)`, captureSessionID).Scan(&footprint.ExclusiveIdentityRows, &footprint.IdentityLogicalBytes); err != nil {
		return CaptureEventDatabaseFootprint{}, fmt.Errorf("read capture event identity footprint: %w", err)
	}
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM normalized_event_deletion_tombstones WHERE capture_session_id=$1)", captureSessionID).Scan(&footprint.TombstonePresent); err != nil {
		return CaptureEventDatabaseFootprint{}, fmt.Errorf("read capture event tombstone footprint: %w", err)
	}
	if err := footprint.Validate(); err != nil {
		return CaptureEventDatabaseFootprint{}, err
	}
	return footprint, nil
}

func readCaptureEventDeletionReceipt(ctx context.Context, tx *sql.Tx, captureSessionID string) (CaptureEventDeletionReceipt, bool, error) {
	receipt := CaptureEventDeletionReceipt{Schema: CaptureEventDeletionPreviewSchema, DatabaseReclaimMode: DatabaseReclaimDeferred, VerifiedAbsent: true}
	err := tx.QueryRowContext(ctx, `SELECT capture_session_id,operation_id,preview_sha256,deleted_event_rows,
deleted_identity_rows,deleted_event_logical_bytes,deleted_identity_logical_bytes,completed_at
FROM normalized_event_deletion_receipts WHERE capture_session_id=$1`, captureSessionID).Scan(&receipt.CaptureSessionID, &receipt.OperationID, &receipt.PreviewSHA256, &receipt.DeletedEventRows, &receipt.DeletedIdentityRows, &receipt.DeletedEventLogicalBytes, &receipt.DeletedIdentityLogicalBytes, &receipt.CompletedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return CaptureEventDeletionReceipt{}, false, nil
	}
	if err != nil {
		return CaptureEventDeletionReceipt{}, false, fmt.Errorf("read capture event deletion receipt: %w", err)
	}
	receipt.CompletedAt = receipt.CompletedAt.UTC().Truncate(time.Microsecond)
	if err := receipt.Validate(); err != nil {
		return CaptureEventDeletionReceipt{}, false, err
	}
	return receipt, true, nil
}

func readDatabaseCaptureTombstone(ctx context.Context, tx *sql.Tx, captureSessionID string) (CaptureTombstone, bool, error) {
	tombstone := CaptureTombstone{Schema: CaptureTombstoneSchemaVersion}
	err := tx.QueryRowContext(ctx, `SELECT capture_session_id,operation_id,actor_name,created_at
FROM normalized_event_deletion_tombstones WHERE capture_session_id=$1`, captureSessionID).Scan(&tombstone.CaptureSessionID, &tombstone.OperationID, &tombstone.Actor, &tombstone.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return CaptureTombstone{}, false, nil
	}
	if err != nil {
		return CaptureTombstone{}, false, fmt.Errorf("read capture event deletion tombstone: %w", err)
	}
	tombstone.CreatedAt = tombstone.CreatedAt.UTC().Truncate(time.Microsecond)
	if err := tombstone.Validate(); err != nil {
		return CaptureTombstone{}, false, err
	}
	return tombstone, true, nil
}

func sameCaptureEventRows(left, right CaptureEventDatabaseFootprint) bool {
	return left.EventRows == right.EventRows && left.ExclusiveIdentityRows == right.ExclusiveIdentityRows && left.EventLogicalBytes == right.EventLogicalBytes && left.IdentityLogicalBytes == right.IdentityLogicalBytes && left.MaxIngestSequence == right.MaxIngestSequence
}
