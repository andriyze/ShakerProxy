package ingest

import (
	"context"
	"errors"
	"fmt"
)

type BatchSink interface {
	WriteBatch(context.Context, []PendingRecord) error
}

// RecordError reports pending records that can never be written as part of any
// batch (for example an identity conflict or a row PostgreSQL rejects as data).
// The drain sets them aside so one poison record cannot stall ingestion.
// Purge marks records that belong to deleted data and must be discarded rather
// than retained.
type RecordError struct {
	RecordIDs []string
	Purge     bool
	Err       error
}

func (e *RecordError) Error() string {
	return fmt.Sprintf("%d pending record(s) cannot be stored: %v", len(e.RecordIDs), e.Err)
}

func (e *RecordError) Unwrap() error { return e.Err }

func DrainOnce(ctx context.Context, spool *Spool, sink BatchSink, limit int) (DrainResult, error) {
	if spool == nil || sink == nil {
		return DrainResult{}, errors.New("ingestion spool and sink are required")
	}
	batch, err := spool.PendingBatch(limit)
	if err != nil || len(batch) == 0 {
		return DrainResult{}, err
	}
	result := DrainResult{Attempted: len(batch)}
	if err := sink.WriteBatch(ctx, batch); err != nil {
		var recordErr *RecordError
		if !errors.As(err, &recordErr) || len(recordErr.RecordIDs) == 0 || len(recordErr.RecordIDs) > len(batch) || ctx.Err() != nil {
			return result, err
		}
		moved, setAsideErr := spool.SetAside(recordErr.RecordIDs, recordErr.Purge)
		if setAsideErr != nil {
			return result, errors.Join(err, setAsideErr)
		}
		if recordErr.Purge {
			result.Purged = moved
		} else {
			result.Rejected = moved
		}
		result.SetAsideReason = recordErr.Err.Error()
		if moved == 0 {
			return result, err
		}
		// The remaining records are retried by the caller's next drain pass.
		return result, nil
	}
	identities := make([]string, len(batch))
	for index := range batch {
		identities[index] = batch[index].RecordID
	}
	if err := spool.Acknowledge(identities); err != nil {
		return result, err
	}
	result.Committed = len(batch)
	return result, nil
}
