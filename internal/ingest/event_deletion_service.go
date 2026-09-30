package ingest

import (
	"context"
	"errors"
	"time"
)

const CaptureEventDeletionOperationSchema = 1

type CaptureEventDeletionDatabase interface {
	CaptureEventFootprintReader
	PrepareCaptureEventDeletion(context.Context, CaptureEventDeletionPreview, CaptureTombstone) (CaptureTombstone, bool, error)
	DeleteCaptureEvents(context.Context, CaptureEventDeletionPreview) (CaptureEventDeletionReceipt, error)
}

type CaptureEventDeletionRequest struct {
	Schema      int                         `json:"schema"`
	Preview     CaptureEventDeletionPreview `json:"preview"`
	OperationID string                      `json:"operation_id"`
	Actor       string                      `json:"actor"`
}

type CaptureEventDeletionOutcome struct {
	Schema           int                         `json:"schema"`
	CaptureSessionID string                      `json:"capture_session_id"`
	PreviewSHA256    string                      `json:"preview_sha256"`
	Tombstone        CaptureTombstone            `json:"tombstone"`
	Spool            SpoolTombstoneResult        `json:"spool"`
	Database         CaptureEventDeletionReceipt `json:"database"`
	CompletedAt      time.Time                   `json:"completed_at"`
	Replayed         bool                        `json:"replayed"`
}

type CaptureEventDeletionService struct {
	Spool    *Spool
	Database CaptureEventDeletionDatabase
	Now      func() time.Time
}

func (s CaptureEventDeletionService) Preview(ctx context.Context, captureSessionID string) (CaptureEventDeletionPreview, error) {
	return CaptureEventDeletionPlanner{Spool: s.Spool, Database: s.Database, Now: s.Now}.Preview(ctx, captureSessionID)
}

func (s CaptureEventDeletionService) Delete(ctx context.Context, request CaptureEventDeletionRequest) (CaptureEventDeletionOutcome, error) {
	if s.Spool == nil || s.Database == nil || request.Validate() != nil {
		return CaptureEventDeletionOutcome{}, errors.New("capture event deletion request is invalid")
	}
	now := s.now()
	tombstone := CaptureTombstone{Schema: CaptureTombstoneSchemaVersion, CaptureSessionID: request.Preview.CaptureSessionID, OperationID: request.OperationID, Actor: request.Actor, CreatedAt: now}
	stored, _, err := s.Database.PrepareCaptureEventDeletion(ctx, request.Preview, tombstone)
	if err != nil {
		return CaptureEventDeletionOutcome{}, err
	}
	spoolResult, err := s.Spool.PutCaptureTombstoneForPreview(stored, request.Preview.Spool)
	if err != nil {
		return CaptureEventDeletionOutcome{}, err
	}
	if spoolResult.Tombstone != stored {
		return CaptureEventDeletionOutcome{}, errors.New("capture event deletion barriers do not match")
	}
	receipt, err := s.Database.DeleteCaptureEvents(ctx, request.Preview)
	if err != nil {
		return CaptureEventDeletionOutcome{}, err
	}
	outcome := CaptureEventDeletionOutcome{
		Schema: CaptureEventDeletionOperationSchema, CaptureSessionID: request.Preview.CaptureSessionID,
		PreviewSHA256: request.Preview.PreviewSHA256, Tombstone: stored, Spool: spoolResult,
		Database: receipt, CompletedAt: receipt.CompletedAt,
		Replayed: receipt.Replayed && spoolResult.Existing,
	}
	if err := outcome.Validate(); err != nil {
		return CaptureEventDeletionOutcome{}, err
	}
	return outcome, nil
}

func (r CaptureEventDeletionRequest) Validate() error {
	if r.Schema != CaptureEventDeletionOperationSchema || r.Preview.Validate() != nil || !opaqueIDPattern.MatchString(r.OperationID) || !validText(r.Actor, 1, 96) {
		return errors.New("capture event deletion request is invalid")
	}
	return nil
}

func (o CaptureEventDeletionOutcome) Validate() error {
	if o.Schema != CaptureEventDeletionOperationSchema || o.Tombstone.Validate() != nil || o.Database.Validate() != nil || o.CaptureSessionID != o.Tombstone.CaptureSessionID || o.CaptureSessionID != o.Database.CaptureSessionID || o.PreviewSHA256 != o.Database.PreviewSHA256 || o.PreviewSHA256 == "" || o.Spool.Tombstone != o.Tombstone || o.Database.OperationID != o.Tombstone.OperationID || !o.CompletedAt.Equal(o.Database.CompletedAt) || o.Replayed && (!o.Database.Replayed || !o.Spool.Existing) {
		return errors.New("capture event deletion outcome is invalid")
	}
	if o.Spool.PurgedRecords < 0 || o.Spool.PurgedBytes < 0 {
		return errors.New("capture event deletion spool outcome is invalid")
	}
	return nil
}

func (s CaptureEventDeletionService) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC().Truncate(time.Microsecond)
	}
	return time.Now().UTC().Truncate(time.Microsecond)
}
