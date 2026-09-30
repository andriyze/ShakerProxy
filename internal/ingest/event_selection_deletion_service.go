package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"time"
)

const EventSelectionDeletionOperationSchema = 1

type EventSelectionDeletionDatabase interface {
	PreviewEventSelectionDeletion(context.Context, string, EventSelection, EventQuerySnapshot) (EventSelectionDeletionPreview, error)
	PrepareEventSelectionDeletion(context.Context, EventSelectionDeletionPreview, EventSelectionTombstone) (EventSelectionTombstone, bool, error)
	DeleteEventSelection(context.Context, EventSelectionDeletionPreview, string) (EventSelectionDeletionReceipt, error)
}

type EventSelectionDeletionPreviewRequest struct {
	Actor         string             `json:"actor"`
	Selection     EventSelection     `json:"selection"`
	QuerySnapshot EventQuerySnapshot `json:"query_snapshot"`
}

type EventSelectionDeletionBundle struct {
	Schema                                  int                           `json:"schema"`
	Actor                                   string                        `json:"actor"`
	Selection                               EventSelection                `json:"selection"`
	SelectionSHA256                         string                        `json:"selection_sha256"`
	QuerySnapshot                           EventQuerySnapshot            `json:"query_snapshot"`
	Spool                                   EventSelectionSpoolFootprint  `json:"spool"`
	Database                                EventSelectionDeletionPreview `json:"database"`
	EstimatedImmediatelyReclaimableBytes    int64                         `json:"estimated_immediately_reclaimable_bytes"`
	LogicalBytesReclaimableAfterMaintenance int64                         `json:"logical_bytes_reclaimable_after_maintenance"`
	DatabaseReclaimMode                     string                        `json:"database_reclaim_mode"`
	GeneratedAt                             time.Time                     `json:"generated_at"`
	ExpiresAt                               time.Time                     `json:"expires_at"`
	PreviewSHA256                           string                        `json:"preview_sha256"`
}

type EventSelectionDeletionRequest struct {
	Schema      int                          `json:"schema"`
	Preview     EventSelectionDeletionBundle `json:"preview"`
	OperationID string                       `json:"operation_id"`
	Actor       string                       `json:"actor"`
}

type EventSelectionDeletionOutcome struct {
	Schema        int                           `json:"schema"`
	OperationID   string                        `json:"operation_id"`
	Actor         string                        `json:"actor"`
	PreviewSHA256 string                        `json:"preview_sha256"`
	Tombstone     EventSelectionTombstone       `json:"tombstone"`
	Spool         EventSelectionTombstoneResult `json:"spool"`
	Database      EventSelectionDeletionReceipt `json:"database"`
	CompletedAt   time.Time                     `json:"completed_at"`
	Replayed      bool                          `json:"replayed"`
}

type EventSelectionDeletionService struct {
	Spool    *Spool
	Database EventSelectionDeletionDatabase
}

func (r EventSelectionDeletionPreviewRequest) Validate() error {
	if !validSnapshotActor(r.Actor) || r.Selection.Validate() != nil || ValidateEventQuerySnapshot(r.QuerySnapshot) != nil || validateEventSelectionSnapshotScope(r.Selection, r.QuerySnapshot) != nil {
		return errors.New("event selection deletion preview request is invalid")
	}
	return nil
}

func (s EventSelectionDeletionService) Preview(ctx context.Context, request EventSelectionDeletionPreviewRequest) (EventSelectionDeletionBundle, error) {
	if s.Spool == nil || s.Database == nil || request.Validate() != nil {
		return EventSelectionDeletionBundle{}, errors.New("event selection deletion preview configuration or request is invalid")
	}
	database, err := s.Database.PreviewEventSelectionDeletion(ctx, request.Actor, request.Selection, request.QuerySnapshot)
	if err != nil {
		return EventSelectionDeletionBundle{}, err
	}
	spool, err := s.Spool.ReadEventSelectionSpoolFootprint(request.Selection)
	if err != nil {
		return EventSelectionDeletionBundle{}, err
	}
	selectionSHA, _ := request.Selection.SHA256()
	preview := EventSelectionDeletionBundle{
		Schema: EventSelectionDeletionOperationSchema, Actor: request.Actor, Selection: request.Selection,
		SelectionSHA256: selectionSHA, QuerySnapshot: request.QuerySnapshot, Spool: spool, Database: database,
		EstimatedImmediatelyReclaimableBytes:    spool.PendingFileBytes,
		LogicalBytesReclaimableAfterMaintenance: database.LogicalBytesReclaimableAfterMaintenance,
		DatabaseReclaimMode:                     database.DatabaseReclaimMode, GeneratedAt: database.GeneratedAt, ExpiresAt: database.ExpiresAt,
	}
	preview.PreviewSHA256, err = eventSelectionDeletionBundleHash(preview)
	if err != nil || preview.Validate() != nil {
		return EventSelectionDeletionBundle{}, errors.New("event selection deletion preview could not be bound")
	}
	return preview, nil
}

func (s EventSelectionDeletionService) Delete(ctx context.Context, request EventSelectionDeletionRequest) (EventSelectionDeletionOutcome, error) {
	if s.Spool == nil || s.Database == nil || request.Validate() != nil {
		return EventSelectionDeletionOutcome{}, errors.New("event selection deletion request is invalid")
	}
	tombstone := EventSelectionTombstone{
		Schema: EventSelectionSchemaVersion, OperationID: request.OperationID, Actor: request.Actor,
		Selection: request.Preview.Selection, SelectionSHA256: request.Preview.SelectionSHA256,
		QuerySnapshotID: request.Preview.QuerySnapshot.ID, QuerySnapshotSHA256: request.Preview.QuerySnapshot.SnapshotSHA256,
		DeletionPreviewSHA256: request.Preview.PreviewSHA256, CreatedAt: request.Preview.GeneratedAt,
	}
	stored, _, err := s.Database.PrepareEventSelectionDeletion(ctx, request.Preview.Database, tombstone)
	if err != nil {
		return EventSelectionDeletionOutcome{}, err
	}
	spoolResult, err := s.Spool.PutEventSelectionTombstoneForPreview(stored, request.Preview.Spool)
	if err != nil {
		return EventSelectionDeletionOutcome{}, err
	}
	if !reflect.DeepEqual(spoolResult.Tombstone, stored) {
		return EventSelectionDeletionOutcome{}, errors.New("event selection deletion barriers do not match")
	}
	receipt, err := s.Database.DeleteEventSelection(ctx, request.Preview.Database, request.OperationID)
	if err != nil {
		return EventSelectionDeletionOutcome{}, err
	}
	outcome := EventSelectionDeletionOutcome{
		Schema: EventSelectionDeletionOperationSchema, OperationID: request.OperationID, Actor: request.Actor,
		PreviewSHA256: request.Preview.PreviewSHA256, Tombstone: stored, Spool: spoolResult,
		Database: receipt, CompletedAt: receipt.CompletedAt, Replayed: receipt.Replayed && spoolResult.Existing,
	}
	if err := outcome.Validate(); err != nil {
		return EventSelectionDeletionOutcome{}, err
	}
	return outcome, nil
}

func (p EventSelectionDeletionBundle) Validate() error {
	selectionSHA, err := p.Selection.SHA256()
	if p.Schema != EventSelectionDeletionOperationSchema || !validSnapshotActor(p.Actor) || err != nil || p.SelectionSHA256 != selectionSHA || ValidateEventQuerySnapshot(p.QuerySnapshot) != nil || validateEventSelectionSnapshotScope(p.Selection, p.QuerySnapshot) != nil || p.Spool.Validate() != nil || p.Database.Validate() != nil || p.Database.Actor != p.Actor || !reflect.DeepEqual(p.Database.Selection, p.Selection) || p.Database.SelectionSHA256 != p.SelectionSHA256 || !reflect.DeepEqual(p.Database.QuerySnapshot, p.QuerySnapshot) || p.EstimatedImmediatelyReclaimableBytes != p.Spool.PendingFileBytes || p.LogicalBytesReclaimableAfterMaintenance != p.Database.LogicalBytesReclaimableAfterMaintenance || p.DatabaseReclaimMode != DatabaseReclaimDeferred || !p.GeneratedAt.Equal(p.Database.GeneratedAt) || !p.ExpiresAt.Equal(p.Database.ExpiresAt) || len(p.PreviewSHA256) != sha256.Size*2 {
		return errors.New("event selection deletion bundle is invalid")
	}
	if _, err := hex.DecodeString(p.PreviewSHA256); err != nil {
		return errors.New("event selection deletion bundle digest is invalid")
	}
	expected, err := eventSelectionDeletionBundleHash(p)
	if err != nil || expected != p.PreviewSHA256 {
		return errors.New("event selection deletion bundle digest does not match")
	}
	return nil
}

func (r EventSelectionDeletionRequest) Validate() error {
	if r.Schema != EventSelectionDeletionOperationSchema || r.Preview.Validate() != nil || !opaqueIDPattern.MatchString(r.OperationID) || !validText(r.Actor, 1, 96) || r.Actor != r.Preview.Actor {
		return errors.New("event selection deletion request is invalid")
	}
	return nil
}

func (o EventSelectionDeletionOutcome) Validate() error {
	if o.Schema != EventSelectionDeletionOperationSchema || !opaqueIDPattern.MatchString(o.OperationID) || !validText(o.Actor, 1, 96) || !querySnapshotSHA256.MatchString(o.PreviewSHA256) || o.Tombstone.Validate() != nil || o.Database.Validate() != nil || o.Tombstone.OperationID != o.OperationID || o.Tombstone.Actor != o.Actor || o.Tombstone.DeletionPreviewSHA256 != o.PreviewSHA256 || !reflect.DeepEqual(o.Spool.Tombstone, o.Tombstone) || o.Database.OperationID != o.OperationID || !o.CompletedAt.Equal(o.Database.CompletedAt) || o.Replayed && (!o.Database.Replayed || !o.Spool.Existing) || o.Spool.PurgedRecords < 0 || o.Spool.PurgedBytes < 0 {
		return errors.New("event selection deletion outcome is invalid")
	}
	return nil
}

func eventSelectionDeletionBundleHash(preview EventSelectionDeletionBundle) (string, error) {
	preview.PreviewSHA256 = ""
	encoded, err := json.Marshal(preview)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
