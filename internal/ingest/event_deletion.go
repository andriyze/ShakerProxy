package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
)

const (
	CaptureEventDeletionPreviewSchema = 1
	DefaultEventDeletionPreviewTTL    = 10 * time.Minute
	DatabaseReclaimDeferred           = "DEFERRED_UNTIL_DATABASE_MAINTENANCE"
)

var (
	ErrCaptureEventDeletionPreviewExpired = errors.New("capture event deletion preview has expired")
	ErrCaptureEventDeletionPreviewStale   = errors.New("capture event deletion preview is stale")
	ErrCaptureEventDeletionConflict       = errors.New("capture event deletion already completed for different preview evidence")
	ErrCaptureEventTombstoneMissing       = errors.New("capture event deletion tombstone is missing")
)

type CaptureEventSpoolFootprint struct {
	PendingRecords   int   `json:"pending_records"`
	PendingFileBytes int64 `json:"pending_file_bytes"`
	TombstonePresent bool  `json:"tombstone_present"`
}

type CaptureEventDatabaseFootprint struct {
	EventRows             int64 `json:"event_rows"`
	ExclusiveIdentityRows int64 `json:"exclusive_identity_rows"`
	EventLogicalBytes     int64 `json:"event_logical_bytes"`
	IdentityLogicalBytes  int64 `json:"identity_logical_bytes"`
	MaxIngestSequence     int64 `json:"max_ingest_sequence"`
	TombstonePresent      bool  `json:"tombstone_present"`
}

type CaptureEventDeletionPreview struct {
	Schema                                  int                           `json:"schema"`
	CaptureSessionID                        string                        `json:"capture_session_id"`
	Spool                                   CaptureEventSpoolFootprint    `json:"spool"`
	Database                                CaptureEventDatabaseFootprint `json:"database"`
	EstimatedImmediatelyReclaimableBytes    int64                         `json:"estimated_immediately_reclaimable_bytes"`
	LogicalBytesReclaimableAfterMaintenance int64                         `json:"logical_bytes_reclaimable_after_maintenance"`
	DatabaseReclaimMode                     string                        `json:"database_reclaim_mode"`
	GeneratedAt                             time.Time                     `json:"generated_at"`
	ExpiresAt                               time.Time                     `json:"expires_at"`
	PreviewSHA256                           string                        `json:"preview_sha256"`
}

type CaptureEventDeletionReceipt struct {
	Schema                      int       `json:"schema"`
	CaptureSessionID            string    `json:"capture_session_id"`
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

type CaptureEventFootprintReader interface {
	ReadCaptureEventFootprint(context.Context, string) (CaptureEventDatabaseFootprint, error)
}

type CaptureEventDeletionPlanner struct {
	Spool    *Spool
	Database CaptureEventFootprintReader
	Now      func() time.Time
}

func (p CaptureEventDeletionPlanner) Preview(ctx context.Context, captureSessionID string) (CaptureEventDeletionPreview, error) {
	if p.Spool == nil || p.Database == nil || !capture.ValidSessionID(captureSessionID) {
		return CaptureEventDeletionPreview{}, errors.New("capture event deletion preview configuration or session ID is invalid")
	}
	database, err := p.Database.ReadCaptureEventFootprint(ctx, captureSessionID)
	if err != nil {
		return CaptureEventDeletionPreview{}, err
	}
	if err := database.Validate(); err != nil {
		return CaptureEventDeletionPreview{}, err
	}
	spool, err := p.Spool.ReadCaptureEventFootprint(captureSessionID)
	if err != nil {
		return CaptureEventDeletionPreview{}, err
	}
	generatedAt := p.now()
	preview := CaptureEventDeletionPreview{
		Schema: CaptureEventDeletionPreviewSchema, CaptureSessionID: captureSessionID,
		Spool: spool, Database: database,
		EstimatedImmediatelyReclaimableBytes:    spool.PendingFileBytes,
		LogicalBytesReclaimableAfterMaintenance: database.EventLogicalBytes + database.IdentityLogicalBytes,
		DatabaseReclaimMode:                     DatabaseReclaimDeferred,
		GeneratedAt:                             generatedAt, ExpiresAt: generatedAt.Add(DefaultEventDeletionPreviewTTL),
	}
	hash, err := previewHash(preview)
	if err != nil {
		return CaptureEventDeletionPreview{}, err
	}
	preview.PreviewSHA256 = hash
	return preview, preview.Validate()
}

func (f CaptureEventDatabaseFootprint) Validate() error {
	if f.EventRows < 0 || f.ExclusiveIdentityRows < 0 || f.ExclusiveIdentityRows > f.EventRows || f.EventLogicalBytes < 0 || f.IdentityLogicalBytes < 0 || f.MaxIngestSequence < 0 {
		return errors.New("capture event database footprint is invalid")
	}
	if f.EventRows == 0 && (f.EventLogicalBytes != 0 || f.ExclusiveIdentityRows != 0 || f.IdentityLogicalBytes != 0 || f.MaxIngestSequence != 0) {
		return errors.New("empty capture event database footprint contains row evidence")
	}
	if f.EventRows > 0 && (f.EventLogicalBytes == 0 || f.MaxIngestSequence == 0) || f.ExclusiveIdentityRows > 0 && f.IdentityLogicalBytes == 0 {
		return errors.New("capture event database footprint omits byte or sequence evidence")
	}
	return nil
}

func (f CaptureEventSpoolFootprint) Validate() error {
	if f.PendingRecords < 0 || f.PendingRecords > MaxPendingRecords || f.PendingFileBytes < 0 || f.PendingRecords == 0 && f.PendingFileBytes != 0 || f.PendingRecords > 0 && f.PendingFileBytes == 0 {
		return errors.New("capture event spool footprint is invalid")
	}
	return nil
}

func (p CaptureEventDeletionPreview) Validate() error {
	if p.Schema != CaptureEventDeletionPreviewSchema || !capture.ValidSessionID(p.CaptureSessionID) || p.Spool.Validate() != nil || p.Database.Validate() != nil || p.EstimatedImmediatelyReclaimableBytes != p.Spool.PendingFileBytes || p.LogicalBytesReclaimableAfterMaintenance != p.Database.EventLogicalBytes+p.Database.IdentityLogicalBytes || p.DatabaseReclaimMode != DatabaseReclaimDeferred || p.GeneratedAt.IsZero() || p.ExpiresAt.Sub(p.GeneratedAt) != DefaultEventDeletionPreviewTTL || len(p.PreviewSHA256) != sha256.Size*2 {
		return errors.New("capture event deletion preview is invalid")
	}
	if _, err := hex.DecodeString(p.PreviewSHA256); err != nil {
		return errors.New("capture event deletion preview digest is invalid")
	}
	expected, err := previewHash(p)
	if err != nil || expected != p.PreviewSHA256 {
		return errors.New("capture event deletion preview digest does not match")
	}
	return nil
}

func (r CaptureEventDeletionReceipt) Validate() error {
	if r.Schema != CaptureEventDeletionPreviewSchema || !capture.ValidSessionID(r.CaptureSessionID) || !opaqueIDPattern.MatchString(r.OperationID) || len(r.PreviewSHA256) != sha256.Size*2 || r.DeletedEventRows < 0 || r.DeletedIdentityRows < 0 || r.DeletedIdentityRows > r.DeletedEventRows || r.DeletedEventLogicalBytes < 0 || r.DeletedIdentityLogicalBytes < 0 || r.DatabaseReclaimMode != DatabaseReclaimDeferred || !r.VerifiedAbsent || r.CompletedAt.IsZero() {
		return errors.New("capture event deletion receipt is invalid")
	}
	if _, err := hex.DecodeString(r.PreviewSHA256); err != nil {
		return errors.New("capture event deletion receipt digest is invalid")
	}
	return nil
}

func previewHash(preview CaptureEventDeletionPreview) (string, error) {
	evidence := struct {
		Schema                                  int                           `json:"schema"`
		CaptureSessionID                        string                        `json:"capture_session_id"`
		Spool                                   CaptureEventSpoolFootprint    `json:"spool"`
		Database                                CaptureEventDatabaseFootprint `json:"database"`
		EstimatedImmediatelyReclaimableBytes    int64                         `json:"estimated_immediately_reclaimable_bytes"`
		LogicalBytesReclaimableAfterMaintenance int64                         `json:"logical_bytes_reclaimable_after_maintenance"`
		DatabaseReclaimMode                     string                        `json:"database_reclaim_mode"`
		ExpiresAt                               time.Time                     `json:"expires_at"`
	}{preview.Schema, preview.CaptureSessionID, preview.Spool, preview.Database, preview.EstimatedImmediatelyReclaimableBytes, preview.LogicalBytesReclaimableAfterMaintenance, preview.DatabaseReclaimMode, preview.ExpiresAt.UTC()}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (p CaptureEventDeletionPlanner) now() time.Time {
	if p.Now != nil {
		return p.Now().UTC().Truncate(time.Microsecond)
	}
	return time.Now().UTC().Truncate(time.Microsecond)
}
