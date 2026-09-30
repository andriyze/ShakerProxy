package analyzer

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
)

const CheckpointReindexSchema = 1

var (
	ErrCheckpointReindexConflict = errors.New("analyzer checkpoint reindex conflicts with a prior operation")
	ErrCheckpointReindexBarrier  = errors.New("analyzer checkpoint reindex lacks a completed deletion barrier")
)

type CheckpointReindexRequest struct {
	Schema                int    `json:"schema"`
	OperationID           string `json:"operation_id"`
	Actor                 string `json:"actor"`
	Engine                Engine `json:"engine"`
	CaptureSessionID      string `json:"capture_session_id"`
	DeletionOperationID   string `json:"deletion_operation_id"`
	DeletionPreviewSHA256 string `json:"deletion_preview_sha256"`
	TargetManifestSHA256  string `json:"target_manifest_sha256"`
}

type CheckpointReindexOutcome struct {
	Schema                int        `json:"schema"`
	OperationID           string     `json:"operation_id"`
	Actor                 string     `json:"actor"`
	Engine                Engine     `json:"engine"`
	CaptureSessionID      string     `json:"capture_session_id"`
	DeletionOperationID   string     `json:"deletion_operation_id"`
	DeletionPreviewSHA256 string     `json:"deletion_preview_sha256"`
	TargetManifestSHA256  string     `json:"target_manifest_sha256"`
	State                 string     `json:"state"`
	AuthorizedAt          time.Time  `json:"authorized_at"`
	CompletedAt           *time.Time `json:"completed_at,omitempty"`
	Replayed              bool       `json:"replayed"`
}

type checkpointReindexRecord struct {
	Schema                int        `json:"schema"`
	OperationID           string     `json:"operation_id"`
	Actor                 string     `json:"actor"`
	Engine                Engine     `json:"engine"`
	CaptureSessionID      string     `json:"capture_session_id"`
	DeletionOperationID   string     `json:"deletion_operation_id"`
	DeletionPreviewSHA256 string     `json:"deletion_preview_sha256"`
	TargetManifestSHA256  string     `json:"target_manifest_sha256"`
	State                 string     `json:"state"`
	AuthorizedAt          time.Time  `json:"authorized_at"`
	CompletedAt           *time.Time `json:"completed_at,omitempty"`
}

func (r CheckpointReindexRequest) Validate() error {
	if r.Schema != CheckpointReindexSchema || !checkpointOperationIDPattern.MatchString(r.OperationID) || !checkpointOperationIDPattern.MatchString(r.DeletionOperationID) || !validText(r.Actor, 1, 96) || !capture.ValidSessionID(r.CaptureSessionID) || !validDigest(r.DeletionPreviewSHA256) || !validDigest(r.TargetManifestSHA256) {
		return errors.New("analyzer checkpoint reindex request is invalid")
	}
	if _, err := ParseEngine(string(r.Engine)); err != nil {
		return errors.New("analyzer checkpoint reindex request is invalid")
	}
	return nil
}

func (o CheckpointReindexOutcome) Validate() error {
	record := checkpointReindexRecord{
		Schema: o.Schema, OperationID: o.OperationID, Actor: o.Actor, Engine: o.Engine,
		CaptureSessionID: o.CaptureSessionID, DeletionOperationID: o.DeletionOperationID,
		DeletionPreviewSHA256: o.DeletionPreviewSHA256, TargetManifestSHA256: o.TargetManifestSHA256,
		State: o.State, AuthorizedAt: o.AuthorizedAt, CompletedAt: o.CompletedAt,
	}
	return record.validate()
}

func (s *CheckpointDeletionService) AuthorizeReindex(request CheckpointReindexRequest) (CheckpointReindexOutcome, error) {
	if err := s.validate(); err != nil || request.Validate() != nil || request.Engine != s.Engine {
		return CheckpointReindexOutcome{}, errors.New("analyzer checkpoint reindex request is invalid")
	}
	s.Store.writeLock()
	defer s.Store.writeUnlock()
	if historical, exists, err := s.Store.readCheckpointReindexHistory(request.OperationID); err != nil {
		return CheckpointReindexOutcome{}, err
	} else if exists {
		if !historical.matches(request) {
			return CheckpointReindexOutcome{}, ErrCheckpointReindexConflict
		}
		return historical.outcome(true), nil
	}
	if existing, exists, err := s.Store.readCheckpointReindexRecord(s.Engine, request.CaptureSessionID); err != nil {
		return CheckpointReindexOutcome{}, err
	} else if exists {
		if !existing.matches(request) {
			return CheckpointReindexOutcome{}, ErrCheckpointReindexConflict
		}
		return existing.outcome(true), nil
	}
	deletion, exists, err := s.Store.readCheckpointDeletionRecord(s.Engine, request.CaptureSessionID)
	if err != nil {
		return CheckpointReindexOutcome{}, err
	}
	if !exists || !deletion.VerifiedAbsent || deletion.OperationID != request.DeletionOperationID || deletion.PreviewSHA256 != request.DeletionPreviewSHA256 || deletion.Actor != request.Actor {
		return CheckpointReindexOutcome{}, ErrCheckpointReindexBarrier
	}
	if _, checkpointExists, err := s.Store.readCheckpoint(s.Engine, request.CaptureSessionID); err != nil {
		return CheckpointReindexOutcome{}, err
	} else if checkpointExists {
		return CheckpointReindexOutcome{}, ErrCheckpointReindexBarrier
	}
	record := checkpointReindexRecord{
		Schema: CheckpointReindexSchema, OperationID: request.OperationID, Actor: request.Actor, Engine: s.Engine,
		CaptureSessionID: request.CaptureSessionID, DeletionOperationID: request.DeletionOperationID,
		DeletionPreviewSHA256: request.DeletionPreviewSHA256, TargetManifestSHA256: request.TargetManifestSHA256,
		State: "AUTHORIZED", AuthorizedAt: s.Now().UTC(),
	}
	if err := s.Store.writeCheckpointReindexRecord(record); err != nil {
		return CheckpointReindexOutcome{}, err
	}
	return record.outcome(false), nil
}

func (s StateStore) HasCheckpointReindexAuthorization(engine Engine, sessionID, manifestSHA string) (bool, error) {
	s.readLock()
	defer s.readUnlock()
	return s.checkpointReindexAuthorized(engine, sessionID, manifestSHA)
}

func (s StateStore) checkpointReindexAuthorized(engine Engine, sessionID, manifestSHA string) (bool, error) {
	record, exists, err := s.readCheckpointReindexRecord(engine, sessionID)
	if err != nil || !exists {
		return false, err
	}
	return record.State == "AUTHORIZED" && record.TargetManifestSHA256 == manifestSHA, nil
}

func (s StateStore) FinalizeCheckpointReindex(checkpoint Checkpoint) error {
	if !validCheckpoint(checkpoint) {
		return errors.New("analyzer checkpoint reindex completion is invalid")
	}
	s.writeLock()
	defer s.writeUnlock()
	return s.finalizeCheckpointReindexLocked(checkpoint)
}

func (s StateStore) finalizeCheckpointReindexLocked(checkpoint Checkpoint) error {
	reindex, exists, err := s.readCheckpointReindexRecord(checkpoint.Engine, checkpoint.CaptureSessionID)
	if err != nil || !exists {
		return err
	}
	if reindex.TargetManifestSHA256 != checkpoint.ManifestSHA256 {
		return ErrCheckpointDeletionBarrier
	}
	deletion, deletionExists, err := s.readCheckpointDeletionRecord(checkpoint.Engine, checkpoint.CaptureSessionID)
	if err != nil {
		return err
	}
	if !deletionExists || deletion.OperationID != reindex.DeletionOperationID || deletion.PreviewSHA256 != reindex.DeletionPreviewSHA256 {
		return ErrCheckpointReindexBarrier
	}
	now := checkpoint.AnalysisCompletedAt.UTC()
	reindex.State, reindex.CompletedAt = "COMPLETED", &now
	if err := s.writeCheckpointReindexHistory(reindex); err != nil {
		return err
	}
	if err := s.writeCheckpointDeletionHistory(deletion); err != nil {
		return err
	}
	for _, path := range []string{
		filepath.Join(s.Root, "reindexes", checkpoint.CaptureSessionID+".json"),
		filepath.Join(s.Root, "deletions", checkpoint.CaptureSessionID+".json"),
	} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := syncDirectory(filepath.Join(s.Root, "reindexes")); err != nil {
		return err
	}
	return syncDirectory(filepath.Join(s.Root, "deletions"))
}

func (s StateStore) readCheckpointReindexRecord(engine Engine, sessionID string) (checkpointReindexRecord, bool, error) {
	return s.readCheckpointReindexPath(filepath.Join(s.Root, "reindexes", sessionID+".json"), engine, sessionID)
}

func (s StateStore) readCheckpointReindexHistory(operationID string) (checkpointReindexRecord, bool, error) {
	if !checkpointOperationIDPattern.MatchString(operationID) {
		return checkpointReindexRecord{}, false, errors.New("analyzer checkpoint reindex operation is invalid")
	}
	var record checkpointReindexRecord
	err := readBoundedJSON(filepath.Join(s.Root, "reindex-history", operationID+".json"), &record)
	if errors.Is(err, os.ErrNotExist) {
		return checkpointReindexRecord{}, false, nil
	}
	if err != nil || record.validate() != nil || record.OperationID != operationID || record.State != "COMPLETED" {
		return checkpointReindexRecord{}, false, errors.New("stored analyzer checkpoint reindex history is invalid")
	}
	return record, true, nil
}

func (s StateStore) readCheckpointReindexPath(path string, engine Engine, sessionID string) (checkpointReindexRecord, bool, error) {
	var record checkpointReindexRecord
	err := readBoundedJSON(path, &record)
	if errors.Is(err, os.ErrNotExist) {
		return checkpointReindexRecord{}, false, nil
	}
	if err != nil || record.validate() != nil || record.Engine != engine || record.CaptureSessionID != sessionID {
		return checkpointReindexRecord{}, false, errors.New("stored analyzer checkpoint reindex record is invalid")
	}
	return record, true, nil
}

func (s StateStore) writeCheckpointReindexRecord(record checkpointReindexRecord) error {
	if record.validate() != nil || record.State != "AUTHORIZED" {
		return errors.New("analyzer checkpoint reindex record is invalid")
	}
	return writeJSONAtomic(filepath.Join(s.Root, "reindexes"), record.CaptureSessionID+".json", record, 0o600)
}

func (s StateStore) writeCheckpointReindexHistory(record checkpointReindexRecord) error {
	if record.validate() != nil || record.State != "COMPLETED" {
		return errors.New("analyzer checkpoint reindex history is invalid")
	}
	return writeJSONAtomic(filepath.Join(s.Root, "reindex-history"), record.OperationID+".json", record, 0o600)
}

func (s StateStore) writeCheckpointDeletionHistory(record checkpointDeletionRecord) error {
	if record.validate() != nil || !record.VerifiedAbsent {
		return errors.New("analyzer checkpoint deletion history is invalid")
	}
	return writeJSONAtomic(filepath.Join(s.Root, "deletion-history"), record.OperationID+".json", record, 0o600)
}

func (r checkpointReindexRecord) validate() error {
	request := CheckpointReindexRequest{
		Schema: r.Schema, OperationID: r.OperationID, Actor: r.Actor, Engine: r.Engine,
		CaptureSessionID: r.CaptureSessionID, DeletionOperationID: r.DeletionOperationID,
		DeletionPreviewSHA256: r.DeletionPreviewSHA256, TargetManifestSHA256: r.TargetManifestSHA256,
	}
	if request.Validate() != nil || r.AuthorizedAt.IsZero() {
		return errors.New("analyzer checkpoint reindex record is invalid")
	}
	if r.State == "AUTHORIZED" && r.CompletedAt != nil || r.State == "COMPLETED" && (r.CompletedAt == nil || r.CompletedAt.Before(r.AuthorizedAt)) || r.State != "AUTHORIZED" && r.State != "COMPLETED" {
		return errors.New("analyzer checkpoint reindex state is invalid")
	}
	return nil
}

func (r checkpointReindexRecord) matches(request CheckpointReindexRequest) bool {
	return r.Schema == request.Schema && r.OperationID == request.OperationID && r.Actor == request.Actor && r.Engine == request.Engine && r.CaptureSessionID == request.CaptureSessionID && r.DeletionOperationID == request.DeletionOperationID && r.DeletionPreviewSHA256 == request.DeletionPreviewSHA256 && r.TargetManifestSHA256 == request.TargetManifestSHA256
}

func (r checkpointReindexRecord) outcome(replayed bool) CheckpointReindexOutcome {
	return CheckpointReindexOutcome{
		Schema: r.Schema, OperationID: r.OperationID, Actor: r.Actor, Engine: r.Engine,
		CaptureSessionID: r.CaptureSessionID, DeletionOperationID: r.DeletionOperationID,
		DeletionPreviewSHA256: r.DeletionPreviewSHA256, TargetManifestSHA256: r.TargetManifestSHA256,
		State: r.State, AuthorizedAt: r.AuthorizedAt, CompletedAt: r.CompletedAt, Replayed: replayed,
	}
}
