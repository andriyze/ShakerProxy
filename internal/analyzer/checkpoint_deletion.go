package analyzer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
)

const (
	CheckpointDeletionSchema     = 1
	DefaultCheckpointPreviewTTL  = 10 * time.Minute
	minCheckpointPreviewLifetime = time.Minute
	maxCheckpointPreviewLifetime = 30 * time.Minute
)

var (
	ErrCheckpointDeletionPreviewExpired = errors.New("analyzer checkpoint deletion preview expired")
	ErrCheckpointDeletionPreviewStale   = errors.New("analyzer checkpoint deletion preview is stale")
	ErrCheckpointDeletionConflict       = errors.New("analyzer checkpoint deletion conflicts with a prior operation")
	ErrCheckpointDeletionBarrier        = errors.New("analyzer checkpoint deletion barrier prevents replay")
	checkpointOperationIDPattern        = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
)

type CheckpointDeletionPreview struct {
	Schema                int       `json:"schema"`
	Engine                Engine    `json:"engine"`
	CaptureSessionID      string    `json:"capture_session_id"`
	CheckpointPresent     bool      `json:"checkpoint_present"`
	CheckpointBytes       int64     `json:"checkpoint_bytes"`
	CheckpointSHA256      string    `json:"checkpoint_sha256,omitempty"`
	ActiveProgressPresent bool      `json:"active_progress_present"`
	ActiveProgressBytes   int64     `json:"active_progress_bytes"`
	ActiveProgressSHA256  string    `json:"active_progress_sha256,omitempty"`
	ManifestSHA256        string    `json:"manifest_sha256,omitempty"`
	CaptureFiles          int       `json:"capture_files"`
	EventsDelivered       int       `json:"events_delivered"`
	AnalyzerOutputBytes   int64     `json:"analyzer_output_bytes"`
	GeneratedAt           time.Time `json:"generated_at"`
	ExpiresAt             time.Time `json:"expires_at"`
	PreviewSHA256         string    `json:"preview_sha256"`
}

type CheckpointDeletionRequest struct {
	Schema      int                       `json:"schema"`
	OperationID string                    `json:"operation_id"`
	Actor       string                    `json:"actor"`
	Preview     CheckpointDeletionPreview `json:"preview"`
}

type CheckpointDeletionOutcome struct {
	Schema                     int       `json:"schema"`
	Engine                     Engine    `json:"engine"`
	CaptureSessionID           string    `json:"capture_session_id"`
	OperationID                string    `json:"operation_id"`
	Actor                      string    `json:"actor"`
	PreviewSHA256              string    `json:"preview_sha256"`
	CheckpointWasPresent       bool      `json:"checkpoint_was_present"`
	DeletedCheckpointBytes     int64     `json:"deleted_checkpoint_bytes"`
	ActiveProgressWasPresent   bool      `json:"active_progress_was_present"`
	DeletedActiveProgressBytes int64     `json:"deleted_active_progress_bytes"`
	VerifiedAbsent             bool      `json:"verified_absent"`
	CreatedAt                  time.Time `json:"created_at"`
	CompletedAt                time.Time `json:"completed_at"`
	Replayed                   bool      `json:"replayed"`
}

type checkpointDeletionRecord struct {
	Schema                     int       `json:"schema"`
	Engine                     Engine    `json:"engine"`
	CaptureSessionID           string    `json:"capture_session_id"`
	OperationID                string    `json:"operation_id"`
	Actor                      string    `json:"actor"`
	PreviewSHA256              string    `json:"preview_sha256"`
	CheckpointWasPresent       bool      `json:"checkpoint_was_present"`
	DeletedCheckpointBytes     int64     `json:"deleted_checkpoint_bytes"`
	ActiveProgressWasPresent   bool      `json:"active_progress_was_present"`
	DeletedActiveProgressBytes int64     `json:"deleted_active_progress_bytes"`
	VerifiedAbsent             bool      `json:"verified_absent"`
	CreatedAt                  time.Time `json:"created_at"`
	CompletedAt                time.Time `json:"completed_at,omitempty"`
}

type CheckpointDeletionService struct {
	Store      StateStore
	Engine     Engine
	Now        func() time.Time
	PreviewTTL time.Duration
}

func NewCheckpointDeletionService(store StateStore, engine Engine) (*CheckpointDeletionService, error) {
	if _, err := ParseEngine(string(engine)); err != nil {
		return nil, err
	}
	if err := store.Prepare(); err != nil {
		return nil, err
	}
	return &CheckpointDeletionService{Store: store, Engine: engine, Now: time.Now, PreviewTTL: DefaultCheckpointPreviewTTL}, nil
}

func (s *CheckpointDeletionService) Preview(sessionID string) (CheckpointDeletionPreview, error) {
	if err := s.validate(); err != nil || !capture.ValidSessionID(sessionID) {
		return CheckpointDeletionPreview{}, errors.New("analyzer checkpoint deletion preview request is invalid")
	}
	s.Store.readLock()
	defer s.Store.readUnlock()
	preview, err := s.Store.checkpointDeletionPreview(s.Engine, sessionID, s.Now().UTC(), s.PreviewTTL)
	if err != nil {
		return CheckpointDeletionPreview{}, err
	}
	return preview, nil
}

func (s *CheckpointDeletionService) Delete(request CheckpointDeletionRequest) (CheckpointDeletionOutcome, error) {
	if err := s.validate(); err != nil || request.Validate() != nil || request.Preview.Engine != s.Engine {
		return CheckpointDeletionOutcome{}, errors.New("analyzer checkpoint deletion request is invalid")
	}
	now := s.Now().UTC()
	s.Store.writeLock()
	defer s.Store.writeUnlock()
	if historical, historyExists, historyErr := s.Store.readCheckpointDeletionHistory(request.OperationID); historyErr != nil {
		return CheckpointDeletionOutcome{}, historyErr
	} else if historyExists {
		if historical.PreviewSHA256 != request.Preview.PreviewSHA256 || historical.Actor != request.Actor || historical.Engine != request.Preview.Engine || historical.CaptureSessionID != request.Preview.CaptureSessionID {
			return CheckpointDeletionOutcome{}, ErrCheckpointDeletionConflict
		}
		return historical.outcome(true), nil
	}

	record, exists, err := s.Store.readCheckpointDeletionRecord(s.Engine, request.Preview.CaptureSessionID)
	if err != nil {
		return CheckpointDeletionOutcome{}, err
	}
	if exists {
		if record.OperationID != request.OperationID || record.PreviewSHA256 != request.Preview.PreviewSHA256 || record.Actor != request.Actor {
			return CheckpointDeletionOutcome{}, ErrCheckpointDeletionConflict
		}
		if record.VerifiedAbsent {
			return record.outcome(true), nil
		}
	} else {
		if !now.Before(request.Preview.ExpiresAt) {
			return CheckpointDeletionOutcome{}, ErrCheckpointDeletionPreviewExpired
		}
		current, previewErr := s.Store.checkpointDeletionPreview(s.Engine, request.Preview.CaptureSessionID, request.Preview.GeneratedAt, request.Preview.ExpiresAt.Sub(request.Preview.GeneratedAt))
		if previewErr != nil {
			return CheckpointDeletionOutcome{}, previewErr
		}
		if !sameCheckpointEvidence(current, request.Preview) {
			return CheckpointDeletionOutcome{}, ErrCheckpointDeletionPreviewStale
		}
		record = checkpointDeletionRecord{
			Schema: CheckpointDeletionSchema, Engine: s.Engine, CaptureSessionID: request.Preview.CaptureSessionID,
			OperationID: request.OperationID, Actor: request.Actor, PreviewSHA256: request.Preview.PreviewSHA256,
			CheckpointWasPresent: request.Preview.CheckpointPresent, ActiveProgressWasPresent: request.Preview.ActiveProgressPresent, CreatedAt: now,
		}
		if err := s.Store.writeCheckpointDeletionRecord(record); err != nil {
			return CheckpointDeletionOutcome{}, err
		}
	}

	checkpointPath := filepath.Join(s.Store.Root, "checkpoints", request.Preview.CaptureSessionID+".json")
	activeProgressPath := filepath.Join(s.Store.Root, "active", request.Preview.CaptureSessionID+".json")
	current, currentErr := s.Store.checkpointDeletionPreview(s.Engine, request.Preview.CaptureSessionID, request.Preview.GeneratedAt, request.Preview.ExpiresAt.Sub(request.Preview.GeneratedAt))
	if currentErr != nil {
		return CheckpointDeletionOutcome{}, currentErr
	}
	if current.CheckpointPresent {
		if !sameCheckpointFileEvidence(current, request.Preview) {
			return CheckpointDeletionOutcome{}, ErrCheckpointDeletionPreviewStale
		}
		if err := os.Remove(checkpointPath); err != nil {
			return CheckpointDeletionOutcome{}, fmt.Errorf("remove analyzer checkpoint: %w", err)
		}
		if err := syncDirectory(filepath.Dir(checkpointPath)); err != nil {
			return CheckpointDeletionOutcome{}, err
		}
	} else if !exists && request.Preview.CheckpointPresent {
		return CheckpointDeletionOutcome{}, ErrCheckpointDeletionPreviewStale
	}
	if current.ActiveProgressPresent {
		if !sameActiveProgressEvidence(current, request.Preview) {
			return CheckpointDeletionOutcome{}, ErrCheckpointDeletionPreviewStale
		}
		if err := os.Remove(activeProgressPath); err != nil {
			return CheckpointDeletionOutcome{}, fmt.Errorf("remove active analyzer progress: %w", err)
		}
		if err := syncDirectory(filepath.Dir(activeProgressPath)); err != nil {
			return CheckpointDeletionOutcome{}, err
		}
	} else if !exists && request.Preview.ActiveProgressPresent {
		return CheckpointDeletionOutcome{}, ErrCheckpointDeletionPreviewStale
	}
	if _, err := os.Lstat(checkpointPath); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return CheckpointDeletionOutcome{}, errors.New("analyzer checkpoint remains after deletion")
		}
		return CheckpointDeletionOutcome{}, err
	}
	if _, err := os.Lstat(activeProgressPath); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return CheckpointDeletionOutcome{}, errors.New("active analyzer progress remains after deletion")
		}
		return CheckpointDeletionOutcome{}, err
	}
	record.DeletedCheckpointBytes = request.Preview.CheckpointBytes
	record.DeletedActiveProgressBytes = request.Preview.ActiveProgressBytes
	record.VerifiedAbsent = true
	record.CompletedAt = now
	if err := s.Store.writeCheckpointDeletionRecord(record); err != nil {
		return CheckpointDeletionOutcome{}, err
	}
	return record.outcome(false), nil
}

func (s *CheckpointDeletionService) validate() error {
	if s == nil || s.Now == nil || s.PreviewTTL < minCheckpointPreviewLifetime || s.PreviewTTL > maxCheckpointPreviewLifetime {
		return errors.New("analyzer checkpoint deletion service is invalid")
	}
	_, err := ParseEngine(string(s.Engine))
	return err
}

func (p CheckpointDeletionPreview) Validate() error {
	if p.Schema != CheckpointDeletionSchema || !capture.ValidSessionID(p.CaptureSessionID) || p.GeneratedAt.IsZero() || p.ExpiresAt.Sub(p.GeneratedAt) < minCheckpointPreviewLifetime || p.ExpiresAt.Sub(p.GeneratedAt) > maxCheckpointPreviewLifetime || !validDigest(p.PreviewSHA256) || p.CheckpointBytes < 0 || p.ActiveProgressBytes < 0 || p.CaptureFiles < 0 || p.EventsDelivered < 0 || p.AnalyzerOutputBytes < 0 {
		return errors.New("analyzer checkpoint deletion preview is invalid")
	}
	if _, err := ParseEngine(string(p.Engine)); err != nil {
		return errors.New("analyzer checkpoint deletion preview is invalid")
	}
	if p.CheckpointPresent {
		if p.CheckpointBytes < 2 || !validDigest(p.CheckpointSHA256) || !validDigest(p.ManifestSHA256) || p.CaptureFiles < 1 || p.CaptureFiles > 128 || p.EventsDelivered > MaxEventsPerCapture || p.AnalyzerOutputBytes > 1<<30 {
			return errors.New("analyzer checkpoint deletion preview is invalid")
		}
	} else if p.CheckpointBytes != 0 || p.CheckpointSHA256 != "" || p.ManifestSHA256 != "" || p.CaptureFiles != 0 || p.EventsDelivered != 0 || p.AnalyzerOutputBytes != 0 {
		return errors.New("absent analyzer checkpoint preview contains evidence")
	}
	if p.ActiveProgressPresent {
		if p.ActiveProgressBytes < 2 || !validDigest(p.ActiveProgressSHA256) {
			return errors.New("analyzer active progress deletion preview is invalid")
		}
	} else if p.ActiveProgressBytes != 0 || p.ActiveProgressSHA256 != "" {
		return errors.New("absent analyzer active progress preview contains evidence")
	}
	expected, err := checkpointPreviewDigest(p)
	if err != nil || expected != p.PreviewSHA256 {
		return errors.New("analyzer checkpoint deletion preview digest is invalid")
	}
	return nil
}

func (r CheckpointDeletionRequest) Validate() error {
	if r.Schema != CheckpointDeletionSchema || !checkpointOperationIDPattern.MatchString(r.OperationID) || !validText(r.Actor, 1, 96) || r.Preview.Validate() != nil {
		return errors.New("analyzer checkpoint deletion request is invalid")
	}
	return nil
}

func (o CheckpointDeletionOutcome) Validate() error {
	if o.Schema != CheckpointDeletionSchema || !capture.ValidSessionID(o.CaptureSessionID) || !checkpointOperationIDPattern.MatchString(o.OperationID) || !validText(o.Actor, 1, 96) || !validDigest(o.PreviewSHA256) || o.DeletedCheckpointBytes < 0 || o.DeletedActiveProgressBytes < 0 || !o.VerifiedAbsent || o.CreatedAt.IsZero() || o.CompletedAt.Before(o.CreatedAt) {
		return errors.New("analyzer checkpoint deletion outcome is invalid")
	}
	if _, err := ParseEngine(string(o.Engine)); err != nil {
		return errors.New("analyzer checkpoint deletion outcome is invalid")
	}
	if !o.CheckpointWasPresent && o.DeletedCheckpointBytes != 0 {
		return errors.New("absent analyzer checkpoint reported deleted bytes")
	}
	if !o.ActiveProgressWasPresent && o.DeletedActiveProgressBytes != 0 {
		return errors.New("absent active analyzer progress reported deleted bytes")
	}
	return nil
}

func (s StateStore) checkpointDeletionPreview(engine Engine, sessionID string, generatedAt time.Time, ttl time.Duration) (CheckpointDeletionPreview, error) {
	preview := CheckpointDeletionPreview{Schema: CheckpointDeletionSchema, Engine: engine, CaptureSessionID: sessionID, GeneratedAt: generatedAt, ExpiresAt: generatedAt.Add(ttl)}
	path := filepath.Join(s.Root, "checkpoints", sessionID+".json")
	contents, err := readNoFollowFile(path, maxMetadataBytes)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return CheckpointDeletionPreview{}, err
	}
	if err == nil {
		var checkpoint Checkpoint
		decoder := json.NewDecoder(bytes.NewReader(contents))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&checkpoint); err != nil || decoder.Decode(&struct{}{}) != io.EOF || !validCheckpoint(checkpoint) || checkpoint.Engine != engine || checkpoint.CaptureSessionID != sessionID {
			return CheckpointDeletionPreview{}, errors.New("stored analyzer checkpoint is invalid")
		}
		digest := sha256.Sum256(contents)
		preview.CheckpointPresent = true
		preview.CheckpointBytes = int64(len(contents))
		preview.CheckpointSHA256 = hex.EncodeToString(digest[:])
		preview.ManifestSHA256 = checkpoint.ManifestSHA256
		preview.CaptureFiles = checkpoint.CaptureFiles
		preview.EventsDelivered = checkpoint.EventsDelivered
		preview.AnalyzerOutputBytes = checkpoint.OutputBytes
	}
	activeContents, activeErr := readNoFollowFile(filepath.Join(s.Root, "active", sessionID+".json"), maxMetadataBytes)
	if activeErr != nil && !errors.Is(activeErr, os.ErrNotExist) {
		return CheckpointDeletionPreview{}, activeErr
	}
	if activeErr == nil {
		var progress ActiveProgress
		decoder := json.NewDecoder(bytes.NewReader(activeContents))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&progress); err != nil || decoder.Decode(&struct{}{}) != io.EOF || !validActiveProgress(progress) || progress.Engine != engine || progress.CaptureSessionID != sessionID {
			return CheckpointDeletionPreview{}, errors.New("stored active analyzer progress is invalid")
		}
		digest := sha256.Sum256(activeContents)
		preview.ActiveProgressPresent = true
		preview.ActiveProgressBytes = int64(len(activeContents))
		preview.ActiveProgressSHA256 = hex.EncodeToString(digest[:])
	}
	preview.PreviewSHA256, err = checkpointPreviewDigest(preview)
	return preview, err
}

func (s StateStore) HasCheckpointDeletionBarrier(engine Engine, sessionID string) (bool, error) {
	if !capture.ValidSessionID(sessionID) {
		return false, errors.New("checkpoint deletion capture identity is invalid")
	}
	s.readLock()
	defer s.readUnlock()
	_, exists, err := s.readCheckpointDeletionRecord(engine, sessionID)
	return exists, err
}

func (s StateStore) readCheckpointDeletionRecord(engine Engine, sessionID string) (checkpointDeletionRecord, bool, error) {
	var record checkpointDeletionRecord
	err := readBoundedJSON(filepath.Join(s.Root, "deletions", sessionID+".json"), &record)
	if errors.Is(err, os.ErrNotExist) {
		return checkpointDeletionRecord{}, false, nil
	}
	if err != nil {
		return checkpointDeletionRecord{}, false, err
	}
	if record.validate() != nil || record.Engine != engine || record.CaptureSessionID != sessionID {
		return checkpointDeletionRecord{}, false, errors.New("stored analyzer checkpoint deletion record is invalid")
	}
	return record, true, nil
}

func (s StateStore) readCheckpointDeletionHistory(operationID string) (checkpointDeletionRecord, bool, error) {
	if !checkpointOperationIDPattern.MatchString(operationID) {
		return checkpointDeletionRecord{}, false, errors.New("checkpoint deletion operation is invalid")
	}
	var record checkpointDeletionRecord
	err := readBoundedJSON(filepath.Join(s.Root, "deletion-history", operationID+".json"), &record)
	if errors.Is(err, os.ErrNotExist) {
		return checkpointDeletionRecord{}, false, nil
	}
	if err != nil || record.validate() != nil || record.OperationID != operationID || !record.VerifiedAbsent {
		return checkpointDeletionRecord{}, false, errors.New("stored analyzer checkpoint deletion history is invalid")
	}
	return record, true, nil
}

func (s StateStore) writeCheckpointDeletionRecord(record checkpointDeletionRecord) error {
	if record.validate() != nil {
		return errors.New("analyzer checkpoint deletion record is invalid")
	}
	return writeJSONAtomic(filepath.Join(s.Root, "deletions"), record.CaptureSessionID+".json", record, 0o600)
}

func (r checkpointDeletionRecord) validate() error {
	if r.Schema != CheckpointDeletionSchema || !capture.ValidSessionID(r.CaptureSessionID) || !checkpointOperationIDPattern.MatchString(r.OperationID) || !validText(r.Actor, 1, 96) || !validDigest(r.PreviewSHA256) || r.DeletedCheckpointBytes < 0 || r.DeletedActiveProgressBytes < 0 || r.CreatedAt.IsZero() || !r.CompletedAt.IsZero() && r.CompletedAt.Before(r.CreatedAt) || r.VerifiedAbsent != !r.CompletedAt.IsZero() || !r.CheckpointWasPresent && r.DeletedCheckpointBytes != 0 || !r.ActiveProgressWasPresent && r.DeletedActiveProgressBytes != 0 {
		return errors.New("analyzer checkpoint deletion record is invalid")
	}
	_, err := ParseEngine(string(r.Engine))
	return err
}

func (r checkpointDeletionRecord) outcome(replayed bool) CheckpointDeletionOutcome {
	return CheckpointDeletionOutcome{
		Schema: r.Schema, Engine: r.Engine, CaptureSessionID: r.CaptureSessionID, OperationID: r.OperationID,
		Actor: r.Actor, PreviewSHA256: r.PreviewSHA256, CheckpointWasPresent: r.CheckpointWasPresent,
		DeletedCheckpointBytes: r.DeletedCheckpointBytes, ActiveProgressWasPresent: r.ActiveProgressWasPresent, DeletedActiveProgressBytes: r.DeletedActiveProgressBytes, VerifiedAbsent: r.VerifiedAbsent,
		CreatedAt: r.CreatedAt, CompletedAt: r.CompletedAt, Replayed: replayed,
	}
}

func checkpointPreviewDigest(preview CheckpointDeletionPreview) (string, error) {
	preview.PreviewSHA256 = ""
	encoded, err := json.Marshal(preview)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func sameCheckpointEvidence(left, right CheckpointDeletionPreview) bool {
	return left.Engine == right.Engine && left.CaptureSessionID == right.CaptureSessionID && sameCheckpointFileEvidence(left, right) && sameActiveProgressEvidence(left, right)
}

func sameCheckpointFileEvidence(left, right CheckpointDeletionPreview) bool {
	return left.CheckpointPresent == right.CheckpointPresent && left.CheckpointBytes == right.CheckpointBytes && left.CheckpointSHA256 == right.CheckpointSHA256 && left.ManifestSHA256 == right.ManifestSHA256 && left.CaptureFiles == right.CaptureFiles && left.EventsDelivered == right.EventsDelivered && left.AnalyzerOutputBytes == right.AnalyzerOutputBytes
}

func sameActiveProgressEvidence(left, right CheckpointDeletionPreview) bool {
	return left.ActiveProgressPresent == right.ActiveProgressPresent && left.ActiveProgressBytes == right.ActiveProgressBytes && left.ActiveProgressSHA256 == right.ActiveProgressSHA256
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
