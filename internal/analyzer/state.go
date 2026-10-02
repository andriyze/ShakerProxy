package analyzer

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
)

type StateStore struct {
	Root  string
	mutex *sync.RWMutex
}

func NewStateStore(root string) StateStore {
	return StateStore{Root: root, mutex: &sync.RWMutex{}}
}

func (s StateStore) Prepare() error {
	if s.Root == "" || !filepath.IsAbs(s.Root) || filepath.Clean(s.Root) == "/" {
		return errors.New("analyzer state root must be an absolute non-root path")
	}
	if _, err := os.Lstat(s.Root); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(s.Root, 0o700); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := safeDirectory(s.Root); err != nil {
		return errors.New("analyzer state root is not a safe directory")
	}
	for _, name := range []string{"active", "checkpoints", "deletions", "deletion-history", "reindexes", "reindex-history"} {
		if err := os.Mkdir(filepath.Join(s.Root, name), 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
	}
	for _, path := range []string{s.Root, filepath.Join(s.Root, "active"), filepath.Join(s.Root, "checkpoints"), filepath.Join(s.Root, "deletions"), filepath.Join(s.Root, "deletion-history"), filepath.Join(s.Root, "reindexes"), filepath.Join(s.Root, "reindex-history")} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("analyzer state path is not a safe directory")
		}
	}
	return nil
}

// AnalysisSeedKey returns the analyzer's persistent secret used to derive
// per-artifact parser seeds. Deterministic seeds make re-analysis of the same
// capture artifact produce identical output (and therefore identical event
// IDs), while the secret keeps the seeds unpredictable to observed traffic.
func (s StateStore) AnalysisSeedKey() ([]byte, error) {
	path := filepath.Join(s.Root, "analysis-seed.key")
	key, err := readNoFollowFile(path, 64)
	if err == nil {
		if len(key) != 32 {
			return nil, errors.New("analyzer seed key is invalid")
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	s.writeLock()
	defer s.writeUnlock()
	if key, err := readNoFollowFile(path, 64); err == nil && len(key) == 32 {
		return key, nil
	}
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	temporary, err := os.CreateTemp(s.Root, ".analysis-seed-*")
	if err != nil {
		return nil, err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return nil, err
	}
	if _, err := temporary.Write(key); err != nil {
		temporary.Close()
		return nil, err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return nil, err
	}
	if err := temporary.Close(); err != nil {
		return nil, err
	}
	if err := os.Link(temporaryName, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			existing, readErr := readNoFollowFile(path, 64)
			if readErr != nil || len(existing) != 32 {
				return nil, errors.New("analyzer seed key is invalid")
			}
			return existing, nil
		}
		return nil, err
	}
	return key, nil
}

func (s StateStore) ReadCheckpoint(engine Engine, sessionID string) (Checkpoint, bool, error) {
	s.readLock()
	defer s.readUnlock()
	return s.readCheckpoint(engine, sessionID)
}

func (s StateStore) readCheckpoint(engine Engine, sessionID string) (Checkpoint, bool, error) {
	if !capture.ValidSessionID(sessionID) {
		return Checkpoint{}, false, errors.New("checkpoint capture identity is invalid")
	}
	path := filepath.Join(s.Root, "checkpoints", sessionID+".json")
	var checkpoint Checkpoint
	err := readBoundedJSON(path, &checkpoint)
	if errors.Is(err, os.ErrNotExist) {
		return Checkpoint{}, false, nil
	}
	if err != nil {
		return Checkpoint{}, false, err
	}
	if !validCheckpoint(checkpoint) || checkpoint.Engine != engine || checkpoint.CaptureSessionID != sessionID {
		return Checkpoint{}, false, errors.New("stored analyzer checkpoint is invalid")
	}
	return checkpoint, true, nil
}

func (s StateStore) WriteCheckpoint(checkpoint Checkpoint) error {
	if !validCheckpoint(checkpoint) {
		return errors.New("analyzer checkpoint is invalid")
	}
	s.writeLock()
	defer s.writeUnlock()
	if _, exists, err := s.readCheckpointDeletionRecord(checkpoint.Engine, checkpoint.CaptureSessionID); err != nil {
		return err
	} else if exists {
		authorized, authorizationErr := s.checkpointReindexAuthorized(checkpoint.Engine, checkpoint.CaptureSessionID, checkpoint.ManifestSHA256)
		if authorizationErr != nil {
			return authorizationErr
		}
		if !authorized {
			return ErrCheckpointDeletionBarrier
		}
	}
	if err := writeJSONAtomic(filepath.Join(s.Root, "checkpoints"), checkpoint.CaptureSessionID+".json", checkpoint, 0o600); err != nil {
		return err
	}
	return s.finalizeCheckpointReindexLocked(checkpoint)
}

func (s StateStore) ReadActiveProgress(engine Engine, sessionID string) (ActiveProgress, bool, error) {
	s.readLock()
	defer s.readUnlock()
	if !capture.ValidSessionID(sessionID) {
		return ActiveProgress{}, false, errors.New("active analyzer progress identity is invalid")
	}
	var progress ActiveProgress
	err := readBoundedJSON(filepath.Join(s.Root, "active", sessionID+".json"), &progress)
	if errors.Is(err, os.ErrNotExist) {
		return ActiveProgress{}, false, nil
	}
	if err != nil {
		return ActiveProgress{}, false, err
	}
	if !validActiveProgress(progress) || progress.Engine != engine || progress.CaptureSessionID != sessionID {
		return ActiveProgress{}, false, errors.New("stored active analyzer progress is invalid")
	}
	return progress, true, nil
}

func (s StateStore) WriteActiveProgress(progress ActiveProgress) error {
	if !validActiveProgress(progress) {
		return errors.New("active analyzer progress is invalid")
	}
	s.writeLock()
	defer s.writeUnlock()
	if _, exists, err := s.readCheckpointDeletionRecord(progress.Engine, progress.CaptureSessionID); err != nil {
		return err
	} else if exists {
		return ErrCheckpointDeletionBarrier
	}
	return writeJSONAtomic(filepath.Join(s.Root, "active"), progress.CaptureSessionID+".json", progress, 0o600)
}

func (s StateStore) DeleteActiveProgress(sessionID string) error {
	if !capture.ValidSessionID(sessionID) {
		return errors.New("active analyzer progress identity is invalid")
	}
	s.writeLock()
	defer s.writeUnlock()
	path := filepath.Join(s.Root, "active", sessionID+".json")
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (s StateStore) ReadStatus() (Status, error) {
	var status Status
	if err := readBoundedJSON(filepath.Join(s.Root, "status.json"), &status); err != nil {
		return Status{}, err
	}
	if !validStatus(status) {
		return Status{}, errors.New("stored analyzer status is invalid")
	}
	return status, nil
}

func (s StateStore) WriteStatus(status Status) error {
	if !validStatus(status) {
		return errors.New("analyzer status is invalid")
	}
	return writeJSONAtomic(s.Root, "status.json", status, 0o600)
}

func (s StateStore) readLock() {
	if s.mutex != nil {
		s.mutex.RLock()
	}
}

func (s StateStore) readUnlock() {
	if s.mutex != nil {
		s.mutex.RUnlock()
	}
}

func (s StateStore) writeLock() {
	if s.mutex != nil {
		s.mutex.Lock()
	}
}

func (s StateStore) writeUnlock() {
	if s.mutex != nil {
		s.mutex.Unlock()
	}
}

func validCheckpoint(checkpoint Checkpoint) bool {
	_, engineErr := ParseEngine(string(checkpoint.Engine))
	return checkpoint.Schema == SchemaVersion && engineErr == nil && capture.ValidSessionID(checkpoint.CaptureSessionID) &&
		sha256Pattern.MatchString(checkpoint.ManifestSHA256) && checkpoint.CaptureFiles >= 1 && checkpoint.CaptureFiles <= 128 &&
		checkpoint.EventsDelivered >= 0 && checkpoint.EventsDelivered <= MaxEventsPerCapture && checkpoint.OutputBytes >= 0 &&
		checkpoint.OutputBytes <= 1<<30 && checkpoint.ActiveSegments <= 1_000_000 && checkpoint.MissedSegments <= 1_000_000 && !checkpoint.AnalysisCompletedAt.IsZero()
}

func validActiveProgress(progress ActiveProgress) bool {
	_, engineErr := ParseEngine(string(progress.Engine))
	if progress.Schema != SchemaVersion || engineErr != nil || !capture.ValidSessionID(progress.CaptureSessionID) || progress.FeedRevision < progress.LastCompletedSequence || progress.FeedEvictedSegments > progress.FeedRevision || progress.SegmentsProcessed > 1_000_000 || progress.MissedSegments > 1_000_000 || progress.SegmentsProcessed+progress.MissedSegments != progress.LastCompletedSequence || progress.EventsDelivered < 0 || progress.EventsDelivered > MaxEventsPerCapture || progress.OutputBytes < 0 || progress.OutputBytes > 1<<30 || progress.UpdatedAt.IsZero() || len(progress.Recent) > MaxActiveRecent {
		return false
	}
	var previous uint64
	for _, segment := range progress.Recent {
		if segment.Sequence == 0 || segment.Sequence <= previous || segment.Sequence > progress.LastCompletedSequence || !safeCaptureName(segment.Name) || segment.SizeBytes < 1 || segment.Modified.IsZero() || !sha256Pattern.MatchString(segment.SHA256) {
			return false
		}
		previous = segment.Sequence
	}
	return len(progress.Recent) == 0 || progress.Recent[len(progress.Recent)-1].Sequence == progress.LastCompletedSequence
}

func validStatus(status Status) bool {
	_, engineErr := ParseEngine(string(status.Engine))
	if status.Schema != SchemaVersion || engineErr != nil || !validText(status.SourceVersion, 1, 64) || status.StartedAt.IsZero() || status.UpdatedAt.Before(status.StartedAt) ||
		(status.CurrentCaptureID != "" && !capture.ValidSessionID(status.CurrentCaptureID)) || len(status.LastError) > 2048 {
		return false
	}
	for _, timestamp := range []time.Time{status.LastScanAt, status.LastSuccessAt} {
		if !timestamp.IsZero() && (timestamp.Before(status.StartedAt) || timestamp.After(status.UpdatedAt)) {
			return false
		}
	}
	if status.LastError != "" && !validText(status.LastError, 1, 2048) {
		return false
	}
	rulesetPresent := status.RulesetID != "" || status.RulesetVersion != "" || status.RulesetSHA256 != ""
	if rulesetPresent && (status.Engine != EngineSuricata || !rulesetIDPattern.MatchString(status.RulesetID) || !rulesetVersionPattern.MatchString(status.RulesetVersion) || !sha256Pattern.MatchString(status.RulesetSHA256)) {
		return false
	}
	for _, live := range []*LiveStatus{status.Live, status.LiveVPN} {
		if live != nil && (status.Engine != EngineZeek || !validLiveStatus(*live)) {
			return false
		}
	}
	return true
}

func readBoundedJSON(path string, target any) error {
	contents, err := readNoFollowFile(path, maxMetadataBytes)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("analyzer metadata contains multiple JSON values")
	}
	return nil
}

func writeJSONAtomic(directory, name string, value any, mode os.FileMode) error {
	if name == "" || strings.ContainsAny(name, `/\\`) {
		return errors.New("analyzer metadata filename is invalid")
	}
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxMetadataBytes {
		return errors.New("analyzer metadata exceeds its byte limit")
	}
	if info, statErr := os.Lstat(filepath.Join(directory, name)); statErr == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return errors.New("analyzer metadata destination is unsafe")
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	temporary, err := os.CreateTemp(directory, ".analyzer-state-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, filepath.Join(directory, name)); err != nil {
		return fmt.Errorf("publish analyzer metadata: %w", err)
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryHandle.Close()
	return directoryHandle.Sync()
}
