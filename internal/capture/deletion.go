package capture

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	DeletionPreviewLifetime = 10 * time.Minute
	MaxDeletionJobs         = 1024
)

type DeletionState string

const (
	DeletionPending   DeletionState = "PENDING"
	DeletionVerifying DeletionState = "VERIFYING"
	DeletionDeleting  DeletionState = "DELETING"
	DeletionCompleted DeletionState = "COMPLETED"
	DeletionFailed    DeletionState = "FAILED"
)

type DeletionFootprint struct {
	CaptureFiles  int   `json:"capture_files"`
	CaptureBytes  int64 `json:"capture_bytes"`
	MetadataFiles int   `json:"metadata_files"`
	MetadataBytes int64 `json:"metadata_bytes"`
}

func (f DeletionFootprint) TotalFiles() int   { return f.CaptureFiles + f.MetadataFiles }
func (f DeletionFootprint) TotalBytes() int64 { return f.CaptureBytes + f.MetadataBytes }

type DeletionPreview struct {
	Schema                    int               `json:"schema"`
	SessionID                 string            `json:"session_id"`
	PreviewSHA256             string            `json:"preview_sha256"`
	GeneratedAt               time.Time         `json:"generated_at"`
	ExpiresAt                 time.Time         `json:"expires_at"`
	State                     State             `json:"capture_state"`
	RetentionLock             bool              `json:"retention_lock"`
	Footprint                 DeletionFootprint `json:"footprint"`
	EstimatedRecoverableBytes int64             `json:"estimated_recoverable_bytes"`
	SharedPCAPCollateralKnown bool              `json:"shared_pcap_collateral_known"`
	DeletedDataClasses        []string          `json:"deleted_data_classes"`
	RetainedDataClasses       []string          `json:"retained_data_classes"`
	Confirmation              string            `json:"confirmation"`
}

type DeleteRequest struct {
	SessionID        string    `json:"session_id"`
	PreviewSHA256    string    `json:"preview_sha256"`
	PreviewExpiresAt time.Time `json:"preview_expires_at"`
	Confirmation     string    `json:"confirmation"`
	Administrator    string    `json:"administrator"`
	IdempotencyKey   string    `json:"idempotency_key"`
}

type DeletionJob struct {
	Schema                    int               `json:"schema"`
	ID                        string            `json:"id"`
	SessionID                 string            `json:"session_id"`
	State                     DeletionState     `json:"state"`
	Phase                     string            `json:"phase"`
	ProgressPercent           int               `json:"progress_percent"`
	Administrator             string            `json:"administrator"`
	PreviewSHA256             string            `json:"preview_sha256"`
	Footprint                 DeletionFootprint `json:"footprint"`
	SharedPCAPCollateralKnown bool              `json:"shared_pcap_collateral_known"`
	RetainedDataClasses       []string          `json:"retained_data_classes"`
	CreatedAt                 time.Time         `json:"created_at"`
	UpdatedAt                 time.Time         `json:"updated_at"`
	CompletedAt               *time.Time        `json:"completed_at,omitempty"`
	Failure                   string            `json:"failure,omitempty"`
	RemainingFiles            int               `json:"remaining_files"`
	RemainingBytes            int64             `json:"remaining_bytes"`
}

type deletionJobRecord struct {
	Job            DeletionJob `json:"job"`
	IdempotencyKey string      `json:"idempotency_key"`
	RequestSHA256  string      `json:"request_sha256"`
}

type deletionReceipt struct {
	Schema        int       `json:"schema"`
	SessionID     string    `json:"session_id"`
	JobID         string    `json:"job_id"`
	PreviewSHA256 string    `json:"preview_sha256"`
	Administrator string    `json:"administrator"`
	DeletedAt     time.Time `json:"deleted_at"`
}

type deletionEvidence struct {
	Schema        int               `json:"schema"`
	SessionID     string            `json:"session_id"`
	State         State             `json:"capture_state"`
	RetentionLock bool              `json:"retention_lock"`
	ManifestHash  string            `json:"manifest_sha256"`
	Footprint     DeletionFootprint `json:"footprint"`
	ExpiresAt     time.Time         `json:"expires_at"`
}

var deletionJobIDPattern = regexp.MustCompile(`^capture-delete-[a-f0-9]{32}$`)

func (m *Manager) PreviewDeletion(ctx context.Context, id string) (DeletionPreview, error) {
	return m.previewDeletion(ctx, id, m.now().Add(DeletionPreviewLifetime))
}

func (m *Manager) PreviewDeletionUntil(ctx context.Context, id string, expiresAt time.Time) (DeletionPreview, error) {
	return m.previewDeletion(ctx, id, expiresAt)
}

func (m *Manager) previewDeletion(ctx context.Context, id string, expiresAt time.Time) (DeletionPreview, error) {
	if !ValidSessionID(id) {
		return DeletionPreview{}, errors.New("invalid capture session ID")
	}
	view, err := m.Get(ctx, id)
	if err != nil {
		return DeletionPreview{}, err
	}
	if view.Active {
		return DeletionPreview{}, errors.New("active captures cannot be deleted")
	}
	if view.Manifest == nil || (view.State != StateCompleted && view.State != StateStopped && view.State != StateStoragePressure && view.State != StateFailed) {
		return DeletionPreview{}, errors.New("capture must be finalized before deletion preview")
	}
	footprint, manifestHash, err := m.Store.DeletionFootprint(id, *view.Manifest)
	if err != nil {
		return DeletionPreview{}, err
	}
	now := m.now()
	expiresAt = expiresAt.UTC()
	if !expiresAt.After(now) || expiresAt.After(now.Add(DeletionPreviewLifetime)) {
		return DeletionPreview{}, errors.New("capture deletion preview expiry is invalid")
	}
	retentionLock, _, err := m.effectiveRetentionLock(id, view.Session.Request.RetentionLock)
	if err != nil {
		return DeletionPreview{}, err
	}
	evidence := deletionEvidence{Schema: 1, SessionID: id, State: view.State, RetentionLock: retentionLock, ManifestHash: manifestHash, Footprint: footprint, ExpiresAt: expiresAt}
	hash, err := hashJSON(evidence)
	if err != nil {
		return DeletionPreview{}, err
	}
	return DeletionPreview{
		Schema: 1, SessionID: id, PreviewSHA256: hash, GeneratedAt: now, ExpiresAt: expiresAt,
		State: view.State, RetentionLock: retentionLock, Footprint: footprint,
		EstimatedRecoverableBytes: footprint.TotalBytes(), SharedPCAPCollateralKnown: false,
		DeletedDataClasses:  []string{"capture_session_metadata", "pcap_artifacts"},
		RetainedDataClasses: retainedCaptureDeletionClasses(), Confirmation: id,
	}, nil
}

func (m *Manager) Delete(ctx context.Context, request DeleteRequest) (DeletionJob, error) {
	m.deletionMu.Lock()
	defer m.deletionMu.Unlock()
	if !ValidSessionID(request.SessionID) || request.Confirmation != request.SessionID || !validSHA256String(request.PreviewSHA256) || !validOpaqueKey(request.IdempotencyKey) {
		return DeletionJob{}, errors.New("capture deletion request is invalid")
	}
	if err := validateText("administrator", request.Administrator, 1, 96); err != nil {
		return DeletionJob{}, err
	}
	requestHash, err := hashJSON(request)
	if err != nil {
		return DeletionJob{}, err
	}
	records, err := m.Store.ListDeletionJobRecords()
	if err != nil {
		return DeletionJob{}, err
	}
	for _, record := range records {
		if record.IdempotencyKey != request.IdempotencyKey {
			continue
		}
		if record.RequestSHA256 != requestHash {
			return DeletionJob{}, errors.New("capture deletion idempotency key conflicts with an existing request")
		}
		return record.Job, nil
	}
	if len(records) >= MaxDeletionJobs {
		return DeletionJob{}, errors.New("capture deletion job limit exceeded")
	}
	preview, err := m.previewDeletion(ctx, request.SessionID, request.PreviewExpiresAt)
	if err != nil {
		return DeletionJob{}, err
	}
	if preview.PreviewSHA256 != request.PreviewSHA256 {
		return DeletionJob{}, errors.New("capture deletion preview is stale")
	}
	if preview.RetentionLock {
		return DeletionJob{}, errors.New("capture retention lock prevents deletion")
	}
	jobID, err := newUniqueDeletionJobID(records, m.Random)
	if err != nil {
		return DeletionJob{}, err
	}
	now := m.now()
	job := DeletionJob{Schema: 1, ID: jobID, SessionID: request.SessionID, State: DeletionPending, Phase: "RECORDING_INTENT", ProgressPercent: 5, Administrator: request.Administrator, PreviewSHA256: request.PreviewSHA256, Footprint: preview.Footprint, SharedPCAPCollateralKnown: false, RetainedDataClasses: retainedCaptureDeletionClasses(), CreatedAt: now, UpdatedAt: now, RemainingFiles: preview.Footprint.TotalFiles(), RemainingBytes: preview.Footprint.TotalBytes()}
	record := deletionJobRecord{Job: job, IdempotencyKey: request.IdempotencyKey, RequestSHA256: requestHash}
	if err := m.Store.WriteDeletionJobRecord(record); err != nil {
		return DeletionJob{}, err
	}
	job.State, job.Phase, job.ProgressPercent, job.UpdatedAt = DeletionVerifying, "VERIFYING_PREVIEW", 20, m.now()
	record.Job = job
	if err := m.Store.WriteDeletionJobRecord(record); err != nil {
		return m.failDeletion(record, "RECORDING_VERIFICATION", err)
	}
	if err := m.Store.WriteDeletionReceipt(deletionReceipt{Schema: 1, SessionID: request.SessionID, JobID: job.ID, PreviewSHA256: preview.PreviewSHA256, Administrator: request.Administrator, DeletedAt: time.Time{}}); err != nil {
		return m.failDeletion(record, "RECORDING_RECEIPT", err)
	}
	if err := ctx.Err(); err != nil {
		return m.failDeletion(record, "VERIFYING_PREVIEW", err)
	}
	_, err = m.Store.QuarantineSession(request.SessionID, job.ID)
	if err != nil {
		return m.failDeletion(record, "QUARANTINING_CAPTURE", err)
	}
	job.State, job.Phase, job.ProgressPercent, job.UpdatedAt = DeletionDeleting, "DELETING_CAPTURE", 65, m.now()
	record.Job = job
	if err := m.Store.WriteDeletionJobRecord(record); err != nil {
		return m.failDeletion(record, "RECORDING_DELETION", err)
	}
	if err := ctx.Err(); err != nil {
		return m.failDeletion(record, "DELETING_CAPTURE", err)
	}
	if err := m.Store.RemoveQuarantinedSession(job.ID); err != nil {
		return m.failDeletion(record, "DELETING_CAPTURE", err)
	}
	if exists, err := m.Store.SessionOrQuarantineExists(request.SessionID, job.ID); err != nil || exists {
		if err == nil {
			err = errors.New("capture files remain after deletion")
		}
		return m.failDeletion(record, "VERIFYING_DELETION", err)
	}
	completedAt := m.now()
	if err := m.Store.WriteDeletionReceipt(deletionReceipt{Schema: 1, SessionID: request.SessionID, JobID: job.ID, PreviewSHA256: preview.PreviewSHA256, Administrator: request.Administrator, DeletedAt: completedAt}); err != nil {
		return m.failDeletion(record, "FINALIZING_RECEIPT", err)
	}
	job.State, job.Phase, job.ProgressPercent, job.UpdatedAt, job.CompletedAt = DeletionCompleted, "VERIFIED", 100, completedAt, &completedAt
	job.RemainingFiles, job.RemainingBytes = 0, 0
	record.Job = job
	if err := m.Store.WriteDeletionJobRecord(record); err != nil {
		return m.failDeletion(record, "RECORDING_COMPLETION", err)
	}
	return job, nil
}

func (m *Manager) ListDeletionJobs() ([]DeletionJob, error) {
	records, err := m.Store.ListDeletionJobRecords()
	if err != nil {
		return nil, err
	}
	jobs := make([]DeletionJob, len(records))
	for index := range records {
		jobs[index] = records[index].Job
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].CreatedAt.After(jobs[j].CreatedAt) })
	return jobs, nil
}

func (m *Manager) failDeletion(record deletionJobRecord, phase string, cause error) (DeletionJob, error) {
	record.Job.State, record.Job.Phase, record.Job.UpdatedAt, record.Job.Failure = DeletionFailed, phase, m.now(), "capture artifact deletion did not complete"
	record.Job.CompletedAt = nil
	if record.Job.ProgressPercent >= 100 {
		record.Job.ProgressPercent = 99
	}
	if files, bytes, err := m.Store.DeletionRemaining(record.Job.SessionID, record.Job.ID); err == nil {
		record.Job.RemainingFiles, record.Job.RemainingBytes = files, bytes
	}
	_ = m.Store.WriteDeletionJobRecord(record)
	return record.Job, fmt.Errorf("%s: %w", strings.ToLower(strings.ReplaceAll(phase, "_", " ")), cause)
}

func (s Store) DeletionFootprint(id string, manifest Manifest) (DeletionFootprint, string, error) {
	if !ValidSessionID(id) || manifest.SessionID != id || manifest.Schema != SchemaVersion {
		return DeletionFootprint{}, "", errors.New("capture deletion manifest is invalid")
	}
	directory, err := s.SessionDirectory(id)
	if err != nil {
		return DeletionFootprint{}, "", err
	}
	rootEntries, err := os.ReadDir(directory)
	if err != nil {
		return DeletionFootprint{}, "", err
	}
	if len(rootEntries) < 3 || len(rootEntries) > 4 {
		return DeletionFootprint{}, "", errors.New("capture directory footprint is incomplete")
	}
	allowedRoot := map[string]bool{"session.json": false, "hold.json": false, "artifacts": true, "runtime": true}
	for _, entry := range rootEntries {
		expectsDirectory, allowed := allowedRoot[entry.Name()]
		if !allowed {
			return DeletionFootprint{}, "", errors.New("capture directory contains an unexpected entry")
		}
		if entry.IsDir() != expectsDirectory {
			return DeletionFootprint{}, "", errors.New("capture directory structure is invalid")
		}
	}
	var footprint DeletionFootprint
	metadataPaths := []string{filepath.Join(directory, "session.json"), filepath.Join(directory, "runtime", "worker-status.json"), filepath.Join(directory, "runtime", "manifest.json")}
	if _, err := os.Lstat(filepath.Join(directory, "hold.json")); err == nil {
		if _, err := s.ReadEvidenceHold(id); err != nil {
			return DeletionFootprint{}, "", errors.New("capture evidence hold footprint is invalid")
		}
		metadataPaths = append(metadataPaths, filepath.Join(directory, "hold.json"))
	} else if !errors.Is(err, os.ErrNotExist) {
		return DeletionFootprint{}, "", err
	}
	runtimeMetadataCount := 2
	activeFeedPath := filepath.Join(directory, "runtime", "active-segments.json")
	if _, err := os.Lstat(activeFeedPath); err == nil {
		if _, err := s.ReadActiveSegmentFeed(id); err != nil {
			return DeletionFootprint{}, "", errors.New("capture active segment feed footprint is invalid")
		}
		metadataPaths = append(metadataPaths, activeFeedPath)
		runtimeMetadataCount++
	} else if !errors.Is(err, os.ErrNotExist) {
		return DeletionFootprint{}, "", err
	}
	for _, path := range metadataPaths {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maxMetadataBytes {
			return DeletionFootprint{}, "", errors.New("capture metadata footprint is invalid")
		}
		footprint.MetadataFiles++
		footprint.MetadataBytes += info.Size()
	}
	artifactDirectory := filepath.Join(directory, "artifacts")
	for _, child := range []string{artifactDirectory, filepath.Join(directory, "runtime")} {
		info, err := os.Lstat(child)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return DeletionFootprint{}, "", errors.New("capture deletion directory is invalid")
		}
	}
	runtimeEntries, err := os.ReadDir(filepath.Join(directory, "runtime"))
	if err != nil || len(runtimeEntries) != runtimeMetadataCount {
		return DeletionFootprint{}, "", errors.New("capture runtime footprint is invalid")
	}
	for _, entry := range runtimeEntries {
		if entry.IsDir() || entry.Name() != "worker-status.json" && entry.Name() != "manifest.json" && entry.Name() != "active-segments.json" {
			return DeletionFootprint{}, "", errors.New("capture runtime contains an unexpected entry")
		}
	}
	artifactEntries, err := os.ReadDir(artifactDirectory)
	if err != nil {
		return DeletionFootprint{}, "", err
	}
	manifestFiles := make(map[string]CaptureFile, len(manifest.Files))
	for _, file := range manifest.Files {
		if !captureFileName(file.Name) || file.SizeBytes < 0 || !validSHA256String(file.SHA256) || file.PacketMembership != nil && file.PacketMembership.Validate() != nil || file.RewriteManifestID != "" && !ValidPCAPRewriteID(file.RewriteManifestID) {
			return DeletionFootprint{}, "", errors.New("capture deletion manifest file is invalid")
		}
		if _, duplicate := manifestFiles[file.Name]; duplicate {
			return DeletionFootprint{}, "", errors.New("capture deletion manifest contains duplicates")
		}
		manifestFiles[file.Name] = file
	}
	for _, entry := range artifactEntries {
		file, exists := manifestFiles[entry.Name()]
		info, infoErr := entry.Info()
		if !exists || infoErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != file.SizeBytes || !info.ModTime().Equal(file.Modified) {
			return DeletionFootprint{}, "", errors.New("capture artifact footprint no longer matches its manifest")
		}
		footprint.CaptureFiles++
		footprint.CaptureBytes += info.Size()
	}
	if footprint.CaptureFiles != len(manifestFiles) || footprint.CaptureBytes != manifest.TotalSizeBytes {
		return DeletionFootprint{}, "", errors.New("capture artifact footprint is incomplete")
	}
	manifestHash, err := hashJSON(manifest)
	return footprint, manifestHash, err
}

func (s Store) WriteDeletionJobRecord(record deletionJobRecord) error {
	if err := validateDeletionJobRecord(record); err != nil {
		return err
	}
	directory, err := s.deletionDirectory(".deletion-jobs")
	if err != nil {
		return err
	}
	return writeJSONAtomic(directory, record.Job.ID+".json", record, 0o640)
}

func (s Store) ListDeletionJobRecords() ([]deletionJobRecord, error) {
	directory, err := s.deletionDirectory(".deletion-jobs")
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	if len(entries) > MaxDeletionJobs {
		return nil, errors.New("capture deletion job limit exceeded")
	}
	records := make([]deletionJobRecord, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || !deletionJobIDPattern.MatchString(strings.TrimSuffix(entry.Name(), ".json")) {
			return nil, errors.New("capture deletion job directory contains an invalid entry")
		}
		var record deletionJobRecord
		if err := readBoundedJSON(filepath.Join(directory, entry.Name()), &record); err != nil || validateDeletionJobRecord(record) != nil {
			return nil, errors.New("capture deletion job record is invalid")
		}
		records = append(records, record)
	}
	return records, nil
}

func (s Store) WriteDeletionReceipt(receipt deletionReceipt) error {
	if receipt.Schema != 1 || !ValidSessionID(receipt.SessionID) || !deletionJobIDPattern.MatchString(receipt.JobID) || !validSHA256String(receipt.PreviewSHA256) || receipt.Administrator == "" || len(receipt.Administrator) > 96 {
		return errors.New("capture deletion receipt is invalid")
	}
	directory, err := s.deletionDirectory(".deleted-sessions")
	if err != nil {
		return err
	}
	return writeJSONAtomic(directory, receipt.SessionID+".json", receipt, 0o640)
}

func (s Store) HasDeletionReceipt(sessionID string) (bool, error) {
	if !ValidSessionID(sessionID) {
		return false, errors.New("capture session ID is invalid")
	}
	directory, err := s.deletionDirectory(".deleted-sessions")
	if err != nil {
		return false, err
	}
	path := filepath.Join(directory, sessionID+".json")
	var receipt deletionReceipt
	if err := readBoundedJSON(path, &receipt); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if receipt.Schema != 1 || receipt.SessionID != sessionID || !deletionJobIDPattern.MatchString(receipt.JobID) || !validSHA256String(receipt.PreviewSHA256) {
		return false, errors.New("capture deletion receipt is invalid")
	}
	return true, nil
}

func (s Store) QuarantineSession(sessionID, jobID string) (string, error) {
	if !ValidSessionID(sessionID) || !deletionJobIDPattern.MatchString(jobID) {
		return "", errors.New("capture deletion quarantine identity is invalid")
	}
	source, err := s.SessionDirectory(sessionID)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(source)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("capture deletion source is invalid")
	}
	directory, err := s.deletionDirectory(".deleting")
	if err != nil {
		return "", err
	}
	target := filepath.Join(directory, jobID)
	if _, err := os.Lstat(target); err == nil || !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("capture deletion quarantine target already exists")
	}
	if err := os.Rename(source, target); err != nil {
		return "", err
	}
	return target, nil
}

func (s Store) RemoveQuarantinedSession(jobID string) error {
	if !deletionJobIDPattern.MatchString(jobID) {
		return errors.New("capture deletion job ID is invalid")
	}
	directory, err := s.deletionDirectory(".deleting")
	if err != nil {
		return err
	}
	target := filepath.Join(directory, jobID)
	info, err := os.Lstat(target)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || filepath.Dir(target) != directory {
		return errors.New("quarantined capture directory is invalid")
	}
	return os.RemoveAll(target)
}

func (s Store) SessionOrQuarantineExists(sessionID, jobID string) (bool, error) {
	session, err := s.SessionDirectory(sessionID)
	if err != nil {
		return false, err
	}
	deleting, err := s.deletionDirectory(".deleting")
	if err != nil {
		return false, err
	}
	for _, path := range []string{session, filepath.Join(deleting, jobID)} {
		_, statErr := os.Lstat(path)
		if statErr == nil {
			return true, nil
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			return false, statErr
		}
	}
	return false, nil
}

func (s Store) DeletionRemaining(sessionID, jobID string) (int, int64, error) {
	if !ValidSessionID(sessionID) || !deletionJobIDPattern.MatchString(jobID) {
		return 0, 0, errors.New("capture deletion identity is invalid")
	}
	session, err := s.SessionDirectory(sessionID)
	if err != nil {
		return 0, 0, err
	}
	deleting, err := s.deletionDirectory(".deleting")
	if err != nil {
		return 0, 0, err
	}
	files := 0
	var bytes int64
	for _, root := range []string{session, filepath.Join(deleting, jobID)} {
		info, statErr := os.Lstat(root)
		if errors.Is(statErr, os.ErrNotExist) {
			continue
		}
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return 0, 0, errors.New("capture deletion remainder is invalid")
		}
		walkErr := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			info, err := entry.Info()
			if err != nil || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("capture deletion remainder contains an unsafe entry")
			}
			if info.IsDir() {
				return nil
			}
			if !info.Mode().IsRegular() {
				return errors.New("capture deletion remainder contains a non-regular file")
			}
			files++
			bytes += info.Size()
			return nil
		})
		if walkErr != nil {
			return 0, 0, walkErr
		}
	}
	return files, bytes, nil
}

func (s Store) deletionDirectory(name string) (string, error) {
	if name != ".deletion-jobs" && name != ".deleted-sessions" && name != ".deleting" {
		return "", errors.New("capture deletion directory is invalid")
	}
	if err := s.ensureRoot(); err != nil {
		return "", err
	}
	path := filepath.Join(s.Root, name)
	if err := os.Mkdir(path, 0o750); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("capture deletion state directory is unsafe")
	}
	return path, nil
}

func validateDeletionJobRecord(record deletionJobRecord) error {
	job := record.Job
	if job.Schema != 1 || !deletionJobIDPattern.MatchString(job.ID) || !ValidSessionID(job.SessionID) || !validOpaqueKey(record.IdempotencyKey) || !validSHA256String(record.RequestSHA256) || !validSHA256String(job.PreviewSHA256) || validateText("administrator", job.Administrator, 1, 96) != nil || validateText("deletion phase", job.Phase, 1, 64) != nil || len(job.Failure) > 256 || job.CreatedAt.IsZero() || job.UpdatedAt.Before(job.CreatedAt) || job.ProgressPercent < 0 || job.ProgressPercent > 100 || job.RemainingFiles < 0 || job.RemainingBytes < 0 || job.Footprint.CaptureFiles < 0 || job.Footprint.CaptureFiles > maxCaptureFiles || job.Footprint.CaptureBytes < 0 || job.Footprint.MetadataFiles != 3 || job.Footprint.MetadataBytes < 0 || job.Footprint.MetadataBytes > 3*maxMetadataBytes || !equalStrings(job.RetainedDataClasses, retainedCaptureDeletionClasses()) {
		return errors.New("capture deletion job record is invalid")
	}
	switch job.State {
	case DeletionPending, DeletionVerifying, DeletionDeleting, DeletionFailed:
		if job.CompletedAt != nil {
			return errors.New("unfinished capture deletion job has completion time")
		}
	case DeletionCompleted:
		if job.CompletedAt == nil || job.CompletedAt.IsZero() || job.CompletedAt.Before(job.CreatedAt) || job.ProgressPercent != 100 || job.RemainingFiles != 0 || job.RemainingBytes != 0 {
			return errors.New("completed capture deletion job is incomplete")
		}
	default:
		return errors.New("capture deletion job state is invalid")
	}
	return nil
}

func retainedCaptureDeletionClasses() []string {
	return []string{"normalized_event_metadata", "analyzer_checkpoints", "capture_export_audit", "external_exported_copies"}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func newUniqueDeletionJobID(records []deletionJobRecord, random func([]byte) (int, error)) (string, error) {
	if random == nil {
		random = rand.Read
	}
	existing := make(map[string]struct{}, len(records))
	for _, record := range records {
		existing[record.Job.ID] = struct{}{}
	}
	for attempt := 0; attempt < 8; attempt++ {
		value := make([]byte, 16)
		count, err := random(value)
		if err != nil || count != len(value) {
			return "", errors.New("generate capture deletion job ID")
		}
		id := "capture-delete-" + hex.EncodeToString(value)
		if _, duplicate := existing[id]; !duplicate {
			return id, nil
		}
	}
	return "", errors.New("generate unique capture deletion job ID")
}

func validSHA256String(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func hashJSON(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func manifestFileSHA256(manifest Manifest) (string, error) {
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", err
	}
	encoded = append(encoded, '\n')
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func readBoundedJSON(path string, destination any) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maxMetadataBytes {
		return errors.New("capture deletion metadata is not a bounded regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("capture deletion metadata contains trailing data")
	}
	return nil
}
