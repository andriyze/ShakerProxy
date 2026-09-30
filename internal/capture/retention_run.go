package capture

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const MaxRetentionRuns = 1024

type RetentionRunState string
type RetentionRunItemState string
type RetentionRunTrigger string

const (
	RetentionRunPending   RetentionRunState = "PENDING"
	RetentionRunRunning   RetentionRunState = "RUNNING"
	RetentionRunCompleted RetentionRunState = "COMPLETED"
	RetentionRunPartial   RetentionRunState = "PARTIAL"
	RetentionRunFailed    RetentionRunState = "FAILED"

	RetentionItemPending RetentionRunItemState = "PENDING"
	RetentionItemDeleted RetentionRunItemState = "DELETED"
	RetentionItemFailed  RetentionRunItemState = "FAILED"

	RetentionTriggerManual    RetentionRunTrigger = "MANUAL"
	RetentionTriggerAutomatic RetentionRunTrigger = "AUTOMATIC"
)

type StartRetentionRunRequest struct {
	PolicyRevision   uint64              `json:"policy_revision"`
	PreviewSHA256    string              `json:"preview_sha256"`
	PreviewExpiresAt time.Time           `json:"preview_expires_at"`
	Administrator    string              `json:"administrator"`
	IdempotencyKey   string              `json:"idempotency_key"`
	Trigger          RetentionRunTrigger `json:"trigger"`
	ScheduledFor     *time.Time          `json:"scheduled_for,omitempty"`
}

type RetentionRunItem struct {
	SessionID                string                `json:"session_id"`
	Name                     string                `json:"name"`
	Reasons                  []string              `json:"reasons"`
	Footprint                DeletionFootprint     `json:"footprint"`
	State                    RetentionRunItemState `json:"state"`
	DeletionPreviewSHA256    string                `json:"deletion_preview_sha256"`
	DeletionPreviewExpiresAt time.Time             `json:"deletion_preview_expires_at"`
	DeletionIdempotencyKey   string                `json:"deletion_idempotency_key"`
	DeletionJobID            string                `json:"deletion_job_id,omitempty"`
	CoordinatedDeletionJobID string                `json:"coordinated_deletion_job_id,omitempty"`
	Failure                  string                `json:"failure,omitempty"`
	UpdatedAt                time.Time             `json:"updated_at"`
}

type RetentionRun struct {
	Schema           int                  `json:"schema"`
	ID               string               `json:"id"`
	State            RetentionRunState    `json:"state"`
	Phase            string               `json:"phase"`
	PolicyRevision   uint64               `json:"policy_revision"`
	Policy           RetentionPolicyInput `json:"policy"`
	PreviewSHA256    string               `json:"preview_sha256"`
	Administrator    string               `json:"administrator"`
	Trigger          RetentionRunTrigger  `json:"trigger"`
	ScheduledFor     *time.Time           `json:"scheduled_for,omitempty"`
	Items            []RetentionRunItem   `json:"items"`
	SelectedSessions int                  `json:"selected_sessions"`
	DeletedSessions  int                  `json:"deleted_sessions"`
	FailedSessions   int                  `json:"failed_sessions"`
	RemainingFiles   int                  `json:"remaining_files"`
	RemainingBytes   int64                `json:"remaining_bytes"`
	CreatedAt        time.Time            `json:"created_at"`
	UpdatedAt        time.Time            `json:"updated_at"`
	CompletedAt      *time.Time           `json:"completed_at,omitempty"`
}

type retentionRunRecord struct {
	Run            RetentionRun `json:"run"`
	IdempotencyKey string       `json:"idempotency_key"`
	RequestSHA256  string       `json:"request_sha256"`
}

type RecordRetentionItemOutcomeRequest struct {
	RunID                    string                `json:"run_id"`
	SessionID                string                `json:"session_id"`
	State                    RetentionRunItemState `json:"state"`
	CoordinatedDeletionJobID string                `json:"coordinated_deletion_job_id,omitempty"`
	DeletionJobID            string                `json:"deletion_job_id,omitempty"`
	Failure                  string                `json:"failure,omitempty"`
}

var retentionRunIDPattern = regexp.MustCompile(`^retention-run-[a-f0-9]{32}$`)
var coordinatedRetentionDeletionIDPattern = regexp.MustCompile(`^capture-delete-operation-[a-f0-9]{32}$`)

func (m *Manager) StartRetentionRun(ctx context.Context, request StartRetentionRunRequest) (RetentionRun, error) {
	m.retentionRunMu.Lock()
	defer m.retentionRunMu.Unlock()
	record, err := m.planRetentionRunLocked(ctx, request)
	if err != nil {
		return RetentionRun{}, err
	}
	return m.executeRetentionRunLocked(ctx, record)
}

func (m *Manager) PlanRetentionRun(ctx context.Context, request StartRetentionRunRequest) (RetentionRun, error) {
	m.retentionRunMu.Lock()
	defer m.retentionRunMu.Unlock()
	record, err := m.planRetentionRunLocked(ctx, request)
	if err != nil {
		return RetentionRun{}, err
	}
	return record.Run, nil
}

func (m *Manager) planRetentionRunLocked(ctx context.Context, request StartRetentionRunRequest) (retentionRunRecord, error) {
	if !validSHA256String(request.PreviewSHA256) || !validOpaqueKey(request.IdempotencyKey) || request.PolicyRevision == 0 || request.PreviewExpiresAt.IsZero() || validateText("administrator", request.Administrator, 1, 96) != nil || !validRetentionRunTrigger(request.Trigger, request.ScheduledFor, request.Administrator) {
		return retentionRunRecord{}, errors.New("capture retention run request is invalid")
	}
	requestHash, err := hashJSON(request)
	if err != nil {
		return retentionRunRecord{}, err
	}
	records, err := m.Store.ListRetentionRunRecords()
	if err != nil {
		return retentionRunRecord{}, err
	}
	for _, record := range records {
		if record.IdempotencyKey != request.IdempotencyKey {
			continue
		}
		if record.RequestSHA256 != requestHash {
			return retentionRunRecord{}, errors.New("capture retention run idempotency key conflicts with an existing request")
		}
		return record, nil
	}
	if len(records) >= MaxRetentionRuns {
		// Every scheduled slot records a run, even when nothing is selected, so
		// a bounded history must be pruned or automatic retention stops for
		// good (after about six weeks at the default hourly cadence).
		records, err = m.Store.pruneRetentionRunRecords(records, MaxRetentionRuns-retentionRunPruneHeadroom)
		if err != nil {
			return retentionRunRecord{}, err
		}
	}
	if len(records) >= MaxRetentionRuns {
		return retentionRunRecord{}, errors.New("capture retention run limit exceeded")
	}
	policy, err := m.GetRetentionPolicy()
	if err != nil {
		return retentionRunRecord{}, err
	}
	if policy.Revision != request.PolicyRevision {
		return retentionRunRecord{}, errors.New("capture retention policy revision conflict")
	}
	if request.Trigger == RetentionTriggerAutomatic {
		scheduledFor, due := currentRetentionScheduleSlot(policy, m.now())
		if !policy.Enabled || !due || request.ScheduledFor == nil || !request.ScheduledFor.Equal(scheduledFor) {
			return retentionRunRecord{}, errors.New("automatic capture retention run is outside the current cadence slot")
		}
	}
	preview, err := m.previewRetention(ctx, policy.Rules, request.PreviewExpiresAt)
	if err != nil {
		return retentionRunRecord{}, err
	}
	if preview.PreviewSHA256 != request.PreviewSHA256 {
		return retentionRunRecord{}, errors.New("capture retention run preview is stale")
	}
	runID, err := newUniqueRetentionRunID(records, m.Random)
	if err != nil {
		return retentionRunRecord{}, err
	}
	now := m.now()
	run := RetentionRun{Schema: 1, ID: runID, State: RetentionRunPending, Phase: "RECORDING_INTENT", PolicyRevision: policy.Revision, Policy: policy.Rules, PreviewSHA256: preview.PreviewSHA256, Administrator: request.Administrator, Trigger: request.Trigger, ScheduledFor: request.ScheduledFor, Items: []RetentionRunItem{}, SelectedSessions: len(preview.Selected), CreatedAt: now, UpdatedAt: now}
	for _, candidate := range preview.Selected {
		deletionPreview, err := m.previewDeletion(ctx, candidate.SessionID, preview.ExpiresAt)
		if err != nil {
			return retentionRunRecord{}, err
		}
		keyHash, err := hashJSON(struct{ RunID, SessionID string }{runID, candidate.SessionID})
		if err != nil {
			return retentionRunRecord{}, err
		}
		item := RetentionRunItem{SessionID: candidate.SessionID, Name: candidate.Name, Reasons: append([]string(nil), candidate.Reasons...), Footprint: candidate.Footprint, State: RetentionItemPending, DeletionPreviewSHA256: deletionPreview.PreviewSHA256, DeletionPreviewExpiresAt: deletionPreview.ExpiresAt, DeletionIdempotencyKey: "retention-delete-" + keyHash[:32], UpdatedAt: now}
		run.Items = append(run.Items, item)
		run.RemainingFiles += item.Footprint.TotalFiles()
		run.RemainingBytes += item.Footprint.TotalBytes()
	}
	record := retentionRunRecord{Run: run, IdempotencyKey: request.IdempotencyKey, RequestSHA256: requestHash}
	if len(run.Items) == 0 {
		completedAt := m.now()
		record.Run.State, record.Run.Phase = RetentionRunCompleted, "VERIFIED"
		record.Run.UpdatedAt, record.Run.CompletedAt = completedAt, &completedAt
	}
	if err := m.Store.WriteRetentionRunRecord(record); err != nil {
		return retentionRunRecord{}, err
	}
	return record, nil
}

func (m *Manager) executeRetentionRunLocked(ctx context.Context, record retentionRunRecord) (RetentionRun, error) {
	if record.Run.State == RetentionRunCompleted || record.Run.State == RetentionRunPartial || record.Run.State == RetentionRunFailed {
		return record.Run, nil
	}
	record.Run.State, record.Run.Phase, record.Run.UpdatedAt = RetentionRunRunning, "DELETING_CAPTURES", m.now()
	if err := m.Store.WriteRetentionRunRecord(record); err != nil {
		return RetentionRun{}, err
	}
	for index := range record.Run.Items {
		item := &record.Run.Items[index]
		if item.State != RetentionItemPending {
			continue
		}
		job, err := m.Delete(ctx, DeleteRequest{SessionID: item.SessionID, PreviewSHA256: item.DeletionPreviewSHA256, PreviewExpiresAt: item.DeletionPreviewExpiresAt, Confirmation: item.SessionID, Administrator: record.Run.Administrator, IdempotencyKey: item.DeletionIdempotencyKey})
		item.UpdatedAt = m.now()
		if err != nil || job.State != DeletionCompleted {
			item.State, item.Failure = RetentionItemFailed, "capture artifact deletion did not complete"
			if job.ID != "" {
				item.DeletionJobID = job.ID
			}
			record.Run.FailedSessions++
		} else {
			item.State, item.DeletionJobID = RetentionItemDeleted, job.ID
			record.Run.DeletedSessions++
			record.Run.RemainingFiles -= item.Footprint.TotalFiles()
			record.Run.RemainingBytes -= item.Footprint.TotalBytes()
		}
		record.Run.UpdatedAt = item.UpdatedAt
		if writeErr := m.Store.WriteRetentionRunRecord(record); writeErr != nil {
			return record.Run, writeErr
		}
		if err := ctx.Err(); err != nil {
			return record.Run, err
		}
	}
	completedAt := m.now()
	record.Run.CompletedAt, record.Run.UpdatedAt, record.Run.Phase = &completedAt, completedAt, "VERIFIED"
	switch {
	case record.Run.FailedSessions == 0:
		record.Run.State = RetentionRunCompleted
	case record.Run.DeletedSessions == 0:
		record.Run.State = RetentionRunFailed
	default:
		record.Run.State = RetentionRunPartial
	}
	if err := m.Store.WriteRetentionRunRecord(record); err != nil {
		return record.Run, err
	}
	return record.Run, nil
}

func (m *Manager) RecordRetentionItemOutcome(request RecordRetentionItemOutcomeRequest) (RetentionRun, error) {
	m.retentionRunMu.Lock()
	defer m.retentionRunMu.Unlock()
	if !retentionRunIDPattern.MatchString(request.RunID) || !ValidSessionID(request.SessionID) {
		return RetentionRun{}, errors.New("capture retention item outcome request is invalid")
	}
	if request.State == RetentionItemDeleted {
		if !coordinatedRetentionDeletionIDPattern.MatchString(request.CoordinatedDeletionJobID) || !deletionJobIDPattern.MatchString(request.DeletionJobID) || request.Failure != "" {
			return RetentionRun{}, errors.New("completed capture retention item outcome is invalid")
		}
	} else if request.State == RetentionItemFailed {
		if request.CoordinatedDeletionJobID != "" && !coordinatedRetentionDeletionIDPattern.MatchString(request.CoordinatedDeletionJobID) || request.DeletionJobID != "" || validateText("capture retention item failure", request.Failure, 1, 256) != nil {
			return RetentionRun{}, errors.New("failed capture retention item outcome is invalid")
		}
	} else {
		return RetentionRun{}, errors.New("capture retention item outcome state is invalid")
	}
	records, err := m.Store.ListRetentionRunRecords()
	if err != nil {
		return RetentionRun{}, err
	}
	for _, record := range records {
		if record.Run.ID != request.RunID {
			continue
		}
		for index := range record.Run.Items {
			item := &record.Run.Items[index]
			if item.SessionID != request.SessionID {
				continue
			}
			if item.State != RetentionItemPending {
				if item.State == request.State && item.CoordinatedDeletionJobID == request.CoordinatedDeletionJobID && item.DeletionJobID == request.DeletionJobID && item.Failure == request.Failure {
					return record.Run, nil
				}
				return RetentionRun{}, errors.New("capture retention item outcome conflicts with immutable evidence")
			}
			if request.State == RetentionItemDeleted {
				hostJob, lookupErr := m.getDeletionJob(request.DeletionJobID)
				if lookupErr != nil || hostJob.State != DeletionCompleted || hostJob.SessionID != item.SessionID || hostJob.Administrator != record.Run.Administrator || hostJob.PreviewSHA256 != item.DeletionPreviewSHA256 || hostJob.Footprint != item.Footprint {
					return RetentionRun{}, errors.New("capture retention item lacks a matching host deletion acknowledgement")
				}
				item.State, item.CoordinatedDeletionJobID, item.DeletionJobID = RetentionItemDeleted, request.CoordinatedDeletionJobID, request.DeletionJobID
				record.Run.DeletedSessions++
				record.Run.RemainingFiles -= item.Footprint.TotalFiles()
				record.Run.RemainingBytes -= item.Footprint.TotalBytes()
			} else {
				item.State, item.CoordinatedDeletionJobID, item.Failure = RetentionItemFailed, request.CoordinatedDeletionJobID, request.Failure
				record.Run.FailedSessions++
			}
			now := m.now()
			item.UpdatedAt, record.Run.UpdatedAt = now, now
			completed := record.Run.DeletedSessions + record.Run.FailedSessions
			if completed < record.Run.SelectedSessions {
				record.Run.State, record.Run.Phase, record.Run.CompletedAt = RetentionRunRunning, "COORDINATING_DELETIONS", nil
			} else {
				record.Run.Phase, record.Run.CompletedAt = "VERIFIED", &now
				switch {
				case record.Run.FailedSessions == 0:
					record.Run.State = RetentionRunCompleted
				case record.Run.DeletedSessions == 0:
					record.Run.State = RetentionRunFailed
				default:
					record.Run.State = RetentionRunPartial
				}
			}
			if err := m.Store.WriteRetentionRunRecord(record); err != nil {
				return RetentionRun{}, err
			}
			return record.Run, nil
		}
		return RetentionRun{}, errors.New("capture retention run does not contain the session")
	}
	return RetentionRun{}, os.ErrNotExist
}

func (m *Manager) getDeletionJob(id string) (DeletionJob, error) {
	records, err := m.Store.ListDeletionJobRecords()
	if err != nil {
		return DeletionJob{}, err
	}
	for _, record := range records {
		if record.Job.ID == id {
			return record.Job, nil
		}
	}
	return DeletionJob{}, os.ErrNotExist
}

func (m *Manager) ListRetentionRuns() ([]RetentionRun, error) {
	records, err := m.Store.ListRetentionRunRecords()
	if err != nil {
		return nil, err
	}
	runs := make([]RetentionRun, len(records))
	for index := range records {
		runs[index] = records[index].Run
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].CreatedAt.After(runs[j].CreatedAt) })
	return runs, nil
}

func (m *Manager) ResumeRetentionRuns(ctx context.Context) ([]RetentionRun, error) {
	m.retentionRunMu.Lock()
	defer m.retentionRunMu.Unlock()
	records, err := m.Store.ListRetentionRunRecords()
	if err != nil {
		return nil, err
	}
	resumed := make([]RetentionRun, 0)
	for _, record := range records {
		if record.Run.State != RetentionRunPending && record.Run.State != RetentionRunRunning {
			continue
		}
		run, err := m.executeRetentionRunLocked(ctx, record)
		resumed = append(resumed, run)
		if err != nil {
			return resumed, err
		}
	}
	return resumed, nil
}

func (s Store) WriteRetentionRunRecord(record retentionRunRecord) error {
	if err := validateRetentionRunRecord(record); err != nil {
		return err
	}
	directory, err := s.retentionRunDirectory()
	if err != nil {
		return err
	}
	return writeJSONAtomic(directory, record.Run.ID+".json", record, 0o640)
}

func (s Store) ListRetentionRunRecords() ([]retentionRunRecord, error) {
	directory, err := s.retentionRunDirectory()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	if len(entries) > MaxRetentionRuns {
		return nil, errors.New("capture retention run limit exceeded")
	}
	records := make([]retentionRunRecord, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || !retentionRunIDPattern.MatchString(strings.TrimSuffix(entry.Name(), ".json")) {
			return nil, errors.New("capture retention run directory contains an invalid entry")
		}
		var record retentionRunRecord
		if err := readBoundedJSON(filepath.Join(directory, entry.Name()), &record); err != nil || validateRetentionRunRecord(record) != nil {
			return nil, errors.New("capture retention run record is invalid")
		}
		records = append(records, record)
	}
	return records, nil
}

// retentionRunPruneHeadroom is how many run records pruning frees at once so
// it does not run on every subsequent slot.
const retentionRunPruneHeadroom = 64

// pruneRetentionRunRecords removes the oldest finished run records until at
// most target remain. Runs that selected nothing carry no deletion evidence
// and are removed first; pending or running runs are never removed.
func (s Store) pruneRetentionRunRecords(records []retentionRunRecord, target int) ([]retentionRunRecord, error) {
	directory, err := s.retentionRunDirectory()
	if err != nil {
		return nil, err
	}
	candidates := make([]int, 0, len(records))
	for index, record := range records {
		switch record.Run.State {
		case RetentionRunCompleted, RetentionRunPartial, RetentionRunFailed:
			candidates = append(candidates, index)
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		left, right := records[candidates[i]].Run, records[candidates[j]].Run
		if (len(left.Items) == 0) != (len(right.Items) == 0) {
			return len(left.Items) == 0
		}
		if !left.CreatedAt.Equal(right.CreatedAt) {
			return left.CreatedAt.Before(right.CreatedAt)
		}
		return left.ID < right.ID
	})
	removed := make(map[string]bool)
	for _, index := range candidates {
		if len(records)-len(removed) <= target {
			break
		}
		id := records[index].Run.ID
		if err := os.Remove(filepath.Join(directory, id+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		removed[id] = true
	}
	if len(removed) == 0 {
		return records, nil
	}
	if err := syncDirectory(directory); err != nil {
		return nil, err
	}
	remaining := make([]retentionRunRecord, 0, len(records)-len(removed))
	for _, record := range records {
		if !removed[record.Run.ID] {
			remaining = append(remaining, record)
		}
	}
	return remaining, nil
}

func (s Store) retentionRunDirectory() (string, error) {
	root, err := s.retentionDirectory()
	if err != nil {
		return "", err
	}
	directory := filepath.Join(root, "runs")
	if err := os.Mkdir(directory, 0o750); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("capture retention run directory is unsafe")
	}
	return directory, nil
}

func validateRetentionRunRecord(record retentionRunRecord) error {
	run := record.Run
	if run.Schema != 1 || !retentionRunIDPattern.MatchString(run.ID) || !validOpaqueKey(record.IdempotencyKey) || !validSHA256String(record.RequestSHA256) || run.PolicyRevision == 0 || run.Policy.Validate() != nil || !validSHA256String(run.PreviewSHA256) || validateText("administrator", run.Administrator, 1, 96) != nil || !validRetentionRunTrigger(run.Trigger, run.ScheduledFor, run.Administrator) || len(run.Items) > MaxRetentionCandidates || run.SelectedSessions != len(run.Items) || run.DeletedSessions < 0 || run.FailedSessions < 0 || run.DeletedSessions+run.FailedSessions > len(run.Items) || run.RemainingFiles < 0 || run.RemainingBytes < 0 || run.CreatedAt.IsZero() || run.UpdatedAt.Before(run.CreatedAt) {
		return errors.New("capture retention run record is invalid")
	}
	deleted, failed, remainingFiles := 0, 0, 0
	var remainingBytes int64
	for _, item := range run.Items {
		if !ValidSessionID(item.SessionID) || validateText("capture name", item.Name, 1, 96) != nil || len(item.Reasons) < 1 || len(item.Reasons) > 2 || item.Footprint.MetadataFiles != 3 || !validSHA256String(item.DeletionPreviewSHA256) || item.DeletionPreviewExpiresAt.IsZero() || !validOpaqueKey(item.DeletionIdempotencyKey) || item.UpdatedAt.Before(run.CreatedAt) || len(item.Failure) > 256 || item.CoordinatedDeletionJobID != "" && !coordinatedRetentionDeletionIDPattern.MatchString(item.CoordinatedDeletionJobID) {
			return errors.New("capture retention run item is invalid")
		}
		switch item.State {
		case RetentionItemPending:
			if item.DeletionJobID != "" || item.CoordinatedDeletionJobID != "" || item.Failure != "" {
				return errors.New("pending retention item contains terminal evidence")
			}
			remainingFiles += item.Footprint.TotalFiles()
			remainingBytes += item.Footprint.TotalBytes()
		case RetentionItemDeleted:
			if !deletionJobIDPattern.MatchString(item.DeletionJobID) || item.Failure != "" {
				return errors.New("deleted retention item is invalid")
			}
			deleted++
		case RetentionItemFailed:
			if item.Failure == "" {
				return errors.New("failed retention item is invalid")
			}
			failed++
			remainingFiles += item.Footprint.TotalFiles()
			remainingBytes += item.Footprint.TotalBytes()
		default:
			return errors.New("capture retention item state is invalid")
		}
	}
	if deleted != run.DeletedSessions || failed != run.FailedSessions || remainingFiles != run.RemainingFiles || remainingBytes != run.RemainingBytes {
		return errors.New("capture retention run counters are invalid")
	}
	terminal := run.State == RetentionRunCompleted || run.State == RetentionRunPartial || run.State == RetentionRunFailed
	if terminal != (run.CompletedAt != nil) || terminal && (run.CompletedAt.IsZero() || run.CompletedAt.Before(run.CreatedAt)) {
		return errors.New("capture retention run completion is invalid")
	}
	return nil
}

func validRetentionRunTrigger(trigger RetentionRunTrigger, scheduledFor *time.Time, administrator string) bool {
	switch trigger {
	case RetentionTriggerManual:
		return scheduledFor == nil
	case RetentionTriggerAutomatic:
		return scheduledFor != nil && !scheduledFor.IsZero() && administrator == "system:retention"
	default:
		return false
	}
}

func newUniqueRetentionRunID(records []retentionRunRecord, random func([]byte) (int, error)) (string, error) {
	if random == nil {
		random = rand.Read
	}
	existing := make(map[string]struct{}, len(records))
	for _, record := range records {
		existing[record.Run.ID] = struct{}{}
	}
	for attempt := 0; attempt < 8; attempt++ {
		value := make([]byte, 16)
		count, err := random(value)
		if err != nil || count != len(value) {
			return "", errors.New("generate capture retention run ID")
		}
		id := "retention-run-" + hex.EncodeToString(value)
		if _, duplicate := existing[id]; !duplicate {
			return id, nil
		}
	}
	return "", fmt.Errorf("generate unique capture retention run ID")
}
