package capture

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"
)

type RetentionSchedulerStatus struct {
	Schema         int               `json:"schema"`
	Enabled        bool              `json:"enabled"`
	PolicyRevision uint64            `json:"policy_revision"`
	CheckedAt      time.Time         `json:"checked_at"`
	NextRunAt      *time.Time        `json:"next_run_at,omitempty"`
	LastRunID      string            `json:"last_run_id,omitempty"`
	LastRunState   RetentionRunState `json:"last_run_state,omitempty"`
	LastRunAt      *time.Time        `json:"last_run_at,omitempty"`
	LastFailure    string            `json:"last_failure,omitempty"`
	LastFailureAt  *time.Time        `json:"last_failure_at,omitempty"`
}

type RetentionSchedulerTick struct {
	Status RetentionSchedulerStatus `json:"status"`
	Run    *RetentionRun            `json:"run,omitempty"`
}

type retentionSchedulerEvidence struct {
	Schema        int        `json:"schema"`
	LastFailure   string     `json:"last_failure,omitempty"`
	LastFailureAt *time.Time `json:"last_failure_at,omitempty"`
}

func (m *Manager) RetentionSchedulerStatus() (RetentionSchedulerStatus, error) {
	policy, err := m.GetRetentionPolicy()
	if err != nil {
		return RetentionSchedulerStatus{}, err
	}
	runs, err := m.ListRetentionRuns()
	if err != nil {
		return RetentionSchedulerStatus{}, err
	}
	status := retentionSchedulerStatus(policy, runs, m.now())
	if err := m.Store.bindRetentionSchedulerEvidence(&status); err != nil {
		return RetentionSchedulerStatus{}, err
	}
	return status, nil
}

func (m *Manager) RunRetentionSchedulerOnce(ctx context.Context) (RetentionSchedulerStatus, *RetentionRun, error) {
	policy, err := m.GetRetentionPolicy()
	if err != nil {
		_ = m.Store.writeRetentionSchedulerFailure(m.now())
		return RetentionSchedulerStatus{}, nil, err
	}
	runs, err := m.ListRetentionRuns()
	if err != nil {
		_ = m.Store.writeRetentionSchedulerFailure(m.now())
		return RetentionSchedulerStatus{}, nil, err
	}
	now := m.now()
	status := retentionSchedulerStatus(policy, runs, now)
	if !policy.Enabled {
		_ = m.Store.clearRetentionSchedulerFailure()
		return status, nil, nil
	}
	scheduledFor, due := currentRetentionScheduleSlot(policy, now)
	if !due {
		_ = m.Store.clearRetentionSchedulerFailure()
		return status, nil, nil
	}
	for _, run := range runs {
		if run.Trigger == RetentionTriggerAutomatic && run.PolicyRevision == policy.Revision && run.ScheduledFor != nil && run.ScheduledFor.Equal(scheduledFor) {
			_ = m.Store.clearRetentionSchedulerFailure()
			return status, nil, nil
		}
	}
	preview, err := m.PreviewRetention(ctx, policy.Rules)
	if err != nil {
		_ = m.Store.writeRetentionSchedulerFailure(m.now())
		return status, nil, err
	}
	keyHash, err := hashJSON(struct {
		PolicyRevision uint64    `json:"policy_revision"`
		ScheduledFor   time.Time `json:"scheduled_for"`
	}{policy.Revision, scheduledFor})
	if err != nil {
		_ = m.Store.writeRetentionSchedulerFailure(m.now())
		return status, nil, err
	}
	run, err := m.PlanRetentionRun(ctx, StartRetentionRunRequest{PolicyRevision: policy.Revision, PreviewSHA256: preview.PreviewSHA256, PreviewExpiresAt: preview.ExpiresAt, Administrator: "system:retention", IdempotencyKey: "capture-retention-auto-" + keyHash[:32], Trigger: RetentionTriggerAutomatic, ScheduledFor: &scheduledFor})
	if err != nil {
		_ = m.Store.writeRetentionSchedulerFailure(m.now())
		return status, nil, err
	}
	updatedRuns := append([]RetentionRun{run}, runs...)
	status = retentionSchedulerStatus(policy, updatedRuns, m.now())
	_ = m.Store.clearRetentionSchedulerFailure()
	return status, &run, nil
}

func retentionSchedulerStatus(policy RetentionPolicy, runs []RetentionRun, now time.Time) RetentionSchedulerStatus {
	status := RetentionSchedulerStatus{Schema: 1, Enabled: policy.Enabled, PolicyRevision: policy.Revision, CheckedAt: now}
	if policy.Enabled {
		_, due := currentRetentionScheduleSlot(policy, now)
		if due {
			slot, _ := currentRetentionScheduleSlot(policy, now)
			next := slot.Add(time.Duration(policy.RunEverySeconds) * time.Second)
			status.NextRunAt = &next
		} else {
			next := policy.UpdatedAt.Add(time.Duration(policy.RunEverySeconds) * time.Second)
			status.NextRunAt = &next
		}
	}
	for _, run := range runs {
		if run.Trigger != RetentionTriggerAutomatic {
			continue
		}
		status.LastRunID, status.LastRunState = run.ID, run.State
		last := run.CreatedAt
		status.LastRunAt = &last
		break
	}
	return status
}

func currentRetentionScheduleSlot(policy RetentionPolicy, now time.Time) (time.Time, bool) {
	if !policy.Enabled || policy.Revision == 0 || policy.UpdatedAt.IsZero() || policy.RunEverySeconds < 300 {
		return time.Time{}, false
	}
	interval := time.Duration(policy.RunEverySeconds) * time.Second
	first := policy.UpdatedAt.Add(interval)
	if now.Before(first) {
		return first, false
	}
	elapsed := now.Sub(first)
	if elapsed < 0 {
		return time.Time{}, false
	}
	return first.Add((elapsed / interval) * interval), true
}

func validateRetentionSchedulerStatus(status RetentionSchedulerStatus) error {
	if status.Schema != 1 || status.CheckedAt.IsZero() || status.PolicyRevision == 0 && status.Enabled {
		return errors.New("capture retention scheduler status is invalid")
	}
	return nil
}

func (s Store) bindRetentionSchedulerEvidence(status *RetentionSchedulerStatus) error {
	directory, err := s.retentionDirectory()
	if err != nil {
		return err
	}
	var evidence retentionSchedulerEvidence
	if err := readBoundedJSON(filepath.Join(directory, "scheduler.json"), &evidence); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if evidence.Schema != 1 || evidence.LastFailure != "automatic retention check failed" || evidence.LastFailureAt == nil || evidence.LastFailureAt.IsZero() {
		return errors.New("capture retention scheduler evidence is invalid")
	}
	status.LastFailure, status.LastFailureAt = evidence.LastFailure, evidence.LastFailureAt
	return nil
}

func (s Store) writeRetentionSchedulerFailure(now time.Time) error {
	directory, err := s.retentionDirectory()
	if err != nil {
		return err
	}
	evidence := retentionSchedulerEvidence{Schema: 1, LastFailure: "automatic retention check failed", LastFailureAt: &now}
	return writeJSONAtomic(directory, "scheduler.json", evidence, 0o640)
}

func (s Store) clearRetentionSchedulerFailure() error {
	directory, err := s.retentionDirectory()
	if err != nil {
		return err
	}
	path := filepath.Join(directory, "scheduler.json")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return os.Remove(path)
}
