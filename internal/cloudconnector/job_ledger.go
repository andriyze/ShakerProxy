package cloudconnector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	jobLedgerFile       = "job-ledger.json"
	jobLedgerSchema     = 1
	maxJobLedgerBytes   = 256 << 10
	maxJobLedgerEntries = 128
	maxJobResultBytes   = 32 << 10
)

type jobLedger struct {
	SchemaVersion int              `json:"schema_version"`
	Entries       []jobLedgerEntry `json:"entries"`
}

type jobLedgerEntry struct {
	JobID          string         `json:"job_id"`
	IdempotencyKey string         `json:"idempotency_key"`
	JobType        string         `json:"job_type"`
	State          string         `json:"state"`
	Result         map[string]any `json:"result,omitempty"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

func (c Client) ProcessDiagnosticsJobs(ctx context.Context, appliedRevision uint64, buildVersion string) (SyncResponse, error) {
	capabilities := []string{DiagnosticsCapability}
	response, err := c.Sync(ctx, appliedRevision, capabilities)
	if err != nil {
		return SyncResponse{}, err
	}
	state, err := c.LoadState()
	if err != nil {
		return response, err
	}
	ledger, err := c.loadJobLedger()
	if err != nil {
		return response, err
	}
	executor := DiagnosticsExecutor{BuildVersion: buildVersion}

	for _, job := range response.Jobs {
		entry, found := ledger.lookup(job.ID)
		if found {
			if entry.IdempotencyKey != job.IdempotencyKey || entry.JobType != job.Type {
				return response, fmt.Errorf("job %q changed identity after delivery", job.ID)
			}
			if terminalJobStatus(entry.State) {
				if err := c.SendJobStatus(ctx, job.ID, entry.State, entry.Result); err != nil {
					return response, fmt.Errorf("replay terminal status for job %s: %w", job.ID, err)
				}
				continue
			}
		}

		if validationErr := ValidateDiagnosticsJob(job, state, appliedRevision, capabilities, c.now()); validationErr != nil {
			result := map[string]any{
				"reason": "validation_rejected",
				"detail": boundedError(validationErr),
			}
			if err := ledger.upsert(c, job, "REJECTED", result); err != nil {
				return response, err
			}
			if err := c.SendJobStatus(ctx, job.ID, "REJECTED", result); err != nil {
				return response, fmt.Errorf("report rejected job %s: %w", job.ID, err)
			}
			continue
		}

		if !found {
			if err := ledger.upsert(c, job, "DELIVERED", nil); err != nil {
				return response, err
			}
			if err := c.SendJobStatus(ctx, job.ID, "DELIVERED", nil); err != nil {
				return response, fmt.Errorf("acknowledge delivered job %s: %w", job.ID, err)
			}
		}

		// Persist RUNNING before contacting the cloud. If the status request is
		// lost, a later sync can safely retry diagnostics and resend RUNNING.
		if err := ledger.upsert(c, job, "RUNNING", nil); err != nil {
			return response, err
		}
		if err := c.SendJobStatus(ctx, job.ID, "RUNNING", nil); err != nil {
			return response, fmt.Errorf("start job %s: %w", job.ID, err)
		}

		executionCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		result, executionErr := executor.Execute(executionCtx, c)
		cancel()
		status := "SUCCEEDED"
		if executionErr != nil {
			status = "FAILED"
			result = map[string]any{
				"reason": "execution_failed",
				"detail": boundedError(executionErr),
			}
		}
		if err := validateJobResult(result); err != nil {
			status = "FAILED"
			result = map[string]any{
				"reason": "result_rejected",
				"detail": boundedError(err),
			}
		}

		// Terminal result is made durable before the network acknowledgement.
		// A lost response therefore causes a replay, not a second execution.
		if err := ledger.upsert(c, job, status, result); err != nil {
			return response, err
		}
		if err := c.SendJobStatus(ctx, job.ID, status, result); err != nil {
			return response, fmt.Errorf("report terminal status for job %s: %w", job.ID, err)
		}
	}
	return response, nil
}

func (c Client) loadJobLedger() (*jobLedger, error) {
	path := filepath.Join(c.Root, jobLedgerFile)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &jobLedger{SchemaVersion: jobLedgerSchema, Entries: []jobLedgerEntry{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read cloud job ledger: %w", err)
	}
	if len(data) > maxJobLedgerBytes {
		return nil, errors.New("cloud job ledger exceeds maximum size")
	}
	var ledger jobLedger
	if err := json.Unmarshal(data, &ledger); err != nil {
		return nil, fmt.Errorf("decode cloud job ledger: %w", err)
	}
	if ledger.SchemaVersion != jobLedgerSchema {
		return nil, errors.New("unsupported cloud job ledger schema")
	}
	if len(ledger.Entries) > maxJobLedgerEntries {
		return nil, errors.New("cloud job ledger contains too many entries")
	}
	seen := make(map[string]struct{}, len(ledger.Entries))
	for _, entry := range ledger.Entries {
		if entry.JobID == "" || entry.IdempotencyKey == "" || entry.JobType == "" || !knownLedgerState(entry.State) {
			return nil, errors.New("cloud job ledger contains an invalid entry")
		}
		if _, exists := seen[entry.JobID]; exists {
			return nil, errors.New("cloud job ledger contains duplicate job IDs")
		}
		seen[entry.JobID] = struct{}{}
		if err := validateJobResult(entry.Result); err != nil {
			return nil, fmt.Errorf("cloud job ledger result is invalid: %w", err)
		}
	}
	return &ledger, nil
}

func (l *jobLedger) lookup(jobID string) (jobLedgerEntry, bool) {
	for _, entry := range l.Entries {
		if entry.JobID == jobID {
			return entry, true
		}
	}
	return jobLedgerEntry{}, false
}

func (l *jobLedger) upsert(c Client, job CloudJob, state string, result map[string]any) error {
	if !knownLedgerState(state) {
		return errors.New("refusing to persist an unknown job state")
	}
	if err := validateJobResult(result); err != nil {
		return err
	}
	entry := jobLedgerEntry{
		JobID:          job.ID,
		IdempotencyKey: job.IdempotencyKey,
		JobType:        job.Type,
		State:          state,
		Result:         result,
		UpdatedAt:      c.now(),
	}
	updated := false
	for index := range l.Entries {
		if l.Entries[index].JobID != job.ID {
			continue
		}
		if l.Entries[index].IdempotencyKey != job.IdempotencyKey || l.Entries[index].JobType != job.Type {
			return errors.New("refusing to overwrite a job ledger entry with a different identity")
		}
		l.Entries[index] = entry
		updated = true
		break
	}
	if !updated {
		l.Entries = append(l.Entries, entry)
	}
	if len(l.Entries) > maxJobLedgerEntries {
		sort.Slice(l.Entries, func(i, j int) bool {
			return l.Entries[i].UpdatedAt.Before(l.Entries[j].UpdatedAt)
		})
		l.Entries = append([]jobLedgerEntry(nil), l.Entries[len(l.Entries)-maxJobLedgerEntries:]...)
	}
	return l.save(c)
}

func (l *jobLedger) save(c Client) error {
	encoded, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	if len(encoded) > maxJobLedgerBytes {
		return errors.New("cloud job ledger would exceed maximum size")
	}
	return atomicWrite(filepath.Join(c.Root, jobLedgerFile), append(encoded, '\n'), 0o600)
}

func validateJobResult(result map[string]any) error {
	if result == nil {
		return nil
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("encode job result: %w", err)
	}
	if len(encoded) > maxJobResultBytes {
		return errors.New("job result exceeds maximum size")
	}
	return nil
}

func terminalJobStatus(state string) bool {
	switch state {
	case "SUCCEEDED", "FAILED", "REJECTED":
		return true
	default:
		return false
	}
}

func knownLedgerState(state string) bool {
	switch state {
	case "DELIVERED", "RUNNING", "SUCCEEDED", "FAILED", "REJECTED":
		return true
	default:
		return false
	}
}

func boundedError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.TrimSpace(err.Error())
	if len(value) > 512 {
		return value[:512]
	}
	return value
}
