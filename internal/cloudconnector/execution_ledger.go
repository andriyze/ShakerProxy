package cloudconnector

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	executionLedgerSchema   = 1
	executionLedgerFile     = "execution-ledger.json"
	maxExecutionRecords     = 4096
	maxExecutionLedgerBytes = 4 << 20
)

type ExecutionRecord struct {
	JobID          string         `json:"job_id"`
	IdempotencyKey string         `json:"idempotency_key"`
	JobType        string         `json:"job_type"`
	State          string         `json:"state"`
	Result         map[string]any `json:"result,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	ExpiresAt      time.Time      `json:"expires_at"`
}

type executionLedgerDocument struct {
	SchemaVersion int               `json:"schema_version"`
	Records       []ExecutionRecord `json:"records"`
}

type ExecutionLedger struct {
	Root string
	Now  func() time.Time
	mu   sync.Mutex
}

func (ledger *ExecutionLedger) Get(jobID string) (ExecutionRecord, bool, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	document, err := ledger.load()
	if err != nil {
		return ExecutionRecord{}, false, err
	}
	for _, record := range document.Records {
		if record.JobID == jobID {
			return record, true, nil
		}
	}
	return ExecutionRecord{}, false, nil
}

func (ledger *ExecutionLedger) Put(record ExecutionRecord) error {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	record.JobID = strings.TrimSpace(record.JobID)
	record.IdempotencyKey = strings.TrimSpace(record.IdempotencyKey)
	record.JobType = strings.TrimSpace(record.JobType)
	record.State = strings.ToUpper(strings.TrimSpace(record.State))
	if record.JobID == "" || len(record.JobID) > 64 || record.IdempotencyKey == "" || len(record.IdempotencyKey) > 128 || record.JobType == "" || len(record.JobType) > 96 {
		return errors.New("remote job execution record identity is invalid")
	}
	if !executionStateAllowed(record.State) {
		return errors.New("remote job execution record state is invalid")
	}
	now := ledger.now()
	if record.CreatedAt.IsZero() {
		record.CreatedAt = now
	}
	record.UpdatedAt = now
	if record.Result == nil {
		record.Result = map[string]any{}
	}
	encodedResult, err := json.Marshal(record.Result)
	if err != nil || len(encodedResult) > 64<<10 {
		return errors.New("remote job result is invalid or exceeds 64 KiB")
	}
	document, err := ledger.load()
	if err != nil {
		return err
	}
	updated := false
	for index := range document.Records {
		if document.Records[index].JobID != record.JobID {
			continue
		}
		previous := document.Records[index]
		if previous.IdempotencyKey != record.IdempotencyKey || previous.JobType != record.JobType {
			return errors.New("remote job ID was reused with a different identity")
		}
		if !allowedExecutionTransition(previous.State, record.State) {
			return fmt.Errorf("remote job execution state cannot transition from %s to %s", previous.State, record.State)
		}
		record.CreatedAt = previous.CreatedAt
		document.Records[index] = record
		updated = true
		break
	}
	if !updated {
		document.Records = append(document.Records, record)
	}
	pruneExecutionRecords(&document, now)
	return ledger.save(document)
}

func (ledger *ExecutionLedger) Summary() (map[string]any, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	document, err := ledger.load()
	if err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, record := range document.Records {
		counts[record.State]++
	}
	return map[string]any{
		"schema_version": executionLedgerSchema,
		"record_count":   len(document.Records),
		"states":         counts,
	}, nil
}

func (ledger *ExecutionLedger) load() (executionLedgerDocument, error) {
	if strings.TrimSpace(ledger.Root) == "" {
		return executionLedgerDocument{}, errors.New("connector execution ledger root is required")
	}
	data, err := os.ReadFile(filepath.Join(ledger.Root, executionLedgerFile))
	if errors.Is(err, os.ErrNotExist) {
		return executionLedgerDocument{SchemaVersion: executionLedgerSchema, Records: []ExecutionRecord{}}, nil
	}
	if err != nil {
		return executionLedgerDocument{}, err
	}
	if len(data) > maxExecutionLedgerBytes {
		return executionLedgerDocument{}, errors.New("connector execution ledger exceeds 4 MiB")
	}
	var document executionLedgerDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return executionLedgerDocument{}, fmt.Errorf("decode connector execution ledger: %w", err)
	}
	if document.SchemaVersion != executionLedgerSchema || len(document.Records) > maxExecutionRecords {
		return executionLedgerDocument{}, errors.New("connector execution ledger schema or size is invalid")
	}
	return document, nil
}

func (ledger *ExecutionLedger) save(document executionLedgerDocument) error {
	document.SchemaVersion = executionLedgerSchema
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	if len(encoded)+1 > maxExecutionLedgerBytes {
		return errors.New("connector execution ledger would exceed 4 MiB")
	}
	return atomicWrite(filepath.Join(ledger.Root, executionLedgerFile), append(encoded, '\n'), 0o600)
}

func pruneExecutionRecords(document *executionLedgerDocument, now time.Time) {
	filtered := document.Records[:0]
	for _, record := range document.Records {
		terminal := terminalExecutionState(record.State)
		if terminal && record.UpdatedAt.Before(now.Add(-30*24*time.Hour)) {
			continue
		}
		filtered = append(filtered, record)
	}
	document.Records = filtered
	sort.Slice(document.Records, func(i, j int) bool {
		return document.Records[i].UpdatedAt.After(document.Records[j].UpdatedAt)
	})
	if len(document.Records) > maxExecutionRecords {
		document.Records = document.Records[:maxExecutionRecords]
	}
}

func executionStateAllowed(state string) bool {
	switch state {
	case "DELIVERED", "RUNNING", "SUCCEEDED", "FAILED", "REJECTED":
		return true
	default:
		return false
	}
}

func allowedExecutionTransition(current, next string) bool {
	if current == next {
		return true
	}
	if terminalExecutionState(current) {
		return false
	}
	switch current {
	case "DELIVERED":
		return next == "RUNNING" || terminalExecutionState(next)
	case "RUNNING":
		return terminalExecutionState(next)
	default:
		return false
	}
}

func (ledger *ExecutionLedger) now() time.Time {
	if ledger.Now != nil {
		return ledger.Now().UTC()
	}
	return time.Now().UTC()
}
