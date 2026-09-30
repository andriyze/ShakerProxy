package cloudconnector

import (
	"strings"
	"testing"
	"time"
)

func TestExecutionLedgerRejectsBackwardTransitions(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 9, 4, 21, 30, 0, 0, time.UTC)
	ledger := &ExecutionLedger{Root: root, Now: func() time.Time { return now }}
	record := ExecutionRecord{JobID: "job-1", IdempotencyKey: "attempt-1", JobType: JobDiagnosticsCollect, State: "DELIVERED", ExpiresAt: now.Add(time.Hour)}
	if err := ledger.Put(record); err != nil {
		t.Fatalf("put delivered: %v", err)
	}
	record.State = "RUNNING"
	if err := ledger.Put(record); err != nil {
		t.Fatalf("put running: %v", err)
	}
	record.State = "DELIVERED"
	if err := ledger.Put(record); err == nil || !strings.Contains(err.Error(), "cannot transition") {
		t.Fatalf("expected backward transition rejection, got %v", err)
	}
}

func TestExecutionLedgerTerminalStateIsImmutable(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 9, 4, 21, 30, 0, 0, time.UTC)
	ledger := &ExecutionLedger{Root: root, Now: func() time.Time { return now }}
	record := ExecutionRecord{JobID: "job-2", IdempotencyKey: "attempt-2", JobType: JobDiagnosticsCollect, State: "DELIVERED", ExpiresAt: now.Add(time.Hour)}
	if err := ledger.Put(record); err != nil {
		t.Fatalf("put delivered: %v", err)
	}
	record.State = "SUCCEEDED"
	record.Result = map[string]any{"ok": true}
	if err := ledger.Put(record); err != nil {
		t.Fatalf("put succeeded: %v", err)
	}
	record.State = "RUNNING"
	if err := ledger.Put(record); err == nil {
		t.Fatal("expected terminal state to reject restart")
	}
}

func TestMetadataQueueDepth(t *testing.T) {
	if got := metadataQueueDepth(map[string]any{"event_count": 42}); got != 42 {
		t.Fatalf("queue depth = %d, want 42", got)
	}
	if got := metadataQueueDepth(map[string]any{"event_count": float64(7)}); got != 7 {
		t.Fatalf("float queue depth = %d, want 7", got)
	}
}
