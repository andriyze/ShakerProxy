package cloudconnector

import (
	"testing"
	"time"
)

func TestValidateDiagnosticsJobAcceptsOnlyBoundedReadOnlyJob(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	state := State{SensorID: "sensor-1", OrganizationID: "org-1"}
	job := CloudJob{
		ID:                 "job-1",
		Type:               JobDiagnosticsCollect,
		OrganizationID:     state.OrganizationID,
		SensorID:           state.SensorID,
		CreatedAt:          now.Add(-time.Minute),
		ExpiresAt:          now.Add(10 * time.Minute),
		IdempotencyKey:     "diagnostics-idempotency-key",
		RequiredCapability: DiagnosticsCapability,
		ApprovalState:      "NOT_REQUIRED",
		Parameters:         map[string]any{},
	}
	if err := ValidateDiagnosticsJob(job, state, 0, []string{DiagnosticsCapability}, now); err != nil {
		t.Fatalf("valid diagnostics job rejected: %v", err)
	}

	mutated := job
	mutated.Type = "shell.exec"
	if err := ValidateDiagnosticsJob(mutated, state, 0, []string{DiagnosticsCapability}, now); err == nil {
		t.Fatal("unsupported remote job type was accepted")
	}

	mutated = job
	mutated.Parameters = map[string]any{"command": "id"}
	if err := ValidateDiagnosticsJob(mutated, state, 0, []string{DiagnosticsCapability}, now); err == nil {
		t.Fatal("remote diagnostics parameters were accepted")
	}

	mutated = job
	mutated.SensorID = "different-sensor"
	if err := ValidateDiagnosticsJob(mutated, state, 0, []string{DiagnosticsCapability}, now); err == nil {
		t.Fatal("cross-sensor job was accepted")
	}

	mutated = job
	revision := uint64(7)
	mutated.ExpectedRevision = &revision
	if err := ValidateDiagnosticsJob(mutated, state, 0, []string{DiagnosticsCapability}, now); err == nil {
		t.Fatal("job with mismatched expected revision was accepted")
	}
}

func TestJobLedgerRejectsIdentityMutationAndPersistsTerminalResult(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	client := Client{Root: t.TempDir(), Now: func() time.Time { return now }}
	ledger, err := client.loadJobLedger()
	if err != nil {
		t.Fatal(err)
	}
	job := CloudJob{ID: "job-1", IdempotencyKey: "key-1", Type: JobDiagnosticsCollect}
	result := map[string]any{"ok": true}
	if err := ledger.upsert(client, job, "SUCCEEDED", result); err != nil {
		t.Fatal(err)
	}

	reloaded, err := client.loadJobLedger()
	if err != nil {
		t.Fatal(err)
	}
	entry, found := reloaded.lookup(job.ID)
	if !found || entry.State != "SUCCEEDED" || entry.Result["ok"] != true {
		t.Fatalf("terminal result was not persisted: %#v", entry)
	}

	mutated := job
	mutated.IdempotencyKey = "key-2"
	if err := reloaded.upsert(client, mutated, "RUNNING", nil); err == nil {
		t.Fatal("job identity mutation overwrote durable ledger entry")
	}
}
