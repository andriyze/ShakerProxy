package networktransaction

import (
	"strings"
	"testing"
	"time"
)

const (
	testApplyID  = "apply-0123456789abcdef0123456789abcdef"
	testPlanHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func healthyReport(at time.Time) HealthReport {
	return HealthReport{CheckedAt: at, Checks: []HealthCheck{
		{Name: CheckManagement, Status: CheckPass},
		{Name: CheckWAN, Status: CheckPass},
		{Name: CheckDNS, Status: CheckPass},
		{Name: CheckIPv4Forwarding, Status: CheckPass},
		{Name: CheckDHCP4, Status: CheckPass},
		{Name: CheckIPv6, Status: CheckSkip},
	}}
}

func armedRecord(t *testing.T, now time.Time) Record {
	t.Helper()
	record, err := New(testApplyID, testPlanHash, now)
	if err != nil {
		t.Fatal(err)
	}
	record, err = record.ArmWatchdog(now.Add(time.Second), 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestHealthyTransactionRequiresWatchdogAndConfirmation(t *testing.T) {
	now := time.Unix(1000, 0)
	record := armedRecord(t, now)
	var err error
	record, err = record.BeginApply(now.Add(2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	record, err = record.MarkApplied(now.Add(3 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	record, err = record.RecordHealth(healthyReport(now.Add(4 * time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	if record.Phase != PhaseAwaitingConfirmation {
		t.Fatalf("unexpected phase: %s", record.Phase)
	}
	record, err = record.Confirm(now.Add(5 * time.Second))
	if err != nil || record.Phase != PhaseConfirmed || record.ConfirmedAt == nil {
		t.Fatalf("confirmation failed: record=%+v err=%v", record, err)
	}
}

func TestApplyCannotBeginBeforeWatchdogIsArmed(t *testing.T) {
	record, err := New(testApplyID, testPlanHash, time.Unix(1000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := record.BeginApply(time.Unix(1001, 0)); err == nil {
		t.Fatal("apply began without an independent watchdog deadline")
	}
}

func TestFailedHealthRequiresRollbackAndCannotConfirm(t *testing.T) {
	now := time.Unix(1000, 0)
	record := armedRecord(t, now)
	record, _ = record.BeginApply(now.Add(2 * time.Second))
	record, _ = record.MarkApplied(now.Add(3 * time.Second))
	report := healthyReport(now.Add(4 * time.Second))
	report.Checks[1].Status = CheckFail
	record, err := record.RecordHealth(report)
	if err != nil {
		t.Fatal(err)
	}
	if record.Phase != PhaseRollbackRequired || !record.NeedsRollback(now.Add(5*time.Second)) {
		t.Fatalf("failed health did not require rollback: %+v", record)
	}
	if _, err := record.Confirm(now.Add(5 * time.Second)); err == nil {
		t.Fatal("unhealthy transaction was confirmed")
	}
}

func TestExpiredConfirmationConvergesOnRollback(t *testing.T) {
	now := time.Unix(1000, 0)
	record := armedRecord(t, now)
	record, _ = record.BeginApply(now.Add(2 * time.Second))
	record, _ = record.MarkApplied(now.Add(3 * time.Second))
	record, _ = record.RecordHealth(healthyReport(now.Add(4 * time.Second)))
	deadline := *record.ConfirmBy
	record, err := record.Confirm(deadline)
	if err != nil {
		t.Fatal(err)
	}
	if record.Phase != PhaseRollbackRequired || !strings.Contains(record.Failure, "deadline") {
		t.Fatalf("expired confirmation did not require rollback: %+v", record)
	}
	record, err = record.BeginRollback(deadline.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	record, err = record.CompleteRollback(deadline.Add(2 * time.Second))
	if err != nil || record.Phase != PhaseRolledBack {
		t.Fatalf("rollback did not complete: record=%+v err=%v", record, err)
	}
}

func TestHealthReportRejectsMissingDuplicateAndSkippedRequiredChecks(t *testing.T) {
	now := time.Unix(1000, 0)
	cases := []HealthReport{
		{CheckedAt: now, Checks: []HealthCheck{{Name: CheckManagement, Status: CheckPass}}},
		{CheckedAt: now, Checks: append(healthyReport(now).Checks, HealthCheck{Name: CheckWAN, Status: CheckPass})},
		healthyReport(now),
	}
	cases[2].Checks[0].Status = CheckSkip
	for index, report := range cases {
		if err := report.Validate(); err == nil {
			t.Fatalf("case %d was accepted", index)
		}
	}
}

func TestLifecycleRejectsInvalidIdentityAndWindow(t *testing.T) {
	now := time.Unix(1000, 0)
	if _, err := New("apply-user-input", testPlanHash, now); err == nil {
		t.Fatal("invalid apply ID accepted")
	}
	record, err := New(testApplyID, testPlanHash, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := record.ArmWatchdog(now, 30*time.Second); err == nil {
		t.Fatal("unsafe rollback window accepted")
	}
}

func TestFailedRollbackCanBeRetriedByIndependentRecovery(t *testing.T) {
	now := time.Unix(1000, 0)
	record := armedRecord(t, now)
	record, _ = record.BeginApply(now.Add(2 * time.Second))
	record, _ = record.RequireRollback("initial rollback failed")
	record, _ = record.BeginRollback(now.Add(3 * time.Second))
	record, _ = record.FailRollback(now.Add(4*time.Second), "netplan reload failed")

	retried, err := record.RetryRollback(now.Add(5 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if retried.Phase != PhaseRollingBack || retried.RollbackFinishedAt != nil || retried.RollbackStartedAt == nil || !retried.RollbackStartedAt.Equal(now.Add(5*time.Second)) {
		t.Fatalf("failed rollback was not reset for an independent retry: %+v", retried)
	}
	completed, err := retried.CompleteRollback(now.Add(6 * time.Second))
	if err != nil || completed.Phase != PhaseRolledBack {
		t.Fatalf("retried rollback did not complete: record=%+v err=%v", completed, err)
	}
}
