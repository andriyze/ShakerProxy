package daemon

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkhealth"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
)

type fakeActivationCoordinator struct {
	mu           sync.Mutex
	applyCalls   int
	confirmCalls int
	started      chan struct{}
	release      chan struct{}
	finished     chan struct{}
	staged       networkplan.StagedPlan
	applyErr     error
	confirmErr   error
}

func (f *fakeActivationCoordinator) Apply(context.Context, string) (networkplan.StagedPlan, error) {
	f.mu.Lock()
	f.applyCalls++
	if f.applyCalls == 1 {
		close(f.started)
	}
	f.mu.Unlock()
	<-f.release
	f.mu.Lock()
	if f.applyCalls == 1 {
		close(f.finished)
	}
	f.mu.Unlock()
	result := f.staged
	result.Status = "AWAITING_CONFIRMATION"
	return result, f.applyErr
}

func (f *fakeActivationCoordinator) Confirm(context.Context, string, string) (networkplan.StagedPlan, error) {
	f.mu.Lock()
	f.confirmCalls++
	f.mu.Unlock()
	result := f.staged
	result.Status = "CONFIRMED"
	return result, f.confirmErr
}

func activationFixture(t *testing.T) (*NetworkActivation, networkplan.StagedPlan, *fakeActivationCoordinator, time.Time) {
	t.Helper()
	coordinator, staged, _, _, _ := coordinatorFixture(t)
	now := time.Unix(8000, 0)
	fake := &fakeActivationCoordinator{started: make(chan struct{}), release: make(chan struct{}), finished: make(chan struct{}), staged: staged}
	heartbeats := &networkhealth.HeartbeatGate{Now: func() time.Time { return now }}
	activation := &NetworkActivation{
		Store:      coordinator.Store,
		Heartbeats: heartbeats,
		Secret:     bytes.Repeat([]byte{0x55}, activationSecretBytes),
		Now:        func() time.Time { return now },
		Coordinator: func(time.Duration) transactionCoordinator {
			return fake
		},
	}
	return activation, staged, fake, now
}

func TestNetworkCommitReturnsHeartbeatBeforeAsyncApplyAndIsIdempotent(t *testing.T) {
	activation, staged, coordinator, _ := activationFixture(t)
	params := gatewayprotocol.CommitNetworkPlanParams{
		ApplyID: staged.ApplyID, PlanHash: staged.PlanHash,
		IdempotencyKey: "network-commit-request-0001", RollbackWindowSeconds: 120,
	}
	result, err := activation.Commit(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "ACCEPTED" || result.HealthToken == "" {
		t.Fatalf("unexpected commit acceptance: %+v", result)
	}
	activation.mu.Lock()
	retainedToken := activation.commits[staged.ApplyID].result.HealthToken
	activation.mu.Unlock()
	if retainedToken != "" {
		t.Fatal("plaintext heartbeat token was retained in the activation record")
	}
	<-coordinator.started
	retry, err := activation.Commit(context.Background(), params)
	if err != nil || retry != result {
		t.Fatalf("commit retry changed its result: retry=%+v err=%v", retry, err)
	}
	if err := activation.Signal(gatewayprotocol.SignalNetworkHealthParams{ApplyID: staged.ApplyID, PlanHash: staged.PlanHash, Token: result.HealthToken}); err != nil {
		t.Fatal(err)
	}
	close(coordinator.release)
	activation.mu.Lock()
	done := activation.commits[staged.ApplyID].done
	activation.mu.Unlock()
	<-done
	retry, err = activation.Commit(context.Background(), params)
	if err != nil || retry.Status != "AWAITING_CONFIRMATION" {
		t.Fatalf("completed commit status was not observable: retry=%+v err=%v", retry, err)
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if coordinator.applyCalls != 1 {
		t.Fatalf("idempotent commit started %d applies", coordinator.applyCalls)
	}
}

func TestNetworkCommitRejectsIdentityConflictsAndWrongHeartbeat(t *testing.T) {
	activation, staged, coordinator, _ := activationFixture(t)
	params := gatewayprotocol.CommitNetworkPlanParams{ApplyID: staged.ApplyID, PlanHash: staged.PlanHash, IdempotencyKey: "network-commit-request-0002", RollbackWindowSeconds: 120}
	result, err := activation.Commit(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}
	conflict := params
	conflict.IdempotencyKey = "network-commit-request-0003"
	if _, err := activation.Commit(context.Background(), conflict); err == nil {
		t.Fatal("a second idempotency identity replaced the active commit")
	}
	if err := activation.Signal(gatewayprotocol.SignalNetworkHealthParams{ApplyID: staged.ApplyID, PlanHash: staged.PlanHash, Token: result.HealthToken + "x"}); err == nil {
		t.Fatal("wrong management heartbeat was accepted")
	}
	close(coordinator.release)
	activation.mu.Lock()
	done := activation.commits[staged.ApplyID].done
	activation.mu.Unlock()
	<-done
}

func TestNetworkConfirmationSerializesIdempotentRetries(t *testing.T) {
	activation, staged, coordinator, _ := activationFixture(t)
	close(coordinator.release)
	params := gatewayprotocol.ConfirmNetworkPlanParams{ApplyID: staged.ApplyID, PlanHash: staged.PlanHash, IdempotencyKey: "network-confirm-request-0001"}
	first, err := activation.Confirm(context.Background(), params)
	if err != nil || first.Status != "CONFIRMED" {
		t.Fatalf("confirmation failed: result=%+v err=%v", first, err)
	}
	retry, err := activation.Confirm(context.Background(), params)
	if err != nil || retry.Status != "CONFIRMED" {
		t.Fatalf("confirmation retry failed: result=%+v err=%v", retry, err)
	}
	conflict := params
	conflict.IdempotencyKey = "network-confirm-request-0002"
	if _, err := activation.Confirm(context.Background(), conflict); err == nil {
		t.Fatal("confirmation idempotency conflict was accepted")
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if coordinator.confirmCalls != 1 {
		t.Fatalf("idempotent confirmation ran %d times", coordinator.confirmCalls)
	}
}

func TestNetworkConfirmationAllowsSameIdentityToRetryTransientFailure(t *testing.T) {
	activation, staged, coordinator, _ := activationFixture(t)
	close(coordinator.release)
	coordinator.confirmErr = errors.New("temporary systemd failure")
	params := gatewayprotocol.ConfirmNetworkPlanParams{ApplyID: staged.ApplyID, PlanHash: staged.PlanHash, IdempotencyKey: "network-confirm-request-0003"}
	if _, err := activation.Confirm(context.Background(), params); err == nil {
		t.Fatal("transient confirmation failure was hidden")
	}
	coordinator.confirmErr = nil
	if result, err := activation.Confirm(context.Background(), params); err != nil || result.Status != "CONFIRMED" {
		t.Fatalf("transient confirmation was not retryable: result=%+v err=%v", result, err)
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if coordinator.confirmCalls != 2 {
		t.Fatalf("transient retry made %d confirmation calls", coordinator.confirmCalls)
	}
}

func TestNetworkActivationDoesNotStartWhenUnavailableOrExpired(t *testing.T) {
	activation, staged, coordinator, now := activationFixture(t)
	activation.Secret = nil
	params := gatewayprotocol.CommitNetworkPlanParams{ApplyID: staged.ApplyID, PlanHash: staged.PlanHash, IdempotencyKey: "network-commit-request-0004", RollbackWindowSeconds: 120}
	if _, err := activation.Commit(context.Background(), params); err == nil {
		t.Fatal("activation without a secret was started")
	}
	activation.Secret = bytes.Repeat([]byte{0x55}, activationSecretBytes)
	activation.Now = func() time.Time { return now.Add(10 * time.Minute) }
	if _, err := activation.Commit(context.Background(), params); err == nil {
		t.Fatal("expired stage was committed")
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if coordinator.applyCalls != 0 {
		t.Fatal("rejected activation reached the coordinator")
	}
}

func TestBoundedActivationFailure(t *testing.T) {
	if got := boundedActivationFailure(errors.New(string(bytes.Repeat([]byte{'x'}, 600)))); len(got) != 512 {
		t.Fatalf("unexpected bounded failure length: %d", len(got))
	}
}

func TestParseOSRelease(t *testing.T) {
	for _, version := range []string{"24.04", "26.04"} {
		id, parsedVersion := parseOSRelease("NAME=Ubuntu\nID=ubuntu\nVERSION_ID=\"" + version + "\"\n")
		if id != "ubuntu" || parsedVersion != version {
			t.Fatalf("unexpected release: %q %q", id, parsedVersion)
		}
	}
}

func TestSupportedUbuntuVersion(t *testing.T) {
	tests := map[string]bool{
		"22.04": false,
		"24.04": true,
		"26.04": true,
		"26.10": false,
		"":      false,
	}
	for version, expected := range tests {
		if actual := supportedUbuntuVersion(version); actual != expected {
			t.Fatalf("supportedUbuntuVersion(%q) = %t, want %t", version, actual, expected)
		}
	}
}
