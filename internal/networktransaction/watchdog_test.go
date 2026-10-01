package networktransaction

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeWaiter struct {
	err    error
	called int
}

func (w *fakeWaiter) WaitUntil(context.Context, time.Time) error {
	w.called++
	return w.err
}

func watchdogFixture(t *testing.T) (FileStore, WatchdogManifest, time.Time) {
	t.Helper()
	now := time.Unix(6000, 0)
	manifest, err := NewWatchdogManifest(preparingRecord(t, now), now.Add(time.Second), 2*time.Minute, rollbackSpec())
	if err != nil {
		t.Fatal(err)
	}
	store := FileStore{Root: filepath.Join(t.TempDir(), "transactions")}
	if err := store.WriteManifest(manifest); err != nil {
		t.Fatal(err)
	}
	return store, manifest, now
}

func TestWatchdogExitsOnDurableHashBoundConfirmation(t *testing.T) {
	store, manifest, now := watchdogFixture(t)
	if _, err := store.Confirm(manifest.ApplyID, manifest.PlanHash, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	waiter := &fakeWaiter{}
	rollbacks := 0
	watchdog := Watchdog{Store: store, Waiter: waiter, Rollback: func(context.Context, WatchdogManifest) error { rollbacks++; return nil }, Now: func() time.Time { return now.Add(3 * time.Second) }}
	outcome, err := watchdog.Run(context.Background(), manifest.ApplyID)
	if err != nil || outcome.Status != "CONFIRMED" || waiter.called != 0 || rollbacks != 0 {
		t.Fatalf("confirmed watchdog did not exit cleanly: outcome=%+v err=%v waits=%d rollbacks=%d", outcome, err, waiter.called, rollbacks)
	}
}

func TestWatchdogRollsBackAtDeadlineAndPersistsOutcome(t *testing.T) {
	store, manifest, now := watchdogFixture(t)
	waiter := &fakeWaiter{}
	rollbacks := 0
	watchdog := Watchdog{Store: store, Waiter: waiter, Rollback: func(_ context.Context, got WatchdogManifest) error {
		rollbacks++
		if got != manifest {
			t.Fatalf("rollback received wrong manifest: %+v", got)
		}
		return nil
	}, Now: func() time.Time { return manifest.ConfirmBy }}
	outcome, err := watchdog.Run(context.Background(), manifest.ApplyID)
	if err != nil || outcome.Status != "ROLLED_BACK" || waiter.called != 1 || rollbacks != 1 {
		t.Fatalf("deadline rollback failed: outcome=%+v err=%v waits=%d rollbacks=%d", outcome, err, waiter.called, rollbacks)
	}
	persisted, err := store.ReadOutcome(manifest.ApplyID)
	if err != nil || persisted != outcome {
		t.Fatalf("rollback outcome was not durable: persisted=%+v err=%v", persisted, err)
	}
	second, err := watchdog.Run(context.Background(), manifest.ApplyID)
	if err != nil || second != outcome || waiter.called != 1 || rollbacks != 1 {
		t.Fatalf("watchdog retry was not idempotent: second=%+v err=%v waits=%d rollbacks=%d", second, err, waiter.called, rollbacks)
	}
	_ = now
}

type hookWaiter func()

func (h hookWaiter) WaitUntil(context.Context, time.Time) error {
	h()
	return nil
}

func TestWatchdogStandsDownWhenTheGatewayAlreadyRolledBack(t *testing.T) {
	store, manifest, now := watchdogFixture(t)
	gatewayOutcome := WatchdogOutcome{Schema: SchemaVersion, ApplyID: manifest.ApplyID, PlanHash: manifest.PlanHash, Status: "ROLLED_BACK", FinishedAt: now.Add(30 * time.Second).UTC()}
	rollbacks := 0
	watchdog := Watchdog{Store: store, Waiter: hookWaiter(func() {
		// The gateway daemon rolls back and records its outcome while the
		// watchdog waits for the deadline.
		if err := store.WriteOutcome(gatewayOutcome); err != nil {
			t.Fatal(err)
		}
	}), Rollback: func(context.Context, WatchdogManifest) error {
		rollbacks++
		return nil
	}, Now: func() time.Time { return manifest.ConfirmBy }}
	outcome, err := watchdog.Run(context.Background(), manifest.ApplyID)
	if err != nil || outcome != gatewayOutcome || rollbacks != 0 {
		t.Fatalf("watchdog did not stand down: outcome=%+v err=%v rollbacks=%d", outcome, err, rollbacks)
	}
}

func TestWatchdogAcceptsTheGatewayRollbackWhenItCannotTakeTheLock(t *testing.T) {
	store, manifest, now := watchdogFixture(t)
	gatewayOutcome := WatchdogOutcome{Schema: SchemaVersion, ApplyID: manifest.ApplyID, PlanHash: manifest.PlanHash, Status: "ROLLED_BACK", FinishedAt: now.Add(30 * time.Second).UTC()}
	watchdog := Watchdog{Store: store, Waiter: &fakeWaiter{}, Rollback: func(context.Context, WatchdogManifest) error {
		// The gateway daemon holds the configuration lock while it rolls back.
		if err := store.WriteOutcome(gatewayOutcome); err != nil {
			t.Fatal(err)
		}
		return errors.New("appliance configuration is locked by network operation network-x")
	}, Now: func() time.Time { return manifest.ConfirmBy }}
	outcome, err := watchdog.Run(context.Background(), manifest.ApplyID)
	if err != nil || outcome != gatewayOutcome {
		t.Fatalf("watchdog reported a failure although the gateway rolled back: outcome=%+v err=%v", outcome, err)
	}
}

func TestInterruptedWatchdogUsesFreshContextForRollback(t *testing.T) {
	store, manifest, now := watchdogFixture(t)
	waiter := &fakeWaiter{err: context.Canceled}
	rollbackContextCanceled := true
	watchdog := Watchdog{Store: store, Waiter: waiter, Rollback: func(ctx context.Context, _ WatchdogManifest) error {
		rollbackContextCanceled = ctx.Err() != nil
		return nil
	}, Now: func() time.Time { return now.Add(3 * time.Second) }}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	outcome, err := watchdog.Run(ctx, manifest.ApplyID)
	if err != nil || outcome.Status != "ROLLED_BACK" || rollbackContextCanceled {
		t.Fatalf("interrupted watchdog did not attempt independent rollback: outcome=%+v err=%v canceled=%v", outcome, err, rollbackContextCanceled)
	}
}

func TestWatchdogPersistsRollbackFailureAndDoesNotTrustInvalidMarker(t *testing.T) {
	store, manifest, now := watchdogFixture(t)
	directory, _ := store.TransactionDirectory(manifest.ApplyID)
	if err := os.WriteFile(filepath.Join(directory, "confirmed.json"), []byte(`{"schema":1}`), 0o640); err != nil {
		t.Fatal(err)
	}
	watchdog := Watchdog{Store: store, Waiter: &fakeWaiter{}, Rollback: func(context.Context, WatchdogManifest) error { return errors.New("rollback command failed") }, Now: func() time.Time { return now.Add(3 * time.Second) }}
	outcome, err := watchdog.Run(context.Background(), manifest.ApplyID)
	if err == nil || outcome.Status != "ROLLBACK_FAILED" || outcome.Detail == "" {
		t.Fatalf("rollback failure was not preserved: outcome=%+v err=%v", outcome, err)
	}
	persisted, readErr := store.ReadOutcome(manifest.ApplyID)
	if readErr != nil || persisted.Status != "ROLLBACK_FAILED" {
		t.Fatalf("failed outcome was not durable: persisted=%+v err=%v", persisted, readErr)
	}
}
