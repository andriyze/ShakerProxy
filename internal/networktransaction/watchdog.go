package networktransaction

import (
	"context"
	"errors"
	"os"
	"time"
)

type DeadlineWaiter interface {
	WaitUntil(context.Context, time.Time) error
}

type RealDeadlineWaiter struct{}

func (RealDeadlineWaiter) WaitUntil(ctx context.Context, deadline time.Time) error {
	delay := time.Until(deadline)
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type Watchdog struct {
	Store    FileStore
	Waiter   DeadlineWaiter
	Rollback func(context.Context, WatchdogManifest) error
	Now      func() time.Time
}

func (w Watchdog) Run(ctx context.Context, applyID string) (WatchdogOutcome, error) {
	manifest, err := w.Store.ReadManifest(applyID)
	if err != nil {
		return WatchdogOutcome{}, err
	}
	if current, err := w.Store.ReadOutcome(applyID); err == nil {
		if current.PlanHash != manifest.PlanHash {
			return WatchdogOutcome{}, errors.New("watchdog outcome hash does not match its manifest")
		}
		if current.Status == "ROLLBACK_FAILED" {
			return current, errors.New(current.Detail)
		}
		return current, nil
	}
	if w.Waiter == nil || w.Rollback == nil {
		return WatchdogOutcome{}, errors.New("watchdog waiter and rollback executor are required")
	}
	confirmed, confirmationErr := w.Store.IsConfirmed(manifest)
	if confirmed && confirmationErr == nil {
		return w.finish(manifest, "CONFIRMED", "")
	}
	waitErr := w.Waiter.WaitUntil(ctx, manifest.ConfirmBy)
	confirmed, finalConfirmationErr := w.Store.IsConfirmed(manifest)
	if confirmed && finalConfirmationErr == nil {
		return w.finish(manifest, "CONFIRMED", "")
	}
	rollbackCtx := ctx
	rollbackCancel := func() {}
	if waitErr != nil {
		rollbackCtx, rollbackCancel = context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	}
	defer rollbackCancel()
	rollbackErr := w.Rollback(rollbackCtx, manifest)
	if rollbackErr != nil {
		detail := rollbackErr.Error()
		if waitErr != nil {
			detail = "watchdog interrupted without durable confirmation: " + waitErr.Error() + "; rollback: " + detail
		}
		if finalConfirmationErr != nil {
			detail = "invalid confirmation marker: " + finalConfirmationErr.Error() + "; rollback: " + detail
		} else if confirmationErr != nil {
			detail = "invalid initial confirmation marker: " + confirmationErr.Error() + "; rollback: " + detail
		}
		if len(detail) > 8192 {
			detail = detail[:8192]
		}
		outcome, persistErr := w.finish(manifest, "ROLLBACK_FAILED", detail)
		return outcome, errors.Join(rollbackErr, persistErr)
	}
	outcome, persistErr := w.finish(manifest, "ROLLED_BACK", "")
	return outcome, persistErr
}

func (w Watchdog) finish(manifest WatchdogManifest, status, detail string) (WatchdogOutcome, error) {
	if current, err := w.Store.ReadOutcome(manifest.ApplyID); err == nil {
		if current.PlanHash == manifest.PlanHash && current.Status == status {
			return current, nil
		}
		return WatchdogOutcome{}, errors.New("watchdog already recorded a different terminal outcome")
	} else if !errors.Is(err, os.ErrNotExist) {
		return WatchdogOutcome{}, err
	}
	now := time.Now
	if w.Now != nil {
		now = w.Now
	}
	outcome := WatchdogOutcome{Schema: SchemaVersion, ApplyID: manifest.ApplyID, PlanHash: manifest.PlanHash, Status: status, FinishedAt: now().UTC(), Detail: detail}
	if err := w.Store.WriteOutcome(outcome); err != nil {
		return outcome, err
	}
	return outcome, nil
}
