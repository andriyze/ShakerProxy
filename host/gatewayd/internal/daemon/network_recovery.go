package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

type recoveryWatchdogController interface {
	EnsureArmed(context.Context, networktransaction.WatchdogManifest) error
}

type NetworkRecovery struct {
	Store     *StateStore
	Files     networktransaction.FileStore
	Watchdog  recoveryWatchdogController
	Rollback  rollbackExecutor
	Finalizer confirmationFinalizer
	Now       func() time.Time
	Timeout   time.Duration

	// AccessPoint is required only for confirmed Wi-Fi plans.
	AccessPoint accessPointFinalizer
}

func (r NetworkRecovery) Recover(ctx context.Context) error {
	if err := r.validate(); err != nil {
		return err
	}
	if _, err := r.Store.ReconcileNetworkOutcome(r.Files); err != nil {
		return fmt.Errorf("reconcile existing watchdog outcome: %w", err)
	}
	state := r.Store.Get()
	staged := state.StagedNetworkPlan
	if staged == nil || staged.Transaction == nil {
		return nil
	}
	record := *staged.Transaction
	manifest, err := r.Files.ReadManifest(staged.ApplyID)
	if errors.Is(err, os.ErrNotExist) {
		if record.Phase == networktransaction.PhaseRolledBack && record.WatchdogArmedAt == nil {
			return nil
		}
		if record.Phase != networktransaction.PhasePreparing && record.Phase != networktransaction.PhaseRollbackRequired && record.Phase != networktransaction.PhaseRollingBack {
			return errors.New("active network transaction is missing its watchdog manifest")
		}
		_, recoverErr := r.Store.RecoverUnarmedNetworkTransaction(staged.ApplyID, r.now())
		return recoverErr
	}
	if err != nil {
		return fmt.Errorf("read active watchdog manifest: %w", err)
	}
	if err := validateRecoveryIdentity(*staged, manifest); err != nil {
		return err
	}

	confirmed, confirmationErr := r.Files.IsConfirmed(manifest)
	if confirmed && confirmationErr == nil {
		if err := finalizeRecoveredDHCP4(context.WithoutCancel(ctx), r.Finalizer, staged.Plan); err != nil {
			return fmt.Errorf("ensure confirmed DHCPv4 state: %w", err)
		}
		if err := finalizeAccessPoint(context.WithoutCancel(ctx), r.AccessPoint, staged.Plan); err != nil {
			return fmt.Errorf("ensure confirmed Wi-Fi access point state: %w", err)
		}
		if err := finalizeRadvd(context.WithoutCancel(ctx), r.Finalizer, staged.Plan); err != nil {
			return fmt.Errorf("ensure confirmed router advertisement state: %w", err)
		}
		return r.finishSynchronously(ctx, manifest)
	}
	if record.Phase == networktransaction.PhaseConfirmed {
		return errors.New("confirmed network transaction is missing its durable confirmation")
	}
	if record.Phase == networktransaction.PhaseRolledBack {
		// The rollback that finished this transaction usually recorded its
		// outcome already; recording it again with a new time must not stop
		// the daemon from starting.
		current, readErr := r.Files.ReadOutcome(manifest.ApplyID)
		if readErr != nil || current.PlanHash != manifest.PlanHash || current.Status != "ROLLED_BACK" {
			outcome := networktransaction.WatchdogOutcome{Schema: networktransaction.SchemaVersion, ApplyID: manifest.ApplyID, PlanHash: manifest.PlanHash, Status: "ROLLED_BACK", FinishedAt: r.now()}
			if err := r.Files.WriteOutcome(outcome); err != nil {
				return fmt.Errorf("persist recovered rollback outcome: %w", err)
			}
		}
		_, err := r.Store.ReconcileNetworkOutcome(r.Files)
		return err
	}
	if confirmationErr != nil || record.Phase == networktransaction.PhasePreparing || record.Phase == networktransaction.PhaseRollbackRequired || record.Phase == networktransaction.PhaseRollingBack || record.Phase == networktransaction.PhaseRollbackFailed || !r.now().Before(manifest.ConfirmBy) {
		return r.finishSynchronously(ctx, manifest)
	}
	if err := r.Watchdog.EnsureArmed(ctx, manifest); err != nil {
		return fmt.Errorf("ensure independent watchdog is armed: %w", err)
	}
	return nil
}

func finalizeRecoveredDHCP4(ctx context.Context, finalizer confirmationFinalizer, plan networkplan.Plan) error {
	if networkplan.UsesManagedDHCP4(plan) {
		return finalizer.EnsureDHCP4Enabled(ctx)
	}
	return finalizer.DisableDHCP4(ctx)
}

func (r NetworkRecovery) finishSynchronously(ctx context.Context, manifest networktransaction.WatchdogManifest) error {
	recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.timeout())
	defer cancel()
	watchdog := networktransaction.Watchdog{
		Store:    r.Files,
		Waiter:   immediateRecoveryWaiter{},
		Rollback: r.Rollback.Execute,
		Now:      r.Now,
	}
	outcome, runErr := watchdog.Run(recoveryCtx, manifest.ApplyID)
	_, reconcileErr := r.Store.ReconcileNetworkOutcome(r.Files)
	if reconcileErr != nil {
		return errors.Join(runErr, fmt.Errorf("reconcile synchronous watchdog outcome: %w", reconcileErr))
	}
	if outcome.Status == "ROLLBACK_FAILED" {
		return nil
	}
	return runErr
}

func (r NetworkRecovery) validate() error {
	if r.Store == nil || r.Watchdog == nil || r.Rollback == nil || r.Finalizer == nil {
		return errors.New("network recovery dependencies are incomplete")
	}
	if _, err := r.Files.TransactionDirectory("apply-00000000000000000000000000000000"); err != nil {
		return fmt.Errorf("network recovery transaction store is invalid: %w", err)
	}
	if r.Timeout < 0 {
		return errors.New("network recovery timeout is invalid")
	}
	return nil
}

func (r NetworkRecovery) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func (r NetworkRecovery) timeout() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return 30 * time.Second
}

func validateRecoveryIdentity(staged networkplan.StagedPlan, manifest networktransaction.WatchdogManifest) error {
	record := staged.Transaction
	if record == nil || manifest.ApplyID != staged.ApplyID || manifest.PlanHash != staged.PlanHash || record.ApplyID != manifest.ApplyID || record.PlanHash != manifest.PlanHash {
		return errors.New("watchdog recovery identity does not match the active transaction")
	}
	if record.WatchdogArmedAt != nil && !record.WatchdogArmedAt.Equal(manifest.CreatedAt) {
		return errors.New("watchdog recovery arm time does not match the active transaction")
	}
	if record.ConfirmBy != nil && !record.ConfirmBy.Equal(manifest.ConfirmBy) {
		return errors.New("watchdog recovery deadline does not match the active transaction")
	}
	if record.Phase != networktransaction.PhasePreparing && (record.WatchdogArmedAt == nil || record.ConfirmBy == nil) {
		return errors.New("active network transaction lacks durable watchdog timestamps")
	}
	return nil
}

type immediateRecoveryWaiter struct{}

func (immediateRecoveryWaiter) WaitUntil(context.Context, time.Time) error { return nil }
