package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"

	"shakerproxy.dev/shakerproxy/internal/networkapply"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

type rollbackSnapshotter interface {
	Capture(networkplan.StagedPlan) (networktransaction.RollbackSpec, error)
}

type syntaxValidator interface {
	Validate(context.Context, networkplan.StagedPlan) (networkapply.Evidence, error)
}

type nativeApplier interface {
	Apply(context.Context, networkplan.StagedPlan) error
}

type rollbackExecutor interface {
	Execute(context.Context, networktransaction.WatchdogManifest) error
}

type networkHealthChecker interface {
	Check(context.Context, networkplan.StagedPlan) (networktransaction.HealthReport, error)
}

type watchdogController interface {
	Arm(context.Context, networktransaction.WatchdogManifest) error
	Disarm(context.Context, string) error
}

type confirmationFinalizer interface {
	EnsureDHCP4Enabled(context.Context) error
	DisableDHCP4(context.Context) error
}

type NetworkCoordinator struct {
	Store          *StateStore
	Files          networktransaction.FileStore
	Snapshotter    rollbackSnapshotter
	Syntax         syntaxValidator
	Watchdog       watchdogController
	Applier        nativeApplier
	Health         networkHealthChecker
	Rollback       rollbackExecutor
	Finalizer      confirmationFinalizer
	AccessPoint    accessPointFinalizer
	RollbackWindow time.Duration
	Now            func() time.Time
}

func (c NetworkCoordinator) Apply(ctx context.Context, applyID string) (networkplan.StagedPlan, error) {
	if err := c.validate(); err != nil {
		return networkplan.StagedPlan{}, err
	}
	now := c.now()
	staged, err := c.Store.BeginNetworkTransaction(applyID, now)
	if err != nil {
		return networkplan.StagedPlan{}, err
	}
	rollbackSpec, err := c.Snapshotter.Capture(staged)
	if err != nil {
		return staged, fmt.Errorf("capture rollback state: %w", err)
	}
	if _, err := c.Syntax.Validate(ctx, staged); err != nil {
		return staged, fmt.Errorf("validate native syntax: %w", err)
	}
	manifest, err := networktransaction.NewWatchdogManifest(*staged.Transaction, c.now(), c.RollbackWindow, rollbackSpec)
	if err != nil {
		return staged, err
	}
	if err := c.Files.WriteManifest(manifest); err != nil {
		return staged, fmt.Errorf("persist watchdog manifest: %w", err)
	}
	if err := c.Watchdog.Arm(ctx, manifest); err != nil {
		return staged, fmt.Errorf("arm independent watchdog: %w", err)
	}
	staged, err = c.Store.ArmNetworkWatchdog(applyID, manifest.CreatedAt, manifest.ConfirmBy.Sub(manifest.CreatedAt))
	if err != nil {
		_ = c.Watchdog.Disarm(context.WithoutCancel(ctx), applyID)
		return staged, fmt.Errorf("persist armed watchdog state: %w", err)
	}
	staged, err = c.Store.BeginNetworkHostApply(applyID, c.now())
	if err != nil {
		return c.rollbackAfterFailure(ctx, staged, manifest, "begin host apply: "+err.Error())
	}
	if staged.Transaction.Phase == networktransaction.PhaseRollbackRequired {
		return c.rollbackAfterFailure(ctx, staged, manifest, staged.Transaction.Failure)
	}
	if err := c.Applier.Apply(ctx, staged); err != nil {
		return c.rollbackAfterFailure(ctx, staged, manifest, "native apply failed: "+err.Error())
	}
	staged, err = c.Store.MarkNetworkApplied(applyID, c.now())
	if err != nil {
		return c.rollbackAfterFailure(ctx, staged, manifest, "persist applied state: "+err.Error())
	}
	if staged.Transaction.Phase == networktransaction.PhaseRollbackRequired {
		return c.rollbackAfterFailure(ctx, staged, manifest, staged.Transaction.Failure)
	}
	report, err := c.Health.Check(ctx, staged)
	if err != nil {
		return c.rollbackAfterFailure(ctx, staged, manifest, "health validation failed: "+err.Error())
	}
	staged, err = c.Store.RecordNetworkHealth(applyID, report)
	if err != nil {
		return c.rollbackAfterFailure(ctx, staged, manifest, "persist health validation: "+err.Error())
	}
	if staged.Transaction.Phase == networktransaction.PhaseRollbackRequired {
		return c.rollbackAfterFailure(ctx, staged, manifest, staged.Transaction.Failure)
	}
	return staged, nil
}

func (c NetworkCoordinator) Confirm(ctx context.Context, applyID, planHash string) (networkplan.StagedPlan, error) {
	if err := c.validate(); err != nil {
		return networkplan.StagedPlan{}, err
	}
	current := c.Store.Get().StagedNetworkPlan
	if current == nil || current.ApplyID != applyID || current.PlanHash != planHash || current.Transaction == nil {
		return networkplan.StagedPlan{}, errors.New("confirmation identity does not match the active transaction")
	}
	if current.Transaction.Phase == networktransaction.PhaseConfirmed {
		if err := c.finalizeDHCP4(context.WithoutCancel(ctx), current.Plan); err != nil {
			return *current, fmt.Errorf("network is confirmed but DHCPv4 finalization failed: %w", err)
		}
		if err := finalizeAccessPoint(context.WithoutCancel(ctx), c.AccessPoint, current.Plan); err != nil {
			return *current, fmt.Errorf("network is confirmed but Wi-Fi access point boot enablement failed: %w", err)
		}
		if err := finalizeRadvd(context.WithoutCancel(ctx), c.Finalizer, current.Plan); err != nil {
			return *current, fmt.Errorf("network is confirmed but router advertisement finalization failed: %w", err)
		}
		if err := c.Watchdog.Disarm(context.WithoutCancel(ctx), applyID); err != nil {
			return *current, fmt.Errorf("network is confirmed but watchdog stop failed: %w", err)
		}
		return *current, nil
	}
	confirmation, err := c.Files.Confirm(applyID, planHash, c.now())
	if err != nil {
		return *current, err
	}
	staged, err := c.Store.ConfirmNetworkTransaction(applyID, confirmation.ConfirmedAt)
	if err != nil {
		return *current, fmt.Errorf("persist network confirmation: %w", err)
	}
	if err := c.finalizeDHCP4(context.WithoutCancel(ctx), staged.Plan); err != nil {
		return staged, fmt.Errorf("network confirmed but DHCPv4 finalization failed: %w", err)
	}
	if err := finalizeAccessPoint(context.WithoutCancel(ctx), c.AccessPoint, staged.Plan); err != nil {
		return staged, fmt.Errorf("network confirmed but Wi-Fi access point boot enablement failed: %w", err)
	}
	if err := finalizeRadvd(context.WithoutCancel(ctx), c.Finalizer, staged.Plan); err != nil {
		return staged, fmt.Errorf("network confirmed but router advertisement finalization failed: %w", err)
	}
	if err := c.Watchdog.Disarm(context.WithoutCancel(ctx), applyID); err != nil {
		return staged, fmt.Errorf("network confirmed but watchdog stop failed: %w", err)
	}
	return staged, nil
}

func (c NetworkCoordinator) finalizeDHCP4(ctx context.Context, plan networkplan.Plan) error {
	if networkplan.UsesManagedDHCP4(plan) {
		if err := c.Finalizer.EnsureDHCP4Enabled(ctx); err != nil {
			return fmt.Errorf("DHCPv4 boot enablement: %w", err)
		}
		return nil
	}
	if err := c.Finalizer.DisableDHCP4(ctx); err != nil {
		return fmt.Errorf("DHCPv4 disablement: %w", err)
	}
	return nil
}

func (c NetworkCoordinator) rollbackAfterFailure(ctx context.Context, staged networkplan.StagedPlan, manifest networktransaction.WatchdogManifest, reason string) (networkplan.StagedPlan, error) {
	if staged.Transaction == nil || staged.Transaction.Phase != networktransaction.PhaseRollbackRequired {
		var err error
		staged, err = c.Store.RequireNetworkRollback(manifest.ApplyID, reason)
		if err != nil {
			return staged, errors.Join(errors.New(reason), err)
		}
	}
	rolling, err := c.Store.BeginNetworkRollback(manifest.ApplyID, c.now())
	if err != nil {
		return staged, errors.Join(errors.New(reason), err)
	}
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if rollbackErr := c.Rollback.Execute(rollbackCtx, manifest); rollbackErr != nil {
		failed, stateErr := c.Store.FailNetworkRollback(manifest.ApplyID, c.now(), rollbackErr.Error())
		return failed, errors.Join(errors.New(reason), rollbackErr, stateErr)
	}
	rolledBack, stateErr := c.Store.CompleteNetworkRollback(manifest.ApplyID, c.now())
	if stateErr != nil {
		return rolling, errors.Join(errors.New(reason), stateErr)
	}
	outcome := networktransaction.WatchdogOutcome{Schema: networktransaction.SchemaVersion, ApplyID: manifest.ApplyID, PlanHash: manifest.PlanHash, Status: "ROLLED_BACK", FinishedAt: c.now()}
	if outcomeErr := c.Files.WriteOutcome(outcome); outcomeErr != nil {
		return rolledBack, errors.Join(errors.New(reason), outcomeErr)
	}
	if disarmErr := c.Watchdog.Disarm(context.WithoutCancel(ctx), manifest.ApplyID); disarmErr != nil {
		return rolledBack, errors.Join(errors.New(reason), disarmErr)
	}
	return rolledBack, errors.New(reason)
}

func (c NetworkCoordinator) validate() error {
	if c.Store == nil || c.Snapshotter == nil || c.Syntax == nil || c.Watchdog == nil || c.Applier == nil || c.Health == nil || c.Rollback == nil || c.Finalizer == nil {
		return errors.New("network coordinator dependencies are incomplete")
	}
	if c.RollbackWindow < networktransaction.MinRollbackWindow || c.RollbackWindow > networktransaction.MaxRollbackWindow {
		return errors.New("network coordinator rollback window is invalid")
	}
	if _, err := c.Files.TransactionDirectory("apply-00000000000000000000000000000000"); err != nil {
		return fmt.Errorf("network coordinator transaction store is invalid: %w", err)
	}
	return nil
}

func (c NetworkCoordinator) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}
