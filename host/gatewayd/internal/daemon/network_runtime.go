package daemon

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"shakerproxy.dev/shakerproxy/internal/configlock"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
)

// DefaultRuntimeCheckInterval is how often a confirmed plan's runtime state is
// checked for drift (for example a Docker restart or a flushed ruleset).
const DefaultRuntimeCheckInterval = 30 * time.Second

type confirmedRuntimeRestorer interface {
	Restore(context.Context, networkplan.StagedPlan) error
	Drift(context.Context, networkplan.StagedPlan) ([]string, error)
}

// NetworkRuntimeKeeper re-establishes the kernel runtime state of a confirmed
// network plan (forwarding sysctls and ShakerProxy firewall chains and hooks)
// that a reboot erases. It restores once when gatewayd starts and again
// whenever a periodic read-only check finds drift. Until a restore succeeds,
// forwarding stays at its boot default (off), so the lab fails closed.
type NetworkRuntimeKeeper struct {
	Store      *StateStore
	Restorer   confirmedRuntimeRestorer
	ConfigLock *configlock.Manager
	Logger     *slog.Logger
	Interval   time.Duration

	mu           sync.Mutex
	restoredHash string
	lastProblem  string
}

// Run restores immediately and then checks for drift until ctx ends.
func (k *NetworkRuntimeKeeper) Run(ctx context.Context) {
	interval := k.Interval
	if interval <= 0 {
		interval = DefaultRuntimeCheckInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		_ = k.Tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Tick runs one restore-or-check pass. It acts only on a confirmed plan in
// routed or emergency-bypass mode and skips the pass while another appliance
// configuration change holds the lock.
func (k *NetworkRuntimeKeeper) Tick(ctx context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.Store == nil || k.Restorer == nil {
		return errors.New("network runtime keeper is incomplete")
	}
	staged, ok := k.activePlan()
	if !ok {
		k.restoredHash = ""
		return nil
	}
	if k.ConfigLock != nil {
		lockContext, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		guard, err := k.ConfigLock.Acquire(lockContext, configlock.Request{OperationID: "network-runtime-keeper", Category: configlock.CategoryNetwork, Actor: "gatewayd"})
		cancel()
		if err != nil {
			return nil
		}
		defer guard.Release()
		// A transaction may have finished while we waited for the lock.
		if staged, ok = k.activePlan(); !ok {
			k.restoredHash = ""
			return nil
		}
	}
	if k.restoredHash == staged.PlanHash {
		drift, err := k.Restorer.Drift(ctx, staged)
		if err != nil {
			k.restoredHash = ""
			k.problem("confirmed network plan runtime state cannot be checked; routing stays as it is", staged, err)
			return err
		}
		if len(drift) == 0 {
			k.recovered(staged)
			return nil
		}
		k.log(slog.LevelWarn, "ShakerProxy runtime network state drifted; restoring it", staged, "drift", strings.Join(drift, "; "))
	} else {
		k.log(slog.LevelInfo, "restoring runtime network state of the confirmed plan", staged)
	}
	if err := k.Restorer.Restore(ctx, staged); err != nil {
		k.restoredHash = ""
		k.problem("confirmed network plan runtime state could not be restored; lab forwarding stays off until it succeeds", staged, err)
		return err
	}
	k.restoredHash = staged.PlanHash
	k.lastProblem = ""
	k.log(slog.LevelInfo, "runtime network state of the confirmed plan is in place", staged)
	return nil
}

func (k *NetworkRuntimeKeeper) activePlan() (networkplan.StagedPlan, bool) {
	state := k.Store.Get()
	// A staged candidate must not stop a reboot from restoring the plan the
	// host was running.
	staged := state.activeNetworkPlan()
	if staged == nil {
		return networkplan.StagedPlan{}, false
	}
	// SETUP_SAFE is an explicit administrator choice not to route.
	if state.OperatingMode != gatewayprotocol.ModeRouted && state.OperatingMode != gatewayprotocol.ModeEmergency {
		return networkplan.StagedPlan{}, false
	}
	return *staged, true
}

// problem logs each distinct failure once instead of every interval.
func (k *NetworkRuntimeKeeper) problem(message string, staged networkplan.StagedPlan, err error) {
	if err.Error() == k.lastProblem {
		return
	}
	k.lastProblem = err.Error()
	k.log(slog.LevelError, message, staged, "error", err)
}

func (k *NetworkRuntimeKeeper) recovered(staged networkplan.StagedPlan) {
	if k.lastProblem != "" {
		k.lastProblem = ""
		k.log(slog.LevelInfo, "runtime network state of the confirmed plan is in place", staged)
	}
}

func (k *NetworkRuntimeKeeper) log(level slog.Level, message string, staged networkplan.StagedPlan, attributes ...any) {
	if k.Logger == nil {
		return
	}
	k.Logger.Log(context.Background(), level, message, append([]any{"apply_id", staged.ApplyID, "plan_hash", staged.PlanHash}, attributes...)...)
}

// KeepConfirmedRuntime runs the runtime keeper for the daemon's lifetime.
func (a *NetworkActivation) KeepConfirmedRuntime(ctx context.Context, logger *slog.Logger) {
	if a == nil || a.Runtime == nil {
		return
	}
	if a.Runtime.Logger == nil {
		a.Runtime.Logger = logger
	}
	a.Runtime.Run(ctx)
}
