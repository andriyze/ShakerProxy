package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/firewall"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

type fakeRecoveryWatchdog struct {
	calls    int
	manifest networktransaction.WatchdogManifest
	err      error
}

func (f *fakeRecoveryWatchdog) EnsureArmed(_ context.Context, manifest networktransaction.WatchdogManifest) error {
	f.calls++
	f.manifest = manifest
	return f.err
}

func recoveryFixture(t *testing.T) (NetworkRecovery, NetworkCoordinator, networkplan.StagedPlan, *fakeRecoveryWatchdog, *fakeCoordinatorRollback) {
	t.Helper()
	coordinator, staged, _, _, _ := coordinatorFixture(t)
	watchdog := &fakeRecoveryWatchdog{}
	rollback := &fakeCoordinatorRollback{}
	recovery := NetworkRecovery{Store: coordinator.Store, Files: coordinator.Files, Watchdog: watchdog, Rollback: rollback, Finalizer: coordinator.Finalizer}
	return recovery, coordinator, staged, watchdog, rollback
}

func TestRecoveryRearmsUnexpiredTransaction(t *testing.T) {
	recovery, coordinator, staged, watchdog, rollback := recoveryFixture(t)
	active, err := coordinator.Apply(context.Background(), staged.ApplyID)
	if err != nil {
		t.Fatal(err)
	}
	recovery.Now = func() time.Time { return active.Transaction.AppliedAt.Add(time.Second) }
	if err := recovery.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if watchdog.calls != 1 || watchdog.manifest.ApplyID != staged.ApplyID || rollback.calls != 0 {
		t.Fatalf("unexpired recovery did not preserve the independent deadline: watchdog=%+v rollback=%+v", watchdog, rollback)
	}
}

func TestRecoveryRollsBackExpiredTransactionBeforeServing(t *testing.T) {
	recovery, coordinator, staged, watchdog, rollback := recoveryFixture(t)
	if _, err := coordinator.Apply(context.Background(), staged.ApplyID); err != nil {
		t.Fatal(err)
	}
	manifest, err := coordinator.Files.ReadManifest(staged.ApplyID)
	if err != nil {
		t.Fatal(err)
	}
	recovery.Now = func() time.Time { return manifest.ConfirmBy.Add(time.Second) }
	if err := recovery.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	state := coordinator.Store.Get()
	if watchdog.calls != 0 || rollback.calls != 1 || state.StagedNetworkPlan.Transaction.Phase != networktransaction.PhaseRolledBack || state.OperatingMode != gatewayprotocol.ModeSetupSafe || state.EmergencyBypass {
		t.Fatalf("expired transaction did not recover safely: state=%+v watchdog=%+v rollback=%+v", state, watchdog, rollback)
	}
}

func TestRecoveryStartsCleanlyAgainAfterARolledBackApply(t *testing.T) {
	recovery, coordinator, staged, _, _ := recoveryFixture(t)
	if _, err := coordinator.Apply(context.Background(), staged.ApplyID); err != nil {
		t.Fatal(err)
	}
	manifest, err := coordinator.Files.ReadManifest(staged.ApplyID)
	if err != nil {
		t.Fatal(err)
	}
	recovery.Now = func() time.Time { return manifest.ConfirmBy.Add(time.Second) }
	if err := recovery.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A later restart, such as a reboot, finds the outcome the rollback already
	// recorded; it must start instead of failing on the newer timestamp.
	recovery.Now = func() time.Time { return manifest.ConfirmBy.Add(time.Hour) }
	if err := recovery.Recover(context.Background()); err != nil {
		t.Fatalf("restart after a rolled-back apply failed: %v", err)
	}
	if phase := coordinator.Store.Get().StagedNetworkPlan.Transaction.Phase; phase != networktransaction.PhaseRolledBack {
		t.Fatalf("phase after restart = %s, want ROLLED_BACK", phase)
	}
}

func TestRecoveryHonorsDurableConfirmation(t *testing.T) {
	recovery, coordinator, staged, watchdog, rollback := recoveryFixture(t)
	if _, err := coordinator.Apply(context.Background(), staged.ApplyID); err != nil {
		t.Fatal(err)
	}
	manifest, err := coordinator.Files.ReadManifest(staged.ApplyID)
	if err != nil {
		t.Fatal(err)
	}
	confirmedAt := manifest.CreatedAt.Add(20 * time.Second)
	if _, err := coordinator.Files.Confirm(staged.ApplyID, staged.PlanHash, confirmedAt); err != nil {
		t.Fatal(err)
	}
	recovery.Now = func() time.Time { return confirmedAt.Add(time.Second) }
	if err := recovery.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	state := coordinator.Store.Get()
	if watchdog.calls != 0 || rollback.calls != 0 || state.StagedNetworkPlan.Transaction.Phase != networktransaction.PhaseConfirmed || state.OperatingMode != gatewayprotocol.ModeRouted {
		t.Fatalf("durable confirmation was not recovered: state=%+v watchdog=%+v rollback=%+v", state, watchdog, rollback)
	}
	if finalizer := recovery.Finalizer.(*fakeConfirmationFinalizer); finalizer.calls != 1 {
		t.Fatalf("recovery did not ensure confirmed DHCPv4 boot enablement: %+v", finalizer)
	}
}

func TestRecoveryClosesInterruptedPreArmTransactionWithoutMutation(t *testing.T) {
	base := time.Unix(9000, 0)
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	preview := networkplan.Preview{
		Validation:          networkplan.ValidationResult{Valid: true, PlanHash: stateTestPlanHash},
		FirewallEnvironment: firewall.Inspection{ApplyReady: true, IptablesPath: "/usr/sbin/iptables"},
	}
	staged, err := store.StageNetworkPlan(networkplan.Plan{Schema: 1}, preview, "pre-arm-recovery", base, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BeginNetworkTransaction(staged.ApplyID, base.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	watchdog := &fakeRecoveryWatchdog{}
	rollback := &fakeCoordinatorRollback{}
	recovery := NetworkRecovery{
		Store:     store,
		Files:     networktransaction.FileStore{Root: filepath.Join(t.TempDir(), "transactions")},
		Watchdog:  watchdog,
		Rollback:  rollback,
		Finalizer: &fakeConfirmationFinalizer{},
		Now:       func() time.Time { return base.Add(2 * time.Second) },
	}
	if err := recovery.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	state := store.Get()
	if state.StagedNetworkPlan.Transaction.Phase != networktransaction.PhaseRolledBack || watchdog.calls != 0 || rollback.calls != 0 {
		t.Fatalf("pre-arm recovery crossed the mutation boundary: state=%+v watchdog=%+v rollback=%+v", state, watchdog, rollback)
	}
}

func TestRecoverySurfacesRollbackFailureAsEmergencyMode(t *testing.T) {
	recovery, coordinator, staged, watchdog, rollback := recoveryFixture(t)
	if _, err := coordinator.Apply(context.Background(), staged.ApplyID); err != nil {
		t.Fatal(err)
	}
	manifest, err := coordinator.Files.ReadManifest(staged.ApplyID)
	if err != nil {
		t.Fatal(err)
	}
	rollback.err = errors.New("netplan recovery failed")
	recovery.Now = func() time.Time { return manifest.ConfirmBy.Add(time.Second) }
	if err := recovery.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	state := coordinator.Store.Get()
	if watchdog.calls != 0 || rollback.calls != 1 || state.StagedNetworkPlan.Transaction.Phase != networktransaction.PhaseRollbackFailed || state.OperatingMode != gatewayprotocol.ModeEmergency || !state.EmergencyBypass {
		t.Fatalf("rollback failure was not surfaced safely: state=%+v watchdog=%+v rollback=%+v", state, watchdog, rollback)
	}
}

func TestRecoveryFailsClosedWhenWatchdogCannotBeRearmed(t *testing.T) {
	recovery, coordinator, staged, watchdog, _ := recoveryFixture(t)
	active, err := coordinator.Apply(context.Background(), staged.ApplyID)
	if err != nil {
		t.Fatal(err)
	}
	watchdog.err = errors.New("systemd unavailable")
	recovery.Now = func() time.Time { return active.Transaction.AppliedAt.Add(time.Second) }
	if err := recovery.Recover(context.Background()); err == nil {
		t.Fatal("watchdog re-arm failure was ignored")
	}
}
