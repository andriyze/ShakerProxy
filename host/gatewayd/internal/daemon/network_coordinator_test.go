package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/firewall"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkapply"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

type fakeSnapshotter struct{ err error }

func (f fakeSnapshotter) Capture(networkplan.StagedPlan) (networktransaction.RollbackSpec, error) {
	return networktransaction.RollbackSpec{InitialMode: "SETUP_SAFE_NO_SHAKERPROXY", IptablesPath: "/usr/sbin/iptables"}, f.err
}

type fakeSyntaxValidator struct{ err error }

func (f fakeSyntaxValidator) Validate(context.Context, networkplan.StagedPlan) (networkapply.Evidence, error) {
	return networkapply.Evidence{}, f.err
}

type fakeCoordinatorWatchdog struct {
	arms       int
	disarms    int
	armErr     error
	disarmErr  error
	lastApply  string
	lastRecord networktransaction.WatchdogManifest
}

func (f *fakeCoordinatorWatchdog) Arm(_ context.Context, manifest networktransaction.WatchdogManifest) error {
	f.arms++
	f.lastRecord = manifest
	return f.armErr
}

func (f *fakeCoordinatorWatchdog) Disarm(_ context.Context, applyID string) error {
	f.disarms++
	f.lastApply = applyID
	return f.disarmErr
}

type fakeCoordinatorApplier struct {
	calls int
	err   error
}

func (f *fakeCoordinatorApplier) Apply(context.Context, networkplan.StagedPlan) error {
	f.calls++
	return f.err
}

type fakeHealthChecker struct {
	report networktransaction.HealthReport
	err    error
}

func (f fakeHealthChecker) Check(context.Context, networkplan.StagedPlan) (networktransaction.HealthReport, error) {
	return f.report, f.err
}

type fakeCoordinatorRollback struct {
	calls           int
	err             error
	contextCanceled bool
}

type fakeConfirmationFinalizer struct {
	calls int
	err   error
}

func (f *fakeConfirmationFinalizer) EnsureDHCP4Enabled(context.Context) error {
	f.calls++
	return f.err
}
func (f *fakeConfirmationFinalizer) DisableDHCP4(context.Context) error {
	f.calls++
	return f.err
}

func (f *fakeCoordinatorRollback) Execute(ctx context.Context, _ networktransaction.WatchdogManifest) error {
	f.calls++
	f.contextCanceled = ctx.Err() != nil
	return f.err
}

type incrementingClock struct{ next time.Time }

func (c *incrementingClock) Now() time.Time {
	current := c.next
	c.next = c.next.Add(time.Second)
	return current
}

func coordinatorHealth(at time.Time, healthy bool) networktransaction.HealthReport {
	status := networktransaction.CheckPass
	if !healthy {
		status = networktransaction.CheckFail
	}
	return networktransaction.HealthReport{CheckedAt: at, Checks: []networktransaction.HealthCheck{
		{Name: networktransaction.CheckManagement, Status: networktransaction.CheckPass},
		{Name: networktransaction.CheckWAN, Status: status},
		{Name: networktransaction.CheckDNS, Status: networktransaction.CheckPass},
		{Name: networktransaction.CheckIPv4Forwarding, Status: networktransaction.CheckPass},
		{Name: networktransaction.CheckDHCP4, Status: networktransaction.CheckPass},
		{Name: networktransaction.CheckIPv6, Status: networktransaction.CheckSkip},
	}}
}

func coordinatorFixture(t *testing.T) (NetworkCoordinator, networkplan.StagedPlan, *fakeCoordinatorWatchdog, *fakeCoordinatorApplier, *fakeCoordinatorRollback) {
	t.Helper()
	base := time.Unix(8000, 0)
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	preview := networkplan.Preview{
		Validation:          networkplan.ValidationResult{Valid: true, PlanHash: stateTestPlanHash},
		FirewallBackend:     "iptables-nft",
		FirewallEnvironment: firewall.Inspection{SelectedBackend: "iptables-nft", IptablesPath: "/usr/sbin/iptables", ApplyReady: true},
		NetplanYAML:         "network:\n  version: 2\n",
		FirewallRestoreIPv4: "*filter\nCOMMIT\n",
	}
	staged, err := store.StageNetworkPlan(networkplan.Plan{Schema: 1}, preview, "coordinator-request", base.Add(-time.Second), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	files := networktransaction.FileStore{Root: filepath.Join(t.TempDir(), "transactions")}
	watchdog := &fakeCoordinatorWatchdog{}
	applier := &fakeCoordinatorApplier{}
	rollback := &fakeCoordinatorRollback{}
	finalizer := &fakeConfirmationFinalizer{}
	clock := &incrementingClock{next: base}
	coordinator := NetworkCoordinator{
		Store:          store,
		Files:          files,
		Snapshotter:    fakeSnapshotter{},
		Syntax:         fakeSyntaxValidator{},
		Watchdog:       watchdog,
		Applier:        applier,
		Health:         fakeHealthChecker{report: coordinatorHealth(base.Add(4*time.Second), true)},
		Rollback:       rollback,
		Finalizer:      finalizer,
		RollbackWindow: 2 * time.Minute,
		Now:            clock.Now,
	}
	return coordinator, staged, watchdog, applier, rollback
}

func TestCoordinatorReachesConfirmationOnlyAfterHealthyGuardedApply(t *testing.T) {
	coordinator, staged, watchdog, applier, rollback := coordinatorFixture(t)
	result, err := coordinator.Apply(context.Background(), staged.ApplyID)
	if err != nil {
		t.Fatal(err)
	}
	if result.Transaction == nil || result.Transaction.Phase != networktransaction.PhaseAwaitingConfirmation || watchdog.arms != 1 || applier.calls != 1 || rollback.calls != 0 {
		t.Fatalf("unexpected guarded apply result: result=%+v arms=%d applies=%d rollbacks=%d", result, watchdog.arms, applier.calls, rollback.calls)
	}
	confirmed, err := coordinator.Confirm(context.Background(), staged.ApplyID, staged.PlanHash)
	if err != nil || confirmed.Transaction.Phase != networktransaction.PhaseConfirmed || watchdog.disarms != 1 {
		t.Fatalf("confirmation failed: confirmed=%+v err=%v disarms=%d", confirmed, err, watchdog.disarms)
	}
	if finalizer := coordinator.Finalizer.(*fakeConfirmationFinalizer); finalizer.calls != 1 {
		t.Fatalf("confirmed DHCPv4 service was not enabled exactly once: %+v", finalizer)
	}
	if mode := coordinator.Store.Get().OperatingMode; mode != gatewayprotocol.ModeRouted {
		t.Fatalf("confirmed network did not activate routed mode: %s", mode)
	}
	manifest, err := coordinator.Files.ReadManifest(staged.ApplyID)
	if err != nil {
		t.Fatal(err)
	}
	if durable, err := coordinator.Files.IsConfirmed(manifest); err != nil || !durable {
		t.Fatalf("confirmation marker is not durable: durable=%v err=%v", durable, err)
	}
}

func TestCoordinatorKeepsWatchdogWhenConfirmedDHCP4EnablementFails(t *testing.T) {
	coordinator, staged, watchdog, _, _ := coordinatorFixture(t)
	if _, err := coordinator.Apply(context.Background(), staged.ApplyID); err != nil {
		t.Fatal(err)
	}
	finalizer := coordinator.Finalizer.(*fakeConfirmationFinalizer)
	finalizer.err = errors.New("enable failed")
	confirmed, err := coordinator.Confirm(context.Background(), staged.ApplyID, staged.PlanHash)
	if err == nil || !strings.Contains(err.Error(), "boot enablement") || confirmed.Transaction.Phase != networktransaction.PhaseConfirmed {
		t.Fatalf("confirmed finalization failure was not surfaced: confirmed=%+v err=%v", confirmed, err)
	}
	if watchdog.disarms != 0 {
		t.Fatal("watchdog was disarmed before confirmed service finalization")
	}
}

func TestCoordinatorApplyFailureRollsBackWithFreshContext(t *testing.T) {
	coordinator, staged, watchdog, applier, rollback := coordinatorFixture(t)
	applier.err = errors.New("host mutation failed")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := coordinator.Apply(ctx, staged.ApplyID)
	if err == nil || !strings.Contains(err.Error(), "host mutation failed") || result.Transaction.Phase != networktransaction.PhaseRolledBack {
		t.Fatalf("apply failure did not roll back: result=%+v err=%v", result, err)
	}
	if rollback.calls != 1 || rollback.contextCanceled || watchdog.disarms != 1 {
		t.Fatalf("rollback was not independent: calls=%d canceled=%v disarms=%d", rollback.calls, rollback.contextCanceled, watchdog.disarms)
	}
}

func TestCoordinatorFailedHealthRollsBack(t *testing.T) {
	coordinator, staged, _, _, rollback := coordinatorFixture(t)
	coordinator.Health = fakeHealthChecker{report: coordinatorHealth(time.Unix(8004, 0), false)}
	result, err := coordinator.Apply(context.Background(), staged.ApplyID)
	if err == nil || result.Transaction.Phase != networktransaction.PhaseRolledBack || rollback.calls != 1 {
		t.Fatalf("failed health did not roll back: result=%+v err=%v calls=%d", result, err, rollback.calls)
	}
}

func TestCoordinatorPreparationFailureNeverArmsOrMutates(t *testing.T) {
	coordinator, staged, watchdog, applier, rollback := coordinatorFixture(t)
	coordinator.Syntax = fakeSyntaxValidator{err: errors.New("syntax failed")}
	result, err := coordinator.Apply(context.Background(), staged.ApplyID)
	if err == nil || !strings.Contains(err.Error(), "syntax failed") || result.Transaction.Phase != networktransaction.PhasePreparing {
		t.Fatalf("preparation failure was not retained safely: result=%+v err=%v", result, err)
	}
	if watchdog.arms != 0 || applier.calls != 0 || rollback.calls != 0 {
		t.Fatalf("preparation failure crossed mutation boundary: arms=%d applies=%d rollbacks=%d", watchdog.arms, applier.calls, rollback.calls)
	}
}

func TestCoordinatorRollbackFailureLeavesWatchdogArmedForRetry(t *testing.T) {
	coordinator, staged, watchdog, applier, rollback := coordinatorFixture(t)
	applier.err = errors.New("apply failed")
	rollback.err = errors.New("rollback failed")
	result, err := coordinator.Apply(context.Background(), staged.ApplyID)
	if err == nil || result.Transaction.Phase != networktransaction.PhaseRollbackFailed || watchdog.disarms != 0 {
		t.Fatalf("rollback failure was not retained for watchdog retry: result=%+v err=%v disarms=%d", result, err, watchdog.disarms)
	}
	if _, readErr := coordinator.Files.ReadOutcome(staged.ApplyID); !errors.Is(readErr, os.ErrNotExist) {
		t.Fatalf("terminal outcome suppressed watchdog retry: %v", readErr)
	}
}

func TestCoordinatorRejectsConfirmationIdentityMismatch(t *testing.T) {
	coordinator, staged, watchdog, _, _ := coordinatorFixture(t)
	if _, err := coordinator.Apply(context.Background(), staged.ApplyID); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Confirm(context.Background(), staged.ApplyID, strings.Repeat("f", 64)); err == nil {
		t.Fatal("mismatched plan hash was confirmed")
	}
	if watchdog.disarms != 0 {
		t.Fatal("watchdog was disarmed after rejected confirmation")
	}
}

func TestStateReconcilesIndependentWatchdogRollback(t *testing.T) {
	coordinator, staged, _, _, _ := coordinatorFixture(t)
	if _, err := coordinator.Apply(context.Background(), staged.ApplyID); err != nil {
		t.Fatal(err)
	}
	manifest, err := coordinator.Files.ReadManifest(staged.ApplyID)
	if err != nil {
		t.Fatal(err)
	}
	outcome := networktransaction.WatchdogOutcome{Schema: networktransaction.SchemaVersion, ApplyID: staged.ApplyID, PlanHash: staged.PlanHash, Status: "ROLLED_BACK", FinishedAt: manifest.CreatedAt.Add(30 * time.Second)}
	if err := coordinator.Files.WriteOutcome(outcome); err != nil {
		t.Fatal(err)
	}
	reconciled, err := coordinator.Store.ReconcileNetworkOutcome(coordinator.Files)
	if err != nil || reconciled.Transaction.Phase != networktransaction.PhaseRolledBack {
		t.Fatalf("watchdog rollback was not reconciled: staged=%+v err=%v", reconciled, err)
	}
	state := coordinator.Store.Get()
	if state.OperatingMode != gatewayprotocol.ModeSetupSafe || state.EmergencyBypass {
		t.Fatalf("rollback did not restore safe state: %+v", state)
	}
}

func TestStateReconcilesIndependentWatchdogConfirmation(t *testing.T) {
	coordinator, staged, _, _, _ := coordinatorFixture(t)
	if _, err := coordinator.Apply(context.Background(), staged.ApplyID); err != nil {
		t.Fatal(err)
	}
	manifest, err := coordinator.Files.ReadManifest(staged.ApplyID)
	if err != nil {
		t.Fatal(err)
	}
	confirmation, err := coordinator.Files.Confirm(staged.ApplyID, staged.PlanHash, manifest.CreatedAt.Add(20*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	outcome := networktransaction.WatchdogOutcome{Schema: networktransaction.SchemaVersion, ApplyID: staged.ApplyID, PlanHash: staged.PlanHash, Status: "CONFIRMED", FinishedAt: confirmation.ConfirmedAt.Add(time.Second)}
	if err := coordinator.Files.WriteOutcome(outcome); err != nil {
		t.Fatal(err)
	}
	reconciled, err := coordinator.Store.ReconcileNetworkOutcome(coordinator.Files)
	if err != nil || reconciled.Transaction.Phase != networktransaction.PhaseConfirmed {
		t.Fatalf("watchdog confirmation was not reconciled: staged=%+v err=%v", reconciled, err)
	}
	if mode := coordinator.Store.Get().OperatingMode; mode != gatewayprotocol.ModeRouted {
		t.Fatalf("reconciled confirmation did not activate routed mode: %s", mode)
	}
}

func TestStateSurfacesIndependentWatchdogRollbackFailure(t *testing.T) {
	coordinator, staged, _, _, _ := coordinatorFixture(t)
	if _, err := coordinator.Apply(context.Background(), staged.ApplyID); err != nil {
		t.Fatal(err)
	}
	manifest, err := coordinator.Files.ReadManifest(staged.ApplyID)
	if err != nil {
		t.Fatal(err)
	}
	outcome := networktransaction.WatchdogOutcome{Schema: networktransaction.SchemaVersion, ApplyID: staged.ApplyID, PlanHash: staged.PlanHash, Status: "ROLLBACK_FAILED", FinishedAt: manifest.CreatedAt.Add(30 * time.Second), Detail: "netplan recovery failed"}
	if err := coordinator.Files.WriteOutcome(outcome); err != nil {
		t.Fatal(err)
	}
	reconciled, err := coordinator.Store.ReconcileNetworkOutcome(coordinator.Files)
	if err != nil || reconciled.Transaction.Phase != networktransaction.PhaseRollbackFailed {
		t.Fatalf("watchdog failure was not reconciled: staged=%+v err=%v", reconciled, err)
	}
	state := coordinator.Store.Get()
	if state.OperatingMode != gatewayprotocol.ModeEmergency || !state.EmergencyBypass {
		t.Fatalf("rollback failure was not surfaced as emergency state: %+v", state)
	}
}

func TestStateReconcilesSuccessfulIndependentRetryAfterRollbackFailure(t *testing.T) {
	coordinator, staged, _, _, _ := coordinatorFixture(t)
	if _, err := coordinator.Apply(context.Background(), staged.ApplyID); err != nil {
		t.Fatal(err)
	}
	manifest, err := coordinator.Files.ReadManifest(staged.ApplyID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Store.RequireNetworkRollback(staged.ApplyID, "initial recovery failed"); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Store.BeginNetworkRollback(staged.ApplyID, manifest.CreatedAt.Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Store.FailNetworkRollback(staged.ApplyID, manifest.CreatedAt.Add(11*time.Second), "netplan reload failed"); err != nil {
		t.Fatal(err)
	}
	outcome := networktransaction.WatchdogOutcome{Schema: networktransaction.SchemaVersion, ApplyID: staged.ApplyID, PlanHash: staged.PlanHash, Status: "ROLLED_BACK", FinishedAt: manifest.CreatedAt.Add(20 * time.Second)}
	if err := coordinator.Files.WriteOutcome(outcome); err != nil {
		t.Fatal(err)
	}
	reconciled, err := coordinator.Store.ReconcileNetworkOutcome(coordinator.Files)
	if err != nil || reconciled.Transaction.Phase != networktransaction.PhaseRolledBack {
		t.Fatalf("successful independent retry was not reconciled: staged=%+v err=%v", reconciled, err)
	}
	state := coordinator.Store.Get()
	if state.OperatingMode != gatewayprotocol.ModeSetupSafe || state.EmergencyBypass {
		t.Fatalf("successful retry did not leave safe mode: %+v", state)
	}
}
