package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

const stateTestPlanHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestStateStoreRejectsUnavailableMode(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set("SELECTIVE_MITM", false); err == nil {
		t.Fatal("expected unavailable mode to be rejected")
	}
}

func TestStateStoreStagesIdempotentlyAndRollsBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	plan := networkplan.Plan{Schema: 1, Name: "test"}
	preview := networkplan.Preview{Validation: networkplan.ValidationResult{Valid: true, PlanHash: "abc"}}
	now := time.Unix(100, 0)
	first, err := store.StageNetworkPlan(plan, preview, "request-12345678", now, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.StageNetworkPlan(plan, preview, "request-12345678", now.Add(time.Second), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if first.ApplyID != second.ApplyID {
		t.Fatal("idempotent retry created a second apply ID")
	}
	if _, err := store.StageNetworkPlan(plan, preview, "different-123456", now.Add(time.Second), 5*time.Minute); err == nil {
		t.Fatal("conflicting stage replaced an active transaction")
	}
	if err := store.RollbackStagedNetworkPlan("wrong"); err == nil {
		t.Fatal("wrong apply ID rolled back transaction")
	}
	if err := store.RollbackStagedNetworkPlan(first.ApplyID); err != nil {
		t.Fatal(err)
	}
	if store.Get().StagedNetworkPlan != nil {
		t.Fatal("staged plan remained after rollback")
	}
	reopened, err := OpenStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Get().StagedNetworkPlan != nil {
		t.Fatal("rolled back plan reappeared after restart")
	}
}

func TestStateStorePersistsEmergencyBypass(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(gatewayprotocol.ModeEmergency, true); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	state := reopened.Get()
	if !state.EmergencyBypass || state.OperatingMode != gatewayprotocol.ModeEmergency {
		t.Fatalf("unexpected state: %+v", state)
	}
}

func TestStateStorePersistsGuardedNetworkLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	preview := networkplan.Preview{Validation: networkplan.ValidationResult{Valid: true, PlanHash: stateTestPlanHash}}
	staged, err := store.StageNetworkPlan(networkplan.Plan{Schema: 1, Name: "test"}, preview, "request-12345678", now, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	staged, err = store.BeginNetworkTransaction(staged.ApplyID, now.Add(time.Second))
	if err != nil || staged.Status != string(networktransaction.PhasePreparing) {
		t.Fatalf("begin transaction: staged=%+v err=%v", staged, err)
	}
	staged, err = store.ArmNetworkWatchdog(staged.ApplyID, now.Add(2*time.Second), 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	staged, err = store.BeginNetworkHostApply(staged.ApplyID, now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	staged, err = store.MarkNetworkApplied(staged.ApplyID, now.Add(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	report := networktransaction.HealthReport{CheckedAt: now.Add(5 * time.Second), Checks: []networktransaction.HealthCheck{
		{Name: networktransaction.CheckManagement, Status: networktransaction.CheckPass},
		{Name: networktransaction.CheckWAN, Status: networktransaction.CheckPass},
		{Name: networktransaction.CheckDNS, Status: networktransaction.CheckPass},
		{Name: networktransaction.CheckIPv4Forwarding, Status: networktransaction.CheckPass},
		{Name: networktransaction.CheckDHCP4, Status: networktransaction.CheckPass},
		{Name: networktransaction.CheckIPv6, Status: networktransaction.CheckSkip},
	}}
	staged, err = store.RecordNetworkHealth(staged.ApplyID, report)
	if err != nil {
		t.Fatal(err)
	}
	staged, err = store.ConfirmNetworkTransaction(staged.ApplyID, now.Add(6*time.Second))
	if err != nil || staged.Status != string(networktransaction.PhaseConfirmed) {
		t.Fatalf("confirm transaction: staged=%+v err=%v", staged, err)
	}
	reopened, err := OpenStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	persisted := reopened.Get().StagedNetworkPlan
	if persisted == nil || persisted.Transaction == nil || persisted.Transaction.Phase != networktransaction.PhaseConfirmed {
		t.Fatalf("confirmed lifecycle was not persisted: %+v", persisted)
	}
	if state, err := reopened.SetEmergencyBypass(true); err != nil || state.OperatingMode != gatewayprotocol.ModeEmergency || !state.EmergencyBypass {
		t.Fatalf("enable bypass over confirmed routing: state=%+v err=%v", state, err)
	}
	files := networktransaction.FileStore{Root: filepath.Join(t.TempDir(), "transactions")}
	directory, err := files.TransactionDirectory(staged.ApplyID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	outcome := networktransaction.WatchdogOutcome{Schema: networktransaction.SchemaVersion, ApplyID: staged.ApplyID, PlanHash: staged.PlanHash, Status: "CONFIRMED", FinishedAt: now.Add(7 * time.Second)}
	if err := files.WriteOutcome(outcome); err != nil {
		t.Fatal(err)
	}
	if state, err := reopened.ReconcileNetworkOutcome(files); err != nil || state.Transaction == nil || reopened.Get().OperatingMode != gatewayprotocol.ModeEmergency || !reopened.Get().EmergencyBypass {
		t.Fatalf("confirmed outcome reconciliation cleared explicit bypass: state=%+v err=%v", reopened.Get(), err)
	}
	if state, err := reopened.SetEmergencyBypass(false); err != nil || state.OperatingMode != gatewayprotocol.ModeRouted || state.EmergencyBypass {
		t.Fatalf("disable bypass did not restore confirmed routing: state=%+v err=%v", state, err)
	}
}

func TestPreApplyDiscardRejectedAfterWatchdogArm(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	preview := networkplan.Preview{Validation: networkplan.ValidationResult{Valid: true, PlanHash: stateTestPlanHash}}
	staged, err := store.StageNetworkPlan(networkplan.Plan{Schema: 1}, preview, "request-12345678", now, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BeginNetworkTransaction(staged.ApplyID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ArmNetworkWatchdog(staged.ApplyID, now.Add(2*time.Second), 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := store.RollbackStagedNetworkPlan(staged.ApplyID); err == nil {
		t.Fatal("pre-apply discard removed an armed transaction")
	}
}

func TestOpenStateStoreRejectsCorruptTransactionIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	preview := networkplan.Preview{Validation: networkplan.ValidationResult{Valid: true, PlanHash: stateTestPlanHash}}
	staged, err := store.StageNetworkPlan(networkplan.Plan{Schema: 1}, preview, "request-12345678", now, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	staged, err = store.BeginNetworkTransaction(staged.ApplyID, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	staged.Transaction.PlanHash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	store.mu.Lock()
	next := store.state
	next.StagedNetworkPlan = &staged
	if err := store.persistLocked(next); err != nil {
		store.mu.Unlock()
		t.Fatal(err)
	}
	store.mu.Unlock()
	if _, err := OpenStateStore(path); err == nil {
		t.Fatal("corrupt persisted transaction identity was accepted")
	}
}

// confirmPlanForTest runs one plan through the guarded lifecycle to CONFIRMED.
func confirmPlanForTest(t *testing.T, store *StateStore, plan networkplan.Plan, hash, key string, now time.Time) networkplan.StagedPlan {
	t.Helper()
	preview := networkplan.Preview{Validation: networkplan.ValidationResult{Valid: true, PlanHash: hash}}
	staged, err := store.StageNetworkPlan(plan, preview, key, now, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	steps := []func() (networkplan.StagedPlan, error){
		func() (networkplan.StagedPlan, error) {
			return store.BeginNetworkTransaction(staged.ApplyID, now.Add(time.Second))
		},
		func() (networkplan.StagedPlan, error) {
			return store.ArmNetworkWatchdog(staged.ApplyID, now.Add(2*time.Second), 2*time.Minute)
		},
		func() (networkplan.StagedPlan, error) {
			return store.BeginNetworkHostApply(staged.ApplyID, now.Add(3*time.Second))
		},
		func() (networkplan.StagedPlan, error) {
			return store.MarkNetworkApplied(staged.ApplyID, now.Add(4*time.Second))
		},
		func() (networkplan.StagedPlan, error) {
			return store.RecordNetworkHealth(staged.ApplyID, networktransaction.HealthReport{CheckedAt: now.Add(5 * time.Second), Checks: []networktransaction.HealthCheck{
				{Name: networktransaction.CheckManagement, Status: networktransaction.CheckPass},
				{Name: networktransaction.CheckWAN, Status: networktransaction.CheckPass},
				{Name: networktransaction.CheckDNS, Status: networktransaction.CheckPass},
				{Name: networktransaction.CheckIPv4Forwarding, Status: networktransaction.CheckPass},
				{Name: networktransaction.CheckDHCP4, Status: networktransaction.CheckPass},
				{Name: networktransaction.CheckIPv6, Status: networktransaction.CheckSkip},
			}})
		},
		func() (networkplan.StagedPlan, error) {
			return store.ConfirmNetworkTransaction(staged.ApplyID, now.Add(6*time.Second))
		},
	}
	for _, step := range steps {
		if staged, err = step(); err != nil {
			t.Fatal(err)
		}
	}
	return staged
}

// Regression from a routed EC2 lab: staging a candidate replaced the only
// plan slot, and discarding it made the gateway forget the plan the host was
// still running, so lab DNS, captures and device discovery stopped.
func TestStagingACandidateKeepsTheConfirmedPlanActive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	lab := networkplan.Plan{Schema: 1, Name: "lab", Topology: networkplan.TopologySingleArm,
		Interfaces: []networkplan.Interface{{StableID: "pci-0000:00:05.0", CurrentName: "ens5", Role: networkplan.RoleWANLab}},
		IPv4:       networkplan.IPv4Configuration{Enabled: true, LabCIDR: "172.31.32.0/20", GatewayAddress: "172.31.47.80", NAT44: true}}
	confirmed := confirmPlanForTest(t, store, lab, stateTestPlanHash, "request-12345678", now)

	later := now.Add(time.Hour) // the confirmed plan's staging TTL has passed
	candidate := networkplan.Preview{Validation: networkplan.ValidationResult{Valid: true, PlanHash: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"}}
	staged, err := store.StageNetworkPlan(networkplan.Plan{Schema: 1, Name: "candidate"}, candidate, "request-87654321", later, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if active := store.Get().activeNetworkPlan(); active == nil || active.ApplyID != confirmed.ApplyID {
		t.Fatalf("staging a candidate hid the confirmed plan: %+v", active)
	}
	if err := store.RollbackStagedNetworkPlan(staged.ApplyID); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if active := reopened.Get().activeNetworkPlan(); active == nil || active.ApplyID != confirmed.ApplyID {
		t.Fatalf("discarding a candidate forgot the confirmed plan: %+v", active)
	}
	if iface, _, ok := confirmedLabPlan(reopened); !ok || iface.CurrentName != "ens5" {
		t.Fatalf("the lab context was lost: %+v ok=%v", iface, ok)
	}
	if state, err := reopened.SetEmergencyBypass(true); err != nil || state.OperatingMode != gatewayprotocol.ModeEmergency {
		t.Fatalf("enable bypass: %+v %v", state, err)
	}
	if state, err := reopened.SetEmergencyBypass(false); err != nil || state.OperatingMode != gatewayprotocol.ModeRouted {
		t.Fatalf("disabling bypass must return to routing the confirmed plan: %+v %v", state, err)
	}
}

// After a reboot the runtime keeper must restore the running plan even when
// an unapplied candidate is staged.
func TestRuntimeKeeperRestoresTheConfirmedPlanWithACandidateStaged(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	confirmed := confirmPlanForTest(t, store, networkplan.Plan{Schema: 1, Name: "lab"}, stateTestPlanHash, "request-12345678", now)
	candidate := networkplan.Preview{Validation: networkplan.ValidationResult{Valid: true, PlanHash: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"}}
	if _, err := store.StageNetworkPlan(networkplan.Plan{Schema: 1, Name: "candidate"}, candidate, "request-87654321", now.Add(time.Hour), 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	keeper := &NetworkRuntimeKeeper{Store: store}
	if plan, ok := keeper.activePlan(); !ok || plan.ApplyID != confirmed.ApplyID {
		t.Fatalf("runtime keeper would not restore the confirmed plan: %+v ok=%v", plan, ok)
	}
}

// There was no way out of routed mode: the uninstaller refused while a plan
// ran and nothing could restore the previous network. Revert undoes the
// running plan with the watchdog's rollback executor.
func TestRevertRestoresThePreviousNetworkWithTheRunningPlansSnapshot(t *testing.T) {
	directory := t.TempDir()
	store, err := OpenStateStore(filepath.Join(directory, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0).UTC()
	confirmed := confirmPlanForTest(t, store, networkplan.Plan{Schema: 1, Name: "lab"}, stateTestPlanHash, "request-12345678", now)
	files := networktransaction.FileStore{Root: filepath.Join(directory, "transactions")}
	manifest := networktransaction.WatchdogManifest{Schema: networktransaction.SchemaVersion, ApplyID: confirmed.ApplyID, PlanHash: stateTestPlanHash, CreatedAt: now, ConfirmBy: now.Add(2 * time.Minute),
		Rollback: networktransaction.RollbackSpec{InitialMode: "SETUP_SAFE_NO_SHAKERPROXY", IptablesPath: "/usr/sbin/iptables"}}
	if err := files.WriteManifest(manifest); err != nil {
		t.Fatal(err)
	}
	var restored []string
	activation := &NetworkActivation{Store: store, Files: files, Rollback: func(_ context.Context, m networktransaction.WatchdogManifest) error {
		restored = append(restored, m.ApplyID)
		return nil
	}}
	state, err := activation.Revert(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(restored) != 1 || restored[0] != confirmed.ApplyID || state.OperatingMode != gatewayprotocol.ModeSetupSafe || state.activeNetworkPlan() != nil {
		t.Fatalf("revert did not restore the running plan's snapshot: restored=%v state=%+v", restored, state)
	}
	if _, err := activation.Revert(context.Background()); err == nil {
		t.Fatal("a second revert with no running plan must fail")
	}

	failing := confirmPlanForTest(t, store, networkplan.Plan{Schema: 1, Name: "lab"}, stateTestPlanHash, "request-abcdefgh", now.Add(time.Hour))
	manifest.ApplyID = failing.ApplyID
	if err := files.WriteManifest(manifest); err != nil {
		t.Fatal(err)
	}
	activation.Rollback = func(context.Context, networktransaction.WatchdogManifest) error {
		return errors.New("netplan reload failed")
	}
	state, err = activation.Revert(context.Background())
	if err == nil || !state.EmergencyBypass || state.OperatingMode != gatewayprotocol.ModeEmergency {
		t.Fatalf("a failed restore must fail open into emergency bypass: state=%+v err=%v", state, err)
	}
}

// A gateway that had lost its plan record (an older version dropped it when
// a candidate was staged) still reverts from the newest confirmed snapshot.
func TestRevertFallsBackToTheNewestConfirmedTransaction(t *testing.T) {
	directory := t.TempDir()
	store, err := OpenStateStore(filepath.Join(directory, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0).UTC()
	confirmed := confirmPlanForTest(t, store, networkplan.Plan{Schema: 1, Name: "lab"}, stateTestPlanHash, "request-12345678", now)
	files := networktransaction.FileStore{Root: filepath.Join(directory, "transactions")}
	manifest := networktransaction.WatchdogManifest{Schema: networktransaction.SchemaVersion, ApplyID: confirmed.ApplyID, PlanHash: stateTestPlanHash, CreatedAt: now, ConfirmBy: now.Add(2 * time.Minute),
		Rollback: networktransaction.RollbackSpec{InitialMode: "SETUP_SAFE_NO_SHAKERPROXY", IptablesPath: "/usr/sbin/iptables"}}
	if err := files.WriteManifest(manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := files.Confirm(confirmed.ApplyID, stateTestPlanHash, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	// Simulate the lost record: routed, with no plan in the state.
	store.state.StagedNetworkPlan, store.state.ConfirmedNetworkPlan = nil, nil
	var restored string
	activation := &NetworkActivation{Store: store, Files: files, Rollback: func(_ context.Context, m networktransaction.WatchdogManifest) error {
		restored = m.ApplyID
		return nil
	}}
	state, err := activation.Revert(context.Background())
	if err != nil || restored != confirmed.ApplyID || state.OperatingMode != gatewayprotocol.ModeSetupSafe {
		t.Fatalf("fallback revert: restored=%q state=%+v err=%v", restored, state, err)
	}
}

// Regression from a routed EC2 lab: after the watchdog rolled a plan back,
// staging a retry was refused until the rolled-back plan's TTL expired.
func TestAFinishedTransactionDoesNotBlockStagingARetry(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	confirmed := confirmPlanForTest(t, store, networkplan.Plan{Schema: 1, Name: "lab"}, stateTestPlanHash, "request-12345678", now)
	retry := networkplan.Preview{Validation: networkplan.ValidationResult{Valid: true, PlanHash: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"}}
	// Still inside the confirmed plan's staging TTL.
	staged, err := store.StageNetworkPlan(networkplan.Plan{Schema: 1, Name: "retry"}, retry, "request-87654321", now.Add(time.Minute), 5*time.Minute)
	if err != nil || staged.ApplyID == confirmed.ApplyID {
		t.Fatalf("a finished transaction blocked staging: %+v %v", staged, err)
	}
	if _, err := store.StageNetworkPlan(networkplan.Plan{Schema: 1, Name: "other"}, retry, "request-abcdefgh", now.Add(2*time.Minute), 5*time.Minute); err == nil {
		t.Fatal("an unapplied staged plan must still be protected until it expires")
	}
}
