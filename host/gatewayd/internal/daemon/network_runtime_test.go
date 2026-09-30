package daemon

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"shakerproxy.dev/shakerproxy/internal/configlock"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

type fakeRuntimeRestorer struct {
	calls      []string
	drift      []string
	restoreErr error
	driftErr   error
}

func (f *fakeRuntimeRestorer) Restore(_ context.Context, staged networkplan.StagedPlan) error {
	f.calls = append(f.calls, "restore:"+staged.PlanHash)
	return f.restoreErr
}

func (f *fakeRuntimeRestorer) Drift(_ context.Context, staged networkplan.StagedPlan) ([]string, error) {
	f.calls = append(f.calls, "drift:"+staged.PlanHash)
	return f.drift, f.driftErr
}

func runtimeKeeperFixture(t *testing.T, phase networktransaction.Phase, mode string) (*NetworkRuntimeKeeper, *fakeRuntimeRestorer, *bytes.Buffer, *StateStore) {
	t.Helper()
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.state.OperatingMode = mode
	store.state.StagedNetworkPlan = &networkplan.StagedPlan{
		ApplyID: "apply-0123456789abcdef0123456789abcdef", PlanHash: stateTestPlanHash,
		Status: string(phase), Transaction: &networktransaction.Record{Phase: phase},
	}
	store.mu.Unlock()
	logs := &bytes.Buffer{}
	restorer := &fakeRuntimeRestorer{}
	keeper := &NetworkRuntimeKeeper{Store: store, Restorer: restorer, ConfigLock: &configlock.Manager{Path: filepath.Join(t.TempDir(), "config.lock")}, Logger: slog.New(slog.NewTextHandler(logs, nil))}
	return keeper, restorer, logs, store
}

func TestRuntimeKeeperRestoresOnStartThenOnlyOnDrift(t *testing.T) {
	keeper, restorer, logs, _ := runtimeKeeperFixture(t, networktransaction.PhaseConfirmed, gatewayprotocol.ModeRouted)
	for tick := 0; tick < 2; tick++ {
		if err := keeper.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	restorer.drift = []string{"iptables hook DOCKER-USER -> SHAKERPROXY-FORWARD is missing"}
	if err := keeper.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	expected := []string{"restore:" + stateTestPlanHash, "drift:" + stateTestPlanHash, "drift:" + stateTestPlanHash, "restore:" + stateTestPlanHash}
	if strings.Join(restorer.calls, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected keeper actions: %v", restorer.calls)
	}
	output := logs.String()
	if !strings.Contains(output, "restoring runtime network state of the confirmed plan") || !strings.Contains(output, "drifted") || !strings.Contains(output, "DOCKER-USER -> SHAKERPROXY-FORWARD") || !strings.Contains(output, stateTestPlanHash) {
		t.Fatalf("keeper did not log clearly:\n%s", output)
	}
}

func TestRuntimeKeeperLeavesUnconfirmedAndSetupSafePlansAlone(t *testing.T) {
	for _, test := range []struct {
		phase networktransaction.Phase
		mode  string
	}{
		{networktransaction.PhaseAwaitingConfirmation, gatewayprotocol.ModeSetupSafe},
		{networktransaction.PhaseRolledBack, gatewayprotocol.ModeSetupSafe},
		{networktransaction.PhaseConfirmed, gatewayprotocol.ModeSetupSafe},
	} {
		keeper, restorer, _, _ := runtimeKeeperFixture(t, test.phase, test.mode)
		if err := keeper.Tick(t.Context()); err != nil || len(restorer.calls) != 0 {
			t.Fatalf("%s/%s changed runtime state: %v %v", test.phase, test.mode, restorer.calls, err)
		}
	}
	keeper, restorer, _, _ := runtimeKeeperFixture(t, networktransaction.PhaseConfirmed, gatewayprotocol.ModeEmergency)
	if err := keeper.Tick(t.Context()); err != nil || len(restorer.calls) != 1 {
		t.Fatalf("emergency bypass must keep plain routing: %v %v", restorer.calls, err)
	}
}

func TestRuntimeKeeperRetriesFailuresAndLogsEachProblemOnce(t *testing.T) {
	keeper, restorer, logs, _ := runtimeKeeperFixture(t, networktransaction.PhaseConfirmed, gatewayprotocol.ModeRouted)
	restorer.restoreErr = errors.New("confirmed preview is not bound to the confirmed plan hash")
	for tick := 0; tick < 3; tick++ {
		if err := keeper.Tick(t.Context()); err == nil {
			t.Fatal("restore failure was not reported")
		}
	}
	if strings.Join(restorer.calls, ",") != strings.Repeat("restore:"+stateTestPlanHash+",", 2)+"restore:"+stateTestPlanHash {
		t.Fatalf("failed restore was not retried on every pass: %v", restorer.calls)
	}
	if count := strings.Count(logs.String(), "lab forwarding stays off"); count != 1 {
		t.Fatalf("restore failure was logged %d times:\n%s", count, logs.String())
	}
	restorer.restoreErr = nil
	if err := keeper.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "is in place") {
		t.Fatalf("recovery was not logged:\n%s", logs.String())
	}
}

func TestRuntimeKeeperSkipsWhileAnotherConfigurationChangeHoldsTheLock(t *testing.T) {
	keeper, restorer, _, _ := runtimeKeeperFixture(t, networktransaction.PhaseConfirmed, gatewayprotocol.ModeRouted)
	guard, err := keeper.ConfigLock.Acquire(t.Context(), configlock.Request{OperationID: "network-test-0001", Category: configlock.CategoryNetwork, Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := keeper.Tick(t.Context()); err != nil || len(restorer.calls) != 0 {
		t.Fatalf("keeper ran during another configuration change: %v %v", restorer.calls, err)
	}
	if err := guard.Release(); err != nil {
		t.Fatal(err)
	}
	if err := keeper.Tick(t.Context()); err != nil || len(restorer.calls) != 1 {
		t.Fatalf("keeper did not run after the lock was released: %v %v", restorer.calls, err)
	}
}

func TestRuntimeKeeperRestoresAgainForANewlyConfirmedPlan(t *testing.T) {
	keeper, restorer, _, store := runtimeKeeperFixture(t, networktransaction.PhaseConfirmed, gatewayprotocol.ModeRouted)
	if err := keeper.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	next := *store.state.StagedNetworkPlan
	next.PlanHash = strings.Repeat("b", 64)
	store.state.StagedNetworkPlan = &next
	store.mu.Unlock()
	if err := keeper.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(restorer.calls) != 2 || restorer.calls[1] != "restore:"+next.PlanHash {
		t.Fatalf("a newly confirmed plan was not restored: %v", restorer.calls)
	}
}
