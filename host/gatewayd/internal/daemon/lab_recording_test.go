package daemon

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/configlock"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

type fakeCaptureUnits struct{ active map[string]bool }

func (f *fakeCaptureUnits) Start(_ context.Context, id string) error { f.active[id] = true; return nil }
func (f *fakeCaptureUnits) Stop(_ context.Context, id string) error  { f.active[id] = false; return nil }
func (f *fakeCaptureUnits) Active(_ context.Context, id string) (bool, error) {
	return f.active[id], nil
}

type labRecordingFixture struct {
	recorder *LabRecorder
	store    *StateStore
	captures *capture.Manager
	units    *fakeCaptureUnits
	now      *time.Time
}

func newLabRecordingFixture(t *testing.T) labRecordingFixture {
	t.Helper()
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	setConfirmedLabPlan(store, stateTestPlanHash)
	now := time.Date(2026, 10, 1, 14, 16, 0, 0, time.UTC)
	units := &fakeCaptureUnits{active: map[string]bool{}}
	counter := uint64(0)
	captures := &capture.Manager{
		Store: capture.Store{Root: filepath.Join(t.TempDir(), "pcap")}, Controller: units, SoftwareVersion: "test",
		Now: func() time.Time { return now },
		Random: func(value []byte) (int, error) {
			counter++
			clear(value)
			binary.BigEndian.PutUint64(value[len(value)-8:], counter)
			return len(value), nil
		},
	}
	fixture := labRecordingFixture{store: store, captures: captures, units: units, now: &now}
	fixture.recorder = fixture.newRecorder(t)
	return fixture
}

// newRecorder is a fresh LabRecorder over the same state and captures, as
// after a gatewayd restart.
func (f labRecordingFixture) newRecorder(t *testing.T) *LabRecorder {
	return &LabRecorder{
		Store: f.store, Captures: f.captures, ConfigLock: &configlock.Manager{Path: filepath.Join(t.TempDir(), "config.lock")},
		Now: func() time.Time { return *f.now },
		Source: func(context.Context) (capture.Source, string, error) {
			active := f.store.Get().activeNetworkPlan()
			return capture.Source{InterfaceName: "ens18", InterfaceStableID: "pci-ens18", SingleArmGateway: "192.168.10.177", SingleArmLabCIDR: "192.168.10.0/24"}, active.PlanHash, nil
		},
	}
}

func setConfirmedLabPlan(store *StateStore, planHash string) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.state.OperatingMode = gatewayprotocol.ModeRouted
	store.state.StagedNetworkPlan = &networkplan.StagedPlan{
		ApplyID: "apply-0123456789abcdef0123456789abcdef", PlanHash: planHash,
		Status: string(networktransaction.PhaseConfirmed), Transaction: &networktransaction.Record{Phase: networktransaction.PhaseConfirmed},
	}
}

// finishCapture ends a capture the way its worker does at the deadline.
func (f labRecordingFixture) finishCapture(t *testing.T, id string) {
	t.Helper()
	f.units.active[id] = false
	if err := f.captures.Store.WriteWorkerStatus(capture.WorkerStatus{Schema: capture.SchemaVersion, SessionID: id, State: capture.StateCompleted, StartedAt: *f.now, EndedAt: *f.now, UpdatedAt: *f.now}); err != nil {
		t.Fatal(err)
	}
	manifest, err := f.captures.Store.CollectFiles(id, *f.now)
	if err != nil || f.captures.Store.WriteManifest(manifest) != nil {
		t.Fatalf("finalize %s: %v", id, err)
	}
}

func (f labRecordingFixture) sessions(t *testing.T) []capture.View {
	t.Helper()
	views, err := f.captures.List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return views
}

func TestLabRecorderRecordsAConfirmedLabAndKeepsOneRecording(t *testing.T) {
	fixture := newLabRecordingFixture(t)
	first := fixture.recorder.Tick(t.Context())
	if !first.Enabled || !first.Recording || first.Manual || first.SessionID == "" || first.Reason != "" {
		t.Fatalf("a confirmed lab was not recorded: %+v", first)
	}
	views := fixture.sessions(t)
	if len(views) != 1 || !views[0].Session.Request.Automatic || views[0].Session.Request.Mode != capture.ModeFull || views[0].Session.PolicyRevision != stateTestPlanHash || views[0].Session.Source.SingleArmGateway != "192.168.10.177" {
		t.Fatalf("unexpected lab recording: %+v", views)
	}
	if again := fixture.recorder.Tick(t.Context()); again.SessionID != first.SessionID || len(fixture.sessions(t)) != 1 {
		t.Fatalf("a second check started another recording: %+v", again)
	}
	// A gatewayd restart (or upgrade) adopts the running recording.
	if adopted := fixture.newRecorder(t).Tick(t.Context()); adopted.SessionID != first.SessionID || len(fixture.sessions(t)) != 1 {
		t.Fatalf("a restarted gatewayd did not adopt the running recording: %+v", adopted)
	}
}

func TestLabRecorderStartsANewRecordingWhenOneEnds(t *testing.T) {
	fixture := newLabRecordingFixture(t)
	first := fixture.recorder.Tick(t.Context())
	*fixture.now = fixture.now.Add(capture.LabRecordingDuration)
	fixture.finishCapture(t, first.SessionID)
	next := fixture.recorder.Tick(t.Context())
	if !next.Recording || next.SessionID == "" || next.SessionID == first.SessionID {
		t.Fatalf("recording did not continue after the day ended: %+v", next)
	}
}

func TestLabRecorderRecordsAgainAfterAReboot(t *testing.T) {
	fixture := newLabRecordingFixture(t)
	first := fixture.recorder.Tick(t.Context())
	if err := fixture.captures.Store.WriteWorkerStatus(capture.WorkerStatus{Schema: capture.SchemaVersion, SessionID: first.SessionID, State: capture.StateRunning, StartedAt: *fixture.now, UpdatedAt: *fixture.now}); err != nil {
		t.Fatal(err)
	}
	fixture.units.active = map[string]bool{} // nothing survives a reboot
	*fixture.now = fixture.now.Add(time.Hour)
	next := fixture.newRecorder(t).Tick(t.Context())
	if !next.Recording || next.SessionID == first.SessionID {
		t.Fatalf("recording did not resume after a reboot: %+v", next)
	}
	interrupted, err := fixture.captures.Get(t.Context(), first.SessionID)
	if err != nil || interrupted.Manifest == nil || interrupted.State != capture.StateStopped {
		t.Fatalf("the recording the reboot cut off was not finalized: %+v err=%v", interrupted, err)
	}
}

func TestLabRecorderStopsWhenTheLabIsTurnedOffOrRolledBack(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*StateStore)
		reason string
	}{
		{"network off", func(store *StateStore) {
			store.mu.Lock()
			store.state.OperatingMode, store.state.StagedNetworkPlan = gatewayprotocol.ModeSetupSafe, nil
			store.mu.Unlock()
		}, "The lab is off"},
		{"rolled back", func(store *StateStore) {
			store.mu.Lock()
			store.state.StagedNetworkPlan.Transaction.Phase = networktransaction.PhaseRolledBack
			store.mu.Unlock()
		}, "No lab network plan is confirmed"},
		{"emergency bypass", func(store *StateStore) {
			if _, err := store.SetEmergencyBypass(true); err != nil {
				panic(err)
			}
		}, "Emergency bypass"},
		{"turned off", func(store *StateStore) {
			if err := store.SetLabRecording(false); err != nil {
				panic(err)
			}
		}, "turned off"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newLabRecordingFixture(t)
			first := fixture.recorder.Tick(t.Context())
			test.change(fixture.store)
			stopped := fixture.recorder.Tick(t.Context())
			if stopped.Recording || fixture.units.active[first.SessionID] || !strings.Contains(stopped.Reason, test.reason) {
				t.Fatalf("recording did not stop with a reason: %+v units=%v", stopped, fixture.units.active)
			}
			if again := fixture.recorder.Tick(t.Context()); again.Recording || len(fixture.sessions(t)) != 1 {
				t.Fatalf("recording restarted while it should stay off: %+v", again)
			}
		})
	}
}

func TestLabRecorderTurnsBackOn(t *testing.T) {
	fixture := newLabRecordingFixture(t)
	if err := fixture.store.SetLabRecording(false); err != nil {
		t.Fatal(err)
	}
	if off := fixture.recorder.Tick(t.Context()); off.Enabled || off.Recording {
		t.Fatalf("recording ran while turned off: %+v", off)
	}
	if err := fixture.store.SetLabRecording(true); err != nil {
		t.Fatal(err)
	}
	if on := fixture.recorder.Tick(t.Context()); !on.Enabled || !on.Recording {
		t.Fatalf("recording did not resume when turned on: %+v", on)
	}
}

func TestLabRecorderRestartsForANewLabPlan(t *testing.T) {
	fixture := newLabRecordingFixture(t)
	first := fixture.recorder.Tick(t.Context())
	newPlan := strings.Repeat("b", 64)
	setConfirmedLabPlan(fixture.store, newPlan)
	restarting := fixture.recorder.Tick(t.Context())
	if fixture.units.active[first.SessionID] || !strings.Contains(restarting.Reason, "new network plan") {
		t.Fatalf("the old plan's recording kept running: %+v", restarting)
	}
	next := fixture.recorder.Tick(t.Context())
	view, err := fixture.captures.Get(t.Context(), next.SessionID)
	if err != nil || !next.Recording || view.Session.PolicyRevision != newPlan {
		t.Fatalf("the new plan is not recorded: %+v view=%+v err=%v", next, view.Session, err)
	}
}

func TestLabRecorderStepsAsideForAManualCaptureAndResumesAfterIt(t *testing.T) {
	fixture := newLabRecordingFixture(t)
	automatic := fixture.recorder.Tick(t.Context())
	manual, err := fixture.captures.Start(t.Context(), capture.StartRequest{Name: "Phone test", Administrator: "admin", IdempotencyKey: "capture-request-manual-01", Mode: capture.ModeFull}, capture.Source{InterfaceName: "ens18", InterfaceStableID: "pci-ens18"}, gatewayprotocol.ModeRouted, stateTestPlanHash)
	if err != nil {
		t.Fatal(err)
	}
	during := fixture.recorder.Tick(t.Context())
	if !during.Recording || !during.Manual || during.SessionID != manual.Session.ID || fixture.units.active[automatic.SessionID] || !strings.Contains(during.Reason, "resumes when it ends") {
		t.Fatalf("status during a manual capture: %+v units=%v", during, fixture.units.active)
	}
	fixture.finishCapture(t, manual.Session.ID)
	after := fixture.recorder.Tick(t.Context())
	if !after.Recording || after.Manual || after.SessionID == manual.Session.ID || after.SessionID == automatic.SessionID {
		t.Fatalf("automatic recording did not resume after the manual capture: %+v", after)
	}
}

func TestLabRecorderExplainsWhyItCannotStart(t *testing.T) {
	fixture := newLabRecordingFixture(t)
	fixture.recorder.NewCaptureAllowed = func() bool { return false }
	status := fixture.recorder.Tick(t.Context())
	if status.Recording || !strings.Contains(status.Reason, "pressure") || len(fixture.sessions(t)) != 0 {
		t.Fatalf("status under resource pressure: %+v", status)
	}
}

func TestGatewayLabRecordingRequests(t *testing.T) {
	fixture := newLabRecordingFixture(t)
	server := NewServerWithHostServices(fixture.store, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, fixture.captures)
	server.recorder = fixture.recorder
	call := func(method, params string) (any, *gatewayprotocol.RPCError) {
		return server.dispatch(t.Context(), gatewayprotocol.Request{JSONRPC: gatewayprotocol.JSONRPCVersion, ID: "lab-recording-" + method, Method: method, Params: json.RawMessage(params)})
	}
	// Clients cannot start the automatic recording themselves.
	if _, rpcErr := call("StartCapture", `{"request":{"name":"x","administrator":"admin","idempotency_key":"capture-request-forged-01","automatic":true}}`); rpcErr == nil || rpcErr.Code != -32602 {
		t.Fatalf("a client started an automatic recording: %+v", rpcErr)
	}
	recording := fixture.recorder.Tick(t.Context())
	// Stopping the automatic recording turns it off instead of having it
	// start again moments later.
	if _, rpcErr := call("StopCapture", `{"session_id":"`+recording.SessionID+`"}`); rpcErr != nil {
		t.Fatal(rpcErr)
	}
	if !fixture.store.Get().LabRecordingOff {
		t.Fatal("stopping the automatic recording did not turn it off")
	}
	result, rpcErr := call("SetLabRecording", `{"enabled":true}`)
	status, ok := result.(gatewayprotocol.LabRecordingStatus)
	if rpcErr != nil || !ok || !status.Enabled || !status.Recording || status.SessionID == recording.SessionID {
		t.Fatalf("turning recording back on: %+v %+v", result, rpcErr)
	}
	state, rpcErr := call("GetManagedState", `{}`)
	if rpcErr != nil || state.(gatewayprotocol.Status).LabRecording == nil || !state.(gatewayprotocol.Status).LabRecording.Recording {
		t.Fatalf("managed state does not report the lab recording: %+v %+v", state, rpcErr)
	}
}
