package capture

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func labRecordingManager(t *testing.T) (*Manager, *fakeController, *time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 1, 14, 16, 0, 0, time.UTC)
	controller := &fakeController{active: map[string]bool{}}
	counter := uint64(0)
	manager := &Manager{
		Store: Store{Root: filepath.Join(t.TempDir(), "pcap")}, Controller: controller, SoftwareVersion: "test",
		Now: func() time.Time { return now },
		Random: func(value []byte) (int, error) {
			counter++
			clear(value)
			binary.BigEndian.PutUint64(value[len(value)-8:], counter)
			return len(value), nil
		},
	}
	return manager, controller, &now
}

var labSource = Source{InterfaceName: "ens18", InterfaceStableID: "pci-ens18"}

// finish ends a session the way the worker does when its deadline passes.
func finish(t *testing.T, manager *Manager, controller *fakeController, id string, at time.Time) {
	t.Helper()
	controller.active[id] = false
	directory, _ := manager.Store.ArtifactDirectory(id)
	if err := os.WriteFile(filepath.Join(directory, "capture_00001_20261001141600.pcapng"), []byte("ring member"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := manager.Store.WriteWorkerStatus(WorkerStatus{Schema: SchemaVersion, SessionID: id, State: StateCompleted, StartedAt: at, EndedAt: at, UpdatedAt: at}); err != nil {
		t.Fatal(err)
	}
	manifest, err := manager.Store.CollectFiles(id, at)
	if err != nil || manager.Store.WriteManifest(manifest) != nil {
		t.Fatalf("finalize %s: %v", id, err)
	}
}

func TestLabRecordingIsAValidFullPacketDayLongRing(t *testing.T) {
	request := LabRecordingRequest("37060B93FA71A5D5EE8ED79C23EB6D1ABD154DCF3690C3650F2E497AE4E05F25")
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	if !request.Automatic || request.Mode != ModeFull || request.StopAfterSeconds != 86400 || request.Administrator != LabRecordingAdministrator {
		t.Fatalf("lab recording request = %+v", request)
	}
	// Segments close every 10 s so connection details reach Traffic quickly,
	// and 120 x 4 MiB keeps about 20 minutes within a manual capture's 512 MiB.
	request = request.WithDefaults()
	if request.SegmentSeconds != 10 || request.MaxFiles != 120 || request.SegmentSizeMiB != 4 {
		t.Fatalf("lab recording ring = %d s x %d files x %d MiB", request.SegmentSeconds, request.MaxFiles, request.SegmentSizeMiB)
	}
	if retained := request.SegmentSeconds * request.MaxFiles; retained < 20*60 {
		t.Fatalf("the ring keeps only %d s of low-rate traffic", retained)
	}
	// One 480 MiB ring running plus two finished ones.
	if bound := LabRecordingDiskBound(); bound != 3*480<<20 || bound > 3*512<<20 {
		t.Fatalf("automatic recording disk bound = %d bytes, want 3 x 480 MiB", bound)
	}
	// Only the automatic recording may use more than 64 files.
	manual := request
	manual.Automatic = false
	if err := manual.Validate(); err == nil || !strings.Contains(err.Error(), "between 2 and 64 files") {
		t.Fatalf("a manual 120-file ring was accepted: %v", err)
	}
	request.MaxFiles = 129
	if err := request.Validate(); err == nil {
		t.Fatal("an automatic ring larger than a manifest holds was accepted")
	}
}

func TestManualCaptureTakesOverFromTheLabRecording(t *testing.T) {
	manager, controller, _ := labRecordingManager(t)
	automatic, err := manager.Start(t.Context(), LabRecordingRequest("plan"), labSource, "ROUTED_PASSTHROUGH", "plan")
	if err != nil {
		t.Fatal(err)
	}
	manual, err := manager.Start(t.Context(), StartRequest{Name: "Phone test", Administrator: "admin", IdempotencyKey: "capture-request-manual-01", Mode: ModeFull}, labSource, "ROUTED_PASSTHROUGH", "plan")
	if err != nil {
		t.Fatalf("a manual capture was refused while the lab recording ran: %v", err)
	}
	if controller.active[automatic.Session.ID] || !controller.active[manual.Session.ID] {
		t.Fatalf("the manual capture did not replace the lab recording: %v", controller.active)
	}
	// The lab recording never replaces a manual capture, and two automatic
	// recordings never run together.
	if _, err := manager.Start(t.Context(), LabRecordingRequest("plan"), labSource, "ROUTED_PASSTHROUGH", "plan"); err == nil {
		t.Fatal("the lab recording replaced a running manual capture")
	}
	controller.active[manual.Session.ID] = false
	if _, err := manager.Start(t.Context(), LabRecordingRequest("plan"), labSource, "ROUTED_PASSTHROUGH", "plan"); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Start(t.Context(), LabRecordingRequest("plan"), labSource, "ROUTED_PASSTHROUGH", "plan"); err == nil {
		t.Fatal("a second lab recording started next to the first")
	}
}

func TestTidyLabRecordingsKeepsTheNewestAndNeverTouchesManualCaptures(t *testing.T) {
	manager, controller, now := labRecordingManager(t)
	manual, err := manager.Start(t.Context(), StartRequest{Name: "Phone test", Administrator: "admin", IdempotencyKey: "capture-request-manual-02"}, labSource, "ROUTED_PASSTHROUGH", "plan")
	if err != nil {
		t.Fatal(err)
	}
	finish(t, manager, controller, manual.Session.ID, *now)
	var recordings []string
	for day := 0; day < 5; day++ {
		*now = now.Add(24 * time.Hour)
		view, err := manager.Start(t.Context(), LabRecordingRequest("plan"), labSource, "ROUTED_PASSTHROUGH", "plan")
		if err != nil {
			t.Fatal(err)
		}
		recordings = append(recordings, view.Session.ID)
		if day < 4 {
			finish(t, manager, controller, view.Session.ID, now.Add(time.Hour))
		}
	}
	// The oldest finished recording is under an evidence hold.
	if _, err := manager.SetEvidenceHold(SetHoldRequest{SessionID: recordings[0], Active: true, CaseID: "case-0123456789abcdef0123456789abcdef", Actor: "admin", Reason: "keep for the bug report", IdempotencyKey: "hold-request-000001"}); err != nil {
		t.Fatal(err)
	}
	if err := manager.TidyLabRecordings(t.Context(), LabRecordingKeep); err != nil {
		t.Fatal(err)
	}
	remaining := map[string]bool{}
	ids, _ := manager.Store.ListSessionIDs()
	for _, id := range ids {
		remaining[id] = true
	}
	want := map[string]bool{manual.Session.ID: true, recordings[0]: true, recordings[2]: true, recordings[3]: true, recordings[4]: true}
	if len(remaining) != len(want) {
		t.Fatalf("captures after tidying = %v, want %v", remaining, want)
	}
	for id := range want {
		if !remaining[id] {
			t.Fatalf("capture %s was deleted; remaining %v", id, remaining)
		}
	}
}

func TestTidyLabRecordingsFinalizesARecordingAHostRestartCutOff(t *testing.T) {
	manager, controller, now := labRecordingManager(t)
	view, err := manager.Start(t.Context(), LabRecordingRequest("plan"), labSource, "ROUTED_PASSTHROUGH", "plan")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Store.WriteWorkerStatus(WorkerStatus{Schema: SchemaVersion, SessionID: view.Session.ID, State: StateRunning, StartedAt: *now, UpdatedAt: *now}); err != nil {
		t.Fatal(err)
	}
	controller.active[view.Session.ID] = false // the host rebooted
	*now = now.Add(time.Hour)
	if err := manager.TidyLabRecordings(t.Context(), LabRecordingKeep); err != nil {
		t.Fatal(err)
	}
	after, err := manager.Get(t.Context(), view.Session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Manifest == nil || after.State != StateStopped || after.Worker.StopReason != labRecordingInterrupted {
		t.Fatalf("interrupted recording was not finalized: %+v", after)
	}
}

var vpnSource = Source{InterfaceName: "wg-lab", InterfaceStableID: "wireguard:wg-lab"}

func TestTheVPNRecordingRunsBesideTheLabRecording(t *testing.T) {
	manager, controller, now := labRecordingManager(t)
	lab, err := manager.Start(t.Context(), LabRecordingRequest("plan"), labSource, "ROUTED_PASSTHROUGH", "plan")
	if err != nil {
		t.Fatal(err)
	}
	// A pcapng file mixing the lab's Ethernet frames and the VPN's raw IP
	// packets cannot be read by Zeek or Suricata, so the VPN gets its own.
	vpn, err := manager.Start(t.Context(), VPNRecordingRequest("vpn-0123456789abcdef"), vpnSource, "ROUTED_PASSTHROUGH", "vpn-0123456789abcdef")
	if err != nil {
		t.Fatalf("the VPN recording was refused next to the lab recording: %v", err)
	}
	if vpn.Session.Request.Name != VPNRecordingName || !controller.active[lab.Session.ID] || !controller.active[vpn.Session.ID] {
		t.Fatalf("active = %v", controller.active)
	}
	if _, err := manager.Start(t.Context(), VPNRecordingRequest("vpn-0123456789abcdef"), vpnSource, "ROUTED_PASSTHROUGH", "vpn-0123456789abcdef"); err == nil {
		t.Fatal("a second VPN recording started")
	}
	// A manual capture of the lab replaces only the lab recording.
	manual, err := manager.Start(t.Context(), StartRequest{Name: "Phone test", Administrator: "admin", IdempotencyKey: "capture-request-manual-03", Mode: ModeFull}, labSource, "ROUTED_PASSTHROUGH", "plan")
	if err != nil {
		t.Fatal(err)
	}
	if controller.active[lab.Session.ID] || !controller.active[vpn.Session.ID] || !controller.active[manual.Session.ID] {
		t.Fatalf("after the manual capture: %v", controller.active)
	}
	if _, err := manager.Start(t.Context(), LabRecordingRequest("plan"), labSource, "ROUTED_PASSTHROUGH", "plan"); err == nil {
		t.Fatal("the lab recording replaced a running manual capture")
	}
	// Tidying keeps the newest finished recordings of each interface.
	finish(t, manager, controller, manual.Session.ID, *now)
	finish(t, manager, controller, lab.Session.ID, *now)
	finish(t, manager, controller, vpn.Session.ID, *now)
	var labs []string
	for day := 1; day <= 3; day++ {
		*now = now.Add(24 * time.Hour)
		view, err := manager.Start(t.Context(), LabRecordingRequest("plan"), labSource, "ROUTED_PASSTHROUGH", "plan")
		if err != nil {
			t.Fatal(err)
		}
		finish(t, manager, controller, view.Session.ID, now.Add(time.Hour))
		labs = append(labs, view.Session.ID)
	}
	if err := manager.TidyLabRecordings(t.Context(), LabRecordingKeep); err != nil {
		t.Fatal(err)
	}
	ids, _ := manager.Store.ListSessionIDs()
	remaining := map[string]bool{}
	for _, id := range ids {
		remaining[id] = true
	}
	if !remaining[vpn.Session.ID] || !remaining[manual.Session.ID] || !remaining[labs[1]] || !remaining[labs[2]] || remaining[labs[0]] || remaining[lab.Session.ID] || len(remaining) != 4 {
		t.Fatalf("after tidying: %v", remaining)
	}
}
