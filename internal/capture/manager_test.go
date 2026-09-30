package capture

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

type fakeController struct{ active map[string]bool }

func (f *fakeController) Start(_ context.Context, id string) error { f.active[id] = true; return nil }
func (f *fakeController) Stop(_ context.Context, id string) error  { f.active[id] = false; return nil }
func (f *fakeController) Active(_ context.Context, id string) (bool, error) {
	active, ok := f.active[id]
	if !ok {
		return false, nil
	}
	return active, nil
}

func TestManagerStartIsIdempotentAndAllowsOneActiveSession(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	controller := &fakeController{active: map[string]bool{}}
	manager := Manager{
		Store: Store{Root: filepath.Join(t.TempDir(), "pcap")}, Controller: controller, SoftwareVersion: "test", Now: func() time.Time { return now },
		Random: func(value []byte) (int, error) {
			for index := range value {
				value[index] = byte(index)
			}
			return len(value), nil
		},
	}
	request := StartRequest{Name: "bounded", Administrator: "admin", IdempotencyKey: "capture-request-0004"}
	source := Source{InterfaceName: "lab0", InterfaceStableID: "pci-lab"}
	first, err := manager.Start(t.Context(), request, source, "ROUTED_PASSTHROUGH", "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.Start(t.Context(), request, source, "ROUTED_PASSTHROUGH", "")
	if err != nil || first.Session.ID != second.Session.ID {
		t.Fatalf("idempotent start failed: %#v %v", second, err)
	}
	request.IdempotencyKey = "capture-request-0005"
	if _, err := manager.Start(t.Context(), request, source, "ROUTED_PASSTHROUGH", ""); err == nil {
		t.Fatal("second active capture unexpectedly started")
	}
}

func TestManagerFinalizesStoppedSession(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	controller := &fakeController{active: map[string]bool{}}
	manager := Manager{Store: Store{Root: filepath.Join(t.TempDir(), "pcap")}, Controller: controller, SoftwareVersion: "test", Now: func() time.Time { return now }, Random: func(value []byte) (int, error) { copy(value, []byte("0123456789abcdef")); return len(value), nil }}
	view, err := manager.Start(t.Context(), StartRequest{Name: "bounded", Administrator: "admin", IdempotencyKey: "capture-request-0006"}, Source{InterfaceName: "lab0", InterfaceStableID: "pci-lab"}, "ROUTED_PASSTHROUGH", "")
	if err != nil {
		t.Fatal(err)
	}
	status := WorkerStatus{Schema: SchemaVersion, SessionID: view.Session.ID, State: StateStopped, StartedAt: now, EndedAt: now.Add(time.Second), UpdatedAt: now.Add(time.Second)}
	if err := manager.Store.WriteWorkerStatus(status); err != nil {
		t.Fatal(err)
	}
	manifest, err := manager.Store.CollectFiles(view.Session.ID, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Store.WriteManifest(manifest); err != nil {
		t.Fatal(err)
	}
	stopped, err := manager.Stop(t.Context(), view.Session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stopped.Active || stopped.Manifest == nil || stopped.State != StateStopped {
		t.Fatalf("unexpected stopped view: %#v", stopped)
	}
}

func TestManagerReportsControllerFailure(t *testing.T) {
	manager := Manager{Store: Store{Root: filepath.Join(t.TempDir(), "pcap")}, Controller: failingController{}}
	_, err := manager.Start(t.Context(), StartRequest{Name: "bounded", Administrator: "admin", IdempotencyKey: "capture-request-0007"}, Source{InterfaceName: "lab0", InterfaceStableID: "pci-lab"}, "ROUTED_PASSTHROUGH", "")
	if err == nil {
		t.Fatal("controller failure not reported")
	}
}

func TestManagerRejectsExportWhileCaptureIsActive(t *testing.T) {
	controller := &fakeController{active: map[string]bool{}}
	manager := Manager{Store: Store{Root: filepath.Join(t.TempDir(), "pcap")}, Controller: controller, Random: func(value []byte) (int, error) { copy(value, []byte("0123456789abcdef")); return len(value), nil }}
	view, err := manager.Start(t.Context(), StartRequest{Name: "bounded", Administrator: "admin", IdempotencyKey: "capture-request-0008"}, Source{InterfaceName: "lab0", InterfaceStableID: "pci-lab"}, "ROUTED_PASSTHROUGH", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ReadArtifactChunk(t.Context(), view.Session.ID, "capture.pcapng", 0, 1); err == nil {
		t.Fatal("active capture artifact was exportable")
	}
}

type failingController struct{}

func (failingController) Start(context.Context, string) error          { return errors.New("failed") }
func (failingController) Stop(context.Context, string) error           { return errors.New("failed") }
func (failingController) Active(context.Context, string) (bool, error) { return false, nil }
