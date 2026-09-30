package testsession

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	deviceA = "device-0123456789abcdef0123456789abcdef"
	deviceB = "device-fedcba9876543210fedcba9876543210"
)

func newTestStore(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	now := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	store := &Store{Path: filepath.Join(t.TempDir(), "state", "test-sessions.json"), Now: func() time.Time { return now }}
	return store, &now
}

func TestStartListUpdateStopDelete(t *testing.T) {
	store, now := newTestStore(t)
	session, stopped, err := store.Start(StartInput{DeviceID: deviceA, DeviceName: "Living room TV", Name: " Firmware 2.1 first boot ", Notes: "line one\nline two", Actor: "admin"})
	if err != nil || len(stopped) != 0 {
		t.Fatalf("start: %#v stopped=%v err=%v", session, stopped, err)
	}
	if !ValidID(session.ID) || session.State != StateRunning || session.EndedAt != nil || session.Name != "Firmware 2.1 first boot" || session.CaptureSessionID != nil || session.CreatedBy != "admin" || !session.StartedAt.Equal(*now) {
		t.Fatalf("unexpected session: %#v", session)
	}
	info, err := os.Stat(store.Path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("store file mode: %v err=%v", info, err)
	}
	encoded, _ := json.Marshal(session)
	for _, field := range []string{`"ended_at":null`, `"capture_session_id":null`, `"state":"RUNNING"`, `"schema":1`} {
		if !strings.Contains(string(encoded), field) {
			t.Fatalf("session JSON %s lacks %s", encoded, field)
		}
	}

	attached, err := store.AttachCapture(session.ID, "capture-0123456789abcdef0123456789abcdef")
	if err != nil || attached.CaptureSessionID == nil || *attached.CaptureSessionID != "capture-0123456789abcdef0123456789abcdef" {
		t.Fatalf("attach capture: %#v err=%v", attached, err)
	}
	if _, err := store.AttachCapture(session.ID, "not-a-capture"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid capture link accepted: %v", err)
	}

	name, notes := "Firmware 2.1 — retest", ""
	updated, err := store.Update(session.ID, Update{Name: &name, Notes: &notes})
	if err != nil || updated.Name != name || updated.Notes != "" {
		t.Fatalf("update: %#v err=%v", updated, err)
	}
	*now = now.Add(time.Hour)
	ended, err := store.Stop(session.ID)
	if err != nil || ended.State != StateStopped || ended.EndedAt == nil || !ended.EndedAt.Equal(*now) || !ended.End(now.Add(time.Hour)).Equal(*now) {
		t.Fatalf("stop: %#v err=%v", ended, err)
	}
	again, err := store.Stop(session.ID)
	if err != nil || !again.EndedAt.Equal(*ended.EndedAt) {
		t.Fatalf("second stop changed the session: %#v err=%v", again, err)
	}
	items, total, err := store.List(Filter{DeviceID: deviceA, State: StateStopped})
	if err != nil || total != 1 || len(items) != 1 || items[0].ID != session.ID {
		t.Fatalf("list: %#v total=%d err=%v", items, total, err)
	}
	if _, running, err := store.Running(deviceA); err != nil || running {
		t.Fatalf("stopped session reported as running: %v err=%v", running, err)
	}
	removed, err := store.Delete(session.ID)
	if err != nil || removed.ID != session.ID {
		t.Fatalf("delete: %#v err=%v", removed, err)
	}
	if _, err := store.Get(session.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted session still readable: %v", err)
	}
	if _, err := store.Delete(session.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
}

func TestStartStopsPreviousRunningSessionForSameDeviceOnly(t *testing.T) {
	store, now := newTestStore(t)
	first, _, err := store.Start(StartInput{DeviceID: deviceA, Name: "Run 1", Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := store.Start(StartInput{DeviceID: deviceB, Name: "Other device", Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(10 * time.Minute)
	second, stopped, err := store.Start(StartInput{DeviceID: deviceA, Name: "Run 2", Actor: "admin"})
	if err != nil || len(stopped) != 1 || stopped[0].ID != first.ID || stopped[0].State != StateStopped || !stopped[0].EndedAt.Equal(*now) {
		t.Fatalf("start did not stop previous run: stopped=%#v err=%v", stopped, err)
	}
	running, ok, err := store.Running(deviceA)
	if err != nil || !ok || running.ID != second.ID {
		t.Fatalf("running session: %#v ok=%v err=%v", running, ok, err)
	}
	if session, _ := store.Get(other.ID); session.State != StateRunning {
		t.Fatalf("another device's session was stopped: %#v", session)
	}
	items, total, err := store.List(Filter{Limit: 1})
	if err != nil || total != 3 || len(items) != 1 || items[0].ID != second.ID {
		t.Fatalf("newest-first limited list: %#v total=%d err=%v", items, total, err)
	}
}

func TestInputValidation(t *testing.T) {
	store, _ := newTestStore(t)
	long := strings.Repeat("x", MaxNameBytes+1)
	for name, input := range map[string]StartInput{
		"bad device":      {DeviceID: "Living room TV", Name: "Run", Actor: "admin"},
		"empty name":      {DeviceID: deviceA, Name: "  ", Actor: "admin"},
		"multi-line name": {DeviceID: deviceA, Name: "Run\n2", Actor: "admin"},
		"long name":       {DeviceID: deviceA, Name: long, Actor: "admin"},
		"long notes":      {DeviceID: deviceA, Name: "Run", Notes: strings.Repeat("n", MaxNotesBytes+1), Actor: "admin"},
		"control notes":   {DeviceID: deviceA, Name: "Run", Notes: "bell\x07", Actor: "admin"},
		"missing actor":   {DeviceID: deviceA, Name: "Run"},
	} {
		if _, _, err := store.Start(input); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	session, _, err := store.Start(StartInput{DeviceID: deviceA, Name: "Run", Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(session.ID, Update{}); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty update: %v", err)
	}
	if _, err := store.Update(session.ID, Update{Name: &long}); !errors.Is(err, ErrInvalid) {
		t.Errorf("long rename: %v", err)
	}
	for _, id := range []string{"", "ts-xyz", "../etc/passwd"} {
		if _, err := store.Get(id); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get(%q): %v", id, err)
		}
	}
	if _, _, err := store.List(Filter{Limit: MaxLimit + 1}); !errors.Is(err, ErrInvalid) {
		t.Errorf("unbounded list: %v", err)
	}
	if _, _, err := store.List(Filter{State: "PAUSED"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("unknown state: %v", err)
	}
}

func seedSessions(t *testing.T, store *Store, count int, state State) {
	t.Helper()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	doc := document{Schema: Schema, Sessions: make([]Session, 0, count)}
	for index := 0; index < count; index++ {
		started := base.Add(time.Duration(index) * time.Minute)
		session := Session{Schema: Schema, ID: fmt.Sprintf("ts-%024x", index+1), DeviceID: fmt.Sprintf("device-%032x", index+1), Name: fmt.Sprintf("Run %d", index), State: state, StartedAt: started, CreatedBy: "admin"}
		if state == StateStopped {
			ended := started.Add(time.Minute)
			session.EndedAt = &ended
		}
		doc.Sessions = append(doc.Sessions, session)
	}
	if err := store.write(doc); err != nil {
		t.Fatal(err)
	}
}

func TestStoreStaysBoundedByPruningOldestStoppedSessions(t *testing.T) {
	store, _ := newTestStore(t)
	seedSessions(t, store, MaxSessions, StateStopped)
	created, _, err := store.Start(StartInput{DeviceID: deviceA, Name: "Newest", Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	items, total, err := store.List(Filter{Limit: MaxLimit})
	if err != nil || total != MaxSessions || items[0].ID != created.ID {
		t.Fatalf("bounded store: total=%d err=%v", total, err)
	}
	if _, err := store.Get(fmt.Sprintf("ts-%024x", 1)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("oldest stopped session was not pruned: %v", err)
	}
	if _, err := store.Get(fmt.Sprintf("ts-%024x", 2)); err != nil {
		t.Fatalf("second-oldest session was pruned: %v", err)
	}
}

func TestStoreRefusesToPruneRunningSessions(t *testing.T) {
	store, _ := newTestStore(t)
	seedSessions(t, store, MaxSessions, StateRunning)
	if _, _, err := store.Start(StartInput{DeviceID: deviceA, Name: "One too many", Actor: "admin"}); !errors.Is(err, ErrStoreFull) {
		t.Fatalf("full store of running sessions: %v", err)
	}
	if _, total, _ := store.List(Filter{}); total != MaxSessions {
		t.Fatalf("failed start changed the store: %d", total)
	}
}

func TestStoreRejectsCorruptOrUnknownDocuments(t *testing.T) {
	for name, content := range map[string]string{
		"not json":         "{",
		"unknown field":    `{"schema":1,"sessions":[],"extra":true}`,
		"wrong schema":     `{"schema":2,"sessions":[]}`,
		"running with end": `{"schema":1,"sessions":[{"schema":1,"id":"ts-000000000000000000000001","device_id":"` + deviceA + `","device_name":"","name":"x","notes":"","state":"RUNNING","started_at":"2026-01-01T00:00:00Z","ended_at":"2026-01-01T00:01:00Z","capture_session_id":null,"created_by":"admin"}]}`,
		"trailing data":    `{"schema":1,"sessions":[]} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			store, _ := newTestStore(t)
			if err := os.MkdirAll(filepath.Dir(store.Path), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(store.Path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := store.List(Filter{}); !errors.Is(err, ErrStoreRejected) {
				t.Fatalf("corrupt store accepted: %v", err)
			}
			if _, _, err := store.Start(StartInput{DeviceID: deviceA, Name: "Run", Actor: "admin"}); err == nil {
				t.Fatal("start wrote over a corrupt store")
			}
		})
	}
	relative := &Store{Path: "relative.json"}
	if _, _, err := relative.List(Filter{}); !errors.Is(err, ErrStoreRejected) {
		t.Fatalf("relative path accepted: %v", err)
	}
}

func TestConcurrentStartsKeepOneRunningSessionPerDevice(t *testing.T) {
	store := &Store{Path: filepath.Join(t.TempDir(), "test-sessions.json")}
	var wait sync.WaitGroup
	errs := make(chan error, 40)
	for index := 0; index < 40; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			device := deviceA
			if index%2 == 1 {
				device = deviceB
			}
			if _, _, err := store.Start(StartInput{DeviceID: device, Name: fmt.Sprintf("Run %d", index), Actor: "admin"}); err != nil {
				errs <- err
			}
		}(index)
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	items, total, err := store.List(Filter{Limit: MaxLimit})
	if err != nil || total != 40 {
		t.Fatalf("concurrent starts lost updates: total=%d err=%v", total, err)
	}
	running := map[string]int{}
	for _, item := range items {
		if item.State == StateRunning {
			running[item.DeviceID]++
		}
	}
	if running[deviceA] != 1 || running[deviceB] != 1 {
		t.Fatalf("running sessions per device: %v", running)
	}
}
