package hostevents

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func evtFiles(t *testing.T, directory string) []string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "evt_") {
			names = append(names, entry.Name())
		}
	}
	return names
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSpoolWritesEventsAtomicallyAndStopsAtThePendingLimit(t *testing.T) {
	directory := t.TempDir()
	spool, err := New(directory, "connections", nil)
	if err != nil {
		t.Fatal(err)
	}
	spool.MaxPending = 2
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go spool.Run(ctx)
	at := time.Date(2026, 10, 2, 3, 34, 36, 0, time.UTC)
	for index := 0; index < 3; index++ {
		spool.Enqueue(Event{At: at.Add(time.Duration(index) * time.Second), Encode: func(id string) ([]byte, error) { return []byte(`{"event_id":"` + id + `"}`), nil }})
	}
	waitFor(t, func() bool { return len(evtFiles(t, directory)) == 2 && spool.Dropped() == 1 })
	names := evtFiles(t, directory)
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil || !strings.Contains(string(raw), strings.TrimSuffix(name, ".json")) {
			t.Fatalf("%s holds %s (%v)", name, raw, err)
		}
		info, _ := os.Stat(filepath.Join(directory, name))
		if info.Mode().Perm() != 0o644 {
			t.Fatalf("%s mode %v; the forwarder reads it as another user", name, info.Mode().Perm())
		}
	}
}

func TestSpoolDropsAnEventThatCannotBeEncoded(t *testing.T) {
	directory := t.TempDir()
	spool, err := New(directory, "connections", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go spool.Run(ctx)
	spool.Enqueue(Event{At: time.Now(), Encode: func(string) ([]byte, error) { return nil, errors.New("bad event") }})
	spool.Enqueue(Event{At: time.Now(), Encode: func(id string) ([]byte, error) { return []byte("{}"), nil }})
	waitFor(t, func() bool { return spool.Dropped() == 1 && len(evtFiles(t, directory)) == 1 })
}

func TestNewRejectsAMissingOrRelativeSpool(t *testing.T) {
	if _, err := New("relative/dir", "connections", nil); err == nil {
		t.Fatal("a relative spool was accepted")
	}
	if _, err := New(filepath.Join(t.TempDir(), "missing"), "connections", nil); err == nil {
		t.Fatal("a missing spool was accepted")
	}
}
