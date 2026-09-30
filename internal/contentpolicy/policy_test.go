package contentpolicy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreDefaultsAppliesAndRejectsStaleRevision(t *testing.T) {
	now := time.Date(2026, 9, 3, 18, 0, 0, 0, time.UTC)
	store := &Store{Path: filepath.Join(t.TempDir(), "policy.json"), Now: func() time.Time { return now }}

	initial, err := store.Load()
	if err != nil {
		t.Fatalf("load default policy: %v", err)
	}
	if initial.Schema != SchemaVersion || initial.Revision != 1 || !initial.CaptureHTTPContent {
		t.Fatalf("unexpected default policy: %#v", initial)
	}

	disabled, err := store.Apply(initial.Revision, false, "admin")
	if err != nil {
		t.Fatalf("disable content retention: %v", err)
	}
	if disabled.Revision != 2 || disabled.CaptureHTTPContent || disabled.UpdatedBy != "admin" || !disabled.UpdatedAt.Equal(now) {
		t.Fatalf("unexpected disabled policy: %#v", disabled)
	}

	reloaded, err := store.Load()
	if err != nil || reloaded != disabled {
		t.Fatalf("durable policy mismatch: %#v err=%v", reloaded, err)
	}
	if _, err := store.Apply(initial.Revision, true, "admin"); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale revision returned %v", err)
	}
}

func TestStoreRejectsUntrustedFilesystemObjectsAndCorruption(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, []byte(`{"schema":1,"revision":1,"capture_http_content":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "policy.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Store{Path: link}).Load(); err == nil {
		t.Fatal("symlink content policy was accepted")
	}

	for name, contents := range map[string]string{
		"invalid revision": `{"schema":1,"revision":0,"capture_http_content":true}`,
		"unknown field":    `{"schema":1,"revision":1,"capture_http_content":true,"secret":"unexpected"}`,
		"trailing JSON":    `{"schema":1,"revision":1,"capture_http_content":true}{"schema":1}`,
		"missing actor":    `{"schema":1,"revision":2,"capture_http_content":false,"updated_at":"2026-09-03T18:00:00Z"}`,
	} {
		t.Run(name, func(t *testing.T) {
			corrupt := filepath.Join(root, name+".json")
			if err := os.WriteFile(corrupt, []byte(contents), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := (&Store{Path: corrupt}).Load(); err == nil {
				t.Fatal("invalid content policy was accepted")
			}
		})
	}

	if _, err := (&Store{Path: "relative.json"}).Load(); err == nil {
		t.Fatal("relative content policy path was accepted")
	}
}
