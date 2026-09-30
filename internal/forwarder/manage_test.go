package forwarder

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestForwarderUpdateAndDeleteAreAuditedAndBounded(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	manager := &Manager{Root: t.TempDir(), Now: func() time.Time { return now }}
	created, err := manager.Create(CreateRequest{Name: "SOC", Kind: KindWebhook, Destination: "https://hooks.example.com/events", Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	id := created.Integration.ID
	name, destination := "SOC primary", "https://siem.example.net/shakerproxy"
	classes := []EventClass{ClassAudit, ClassAlert, ClassAlert}
	updated, err := manager.Update(id, created.Integration.Revision, UpdateRequest{Name: &name, Destination: &destination, Classes: &classes, Actor: "admin"})
	if err != nil || updated.Name != name || updated.Destination != destination || len(updated.Classes) != 2 || updated.Revision != 2 || updated.Kind != KindWebhook {
		t.Fatalf("update = %#v %v", updated, err)
	}
	same, err := manager.Update(id, 0, UpdateRequest{Name: &name, Actor: "admin"})
	if err != nil || same.Revision != 2 {
		t.Fatalf("no-op update = %#v %v", same, err)
	}
	if _, err := manager.Update(id, 1, UpdateRequest{Name: &name, Actor: "admin"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update returned %v", err)
	}
	unsafe := "https://127.0.0.1/events"
	if _, err := manager.Update(id, 0, UpdateRequest{Destination: &unsafe, Actor: "admin"}); err == nil {
		t.Fatal("an internal webhook destination was accepted")
	}
	empty := []EventClass{}
	if _, err := manager.Update(id, 0, UpdateRequest{Classes: &empty, Actor: "admin"}); err == nil {
		t.Fatal("an empty class list was accepted")
	}
	if err := os.MkdirAll(filepath.Join(manager.Root, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(manager.Root, "state", id+".json")
	if err := os.WriteFile(statePath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	deleted, err := manager.Delete(id, 0, "admin", "")
	if err != nil || deleted.ID != id {
		t.Fatalf("delete = %#v %v", deleted, err)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("delivery queue was not removed: %v", err)
	}
	status, err := manager.Status()
	if err != nil || len(status) != 0 {
		t.Fatalf("deleted forwarder still listed: %#v %v", status, err)
	}
	if _, err := manager.Delete(id, 0, "admin", ""); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("second delete returned %v", err)
	}
}

func TestForwarderConfigurationAuditRollsOverInsteadOfFilling(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	manager := &Manager{Root: t.TempDir(), Now: func() time.Time { return now }}
	created, err := manager.Create(CreateRequest{Name: "local", Kind: KindJSONL, Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < configAuditRollover+10; index++ {
		if _, err := manager.SetEnabled(created.Integration.ID, 0, index%2 == 0, "admin", "toggle for audit rollover"); err != nil {
			t.Fatalf("toggle %d failed: %v", index, err)
		}
	}
	doc, err := manager.loadConfiguration(false)
	if err != nil {
		t.Fatalf("rolled-over audit does not validate: %v", err)
	}
	if len(doc.Audit) > configAuditRollover || doc.AuditAnchor == "" || doc.Revision != uint64(configAuditRollover+11) || doc.Audit[0].Previous != doc.AuditAnchor {
		t.Fatalf("unexpected audit after rollover: len=%d revision=%d", len(doc.Audit), doc.Revision)
	}
	doc.AuditAnchor = doc.Audit[0].Hash
	if validateConfiguration(doc) == nil {
		t.Fatal("a broken audit anchor was accepted")
	}
}
