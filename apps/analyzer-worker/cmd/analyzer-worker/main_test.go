package main

import (
	"path/filepath"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/analyzer"
)

func TestHealthcheckDistinguishesActiveScanSuccessAndStaleness(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	root := filepath.Join(t.TempDir(), "state")
	store := analyzer.StateStore{Root: root}
	if err := store.Prepare(); err != nil {
		t.Fatal(err)
	}
	status := analyzer.Status{Schema: analyzer.SchemaVersion, Engine: analyzer.EngineZeek, SourceVersion: "8.2.1", StartedAt: now.Add(-10 * time.Minute), UpdatedAt: now, ScanInProgress: true}
	if err := store.WriteStatus(status); err != nil {
		t.Fatal(err)
	}
	if err := healthcheck(root, now); err != nil {
		t.Fatalf("active heartbeating scan was unhealthy: %v", err)
	}
	status.ScanInProgress = false
	if err := store.WriteStatus(status); err != nil {
		t.Fatal(err)
	}
	if err := healthcheck(root, now); err == nil {
		t.Fatal("idle worker without a successful scan was healthy")
	}
	status.LastSuccessAt = now.Add(-time.Minute)
	if err := store.WriteStatus(status); err != nil {
		t.Fatal(err)
	}
	if err := healthcheck(root, now); err != nil {
		t.Fatalf("recent successful scan was unhealthy: %v", err)
	}
	status.UpdatedAt = now.Add(-3 * time.Minute)
	status.LastSuccessAt = now.Add(-4 * time.Minute)
	if err := store.WriteStatus(status); err != nil {
		t.Fatal(err)
	}
	if err := healthcheck(root, now); err == nil {
		t.Fatal("stale broker heartbeat was healthy")
	}
}
