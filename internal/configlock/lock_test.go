package configlock

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestExclusiveCrossManagerLockAndStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run", "config.lock")
	now := time.Date(2026, 9, 2, 5, 0, 0, 0, time.UTC)
	manager := Manager{Path: path, Now: func() time.Time { return now }}
	guard, err := manager.Acquire(context.Background(), Request{OperationID: "update-01234567", Category: CategoryUpdate, Actor: "installer"})
	if err != nil {
		t.Fatal(err)
	}
	status, err := (Manager{Path: path}).Inspect()
	if err != nil || !status.Active || status.Record == nil || status.Record.OperationID != "update-01234567" || status.Record.StartedAt != now {
		t.Fatalf("unexpected active lock status: %+v err=%v", status, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	_, err = (Manager{Path: path}).Acquire(ctx, Request{OperationID: "dns-enforce-0001", Category: CategoryDNS, Actor: "gatewayd"})
	var busy *BusyError
	if !errors.As(err, &busy) || busy.Current == nil || busy.Current.Category != CategoryUpdate {
		t.Fatalf("concurrent mutation did not report current owner: %T %v", err, err)
	}
	if err := guard.Release(); err != nil {
		t.Fatal(err)
	}
	status, err = manager.Inspect()
	if err != nil || status.Active || status.Record != nil || status.Stale {
		t.Fatalf("released lock remained active: %+v err=%v", status, err)
	}
}

func TestExclusiveLockAcrossProcesses(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.lock")
	ready := filepath.Join(directory, "ready")
	release := filepath.Join(directory, "release")
	command := exec.Command(os.Args[0], "-test.run=TestConfigLockHelperProcess")
	command.Env = append(os.Environ(), "SHAKERPROXY_LOCK_HELPER_PATH="+path, "SHAKERPROXY_LOCK_HELPER_READY="+ready, "SHAKERPROXY_LOCK_HELPER_RELEASE="+release)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("helper process did not acquire the lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	_, err := (Manager{Path: path}).Acquire(ctx, Request{OperationID: "restore-01234567", Category: CategoryRestore, Actor: "parent"})
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("second process bypassed the lock: %v", err)
	}
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err = command.Wait()
	waited = true
	if err != nil {
		t.Fatal(err)
	}
}

func TestConfigLockHelperProcess(t *testing.T) {
	path := os.Getenv("SHAKERPROXY_LOCK_HELPER_PATH")
	if path == "" {
		return
	}
	guard, err := (Manager{Path: path}).Acquire(context.Background(), Request{OperationID: "network-helper-01", Category: CategoryNetwork, Actor: "helper"})
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Release()
	if err := os.WriteFile(os.Getenv("SHAKERPROXY_LOCK_HELPER_READY"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(os.Getenv("SHAKERPROXY_LOCK_HELPER_RELEASE")); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("parent did not release helper")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestCrashMetadataIsReportedStaleAndReplaced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.lock")
	manager := Manager{Path: path}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	stale := `{"schema":1,"operation_id":"restore-01234567","category":"restore","actor":"gatewayd","pid":999999,"started_at":"2026-09-02T04:00:00Z"}`
	if err := os.WriteFile(path+".json", []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	status, err := manager.Inspect()
	if err != nil || status.Active || !status.Stale || status.Record == nil {
		t.Fatalf("stale metadata was not distinguished: %+v err=%v", status, err)
	}
	guard, err := manager.Acquire(context.Background(), Request{OperationID: "ruleset-0123456", Category: CategoryRuleset, Actor: "gatewayd"})
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Release()
	status, err = manager.Inspect()
	if err != nil || !status.Active || status.Record == nil || status.Record.OperationID != "ruleset-0123456" || status.Stale {
		t.Fatalf("stale metadata was not replaced: %+v err=%v", status, err)
	}
}

func TestRejectsUnsafePathsAndMetadata(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "config.lock")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_, err := (Manager{Path: link}).Acquire(context.Background(), Request{OperationID: "network-012345", Category: CategoryNetwork, Actor: "gatewayd"})
	if err == nil {
		t.Fatal("symlink lock path was accepted")
	}
	if (Request{OperationID: "short", Category: Category("unknown"), Actor: "bad actor"}).Validate() == nil {
		t.Fatal("invalid request was accepted")
	}
}
