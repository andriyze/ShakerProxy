package policycoordination

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAcquireSerializesIndependentCallers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic-policy.lock")
	first, err := Acquire(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Release()

	ctx, cancel := context.WithTimeout(t.Context(), 75*time.Millisecond)
	defer cancel()
	if _, err := Acquire(ctx, path); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second acquisition error = %v, want deadline exceeded", err)
	}

	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	second, err := Acquire(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestAcquireRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "traffic-policy.lock")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(t.Context(), path); err == nil {
		t.Fatal("symlink lock path was accepted")
	}
}
