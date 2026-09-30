package apitoken

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestLabWriteScopeIsAllowedAndNotSensitive(t *testing.T) {
	if ScopeLabWrite != "lab:write" || !slices.Contains(AllowedScopes(), ScopeLabWrite) || slices.Contains(SensitiveScopes(), ScopeLabWrite) {
		t.Fatalf("lab:write is not an allowed, non-sensitive scope: %v %v", AllowedScopes(), SensitiveScopes())
	}
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	store := &Store{Path: filepath.Join(t.TempDir(), "tokens.json"), Now: func() time.Time { return now }}
	created, err := store.Create(CreateRequest{Name: "lab robot", Creator: "admin", Scopes: []Scope{ScopeLabWrite, ScopeDevicesRead}, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("lab:write without acknowledgement was rejected: %v", err)
	}
	principal, err := store.Authenticate(created.Secret, ScopeLabWrite, "POST", "/api/v1/test-sessions", "")
	if err != nil || !slices.Contains(principal.Scopes, ScopeLabWrite) {
		t.Fatalf("lab:write token did not authenticate for lab:write: %#v %v", principal, err)
	}
	if _, err := store.Authenticate(created.Secret, ScopeCasesWrite, "POST", "/api/v1/cases", ""); !errors.Is(err, ErrForbidden) {
		t.Fatalf("lab:write granted cases:write: %v", err)
	}
	if _, err := store.Create(CreateRequest{Name: "mixed", Creator: "admin", Scopes: []Scope{ScopeLabWrite, ScopeCasesWrite}, ExpiresAt: now.Add(time.Hour)}); err == nil {
		t.Fatal("a sensitive scope next to lab:write skipped the acknowledgement")
	}
}
