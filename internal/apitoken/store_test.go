package apitoken

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTokenLifecycleStoresOnlyDigestAndAuditsEveryUse(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "tokens.json")
	store := &Store{Path: path, Now: func() time.Time { return now }}
	deviceA := "device-0123456789abcdef0123456789abcdef"
	deviceB := "device-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	created, err := store.Create(CreateRequest{Name: "nightly inventory", Creator: "admin", Scopes: []Scope{ScopeDevicesRead}, Restrictions: Restrictions{DeviceIDs: []string{deviceB, deviceA, deviceA}}, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.Secret, "lgt_") || created.Token.State != "active" {
		t.Fatalf("unexpected creation result: %#v", created)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), created.Secret) {
		t.Fatal("clear-text secret was persisted")
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("unsafe store permissions: %v %v", info, err)
	}
	principal, err := store.Authenticate(created.Secret, ScopeDevicesRead, "GET", "/api/v1/devices/"+deviceA, deviceA)
	if err != nil {
		t.Fatal(err)
	}
	if principal.Actor != "token:nightly inventory" || len(principal.Restrictions.DeviceIDs) != 2 {
		t.Fatalf("unexpected principal: %#v", principal)
	}
	if _, err := store.Authenticate(created.Secret, ScopeSystemRead, "GET", "/api/v1/system/status", ""); err == nil {
		t.Fatal("wrong scope was accepted")
	}
	listed, err := store.List()
	if err != nil || len(listed) != 1 || listed[0].UseCount != 1 {
		t.Fatalf("unexpected list: %#v %v", listed, err)
	}
	if _, err := store.Revoke(created.Token.ID, "admin", "credential rotation"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authenticate(created.Secret, ScopeDevicesRead, "GET", "/api/v1/devices/"+deviceA, deviceA); err == nil {
		t.Fatal("revoked token was accepted")
	}
	var doc document
	if err := json.Unmarshal(mustRead(t, path), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Audit) != 3 || doc.Audit[0].Action != "created" || doc.Audit[1].Action != "used" || doc.Audit[2].Action != "revoked" {
		t.Fatalf("unexpected audit: %#v", doc.Audit)
	}
}

func TestTokenExpiryAndRestrictionsFailClosed(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	store := &Store{Path: filepath.Join(t.TempDir(), "tokens.json"), Now: func() time.Time { return now }}
	if _, err := store.Create(CreateRequest{Name: "bad mixed", Creator: "admin", Scopes: []Scope{ScopeDevicesRead, ScopeSystemRead}, Restrictions: Restrictions{DeviceIDs: []string{"dev_a"}}, ExpiresAt: now.Add(time.Hour)}); err == nil {
		t.Fatal("mixed restricted scopes were accepted")
	}
	if _, err := store.Create(CreateRequest{Name: "too long", Creator: "admin", Scopes: []Scope{ScopeSystemRead}, ExpiresAt: now.Add(MaxLifetime + time.Second)}); err == nil {
		t.Fatal("excess lifetime was accepted")
	}
	if _, err := store.Create(CreateRequest{Name: "capture robot", Creator: "admin", Scopes: []Scope{ScopeCapturesWrite}, ExpiresAt: now.Add(time.Hour)}); err == nil {
		t.Fatal("sensitive write scope was accepted without acknowledgement")
	}
	if _, err := store.Create(CreateRequest{Name: "capture robot", Creator: "admin", Scopes: []Scope{ScopeCapturesWrite}, ExpiresAt: now.Add(time.Hour), SensitiveAcknowledged: true}); err != nil {
		t.Fatalf("acknowledged sensitive scope was rejected: %v", err)
	}
	created, err := store.Create(CreateRequest{Name: "short lived", Creator: "admin", Scopes: []Scope{ScopeSystemRead}, ExpiresAt: now.Add(MinLifetime)})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(MinLifetime)
	if _, err := store.Authenticate(created.Secret, ScopeSystemRead, "GET", "/api/v1/system/status", ""); err == nil {
		t.Fatal("expired token was accepted")
	}
}

func TestTamperedAuditStoreIsRejected(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "tokens.json")
	store := &Store{Path: path, Now: func() time.Time { return now }}
	if _, err := store.Create(CreateRequest{Name: "automation", Creator: "admin", Scopes: []Scope{ScopeSystemRead}, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	data := mustRead(t, path)
	data = []byte(strings.Replace(string(data), `"action": "created"`, `"action": "forged"`, 1))
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.List(); err == nil {
		t.Fatal("tampered audit chain was accepted")
	}
}

func TestAuditCompactionRetainsChainAndNeverBlocksAuthentication(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	doc := document{SchemaVersion: SchemaVersion}
	for index := 0; index < MaxAudit+1; index++ {
		if err := appendAudit(&doc, "used", "tok_0123456789abcdef01234567", "token:automation", "GET", "/api/v1/system/status", "", now.Add(time.Duration(index)*time.Second)); err != nil {
			t.Fatalf("audit append %d failed: %v", index, err)
		}
	}
	if doc.Revision != MaxAudit+1 || doc.AuditAnchorRevision != AuditCompactionBatch || len(doc.Audit) != MaxAudit-AuditCompactionBatch+1 {
		t.Fatalf("unexpected compacted audit bounds: revision=%d anchor=%d retained=%d", doc.Revision, doc.AuditAnchorRevision, len(doc.Audit))
	}
	if err := validateDocument(doc); err != nil {
		t.Fatalf("compacted audit chain is invalid: %v", err)
	}
}

func TestTokenRecordCompactionKeepsActiveAndNewestInactive(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	doc := document{SchemaVersion: SchemaVersion}
	for index := 0; index < MaxTokens*4; index++ {
		expires := now.Add(-time.Hour)
		if index == 0 {
			expires = now.Add(time.Hour)
		}
		doc.Tokens = append(doc.Tokens, Record{ID: fmt.Sprintf("tok_%024x", index), ExpiresAt: expires})
	}
	compactTokenRecords(&doc, now)
	if len(doc.Tokens) != MaxTokens*4-1 || doc.Tokens[0].ID != "tok_000000000000000000000000" || doc.Tokens[1].ID != "tok_000000000000000000000002" {
		t.Fatalf("unexpected compacted token records: count=%d first=%q second=%q", len(doc.Tokens), doc.Tokens[0].ID, doc.Tokens[1].ID)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
