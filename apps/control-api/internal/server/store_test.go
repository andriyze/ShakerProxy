package server

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

func TestCreateAdminConsumesTokenAndAuthenticates(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "setup-token")
	digest := sha256.Sum256([]byte("correct horse battery staple"))
	if err := os.WriteFile(tokenPath, digest[:], 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewStore(filepath.Join(dir, "data"), tokenPath)
	codes, err := store.CreateAdmin("correct horse battery staple", "admin", "LongEnough1!Password")
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 8 {
		t.Fatalf("expected 8 recovery codes, got %d", len(codes))
	}
	if _, err := store.CreateAdmin("correct horse battery staple", "admin", "AnotherLong2!Password"); err == nil {
		t.Fatal("consumed token created a second administrator")
	}
	ok, err := store.Authenticate("admin", "LongEnough1!Password")
	if err != nil || !ok {
		t.Fatalf("authentication failed: ok=%v err=%v", ok, err)
	}
	ok, err = store.Authenticate("admin", "wrong password")
	if err != nil || ok {
		t.Fatalf("wrong password accepted: ok=%v err=%v", ok, err)
	}
}

func TestCreateAdminRejectsWeakPasswordWithoutConsumingToken(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "setup-token")
	digest := sha256.Sum256([]byte("token"))
	if err := os.WriteFile(tokenPath, digest[:], 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewStore(filepath.Join(dir, "data"), tokenPath)
	if _, err := store.CreateAdmin("token", "admin", "weak"); err == nil {
		t.Fatal("weak password accepted")
	}
	if _, err := os.Stat(tokenPath); err != nil {
		t.Fatal("verifier should remain readable after validation failure")
	}
}

func TestCaptureExportHistoryIsDurableAndScoped(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir, filepath.Join(dir, "unused-token"))
	record, err := store.RecordCaptureExport(CaptureExportRecord{
		SessionID:  captureTestID,
		FileName:   "capture_00001.pcapng",
		SHA256:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Username:   "admin",
		RangeStart: 4,
		RangeEnd:   9,
		BytesSent:  6,
		Complete:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if record.ID == "" || record.ExportedAt.IsZero() || record.Schema != 1 {
		t.Fatalf("record identity was not assigned: %#v", record)
	}
	reopened := NewStore(dir, filepath.Join(dir, "unused-token"))
	records, err := reopened.ListCaptureExports(captureTestID)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].ID != record.ID || records[0].BytesSent != 6 || !records[0].Complete {
		t.Fatalf("unexpected persisted history: %#v", records)
	}
	other, err := reopened.ListCaptureExports("capture-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil || len(other) != 0 {
		t.Fatalf("history was not session scoped: %#v, %v", other, err)
	}
}

func TestCaptureExportHistoryRejectsTrailingData(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "capture-exports.json"), []byte(`{"schema":1,"records":[]} {}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(dir, "unused").ListCaptureExports(""); err == nil {
		t.Fatal("accepted a capture export ledger with trailing data")
	}
}

func TestCaptureExportStartIsDurableBeforeDelivery(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir, filepath.Join(dir, "unused-token"))
	started, err := store.BeginCaptureExport(CaptureExportRecord{
		SessionID:  captureTestID,
		FileName:   "capture_00002.pcapng",
		SHA256:     "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
		Username:   "admin",
		RangeStart: 0,
		RangeEnd:   99,
	})
	if err != nil {
		t.Fatal(err)
	}
	records, err := NewStore(dir, "unused").ListCaptureExports(captureTestID)
	if err != nil || len(records) != 1 || records[0].ID != started.ID || records[0].Complete || records[0].BytesSent != 0 {
		t.Fatalf("started export was not durably incomplete: %#v, %v", records, err)
	}
}
