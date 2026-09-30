package inventory

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMigrateLegacyStorePreservesDevicesAndAuditWithoutOverwriting(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	legacy := deterministicMutationStore(t, now)
	snapshot, err := legacy.ReconcileDHCP4([]DHCP4Lease{{Address: netip.MustParseAddr("10.77.0.111"), HardwareAddr: "52:54:00:00:00:01", ClientID: "01:01", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.UpdateMetadata(snapshot.Devices[0].ID, "admin", "legacy-migrate-op-01", DeviceMetadata{FriendlyName: "Preserved"}); err != nil {
		t.Fatal(err)
	}
	destination := &Store{Path: filepath.Join(t.TempDir(), "inventory.json"), Now: func() time.Time { return now }}
	if err := MigrateLegacyStore(destination, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(legacy.Path); !os.IsNotExist(err) {
		t.Fatalf("legacy source remained active after migration: %v", err)
	}
	if info, err := os.Lstat(legacy.Path + ".migrated"); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("legacy recovery copy was not archived: info=%#v err=%v", info, err)
	}
	migrated, err := destination.Snapshot()
	audit, auditErr := destination.AuditLog(10)
	if err != nil || auditErr != nil || len(migrated.Devices) != 1 || migrated.Devices[0].FriendlyName != "Preserved" || len(audit) != 1 {
		t.Fatalf("legacy inventory was not preserved: snapshot=%#v audit=%#v errors=%v/%v", migrated, audit, err, auditErr)
	}

	if err := MigrateLegacyStore(destination, legacy); err != nil {
		t.Fatalf("valid destination was not left in place: %v", err)
	}
	unchanged, err := destination.Snapshot()
	if err != nil || unchanged.Devices[0].FriendlyName != "Preserved" {
		t.Fatalf("migration overwrote destination: %#v err=%v", unchanged, err)
	}
}

func TestMigrateLegacyStoreRejectsSymlinkedSource(t *testing.T) {
	directory := t.TempDir()
	realPath := filepath.Join(directory, "real.json")
	if err := os.WriteFile(realPath, []byte(`{"schema":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(directory, "legacy.json")
	if err := os.Symlink(realPath, legacyPath); err != nil {
		t.Fatal(err)
	}
	if err := MigrateLegacyStore(&Store{Path: filepath.Join(directory, "new", "inventory.json")}, &Store{Path: legacyPath}); err == nil {
		t.Fatal("symlinked legacy inventory was migrated")
	}
}
