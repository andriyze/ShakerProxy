package inventory

import (
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestAliasTagExportIsDeterministicAndExcludesSensitiveMetadata(t *testing.T) {
	now := time.Date(2026, 9, 1, 21, 0, 0, 0, time.UTC)
	store := &Store{Path: filepath.Join(t.TempDir(), "inventory.json"), Now: func() time.Time { return now }}
	snapshot, err := store.ReconcileDHCP4([]DHCP4Lease{
		{Address: netip.MustParseAddr("10.77.0.81"), HardwareAddr: "52:54:00:00:00:81", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)},
		{Address: netip.MustParseAddr("10.77.0.82"), HardwareAddr: "52:54:00:00:00:82", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)},
	})
	if err != nil {
		t.Fatal(err)
	}
	for index, device := range snapshot.Devices {
		name := "Fixture B"
		if index == 1 {
			name = "Fixture A"
		}
		if _, err := store.UpdateMetadata(device.ID, "admin", "alias-tag-export-0"+string(rune('1'+index)), DeviceMetadata{FriendlyName: name, Owner: "Private owner", Tags: []string{"reviewed", "bench"}, Notes: "Must not be exported"}); err != nil {
			t.Fatal(err)
		}
	}
	exported, err := store.ExportAliasesTags()
	if err != nil || exported.Schema != SchemaVersion || !exported.GeneratedAt.Equal(now) || len(exported.Entries) != 2 {
		t.Fatalf("unexpected export: %#v err=%v", exported, err)
	}
	if exported.Entries[0].DeviceID > exported.Entries[1].DeviceID || exported.Entries[0].AliasRevision != 1 || len(exported.Entries[0].Tags) != 2 {
		t.Fatalf("export is not canonical: %#v", exported.Entries)
	}
}
