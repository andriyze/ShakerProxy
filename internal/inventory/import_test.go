package inventory

import (
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAliasTagImportParsesExportedJSONAndCSVStrictly(t *testing.T) {
	entry := AliasTagExportEntry{DeviceID: "device-0123456789abcdef0123456789abcdef", FriendlyName: `Bench, "Camera"`, AliasRevision: 2, Tags: []string{"Camera", "lab"}}
	document, err := json.Marshal(AliasTagExport{Schema: SchemaVersion, GeneratedAt: time.Now().UTC(), Entries: []AliasTagExportEntry{entry}})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseAliasTagImport("json", document)
	if err != nil || len(parsed) != 1 || parsed[0].FriendlyName != entry.FriendlyName || !sameStrings(parsed[0].Tags, []string{"camera", "lab"}) {
		t.Fatalf("JSON export did not parse canonically: %#v err=%v", parsed, err)
	}
	csvDocument := "device_id,friendly_name,alias_revision,tags_json\r\n" + entry.DeviceID + ",\"Bench, \"\"Camera\"\"\",2,\"[\"\"Camera\"\",\"\"lab\"\"]\"\r\n"
	parsed, err = ParseAliasTagImport("csv", []byte(csvDocument))
	if err != nil || len(parsed) != 1 || parsed[0].FriendlyName != entry.FriendlyName || !sameStrings(parsed[0].Tags, []string{"camera", "lab"}) {
		t.Fatalf("CSV export did not parse canonically: %#v err=%v", parsed, err)
	}
	if _, err := ParseAliasTagImport("json", append(document[:len(document)-1], []byte(`,"unexpected":true}`)...)); err == nil {
		t.Fatal("unknown JSON import field was accepted")
	}
	nullTags := strings.Replace(string(document), `"tags":["Camera","lab"]`, `"tags":null`, 1)
	if _, err := ParseAliasTagImport("json", []byte(nullTags)); err == nil {
		t.Fatal("null JSON tag array was accepted")
	}
	duplicate := []AliasTagImportEntry{entry, entry}
	if _, err := normalizeAliasTagImportEntries(duplicate); err == nil {
		t.Fatal("duplicate device import row was accepted")
	}
}

func TestAliasTagImportPreviewAndApplyAreAtomicAuditedAndReplaySafe(t *testing.T) {
	now := time.Date(2026, 9, 1, 22, 0, 0, 0, time.UTC)
	store := &Store{Path: filepath.Join(t.TempDir(), "inventory.json"), Now: func() time.Time { return now }}
	snapshot, err := store.ReconcileDHCP4([]DHCP4Lease{
		{Address: netip.MustParseAddr("10.77.0.91"), HardwareAddr: "52:54:00:00:00:91", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)},
		{Address: netip.MustParseAddr("10.77.0.92"), HardwareAddr: "52:54:00:00:00:92", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)},
	})
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]AliasTagImportEntry, 0, 2)
	for index, device := range snapshot.Devices {
		entries = append(entries, AliasTagImportEntry{DeviceID: device.ID, FriendlyName: "Imported fixture " + string(rune('A'+index)), AliasRevision: 0, Tags: []string{"Imported", "bench"}})
	}
	preview, err := store.PreviewAliasTagImport(entries, "Reviewed asset worksheet")
	if err != nil || !preview.Ready || len(preview.Changes) != 2 || len(preview.Blockers) != 0 || preview.PreviewSHA256 == "" || !preview.ExpiresAt.Equal(now.Add(AliasTagPreviewTTL)) {
		t.Fatalf("unexpected import preview: %#v err=%v", preview, err)
	}
	tampered := preview
	tampered.Entries = append([]PreparedAliasTagImportEntry(nil), preview.Entries...)
	tampered.Entries[0].FriendlyName = "Tampered"
	if _, err := store.ApplyAliasTagImport("admin", "alias-tag-import-tamper", tampered); !errors.Is(err, ErrMutationRejected) {
		t.Fatalf("tampered preview was accepted: %v", err)
	}
	result, err := store.ApplyAliasTagImport("admin", "alias-tag-import-apply-1", preview)
	if err != nil || result.Replayed || result.UpdatedDevices != 2 || result.Audit.Action != AuditAliasTagsImported || len(result.Audit.SourceDeviceIDs) != 2 {
		t.Fatalf("unexpected import apply: %#v err=%v", result, err)
	}
	replay, err := store.ApplyAliasTagImport("admin", "alias-tag-import-apply-1", preview)
	if err != nil || !replay.Replayed || replay.Audit.ID != result.Audit.ID {
		t.Fatalf("import replay was not stable: %#v err=%v", replay, err)
	}
	loaded, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range loaded.Devices {
		if !strings.HasPrefix(device.FriendlyName, "Imported fixture ") || device.AliasRevision != 1 || !sameStrings(device.Tags, []string{"bench", "imported"}) {
			t.Fatalf("bulk mutation was not applied: %#v", device)
		}
	}
	if _, err := store.ApplyAliasTagImport("admin", "alias-tag-import-stale-1", preview); !errors.Is(err, ErrAliasTagImportStale) {
		t.Fatalf("stale reviewed import was accepted: %v", err)
	}
}

func TestAliasTagImportRejectsTagDriftWithoutPartialMutation(t *testing.T) {
	now := time.Date(2026, 9, 1, 23, 0, 0, 0, time.UTC)
	store := &Store{Path: filepath.Join(t.TempDir(), "inventory.json"), Now: func() time.Time { return now }}
	snapshot, err := store.ReconcileDHCP4([]DHCP4Lease{
		{Address: netip.MustParseAddr("10.77.0.93"), HardwareAddr: "52:54:00:00:00:93", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)},
		{Address: netip.MustParseAddr("10.77.0.94"), HardwareAddr: "52:54:00:00:00:94", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)},
	})
	if err != nil {
		t.Fatal(err)
	}
	entries := []AliasTagImportEntry{
		{DeviceID: snapshot.Devices[0].ID, FriendlyName: "First imported", AliasRevision: 0, Tags: []string{"imported"}},
		{DeviceID: snapshot.Devices[1].ID, FriendlyName: "Second imported", AliasRevision: 0, Tags: []string{"imported"}},
	}
	preview, err := store.PreviewAliasTagImport(entries, "Atomic drift proof")
	if err != nil || !preview.Ready {
		t.Fatalf("preview failed: %#v err=%v", preview, err)
	}
	changedTags := []string{"concurrent"}
	if _, err := store.PatchMetadata(snapshot.Devices[1].ID, "admin", "alias-tag-concurrent-1", DeviceMetadataPatch{Tags: &changedTags}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApplyAliasTagImport("admin", "alias-tag-import-drift-1", preview); !errors.Is(err, ErrAliasTagImportStale) {
		t.Fatalf("tag drift was accepted: %v", err)
	}
	first, err := store.Get(snapshot.Devices[0].ID)
	if err != nil || first.FriendlyName != "" || len(first.Tags) != 0 {
		t.Fatalf("stale import partially mutated another device: %#v err=%v", first, err)
	}
}
