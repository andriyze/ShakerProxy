package inventory

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSuggestedNamesAreBoundedReviewOnlyProjections(t *testing.T) {
	now := time.Date(2026, 9, 1, 20, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "inventory.json")
	store := &Store{Path: path, Now: func() time.Time { return now }}
	snapshot, err := store.ReconcileDHCP4([]DHCP4Lease{
		{Address: netip.MustParseAddr("10.77.0.41"), HardwareAddr: "52:54:00:00:00:41", ClientID: "01:41", Hostname: "older-camera.local", ValidLifetime: time.Hour, ExpiresAt: now},
		{Address: netip.MustParseAddr("10.77.0.42"), HardwareAddr: "52:54:00:00:00:41", ClientID: "01:41", Hostname: "newer-camera.local", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)},
		{Address: netip.MustParseAddr("10.77.0.43"), HardwareAddr: "52:54:00:00:00:41", ClientID: "01:41", Hostname: strings.Repeat("a", 129), ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)},
	})
	if err != nil {
		t.Fatal(err)
	}
	device := snapshot.Devices[0]
	if device.FriendlyName != "" || len(device.SuggestedNames) != 2 || device.SuggestedNames[0].Name != "newer-camera.local" || device.SuggestedNames[0].Source != SourceDHCP4Lease || device.SuggestedNames[0].Confidence != 75 {
		t.Fatalf("unexpected projected suggestions: %#v", device.SuggestedNames)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(persisted), "suggested_names") {
		t.Fatal("review-only suggestions were persisted as administrator metadata")
	}
	loaded, err := store.Get(device.ID)
	if err != nil || len(loaded.SuggestedNames) != 2 {
		t.Fatalf("single-device projection omitted suggestions: %#v err=%v", loaded.SuggestedNames, err)
	}
	result, err := store.UpdateAlias(device.ID, "admin", "suggested-name-review-01", AliasUpdate{FriendlyName: "newer-camera.local", Reason: "Reviewed DHCP hostname", ExpectedRevision: 0})
	if err != nil || len(result.Devices[0].SuggestedNames) != 1 || result.Devices[0].SuggestedNames[0].Name != "older-camera.local" {
		t.Fatalf("accepted alias was still suggested: %#v err=%v", result.Devices[0].SuggestedNames, err)
	}
}

func TestSuggestedNamesRespectProjectionBound(t *testing.T) {
	device := Device{FriendlyName: "Current"}
	for index := 0; index < MaxSuggestedNames+3; index++ {
		device.Hostnames = append(device.Hostnames, HostnameObservation{Hostname: "fixture-" + string(rune('a'+index)), Source: SourceDHCP4Lease, Confidence: 75, FirstSeen: time.Unix(int64(index), 0), LastSeen: time.Unix(int64(index), 0)})
	}
	projectSuggestedNames(&device)
	if len(device.SuggestedNames) != MaxSuggestedNames || device.SuggestedNames[0].Name != "fixture-k" {
		t.Fatalf("suggestion projection was not bounded or recency ordered: %#v", device.SuggestedNames)
	}
}
