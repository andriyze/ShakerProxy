package cloudconnector

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDeviceRuntimeTracksStableIdentityAcrossAddressChanges(t *testing.T) {
	now := time.Date(2026, 9, 2, 20, 0, 0, 0, time.UTC)
	store := &DeviceRuntimeStore{Root: t.TempDir(), Now: func() time.Time { return now }}
	first, _ := json.Marshal(map[string]any{
		"local_device_id": "device-1",
		"friendly_name":   "Living Room TV",
		"platform":        "android-tv",
		"current_ipv4":    "10.44.0.15",
		"current_ipv6":    "fd44::15",
		"last_seen_at":    now,
	})
	second, _ := json.Marshal(map[string]any{
		"local_device_id": "device-1",
		"platform":        "android-tv",
		"current_ipv4":    "10.44.0.28",
		"last_seen_at":    now.Add(time.Hour),
	})
	if err := store.ObserveMetadata([]LocalMetadataEvent{{Type: MetadataDeviceUpsert, ObservedAt: now, Payload: first}}); err != nil {
		t.Fatal(err)
	}
	if err := store.ObserveMetadata([]LocalMetadataEvent{{Type: MetadataDeviceUpsert, ObservedAt: now.Add(time.Hour), Payload: second}}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.FriendlyNames["device-1"] != "Living Room TV" || snapshot.DevicePlatforms["device-1"] != "android-tv" {
		t.Fatalf("identity metadata was lost: %#v", snapshot)
	}
	if _, stale := snapshot.DeviceByIP["10.44.0.15"]; stale || snapshot.DeviceByIP["10.44.0.28"] != "device-1" || snapshot.DeviceByIP["fd44::15"] != "device-1" {
		t.Fatalf("address history was not associated with stable identity: %#v", snapshot.DeviceByIP)
	}
}

func TestDeviceRuntimeRenameRequiresKnownDevice(t *testing.T) {
	store := &DeviceRuntimeStore{Root: t.TempDir()}
	if _, err := store.Rename("missing-device", "Office TV"); err == nil {
		t.Fatal("unknown device was renamed")
	}
}

func TestDeviceRuntimeNormalizesMobilePlatforms(t *testing.T) {
	cases := map[string]string{
		"iPhone":    "ios",
		"iPadOS":    "ios",
		"Google TV": "android-tv",
		"Android":   "android",
		"other":     "unknown",
	}
	for input, expected := range cases {
		if actual := normalizeDevicePlatform(input); actual != expected {
			t.Fatalf("normalizeDevicePlatform(%q)=%q, want %q", input, actual, expected)
		}
	}
}
