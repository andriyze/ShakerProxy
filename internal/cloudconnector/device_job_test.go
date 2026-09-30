package cloudconnector

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDeviceRenameJobUsesStableDeviceIdentity(t *testing.T) {
	now := time.Date(2026, 9, 2, 20, 0, 0, 0, time.UTC)
	store := &DeviceRuntimeStore{Root: t.TempDir(), Now: func() time.Time { return now }}
	payload, _ := json.Marshal(map[string]any{
		"local_device_id": "device-1",
		"platform":        "ios",
		"current_ipv4":    "10.44.0.15",
		"last_seen_at":    now,
	})
	if err := store.ObserveMetadata([]LocalMetadataEvent{{Type: MetadataDeviceUpsert, ObservedAt: now, Payload: payload}}); err != nil {
		t.Fatal(err)
	}
	state := State{SensorID: "sensor-1", OrganizationID: "org-1"}
	job := CloudJob{
		ID:                 "job-1",
		Type:               JobDeviceRename,
		OrganizationID:     state.OrganizationID,
		SensorID:           state.SensorID,
		CreatedAt:          now,
		ExpiresAt:          now.Add(10 * time.Minute),
		IdempotencyKey:     "rename-1",
		RequiredCapability: DeviceNamingCapability,
		ApprovalState:      "NOT_REQUIRED",
		Parameters: map[string]any{
			"local_device_id": "device-1",
			"friendly_name":   "Test iPhone",
		},
	}
	parameters, err := ValidateDeviceRenameJob(job, state, 0, []string{DeviceNamingCapability}, now)
	if err != nil {
		t.Fatal(err)
	}
	result, err := ExecuteDeviceRenameJob(t.Context(), store, parameters)
	if err != nil {
		t.Fatal(err)
	}
	if result["friendly_name"] != "Test iPhone" {
		t.Fatalf("unexpected rename result: %#v", result)
	}
	snapshot, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.FriendlyNames["device-1"] != "Test iPhone" || snapshot.DeviceByIP["10.44.0.15"] != "device-1" {
		t.Fatalf("stable identity projection was not retained: %#v", snapshot)
	}
}

func TestDeviceRenameJobRejectsAdditionalParameters(t *testing.T) {
	now := time.Now().UTC()
	job := CloudJob{
		ID:                 "job-1",
		Type:               JobDeviceRename,
		OrganizationID:     "org-1",
		SensorID:           "sensor-1",
		CreatedAt:          now,
		ExpiresAt:          now.Add(time.Minute),
		IdempotencyKey:     "rename-1",
		RequiredCapability: DeviceNamingCapability,
		ApprovalState:      "NOT_REQUIRED",
		Parameters: map[string]any{
			"local_device_id": "device-1",
			"friendly_name":   "Phone",
			"shell":           "id",
		},
	}
	if _, err := ValidateDeviceRenameJob(job, State{SensorID: "sensor-1", OrganizationID: "org-1"}, 0, []string{DeviceNamingCapability}, now); err == nil {
		t.Fatal("unexpected device rename parameter was accepted")
	}
}
