package server

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/inventory"
)

func TestProjectAgentDeviceCapsEveryVariableCollection(t *testing.T) {
	now := time.Date(2026, 9, 3, 18, 0, 0, 0, time.UTC)
	device := inventory.Device{
		Schema:                inventory.SchemaVersion,
		ID:                    "device-0123456789abcdef0123456789abcdef",
		FriendlyName:          "Large history TV",
		FirstSeen:             now.Add(-24 * time.Hour),
		LastSeen:              now,
		AttributionConfidence: 95,
	}
	for index := 0; index < maxAgentDeviceAddresses+5; index++ {
		device.Addresses = append(device.Addresses, inventory.AddressObservation{
			Address:    fmt.Sprintf("10.77.0.%d", index+1),
			Family:     "IPv4",
			Confidence: 80 + index%20,
			ValidFrom:  now.Add(-time.Duration(index+1) * time.Hour),
			ValidUntil: now.Add(time.Duration(index+1) * time.Hour),
			Active:     index == maxAgentDeviceAddresses+4,
		})
	}
	for index := 0; index < maxAgentDeviceHostnames+5; index++ {
		device.Hostnames = append(device.Hostnames, inventory.HostnameObservation{
			Hostname:   fmt.Sprintf("tv-%02d.example.test", index),
			Confidence: 70 + index%20,
			FirstSeen:  now.Add(-24 * time.Hour),
			LastSeen:   now.Add(-time.Duration(index) * time.Minute),
		})
	}
	for index := 0; index < maxAgentDeviceTags+5; index++ {
		device.Tags = append(device.Tags, fmt.Sprintf("tag-%02d", index))
	}
	for index := 0; index < maxAgentDeviceWarnings+5; index++ {
		device.AttributionWarnings = append(device.AttributionWarnings, fmt.Sprintf("warning-%02d", index))
	}

	projected := projectAgentDevice(device)
	if len(projected.Addresses) != maxAgentDeviceAddresses || len(projected.Hostnames) != maxAgentDeviceHostnames || len(projected.Tags) != maxAgentDeviceTags || len(projected.AttributionWarnings) != maxAgentDeviceWarnings {
		t.Fatalf("projection bounds changed: addresses=%d hostnames=%d tags=%d warnings=%d", len(projected.Addresses), len(projected.Hostnames), len(projected.Tags), len(projected.AttributionWarnings))
	}
	if !projected.Addresses[0].Active {
		t.Fatal("active address evidence was not prioritized")
	}
	for _, field := range []string{"addresses", "hostnames", "tags", "attribution_warnings"} {
		if !slices.Contains(projected.TruncatedFields, field) {
			t.Fatalf("missing truncation marker %q: %#v", field, projected.TruncatedFields)
		}
	}
	if len(projected.TruncatedFields) != maxAgentTruncatedFieldList {
		t.Fatalf("unexpected truncation marker count: %#v", projected.TruncatedFields)
	}
}
