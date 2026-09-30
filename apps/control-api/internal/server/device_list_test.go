package server

import (
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/inventory"
)

func TestDeviceEvidenceQualityFiltersCompose(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	devices := []inventory.Device{
		{ID: "device-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", LastSeen: now, AttributionConfidence: 90, AttributionWarnings: []string{"ambiguous address evidence"}, Addresses: []inventory.AddressObservation{{Family: "IPv6"}}},
		{ID: "device-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", LastSeen: now, AttributionConfidence: 70, Addresses: []inventory.AddressObservation{{Family: "IPv4"}}},
	}
	minimum := 80
	filtered := filterAndSortDevices(devices, deviceListQuery{View: "all", IPFamily: "ipv6", MinimumConfidence: &minimum, Warnings: "present", Sort: "last_seen", Direction: "desc"}, now)
	if len(filtered) != 1 || filtered[0].ID != devices[0].ID {
		t.Fatalf("composed evidence filters returned %#v", filtered)
	}
	filtered = filterAndSortDevices(devices, deviceListQuery{View: "all", Warnings: "none", Sort: "last_seen", Direction: "desc"}, now)
	if len(filtered) != 1 || filtered[0].ID != devices[1].ID {
		t.Fatalf("warning-free filter returned %#v", filtered)
	}
}
