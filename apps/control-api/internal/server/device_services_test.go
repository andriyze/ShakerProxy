package server

import (
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
	inventory "shakerproxy.dev/shakerproxy/internal/inventory"
)

func TestServiceHintsForIncludeMergedRecordsAndSkipEmpty(t *testing.T) {
	at := time.Date(2026, 10, 3, 1, 0, 0, 0, time.UTC)
	current, former := "device-728223ab536ec3ac309086fdffecb7ff", "device-093b101f10afe8a8128992b54726d5fd"
	plain := "device-ffffffffffffffffffffffffffffffff"
	devices := []inventory.Device{
		{ID: current, FormerIDs: []string{former}},
		{ID: plain},
	}
	hints := []ingest.DeviceServiceHint{
		// Recorded under the record merged into the current device.
		{DeviceID: former, Type: "Chromecast / Google Cast device", Services: []ingest.DeviceService{{Service: "_googlecast._tcp", Label: "Google Cast", LastSeen: at}}, LastSeen: at},
	}
	result := serviceHintsFor(devices, hints)
	got, ok := result[current]
	if !ok || got.Type != "Chromecast / Google Cast device" || len(got.Services) != 1 {
		t.Fatalf("current device hint = %#v", got)
	}
	if _, present := result[plain]; present {
		t.Fatal("a device with no discovery services should be absent")
	}
}
