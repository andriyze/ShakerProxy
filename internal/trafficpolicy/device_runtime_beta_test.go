package trafficpolicy

import (
	"testing"
	"time"

	deviceinventory "shakerproxy.dev/shakerproxy/internal/inventory"
)

func TestProjectStandaloneDeviceRuntimeRequiresFreshUnambiguousEvidence(t *testing.T) {
	now := time.Date(2026, 9, 4, 3, 0, 0, 0, time.UTC)
	active := func(address string, from, until time.Time) deviceinventory.AddressObservation {
		return deviceinventory.AddressObservation{Address: address, Active: true, ValidFrom: from, ValidUntil: until}
	}
	snapshot := deviceinventory.Snapshot{Devices: []deviceinventory.Device{
		{ID: "device-11111111111111111111111111111111", Addresses: []deviceinventory.AddressObservation{
			active("10.77.0.10", now.Add(-time.Hour), now.Add(time.Hour)),
			active("10.77.0.11", now.Add(-2*time.Hour), now),
			active("10.77.0.12", now.Add(time.Minute), now.Add(time.Hour)),
		}},
		{ID: "device-22222222222222222222222222222222", Addresses: []deviceinventory.AddressObservation{
			active("10.77.0.20", now.Add(-time.Hour), now.Add(time.Hour)),
			active("10.77.0.30", now.Add(-time.Hour), now.Add(time.Hour)),
		}},
		{ID: "device-33333333333333333333333333333333", Addresses: []deviceinventory.AddressObservation{
			active("10.77.0.30", now.Add(-time.Hour), now.Add(time.Hour)),
		}},
	}}

	runtime, err := ProjectStandaloneDeviceRuntime(snapshot, now)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.DeviceByIP["10.77.0.10"] != "device-11111111111111111111111111111111" || runtime.DeviceByIP["10.77.0.20"] != "device-22222222222222222222222222222222" {
		t.Fatalf("fresh mappings missing: %#v", runtime.DeviceByIP)
	}
	for _, address := range []string{"10.77.0.11", "10.77.0.12", "10.77.0.30"} {
		if _, found := runtime.DeviceByIP[address]; found {
			t.Fatalf("unsafe mapping %s survived: %#v", address, runtime.DeviceByIP)
		}
	}
}

func TestProjectStandaloneDeviceRuntimeRejectsInvalidClock(t *testing.T) {
	if _, err := ProjectStandaloneDeviceRuntime(deviceinventory.Snapshot{}, time.Time{}); err == nil {
		t.Fatal("zero clock unexpectedly accepted")
	}
}
