package cloudconnector

import (
	"testing"
	"time"
)

func TestMetadataRetryDelayIsBounded(t *testing.T) {
	cases := map[uint32]time.Duration{
		0:  0,
		1:  10 * time.Second,
		2:  20 * time.Second,
		5:  160 * time.Second,
		6:  5 * time.Minute,
		32: 5 * time.Minute,
	}
	for failures, expected := range cases {
		if actual := metadataRetryDelay(failures); actual != expected {
			t.Fatalf("metadataRetryDelay(%d)=%s, want %s", failures, actual, expected)
		}
	}
}

func TestDaemonAlwaysAdvertisesSafeDeviceNaming(t *testing.T) {
	capabilities := daemonCapabilities(DaemonConfig{})
	if !containsCapability(capabilities, DeviceNamingCapability) {
		t.Fatalf("device naming capability is missing: %v", capabilities)
	}
	if containsCapability(capabilities, TrafficPolicyCapability) {
		t.Fatalf("traffic policy was advertised without a configured interface: %v", capabilities)
	}
}
