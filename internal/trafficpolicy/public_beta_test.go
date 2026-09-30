package trafficpolicy

import "testing"

func TestLocalTLSSelectedDeviceValidation(t *testing.T) {
	policy := DefaultPolicy()
	policy.TLS.Enabled = true
	policy.TLS.SelectedDeviceIDs = []string{
		"device-22222222222222222222222222222222",
		"device-11111111111111111111111111111111",
		"device-11111111111111111111111111111111",
	}
	normalized, err := Normalize(policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized.TLS.SelectedDeviceIDs) != 2 || normalized.TLS.SelectedDeviceIDs[0] != "device-11111111111111111111111111111111" {
		t.Fatalf("selected device IDs were not canonicalized: %#v", normalized.TLS.SelectedDeviceIDs)
	}
}

func TestLocalTLSSelectedDevicesRequireInterception(t *testing.T) {
	policy := DefaultPolicy()
	policy.TLS.SelectedDeviceIDs = []string{"device-11111111111111111111111111111111"}
	if _, err := Normalize(policy); err == nil {
		t.Fatal("disabled TLS policy accepted selected device identities")
	}
}

func TestLocalTLSSelectedDevicesRejectNonCanonicalID(t *testing.T) {
	policy := DefaultPolicy()
	policy.TLS.Enabled = true
	policy.TLS.SelectedDeviceIDs = []string{"living-room-tv"}
	if _, err := Normalize(policy); err == nil {
		t.Fatal("TLS policy accepted a non-canonical device identity")
	}
}

func TestSelectiveRuntimeWithNoIdentityEvidenceFailsOpen(t *testing.T) {
	policy := DefaultPolicy()
	policy.TLS.Enabled = true
	policy.TLS.SelectedDeviceIDs = []string{"device-11111111111111111111111111111111"}
	runtime, err := ProjectStandaloneProxyRuntimeWithDevices(policy, EmptyStandaloneDeviceRuntime())
	if err != nil {
		t.Fatal(err)
	}
	if runtime.TLS.Mode != "selective" || len(runtime.DeviceByIP) != 0 {
		t.Fatalf("unexpected selective fail-open runtime: %#v", runtime)
	}
}
