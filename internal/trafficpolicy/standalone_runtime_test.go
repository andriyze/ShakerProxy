package trafficpolicy

import (
	"strings"
	"testing"
	"time"
)

func TestProjectStandaloneProxyRuntimeUsesCompiledSchema(t *testing.T) {
	policy := DefaultPolicy()
	policy.Revision = 7
	policy.EncryptedDNS.Mode = EncryptedDNSBlockKnown
	policy.EncryptedDNS.BlockKnownDoH = true
	policy.TLS.Enabled = true
	policy.TLS.ExcludeHosts = []string{"Pinned.Example"}
	policy.TLS.ExcludeCIDRs = []string{"203.0.113.0/24"}
	policy.TLS.AutoBypassPinned = true
	policy.TLS.AutoBypassTTLSeconds = 900
	policy.TLS.MaxDynamicBypasses = 64
	policy.TLS.MobileClients = []TLSMobileClient{{CIDR: "192.0.2.0/24", Platform: "ios"}}

	runtime, err := ProjectStandaloneProxyRuntimeWithDevices(policy, EmptyStandaloneDeviceRuntime())
	if err != nil {
		t.Fatal(err)
	}
	if runtime.SchemaVersion != SchemaVersion || runtime.Revision != 7 || !runtime.Enabled {
		t.Fatalf("compiled runtime identity changed: %#v", runtime)
	}
	if runtime.TLS.Mode != "all" || !runtime.TLS.AutoBypassPinning || runtime.TLS.PinningThreshold != 3 {
		t.Fatalf("TLS compatibility projection is wrong: %#v", runtime.TLS)
	}
	if len(runtime.TLS.ExcludeHosts) != 1 || runtime.TLS.ExcludeHosts[0] != "pinned.example" {
		t.Fatalf("host exclusions were not normalized: %#v", runtime.TLS.ExcludeHosts)
	}
	if len(runtime.TLS.MobileClients) != 1 || runtime.TLS.MobileClients[0].Platform != "ios" {
		t.Fatalf("mobile compatibility evidence was lost: %#v", runtime.TLS.MobileClients)
	}
	if !runtime.EncryptedDNS.BlockKnownDoH {
		t.Fatal("DoH policy was not projected")
	}
	if len(runtime.TLS.SelectedDeviceIDs) != 0 || len(runtime.TLS.BypassRules) != 0 {
		t.Fatal("all-client standalone projection fabricated selective rules")
	}
}

func TestProjectStandaloneProxyRuntimeUsesStableDeviceSelection(t *testing.T) {
	policy := DefaultPolicy()
	policy.Revision = 9
	policy.TLS.Enabled = true
	policy.TLS.SelectedDeviceIDs = []string{"device-22222222222222222222222222222222", "device-11111111111111111111111111111111"}
	devices := StandaloneDeviceRuntime{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   time.Date(2026, 9, 3, 23, 0, 0, 0, time.UTC),
		DeviceByIP: map[string]string{
			"10.77.0.10": "device-11111111111111111111111111111111",
			"10.77.0.20": "device-22222222222222222222222222222222",
			"10.77.0.30": "device-33333333333333333333333333333333",
		},
	}
	runtime, err := ProjectStandaloneProxyRuntimeWithDevices(policy, devices)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.TLS.Mode != "selective" || len(runtime.TLS.SelectedDeviceIDs) != 2 {
		t.Fatalf("selective TLS mode was not projected: %#v", runtime.TLS)
	}
	if runtime.TLS.SelectedDeviceIDs[0] != "device-11111111111111111111111111111111" {
		t.Fatalf("selected IDs were not normalized: %#v", runtime.TLS.SelectedDeviceIDs)
	}
	if runtime.DeviceByIP["10.77.0.30"] != "device-33333333333333333333333333333333" {
		t.Fatal("identity projection must preserve non-selected devices so mitmproxy can prove passthrough")
	}
}

func TestProjectStandaloneProxyRuntimeRejectsInvalidPolicy(t *testing.T) {
	policy := DefaultPolicy()
	policy.Revision = 0
	if _, err := ProjectStandaloneProxyRuntimeWithDevices(policy, EmptyStandaloneDeviceRuntime()); err == nil {
		t.Fatal("invalid standalone policy was projected")
	}
}

// Regression from a routed EC2 lab: nil lists were written as null and the
// mitmproxy addon could not iterate them, so interception failed open.
func TestStandaloneProxyRuntimeWritesEmptyListsNotNull(t *testing.T) {
	policy := DefaultPolicy()
	policy.Revision = 2
	policy.TLS.Enabled = true
	policy.TLS.SelectedDeviceIDs = []string{"device-35d06eff6436258199f4e8ed887198ed"}
	runtime, err := ProjectStandaloneProxyRuntimeWithDevices(policy, EmptyStandaloneDeviceRuntime())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeStandaloneProxyRuntime(runtime)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"exclude_hosts", "exclude_cidrs", "mobile_clients", "bypass_rules"} {
		if strings.Contains(string(encoded), `"`+field+`": null`) {
			t.Fatalf("%s is encoded as null:\n%s", field, encoded)
		}
	}
}
