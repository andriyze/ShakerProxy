package daemon

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

// Devices behind an inline bridge take their IPv6 addresses from the same
// router advertisements as ShakerProxy's bridge, so the bridge's global /64s
// are published as lab sources for the DNS forwarder.
func TestInlineBridgePublishesTheRouterIPv6PrefixesAsLabSources(t *testing.T) {
	addresses := []net.Addr{
		&net.IPNet{IP: net.ParseIP("2001:db8:1:2::20"), Mask: net.CIDRMask(64, 128)},
		&net.IPNet{IP: net.ParseIP("2001:db8:1:2::abcd"), Mask: net.CIDRMask(64, 128)},
		&net.IPNet{IP: net.ParseIP("fd77::20"), Mask: net.CIDRMask(64, 128)},
		&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
		&net.IPNet{IP: net.ParseIP("192.0.2.20"), Mask: net.CIDRMask(24, 32)},
	}
	if prefixes := globalIPv6Prefixes(addresses); strings.Join(prefixes, ",") != "2001:db8:1:2::/64" {
		t.Fatalf("prefixes = %v", prefixes)
	}

	previous := bridgeIPv6Prefixes
	t.Cleanup(func() { bridgeIPv6Prefixes = previous })
	bridgeIPv6Prefixes = func(name string) []string {
		if name != networkplan.InlineBridgeName {
			t.Errorf("asked for %s", name)
		}
		return []string{"2001:db8:1:2::/64"}
	}
	for _, mode := range []networkplan.WANIPv6Mode{networkplan.WANIPv6SLAAC, networkplan.WANIPv6None} {
		plan := networkplan.Plan{Topology: networkplan.TopologyTransparentBridge,
			Interfaces: []networkplan.Interface{
				{StableID: "up", CurrentName: "eth0", Role: networkplan.RoleWAN},
				{StableID: "dev", CurrentName: "eth1", Role: networkplan.RoleLab},
			},
			WAN:  networkplan.WANConfiguration{IPv4Mode: networkplan.WANIPv4Static, IPv4Address: "192.0.2.20/24", IPv4Gateway: "192.0.2.1", IPv6Mode: mode},
			IPv4: networkplan.IPv4Configuration{Enabled: true, LabCIDR: "192.0.2.0/24", GatewayAddress: "192.0.2.20"},
			IPv6: networkplan.IPv6Configuration{Strategy: networkplan.IPv6ObserveOnly},
		}
		store := &StateStore{state: persistedState{OperatingMode: gatewayprotocol.ModeRouted,
			StagedNetworkPlan: &networkplan.StagedPlan{Plan: plan, Transaction: &networktransaction.Record{Phase: networktransaction.PhaseConfirmed}}}}
		path := filepath.Join(t.TempDir(), "runtime.json")
		manager := &TrafficPolicyManager{NetworkState: store, RuntimePath: path}
		if err := manager.writeRuntimePolicy(t.Context(), trafficpolicy.DefaultPolicy()); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var runtime struct {
			LabSources []string `json:"lab_sources"`
		}
		want := "192.0.2.0/24"
		if mode == networkplan.WANIPv6SLAAC {
			want += ",2001:db8:1:2::/64"
		}
		if err := json.Unmarshal(raw, &runtime); err != nil || strings.Join(runtime.LabSources, ",") != want {
			t.Fatalf("%s: lab sources = %v (%v), want %s", mode, runtime.LabSources, err, want)
		}
	}
}
