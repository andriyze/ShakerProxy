package daemon

import (
	"testing"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

func TestInlineBridgeIsRecordedOnItsDevicePort(t *testing.T) {
	plan := networkplan.Plan{Topology: networkplan.TopologyTransparentBridge, Interfaces: []networkplan.Interface{
		{StableID: "up", CurrentName: "eth0", Role: networkplan.RoleWAN},
		{StableID: "dev", CurrentName: "eth1", Role: networkplan.RoleLab},
	}}
	captured, ok := labCaptureInterface(plan)
	if !ok || captured.CurrentName != "eth1" || captured.StableID != "dev" {
		t.Fatalf("inline bridge capture interface = %+v", captured)
	}
	lab, _ := networkplan.LabInterface(plan)
	if lab.CurrentName != networkplan.InlineBridgeName {
		t.Fatalf("policy and status still use the bridge, got %+v", lab)
	}
	plan.Topology = networkplan.TopologyTwoNIC
	if captured, _ := labCaptureInterface(plan); captured.CurrentName != "eth1" {
		t.Fatalf("two-port lab capture interface = %+v", captured)
	}
}

// The traffic policy learns the bridge's device port and whether ShakerProxy
// has an IPv6 address there (wan.ipv6_mode SLAAC) to answer DNS over IPv6.
func TestInlineBridgeRenderContext(t *testing.T) {
	plan := networkplan.Plan{Topology: networkplan.TopologyTransparentBridge,
		Interfaces: []networkplan.Interface{
			{StableID: "up", CurrentName: "eth0", Role: networkplan.RoleWAN},
			{StableID: "dev", CurrentName: "eth1", Role: networkplan.RoleLab},
		},
		WAN:  networkplan.WANConfiguration{IPv4Mode: networkplan.WANIPv4Static, IPv4Address: "192.0.2.20/24", IPv4Gateway: "192.0.2.1", IPv6Mode: networkplan.WANIPv6SLAAC},
		IPv4: networkplan.IPv4Configuration{Enabled: true, LabCIDR: "192.0.2.0/24", GatewayAddress: "192.0.2.20"},
		IPv6: networkplan.IPv6Configuration{Strategy: networkplan.IPv6ObserveOnly},
	}
	for _, mode := range []networkplan.WANIPv6Mode{networkplan.WANIPv6SLAAC, networkplan.WANIPv6None} {
		plan.WAN.IPv6Mode = mode
		store := &StateStore{state: persistedState{OperatingMode: gatewayprotocol.ModeRouted,
			StagedNetworkPlan: &networkplan.StagedPlan{Plan: plan, Transaction: &networktransaction.Record{Phase: networktransaction.PhaseConfirmed}}}}
		manager := &TrafficPolicyManager{NetworkState: store}
		context, ok, err := manager.activeRenderContext(t.Context(), trafficpolicy.DefaultPolicy())
		if err != nil || !ok {
			t.Fatalf("%s: %v %v", mode, ok, err)
		}
		if context.LabInterface != networkplan.InlineBridgeName || context.LabBridgePort != "eth1" || context.LabBridgeIPv6 != (mode == networkplan.WANIPv6SLAAC) {
			t.Fatalf("%s: render context %+v", mode, context)
		}
	}
}
