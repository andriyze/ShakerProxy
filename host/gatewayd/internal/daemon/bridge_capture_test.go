package daemon

import (
	"testing"

	"shakerproxy.dev/shakerproxy/internal/networkplan"
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
