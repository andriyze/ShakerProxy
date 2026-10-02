package networkplan

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// The plan file in docs/bridge-mode.md must stay valid.
func TestInlineBridgeDocsExamplePlanIsValid(t *testing.T) {
	raw, err := os.ReadFile("../../docs/bridge-mode.md")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, found := strings.Cut(string(raw), "```json\n")
	example, _, closed := strings.Cut(rest, "```")
	if !found || !closed {
		t.Fatal("docs/bridge-mode.md has no JSON plan example")
	}
	var plan Plan
	if err := json.Unmarshal([]byte(example), &plan); err != nil {
		t.Fatal(err)
	}
	if result := Validate(plan); !result.Valid {
		t.Fatalf("the documented plan is invalid: %+v", result.Errors)
	}
}

func validInlineBridgePlan() Plan {
	return Plan{
		Schema: SchemaVersion, Name: "inline bridge", Topology: TopologyTransparentBridge,
		Interfaces: []Interface{
			{StableID: "pci-0000:01:00.0", CurrentName: "enp1s0", PermanentMAC: "52:54:00:aa:bb:01", Role: RoleWAN},
			{StableID: "pci-0000:02:00.0", CurrentName: "enp2s0", Role: RoleLab},
		},
		Management: Management{PreserveActiveSSH: true},
		WAN: WANConfiguration{
			IPv4Mode: WANIPv4Static, IPv4Address: "192.0.2.10/24", IPv4Gateway: "192.0.2.1",
			IPv6Mode: WANIPv6None, DNSMode: WANDNSUseDHCP, AllowWorkingWANChange: true,
		},
		IPv4: IPv4Configuration{Enabled: true, LabCIDR: "192.0.2.0/24", GatewayAddress: "192.0.2.10"},
		IPv6: IPv6Configuration{Strategy: IPv6ObserveOnly},
	}
}

func bridgeObserved() []ObservedInterface {
	return []ObservedInterface{
		{CurrentName: "enp1s0", StableID: "pci-0000:01:00.0", Addresses: []string{"192.0.2.10/24"}, DefaultIPv4: true},
		{CurrentName: "enp2s0", StableID: "pci-0000:02:00.0"},
	}
}

func TestInlineBridgePlanKeepsTheSSHAddressAndMovesItToTheBridge(t *testing.T) {
	plan := validInlineBridgePlan()
	result := ValidateWithObservedSSH(plan, bridgeObserved(), []ActiveSSHSession{{SourceAddress: "192.0.2.50", DestinationAddress: "192.0.2.10", DestinationPort: 22, DestinationInterface: "enp1s0"}})
	if !result.Valid {
		t.Fatalf("valid inline bridge was rejected: %+v", result.Errors)
	}
	for _, code := range []string{"BRIDGE_STP", "BRIDGE_FAIL_CLOSED_POWER", "BRIDGE_EXISTING_NETPLAN"} {
		if !hasIssue(result.Warnings, code) {
			t.Fatalf("warning %s missing: %+v", code, result.Warnings)
		}
	}
	lab, ok := LabInterface(plan)
	if !ok || lab.CurrentName != InlineBridgeName || !IsLabBridge(lab) {
		t.Fatalf("lab interface = %+v", lab)
	}
	uplink, ok := UplinkInterface(plan)
	if !ok || uplink.CurrentName != InlineBridgeName {
		t.Fatalf("uplink = %+v", uplink)
	}
	if UsesManagedDHCP4(plan) || RoutesIPv6(plan) || BlocksLabIPv6(plan) {
		t.Fatal("an inline bridge must run no DHCP and no IPv6 routing or blocking")
	}

	moved := ValidateWithObservedSSH(plan, bridgeObserved(), []ActiveSSHSession{{SourceAddress: "192.0.2.50", DestinationAddress: "192.0.2.11", DestinationPort: 22, DestinationInterface: "enp1s0"}})
	if moved.Valid || !hasIssue(moved.Errors, "BRIDGE_SSH_ADDRESS_CHANGE") {
		t.Fatalf("an SSH session to an address the bridge drops was accepted: %+v", moved.Errors)
	}
	devicePort := ValidateWithObservedSSH(plan, bridgeObserved(), []ActiveSSHSession{{SourceAddress: "192.0.2.50", DestinationAddress: "192.0.2.10", DestinationPort: 22, DestinationInterface: "enp2s0"}})
	if devicePort.Valid || !hasIssue(devicePort.Errors, "ACTIVE_SSH_ON_LAB_INTERFACE") {
		t.Fatalf("an SSH session on the device port was accepted: %+v", devicePort.Errors)
	}
	unacknowledged := plan
	unacknowledged.WAN.AllowWorkingWANChange = false
	if result := ValidateWithObserved(unacknowledged, bridgeObserved()); result.Valid || !hasIssue(result.Errors, "WORKING_WAN_CHANGE_NOT_ACKNOWLEDGED") {
		t.Fatalf("moving the working uplink onto a bridge was not acknowledged: %+v", result.Errors)
	}
}

func TestInlineBridgeRejectsRoutingFeatures(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Plan)
		code   string
	}{
		{"one port", func(p *Plan) { p.Interfaces = p.Interfaces[:1] }, "BRIDGE_ROLES_INVALID"},
		{"nat", func(p *Plan) { p.IPv4.NAT44 = true }, "BRIDGE_NAT_FORBIDDEN"},
		{"dhcp", func(p *Plan) { p.IPv4.DHCPStart, p.IPv4.DHCPEnd = "192.0.2.100", "192.0.2.200" }, "BRIDGE_DHCP_FORBIDDEN"},
		{"dynamic address", func(p *Plan) { p.WAN.IPv4Mode, p.WAN.IPv4Address, p.WAN.IPv4Gateway = WANIPv4DHCP, "", "" }, "BRIDGE_STATIC_ADDRESS_REQUIRED"},
		{"lab cidr", func(p *Plan) { p.IPv4.LabCIDR = "198.51.100.0/24"; p.IPv4.GatewayAddress = "198.51.100.10" }, "BRIDGE_LAB_CIDR_MISMATCH"},
		{"own address", func(p *Plan) { p.IPv4.GatewayAddress = "192.0.2.11" }, "BRIDGE_GATEWAY_MISMATCH"},
		{"router is self", func(p *Plan) { p.WAN.IPv4Gateway = "192.0.2.10" }, "BRIDGE_ROUTER_INVALID"},
		{"ipv6 routing", func(p *Plan) { p.IPv6.Strategy = IPv6ULANAT66Lab }, "BRIDGE_IPV6_STRATEGY_INVALID"},
		{"ipv6 mode", func(p *Plan) { p.WAN.IPv6Mode = WANIPv6KeepExisting }, "BRIDGE_IPV6_MODE_INVALID"},
		{"wifi", func(p *Plan) {
			p.WiFi = &WiFiConfiguration{Enabled: true, SSID: "lab", Security: WiFiSecurityWPA2PSK, Passphrase: "correct horse", CountryCode: "US"}
		}, "BRIDGE_WIFI_UNAVAILABLE"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			plan := validInlineBridgePlan()
			testCase.mutate(&plan)
			result := Validate(plan)
			if result.Valid || !hasIssue(result.Errors, testCase.code) {
				t.Fatalf("expected %s, got %+v", testCase.code, result.Errors)
			}
		})
	}
}

func TestInlineBridgePreviewBridgesBothPortsWithSTPAndNoNAT(t *testing.T) {
	plan := validInlineBridgePlan()
	plan.Interfaces[0].MTU = 1500
	preview := BuildPreview(plan, time.Unix(0, 0))
	if !preview.Validation.Valid {
		t.Fatalf("preview invalid: %+v", preview.Validation.Errors)
	}
	for _, want := range []string{
		"    enp1s0:\n      dhcp4: false\n      dhcp6: false\n      accept-ra: false\n      link-local: []\n      mtu: 1500\n",
		"    enp2s0:\n      dhcp4: false\n",
		"  bridges:\n    spbr0:\n      interfaces: [enp1s0, enp2s0]\n      macaddress: 52:54:00:aa:bb:01\n",
		"      addresses: [192.0.2.10/24]\n      routes:\n        - to: 0.0.0.0/0\n          via: 192.0.2.1\n",
		"      nameservers:\n        addresses: [192.0.2.1]\n",
		"      parameters:\n        stp: true\n        forward-delay: 4\n",
	} {
		if !strings.Contains(preview.NetplanYAML, want) {
			t.Fatalf("netplan lacks %q:\n%s", want, preview.NetplanYAML)
		}
	}
	fixture := validInlineBridgePlan()
	assertFixture(t, "90-shakerproxy-inline-bridge.yaml", BuildPreview(fixture, time.Unix(0, 0)).NetplanYAML)
	if preview.FirewallRestoreIPv4 != "*filter\n:SHAKERPROXY-FORWARD - [0:0]\n-A SHAKERPROXY-FORWARD -i spbr0 -o spbr0 -j ACCEPT\nCOMMIT\n" {
		t.Fatalf("firewall = %q", preview.FirewallRestoreIPv4)
	}
	if preview.KeaDHCP4JSON != "" || preview.RadvdConf != "" || preview.FirewallRestoreIPv6 != "" || strings.Contains(preview.FirewallRestoreIPv4, "nat") {
		t.Fatal("an inline bridge preview must not run DHCP, router advertisements, IPv6 rules or NAT")
	}
	if !strings.Contains(strings.Join(preview.ChangedObjects, "\n"), "net.bridge.bridge-nf-call-iptables") {
		t.Fatalf("changed objects = %v", preview.ChangedObjects)
	}
}
