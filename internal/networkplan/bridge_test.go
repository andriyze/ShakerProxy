package networkplan

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/firewall"
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
		{"unmanaged address", func(p *Plan) { p.WAN.IPv4Mode, p.WAN.IPv4Address, p.WAN.IPv4Gateway = WANIPv4KeepExisting, "", "" }, "BRIDGE_ADDRESS_MODE_INVALID"},
		{"dhcp address outside the network", func(p *Plan) {
			p.WAN.IPv4Mode, p.WAN.IPv4Address, p.WAN.IPv4Gateway = WANIPv4DHCP, "", ""
			p.IPv4.GatewayAddress = "198.51.100.10"
		}, "BRIDGE_DHCP_ADDRESS_INVALID"},
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
	// Bridged IPv6 crosses ip6tables FORWARD too, so it gets the same rule.
	if preview.FirewallRestoreIPv6 != preview.FirewallRestoreIPv4 || LabIPv6FirewallMode(preview) != "BLOCK" {
		t.Fatalf("IPv6 firewall = %q", preview.FirewallRestoreIPv6)
	}
	if preview.KeaDHCP4JSON != "" || preview.RadvdConf != "" || strings.Contains(preview.FirewallRestoreIPv4, "nat") {
		t.Fatal("an inline bridge preview must not run DHCP, router advertisements or NAT")
	}
	changed := strings.Join(preview.ChangedObjects, "\n")
	for _, want := range []string{"net.bridge.bridge-nf-call-iptables", "net.bridge.bridge-nf-call-ip6tables", "ip6tables filter/SHAKERPROXY-FORWARD"} {
		if !strings.Contains(changed, want) {
			t.Fatalf("changed objects lack %s: %v", want, preview.ChangedObjects)
		}
	}
	attached := false
	for _, command := range preview.AttachmentCommands {
		if command.Executable == defaultIp6tablesPath && strings.Join(command.Arguments, " ") == "-w 5 -I DOCKER-USER 1 -j SHAKERPROXY-FORWARD" {
			attached = true
		}
	}
	if !attached {
		t.Fatalf("the IPv6 bridge rule is not attached: %+v", preview.AttachmentCommands)
	}
}

// The bridge can keep asking the router for ShakerProxy's address: it keeps
// the router port's MAC and identifies itself by it, so the lease follows.
func TestInlineBridgeGetsItsAddressOverDHCP(t *testing.T) {
	plan := validInlineBridgePlan()
	plan.WAN.IPv4Mode, plan.WAN.IPv4Address, plan.WAN.IPv4Gateway = WANIPv4DHCP, "", ""
	result := ValidateWithObservedSSH(plan, bridgeObserved(), []ActiveSSHSession{{SourceAddress: "192.0.2.50", DestinationAddress: "192.0.2.10", DestinationPort: 22, DestinationInterface: "enp1s0"}})
	if !result.Valid || !hasIssue(result.Warnings, "BRIDGE_DHCP_ADDRESS_MAY_CHANGE") || hasIssue(result.Warnings, "BRIDGE_DHCP_MAC_UNKNOWN") || !InlineBridgeDHCP(plan) {
		t.Fatalf("DHCP bridge: valid=%v errors=%+v warnings=%+v", result.Valid, result.Errors, result.Warnings)
	}
	moved := ValidateWithObservedSSH(plan, bridgeObserved(), []ActiveSSHSession{{SourceAddress: "192.0.2.50", DestinationAddress: "192.0.2.11", DestinationPort: 22, DestinationInterface: "enp1s0"}})
	if moved.Valid || !hasIssue(moved.Errors, "BRIDGE_SSH_ADDRESS_CHANGE") {
		t.Fatalf("an SSH session to another address was accepted: %+v", moved.Errors)
	}
	preview := BuildPreview(plan, time.Unix(0, 0))
	for _, want := range []string{"      macaddress: 52:54:00:aa:bb:01\n      dhcp4: true\n      dhcp-identifier: mac\n", "      parameters:\n        stp: true\n"} {
		if !strings.Contains(preview.NetplanYAML, want) {
			t.Fatalf("netplan lacks %q:\n%s", want, preview.NetplanYAML)
		}
	}
	if strings.Contains(preview.NetplanYAML, "addresses:") || strings.Contains(preview.NetplanYAML, "routes:") {
		t.Fatalf("a DHCP bridge got static addressing:\n%s", preview.NetplanYAML)
	}
	if impact := strings.Join(preview.Impact, "\n"); !strings.Contains(impact, "over DHCP with enp1s0's MAC") {
		t.Fatalf("impact = %s", impact)
	}
	assertFixture(t, "90-shakerproxy-inline-bridge-dhcp.yaml", preview.NetplanYAML)

	unknownMAC := plan
	unknownMAC.Interfaces = append([]Interface(nil), plan.Interfaces...)
	unknownMAC.Interfaces[0].PermanentMAC = ""
	if result := Validate(unknownMAC); !result.Valid || !hasIssue(result.Warnings, "BRIDGE_DHCP_MAC_UNKNOWN") {
		t.Fatalf("unknown MAC: %+v", result.Warnings)
	}
}

// DNS over IPv6 can be answered only when ShakerProxy has an IPv6 address
// on the bridge, from the router's advertisements.
func TestInlineBridgeIPv6DNSNeedsAnAddressFromTheRouter(t *testing.T) {
	plan := validInlineBridgePlan()
	result := Validate(plan)
	if !result.Valid || !hasIssue(result.Warnings, "BRIDGE_IPV6_DNS_NOT_FORCED") || InlineBridgeIPv6Address(plan) {
		t.Fatalf("without SLAAC: valid=%v warnings=%+v", result.Valid, result.Warnings)
	}
	if impact := strings.Join(BuildPreview(plan, time.Unix(0, 0)).Impact, "\n"); !strings.Contains(impact, "not answered by ShakerProxy") {
		t.Fatalf("impact = %s", impact)
	}
	plan.WAN.IPv6Mode = WANIPv6SLAAC
	result = Validate(plan)
	if !result.Valid || hasIssue(result.Warnings, "BRIDGE_IPV6_DNS_NOT_FORCED") || !InlineBridgeIPv6Address(plan) {
		t.Fatalf("with SLAAC: valid=%v warnings=%+v", result.Valid, result.Warnings)
	}
	preview := BuildPreview(plan, time.Unix(0, 0))
	if !strings.Contains(preview.NetplanYAML, "      dhcp6: false\n      accept-ra: true\n") || !strings.Contains(strings.Join(preview.Impact, "\n"), "over IPv6 is answered by ShakerProxy") {
		t.Fatalf("SLAAC bridge preview:\n%s\n%v", preview.NetplanYAML, preview.Impact)
	}
}

func TestInlineBridgeIPv6ArtifactsFollowTheHost(t *testing.T) {
	plan := validInlineBridgePlan()
	preview := BuildPreview(plan, time.Unix(0, 0))
	preview.FirewallEnvironment = firewall.Inspection{IPv6Available: true, IPv6FirewallReady: true, IptablesPath: "/usr/sbin/iptables", Ip6tablesPath: "/usr/sbin/ip6tables"}
	if err := CheckIPv6Artifacts(plan, preview); err != nil {
		t.Fatal(err)
	}
	missing := preview
	missing.FirewallRestoreIPv6 = ""
	if err := CheckIPv6Artifacts(plan, missing); err == nil {
		t.Fatal("an inline bridge without its IPv6 forward rule was accepted")
	}
	noIPv6 := BuildPreview(plan, time.Unix(0, 0))
	noIPv6.FirewallEnvironment = firewall.Inspection{IptablesPath: "/usr/sbin/iptables"}
	BindIPv6HostEvidence(&noIPv6)
	if noIPv6.FirewallRestoreIPv6 != "" || strings.Contains(strings.Join(noIPv6.ChangedObjects, "\n"), "ip6tables") {
		t.Fatalf("a host without IPv6 still gets IPv6 bridge artifacts: %+v", noIPv6.ChangedObjects)
	}
	if err := CheckIPv6Artifacts(plan, noIPv6); err != nil {
		t.Fatal(err)
	}
}
