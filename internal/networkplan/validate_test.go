package networkplan

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func validTwoNICPlan() Plan {
	return Plan{
		Schema: SchemaVersion, Name: "two nic lab", Topology: TopologyTwoNIC,
		Interfaces: []Interface{
			{StableID: "pci-0000:01:00.0", CurrentName: "enp1s0", Role: RoleWAN},
			{StableID: "pci-0000:02:00.0", CurrentName: "enp2s0", Role: RoleLab},
		},
		Management: Management{PreserveActiveSSH: true, AllowedCIDRs: []string{"192.0.2.0/24"}},
		IPv4:       IPv4Configuration{Enabled: true, LabCIDR: "10.77.0.0/24", GatewayAddress: "10.77.0.1", DHCPStart: "10.77.0.100", DHCPEnd: "10.77.0.200", NAT44: true, ClientIsolation: true},
		IPv6:       IPv6Configuration{Strategy: IPv6Disabled},
	}
}

func TestValidateTwoNICPlan(t *testing.T) {
	result := Validate(validTwoNICPlan())
	if !result.Valid {
		t.Fatalf("expected valid plan, got errors: %+v", result.Errors)
	}
	if len(result.PlanHash) != 64 {
		t.Fatalf("unexpected plan hash %q", result.PlanHash)
	}
	if result.PlanHash != Validate(validTwoNICPlan()).PlanHash {
		t.Fatal("plan hash is not deterministic")
	}
}

func validSingleArmPlan() Plan {
	return Plan{
		Schema: SchemaVersion, Name: "single arm lab", Topology: TopologySingleArm,
		Interfaces: []Interface{{StableID: "pci-0000:01:00.0", CurrentName: "enp1s0", Role: RoleWANLab}},
		Management: Management{PreserveActiveSSH: true, AllowedCIDRs: []string{"192.0.2.0/24"}},
		WAN:        WANConfiguration{IPv4Mode: WANIPv4KeepExisting, IPv6Mode: WANIPv6KeepExisting, DNSMode: WANDNSUseDHCP, UpstreamNAT: true},
		IPv4:       IPv4Configuration{Enabled: true, LabCIDR: "192.0.2.0/24", GatewayAddress: "192.0.2.10", NAT44: true},
		IPv6:       IPv6Configuration{Strategy: IPv6Disabled},
	}
}

func TestSingleArmRequiresObservedExistingGatewayAndDefaultRoute(t *testing.T) {
	plan := validSingleArmPlan()
	result := ValidateWithObservedSSH(plan, []ObservedInterface{{
		CurrentName: "enp1s0", StableID: "pci-0000:01:00.0", Addresses: []string{"192.0.2.10/24"}, DefaultIPv4: true,
	}}, []ActiveSSHSession{{SourceAddress: "192.0.2.100", DestinationAddress: "192.0.2.10", DestinationPort: 22, DestinationInterface: "enp1s0"}})
	if !result.Valid {
		t.Fatalf("valid single-arm plan was rejected: %+v", result.Errors)
	}
	if !hasIssue(result.Warnings, "SINGLE_ARM_MANUAL_CLIENT_SETUP") || !hasIssue(result.Warnings, "SINGLE_ARM_IPV6_BYPASS") {
		t.Fatalf("single-arm limitations were not surfaced: %+v", result.Warnings)
	}

	missing := ValidateWithObserved(plan, []ObservedInterface{{CurrentName: "enp1s0", StableID: "pci-0000:01:00.0", Addresses: []string{"192.0.2.11/24"}}})
	if missing.Valid || !hasIssue(missing.Errors, "SINGLE_ARM_GATEWAY_NOT_CONFIGURED") || !hasIssue(missing.Errors, "SINGLE_ARM_DEFAULT_ROUTE_REQUIRED") {
		t.Fatalf("single-arm host prerequisites were accepted: %+v", missing.Errors)
	}
}

func TestSingleArmRejectsUnsafeOrMisleadingConfiguration(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Plan)
		code string
	}{
		{name: "nat disabled", edit: func(plan *Plan) { plan.IPv4.NAT44 = false }, code: "SINGLE_ARM_NAT44_REQUIRED"},
		{name: "client isolation", edit: func(plan *Plan) { plan.IPv4.ClientIsolation = true }, code: "SINGLE_ARM_CLIENT_ISOLATION_UNAVAILABLE"},
		{name: "dhcp", edit: func(plan *Plan) { plan.IPv4.DHCPStart, plan.IPv4.DHCPEnd = "192.0.2.100", "192.0.2.200" }, code: "SINGLE_ARM_DHCP_FORBIDDEN"},
		{name: "address mutation", edit: func(plan *Plan) { plan.WAN.IPv4Mode = WANIPv4DHCP }, code: "SINGLE_ARM_INTERFACE_MUTATION"},
		{name: "mtu mutation", edit: func(plan *Plan) { plan.Interfaces[0].MTU = 1400 }, code: "SINGLE_ARM_INTERFACE_MUTATION"},
		{name: "long Linux interface name", edit: func(plan *Plan) { plan.Interfaces[0].CurrentName = "interface-name-too-long" }, code: "SINGLE_ARM_INTERFACE_NAME_INVALID"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			plan := validSingleArmPlan()
			test.edit(&plan)
			result := Validate(plan)
			if result.Valid || !hasIssue(result.Errors, test.code) {
				t.Fatalf("unsafe single-arm plan was accepted: %+v", result.Errors)
			}
		})
	}
}

func TestSingleArmPreviewPreservesNetplanDisablesDHCPAndUsesSymmetricNAT(t *testing.T) {
	preview := BuildPreview(validSingleArmPlan(), time.Unix(100, 0))
	if !preview.Validation.Valid {
		t.Fatalf("single-arm preview was invalid: %+v", preview.Validation.Errors)
	}
	if preview.NetplanYAML != "network:\n  version: 2\n" || preview.KeaDHCP4JSON != "" || containsString(preview.ChangedObjects, "/etc/kea/kea-dhcp4.conf") {
		t.Fatalf("single-arm preview mutates addressing or DHCP: %+v\n%s", preview.ChangedObjects, preview.NetplanYAML)
	}
	for _, expected := range []string{
		"-A SHAKERPROXY-FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"-A SHAKERPROXY-FORWARD -i enp1s0 -o enp1s0 -s 192.0.2.0/24 -j ACCEPT",
		"-A SHAKERPROXY-POSTROUTING -s 192.0.2.0/24 -o enp1s0 -j MASQUERADE",
	} {
		if !strings.Contains(preview.FirewallRestoreIPv4, expected) {
			t.Fatalf("single-arm firewall missing %q:\n%s", expected, preview.FirewallRestoreIPv4)
		}
	}
	if strings.Contains(preview.FirewallRestoreIPv4, "! -s") || !containsString(preview.ChangedObjects, "net.ipv4.conf.enp1s0.send_redirects") {
		t.Fatalf("single-arm preview retained two-NIC anti-spoof behavior: %+v\n%s", preview.ChangedObjects, preview.FirewallRestoreIPv4)
	}
}

func TestValidateRejectsGatewayInsideDHCPRange(t *testing.T) {
	plan := validTwoNICPlan()
	plan.IPv4.GatewayAddress = "10.77.0.150"
	result := Validate(plan)
	if result.Valid || !hasIssue(result.Errors, "GATEWAY_IN_DHCP_RANGE") {
		t.Fatalf("expected gateway range error: %+v", result.Errors)
	}
}

func TestValidateRequiresDistinctInterfaceNames(t *testing.T) {
	plan := validTwoNICPlan()
	plan.Interfaces[1].CurrentName = plan.Interfaces[0].CurrentName
	result := Validate(plan)
	if result.Valid || !hasIssue(result.Errors, "INTERFACE_NAME_DUPLICATE") {
		t.Fatalf("expected duplicate interface error: %+v", result.Errors)
	}
}

func TestVLANTrunkAllowsSharedPhysicalIdentity(t *testing.T) {
	plan := validTwoNICPlan()
	plan.Topology = TopologyVLANTrunk
	wanVLAN, labVLAN := 10, 20
	plan.Interfaces[0].StableID, plan.Interfaces[0].CurrentName, plan.Interfaces[0].VLANID = "pci-0000:01:00.0", "enp1s0.10", &wanVLAN
	plan.Interfaces[1].StableID, plan.Interfaces[1].CurrentName, plan.Interfaces[1].VLANID = "pci-0000:01:00.0", "enp1s0.20", &labVLAN
	plan.WAN.IPv4Mode = WANIPv4DHCP
	if result := Validate(plan); !result.Valid {
		t.Fatalf("expected valid VLAN plan: %+v", result.Errors)
	}
}

func TestPassivePreviewHasNoFirewallMutation(t *testing.T) {
	plan := Plan{Schema: 1, Name: "mirror", Topology: TopologyPassiveSensor, Interfaces: []Interface{{StableID: "usb-1", CurrentName: "enxmirror", Role: RoleMirror}}, Management: Management{PreserveActiveSSH: true}, IPv6: IPv6Configuration{Strategy: IPv6ObserveOnly}}
	preview := BuildPreview(plan, time.Unix(100, 0))
	if !preview.Validation.Valid {
		t.Fatalf("invalid passive plan: %+v", preview.Validation.Errors)
	}
	if preview.FirewallRestoreIPv4 != "" || len(preview.AttachmentCommands) != 0 {
		t.Fatal("passive preview included firewall changes")
	}
	if len(preview.ChangedObjects) != 1 || preview.ChangedObjects[0] != "/etc/netplan/90-shakerproxy.yaml" {
		t.Fatalf("passive preview claimed unrelated managed objects: %+v", preview.ChangedObjects)
	}
	for _, expected := range []string{"dhcp6: false", "accept-ra: false", "link-local: []"} {
		if !strings.Contains(preview.NetplanYAML, expected) {
			t.Fatalf("passive interface could acquire IPv6 via %q omission:\n%s", expected, preview.NetplanYAML)
		}
	}
}

func TestRoutedPreviewIsOwnedAndDoesNotRewriteWANAddressing(t *testing.T) {
	preview := BuildPreview(validTwoNICPlan(), time.Unix(100, 0))
	if !strings.Contains(preview.FirewallRestoreIPv4, ":SHAKERPROXY-FORWARD") || !strings.Contains(preview.FirewallRestoreIPv4, ":SHAKERPROXY-POSTROUTING") {
		t.Fatal("missing owned firewall chains")
	}
	if strings.Contains(preview.NetplanYAML, "dhcp4: true") || strings.Contains(preview.NetplanYAML, "enp1s0:") {
		t.Fatalf("preview guessed WAN configuration:\n%s", preview.NetplanYAML)
	}
	if !strings.Contains(preview.NetplanYAML, "enp2s0:") {
		t.Fatal("lab interface missing from Netplan preview")
	}
	for _, expected := range []string{"dhcp6: false", "accept-ra: false", "link-local: []"} {
		if !strings.Contains(preview.NetplanYAML, expected) {
			t.Fatalf("disabled lab IPv6 missing %q:\n%s", expected, preview.NetplanYAML)
		}
	}
}

func TestPrefixDelegationStrategyIsRejectedBeforePreview(t *testing.T) {
	plan := validTwoNICPlan()
	plan.IPv6.Strategy = IPv6PrefixDelegation
	preview := BuildPreview(plan, time.Unix(100, 0))
	if preview.Validation.Valid || !hasIssue(preview.Validation.Errors, "IPV6_PREFIX_DELEGATION_UNAVAILABLE") || preview.NetplanYAML != "" || preview.FirewallRestoreIPv4 != "" || preview.FirewallRestoreIPv6 != "" {
		t.Fatalf("unimplemented prefix delegation reached preview: %+v", preview)
	}
}

func TestExplicitStaticWANRequiresWorkingRouteAndCloudInitAcknowledgements(t *testing.T) {
	plan := validTwoNICPlan()
	plan.WAN = WANConfiguration{IPv4Mode: WANIPv4Static, IPv4Address: "192.0.2.20/24", IPv4Gateway: "192.0.2.1", IPv6Mode: WANIPv6None, DNSMode: WANDNSUseDHCP}
	observed := []ObservedInterface{
		{CurrentName: "enp1s0", StableID: "pci-0000:01:00.0", DefaultIPv4: true, CloudInitManaged: true},
		{CurrentName: "enp2s0", StableID: "pci-0000:02:00.0"},
	}
	result := ValidateWithObserved(plan, observed)
	if result.Valid || !hasIssue(result.Errors, "WORKING_WAN_CHANGE_NOT_ACKNOWLEDGED") || !hasIssue(result.Errors, "CLOUD_INIT_WAN_OVERRIDE_NOT_ACKNOWLEDGED") {
		t.Fatalf("working cloud-init WAN change was accepted: %+v", result)
	}
	plan.WAN.AllowWorkingWANChange = true
	plan.WAN.AllowCloudInitOverride = true
	result = ValidateWithObserved(plan, observed)
	if !result.Valid {
		t.Fatalf("explicit reviewed WAN change was rejected: %+v", result)
	}
	preview := BuildPreview(plan, time.Unix(100, 0))
	for _, expected := range []string{"enp1s0:", "dhcp4: false", "addresses: [192.0.2.20/24]", "to: 0.0.0.0/0", "via: 192.0.2.1", "accept-ra: false"} {
		if !strings.Contains(preview.NetplanYAML, expected) {
			t.Fatalf("static WAN preview missing %q:\n%s", expected, preview.NetplanYAML)
		}
	}
}

func TestExplicitDHCPWANAndMTURenderOnlyAfterSelection(t *testing.T) {
	plan := validTwoNICPlan()
	plan.Interfaces[0].MTU = 1400
	plan.Interfaces[1].MTU = 1400
	plan.WAN = WANConfiguration{IPv4Mode: WANIPv4DHCP, IPv6Mode: WANIPv6SLAAC, DNSMode: WANDNSIgnoreDHCP}
	preview := BuildPreview(plan, time.Unix(100, 0))
	for _, expected := range []string{"enp1s0:", "dhcp4: true", "use-dns: false", "accept-ra: true", "mtu: 1400", "enp2s0:"} {
		if !strings.Contains(preview.NetplanYAML, expected) {
			t.Fatalf("DHCP WAN preview missing %q:\n%s", expected, preview.NetplanYAML)
		}
	}
}

func TestVLANTrunkRendersOwnedSubinterfacesFromObservedParent(t *testing.T) {
	plan := validTwoNICPlan()
	plan.Topology = TopologyVLANTrunk
	wanVLAN, labVLAN := 10, 20
	plan.Interfaces[0] = Interface{StableID: "pci-0000:01:00.0", CurrentName: "enp1s0.10", Role: RoleWAN, VLANID: &wanVLAN}
	plan.Interfaces[1] = Interface{StableID: "pci-0000:01:00.0", CurrentName: "enp1s0.20", Role: RoleLab, VLANID: &labVLAN}
	plan.WAN = WANConfiguration{IPv4Mode: WANIPv4DHCP, IPv6Mode: WANIPv6None, AllowWorkingWANChange: true}
	result := ValidateWithObserved(plan, []ObservedInterface{{CurrentName: "enp1s0", StableID: "pci-0000:01:00.0"}})
	if !result.Valid {
		t.Fatalf("VLAN parent identity was rejected: %+v", result)
	}
	preview := BuildPreview(plan, time.Unix(100, 0))
	for _, expected := range []string{"vlans:", "enp1s0.10:", "id: 10", "link: enp1s0", "enp1s0.20:", "id: 20", "dhcp6: false", "accept-ra: false", "link-local: []"} {
		if !strings.Contains(preview.NetplanYAML, expected) {
			t.Fatalf("VLAN preview missing %q:\n%s", expected, preview.NetplanYAML)
		}
	}
}

func TestVLANTrunkRejectsCallerInventedParentName(t *testing.T) {
	plan := validTwoNICPlan()
	plan.Topology = TopologyVLANTrunk
	wanVLAN, labVLAN := 10, 20
	plan.Interfaces[0] = Interface{StableID: "pci-0000:01:00.0", CurrentName: "invented0.10", Role: RoleWAN, VLANID: &wanVLAN}
	plan.Interfaces[1] = Interface{StableID: "pci-0000:01:00.0", CurrentName: "invented0.20", Role: RoleLab, VLANID: &labVLAN}
	plan.WAN.IPv4Mode = WANIPv4DHCP
	result := ValidateWithObserved(plan, []ObservedInterface{{CurrentName: "enp1s0", StableID: "pci-0000:01:00.0"}})
	if result.Valid || !hasIssue(result.Errors, "VLAN_INTERFACE_NAME_MISMATCH") {
		t.Fatalf("invented VLAN parent name was accepted: %+v", result)
	}
}

func TestUnsupportedWANChoicesFailClosed(t *testing.T) {
	plan := validTwoNICPlan()
	plan.WAN = WANConfiguration{IPv6Mode: WANIPv6PrefixDelegation, RequestedPrefixLength: 56, DNSMode: WANDNSBootstrapOnly, ClampMSS: true}
	result := Validate(plan)
	for _, code := range []string{"WAN_PREFIX_DELEGATION_UNAVAILABLE", "WAN_BOOTSTRAP_DNS_UNAVAILABLE", "WAN_MSS_CLAMP_UNAVAILABLE"} {
		if !hasIssue(result.Errors, code) {
			t.Fatalf("missing fail-closed %s: %+v", code, result)
		}
	}
}

func TestActiveSSHOnMutatedWANAlwaysFailsClosed(t *testing.T) {
	plan := validTwoNICPlan()
	plan.WAN = WANConfiguration{IPv4Mode: WANIPv4DHCP, AllowWorkingWANChange: true, AllowCloudInitOverride: true}
	result := ValidateWithObservedSSH(plan, []ObservedInterface{
		{CurrentName: "enp1s0", StableID: "pci-0000:01:00.0", DefaultIPv4: true},
		{CurrentName: "enp2s0", StableID: "pci-0000:02:00.0"},
	}, []ActiveSSHSession{{SourceAddress: "192.0.2.100", SourcePort: 49152, DestinationAddress: "192.0.2.10", DestinationPort: 22, DestinationInterface: "enp1s0"}})
	if result.Valid || !hasIssue(result.Errors, "ACTIVE_SSH_WAN_MUTATION") {
		t.Fatalf("active SSH WAN mutation was accepted: %+v", result)
	}
}

func TestRoutedPreviewIncludesDeterministicKeaDHCP4Configuration(t *testing.T) {
	plan := validTwoNICPlan()
	plan.IPv4.DHCPLeaseSeconds = 7200
	plan.IPv4.DNSAddresses = []string{"10.77.0.1", "1.1.1.1"}
	plan.IPv4.SearchDomain = "shakerproxy.home"
	plan.IPv4.Reservations = []DHCPReservation{
		{Hostname: "printer.shakerproxy.home", HardwareAddress: "AA-BB-CC-DD-EE-02", IPAddress: "10.77.0.51"},
		{Hostname: "camera.shakerproxy.home", HardwareAddress: "aa:bb:cc:dd:ee:01", IPAddress: "10.77.0.50"},
	}
	preview := BuildPreview(plan, time.Unix(100, 0))
	if !preview.Validation.Valid {
		t.Fatalf("invalid DHCP plan: %+v", preview.Validation.Errors)
	}
	if !json.Valid([]byte(preview.KeaDHCP4JSON)) {
		t.Fatalf("Kea preview is not JSON:\n%s", preview.KeaDHCP4JSON)
	}
	for _, expected := range []string{
		`"interfaces": [`,
		`"dhcp-socket-type": "raw"`,
		`"valid-lifetime": 7200`,
		`"pool": "10.77.0.100 - 10.77.0.200"`,
		`"data": "10.77.0.1, 1.1.1.1"`,
		`"data": "shakerproxy.home"`,
		`"hw-address": "aa:bb:cc:dd:ee:02"`,
	} {
		if !strings.Contains(preview.KeaDHCP4JSON, expected) {
			t.Fatalf("Kea preview missing %q:\n%s", expected, preview.KeaDHCP4JSON)
		}
	}
	if strings.Index(preview.KeaDHCP4JSON, "10.77.0.50") > strings.Index(preview.KeaDHCP4JSON, "10.77.0.51") {
		t.Fatalf("reservations were not sorted deterministically:\n%s", preview.KeaDHCP4JSON)
	}
	if preview.KeaDHCP4JSON != BuildPreview(plan, time.Unix(200, 0)).KeaDHCP4JSON {
		t.Fatal("Kea rendering changed with generation time")
	}
	if !containsString(preview.ChangedObjects, "/etc/kea/kea-dhcp4.conf") {
		t.Fatalf("Kea managed object missing: %+v", preview.ChangedObjects)
	}
}

func TestKeaDHCP4DefaultsLeaseAndDNSOption(t *testing.T) {
	preview := BuildPreview(validTwoNICPlan(), time.Unix(100, 0))
	if !strings.Contains(preview.KeaDHCP4JSON, `"valid-lifetime": 3600`) || !strings.Contains(preview.KeaDHCP4JSON, `"data": "10.77.0.1"`) {
		t.Fatalf("safe DHCP defaults missing:\n%s", preview.KeaDHCP4JSON)
	}
	want, err := os.ReadFile("../../tests/netlab/fixtures/kea-dhcp4.conf")
	if err != nil {
		t.Fatal(err)
	}
	if preview.KeaDHCP4JSON != string(want) {
		t.Fatalf("Kea fixture drifted from renderer:\n%s", preview.KeaDHCP4JSON)
	}
}

func TestDHCPReservationValidationRejectsConflictsAndMalformedValues(t *testing.T) {
	plan := validTwoNICPlan()
	plan.IPv4.DHCPLeaseSeconds = 30
	plan.IPv4.DNSAddresses = []string{"not-an-address", "1.1.1.1", "1.1.1.1"}
	plan.IPv4.SearchDomain = "bad domain"
	plan.IPv4.Reservations = []DHCPReservation{
		{Hostname: "same", HardwareAddress: "not-a-mac", IPAddress: "10.77.0.150"},
		{Hostname: "same", HardwareAddress: "aa:bb:cc:dd:ee:01", IPAddress: "10.77.0.1"},
		{HardwareAddress: "aa:bb:cc:dd:ee:01", IPAddress: "10.77.0.1"},
	}
	result := Validate(plan)
	for _, code := range []string{
		"DHCP_LEASE_DURATION_INVALID",
		"DHCP_DNS_ADDRESS_INVALID",
		"DHCP_DNS_ADDRESS_DUPLICATE",
		"DHCP_SEARCH_DOMAIN_INVALID",
		"DHCP_RESERVATION_MAC_INVALID",
		"DHCP_RESERVATION_MAC_DUPLICATE",
		"DHCP_RESERVATION_IP_DUPLICATE",
		"DHCP_RESERVATION_GATEWAY_CONFLICT",
		"DHCP_RESERVATION_IN_DYNAMIC_POOL",
		"DHCP_RESERVATION_HOSTNAME_DUPLICATE",
	} {
		if !hasIssue(result.Errors, code) {
			t.Errorf("expected %s: %+v", code, result.Errors)
		}
	}
}

func TestObservedIdentityMismatchInvalidatesPlanAndHash(t *testing.T) {
	plan := validTwoNICPlan()
	result := ValidateWithObserved(plan, []ObservedInterface{{CurrentName: "enp1s0", StableID: "different"}, {CurrentName: "enp2s0", StableID: "pci-0000:02:00.0"}})
	if result.Valid || result.PlanHash != "" || !hasIssue(result.Errors, "INTERFACE_IDENTITY_MISMATCH") {
		t.Fatalf("identity drift was not rejected: %+v", result)
	}
}

func TestMissingObservedInterfaceInvalidatesPlan(t *testing.T) {
	result := ValidateWithObserved(validTwoNICPlan(), []ObservedInterface{{CurrentName: "enp1s0", StableID: "pci-0000:01:00.0"}})
	if result.Valid || !hasIssue(result.Errors, "INTERFACE_NOT_FOUND") {
		t.Fatalf("missing interface was not rejected: %+v", result)
	}
}

func TestInterfaceCommandInjectionCannotReachPreview(t *testing.T) {
	plan := validTwoNICPlan()
	plan.Interfaces[1].CurrentName = "eth0;reboot"
	preview := BuildPreview(plan, time.Unix(100, 0))
	if preview.Validation.Valid || preview.FirewallRestoreIPv4 != "" || len(preview.AttachmentCommands) != 0 {
		t.Fatalf("unsafe interface reached renderer: %+v", preview)
	}
}

func TestExistingHostPrefixConflictIsRejected(t *testing.T) {
	plan := validTwoNICPlan()
	observed := []ObservedInterface{{CurrentName: "enp1s0", StableID: "pci-0000:01:00.0", Addresses: []string{"10.77.0.254/24"}}, {CurrentName: "enp2s0", StableID: "pci-0000:02:00.0"}}
	result := ValidateWithObserved(plan, observed)
	if result.Valid || !hasIssue(result.Errors, "LAB_CIDR_HOST_CONFLICT") {
		t.Fatalf("host prefix conflict was not rejected: %+v", result)
	}
}

func TestNetworkAndBroadcastAddressesAreRejected(t *testing.T) {
	plan := validTwoNICPlan()
	plan.IPv4.GatewayAddress = "10.77.0.0"
	plan.IPv4.DHCPEnd = "10.77.0.255"
	result := Validate(plan)
	if result.Valid || !hasIssue(result.Errors, "GATEWAY_RESERVED") || !hasIssue(result.Errors, "DHCP_RANGE_RESERVED") {
		t.Fatalf("reserved addresses were not rejected: %+v", result.Errors)
	}
}

func TestNATPreviewIncludesOwnedPostroutingAttachment(t *testing.T) {
	preview := BuildPreview(validTwoNICPlan(), time.Unix(100, 0))
	ipv4Commands := []CommandPreview{}
	for _, command := range preview.AttachmentCommands {
		if command.Executable == "/usr/sbin/iptables" {
			ipv4Commands = append(ipv4Commands, command)
		}
	}
	if len(ipv4Commands) != 4 {
		t.Fatalf("expected filter and NAT check/insert commands, got %+v", preview.AttachmentCommands)
	}
	last := ipv4Commands[len(ipv4Commands)-1]
	if strings.Join(last.Arguments, " ") != "-w 5 -t nat -I POSTROUTING 1 -j SHAKERPROXY-POSTROUTING" {
		t.Fatalf("unexpected NAT attachment: %+v", last)
	}
}

func TestActiveSSHOnLabInterfaceInvalidatesPlan(t *testing.T) {
	plan := validTwoNICPlan()
	result := ValidateWithObservedSSH(plan, []ObservedInterface{
		{CurrentName: "enp1s0", StableID: "pci-0000:01:00.0"},
		{CurrentName: "enp2s0", StableID: "pci-0000:02:00.0"},
	}, []ActiveSSHSession{{SourceAddress: "192.0.2.100", SourcePort: 49152, DestinationAddress: "192.0.2.10", DestinationPort: 22, DestinationInterface: "enp2s0"}})
	if result.Valid || !hasIssue(result.Errors, "ACTIVE_SSH_ON_LAB_INTERFACE") {
		t.Fatalf("active SSH lab-interface conflict was accepted: %+v", result)
	}
}

func TestActiveSSHOnWANInterfaceIsPreserved(t *testing.T) {
	plan := validTwoNICPlan()
	result := ValidateWithObservedSSH(plan, []ObservedInterface{
		{CurrentName: "enp1s0", StableID: "pci-0000:01:00.0"},
		{CurrentName: "enp2s0", StableID: "pci-0000:02:00.0"},
	}, []ActiveSSHSession{{SourceAddress: "192.0.2.100", SourcePort: 49152, DestinationAddress: "192.0.2.10", DestinationPort: 22, DestinationInterface: "enp1s0"}})
	if !result.Valid {
		t.Fatalf("preserved WAN SSH path was rejected: %+v", result)
	}
}

func TestActiveSSHSourceMustMatchConfiguredManagementCIDR(t *testing.T) {
	plan := validTwoNICPlan()
	plan.Management.AllowedCIDRs = []string{"198.51.100.0/24"}
	result := ValidateWithObservedSSH(plan, []ObservedInterface{
		{CurrentName: "enp1s0", StableID: "pci-0000:01:00.0"},
		{CurrentName: "enp2s0", StableID: "pci-0000:02:00.0"},
	}, []ActiveSSHSession{{SourceAddress: "192.0.2.100", SourcePort: 49152, DestinationAddress: "192.0.2.10", DestinationPort: 22, DestinationInterface: "enp1s0"}})
	if result.Valid || !hasIssue(result.Errors, "ACTIVE_SSH_SOURCE_NOT_ALLOWED") {
		t.Fatalf("SSH source outside management CIDRs was accepted: %+v", result)
	}
}

func TestUnmappedActiveSSHDestinationFailsClosed(t *testing.T) {
	plan := validTwoNICPlan()
	result := ValidateWithObservedSSH(plan, []ObservedInterface{
		{CurrentName: "enp1s0", StableID: "pci-0000:01:00.0"},
		{CurrentName: "enp2s0", StableID: "pci-0000:02:00.0"},
	}, []ActiveSSHSession{{SourceAddress: "192.0.2.100", SourcePort: 49152, DestinationAddress: "192.0.2.10", DestinationPort: 22}})
	if result.Valid || !hasIssue(result.Errors, "ACTIVE_SSH_PATH_UNKNOWN") {
		t.Fatalf("unmapped active SSH path was accepted: %+v", result)
	}
}

func hasIssue(issues []Issue, code string) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
