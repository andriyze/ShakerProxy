package networkplan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/firewall"
)

func validULAPlan() Plan {
	plan := validTwoNICPlan()
	plan.IPv4.ClientIsolation = false
	plan.IPv4.SearchDomain = "lab.example"
	plan.IPv6 = IPv6Configuration{Strategy: IPv6ULANAT66Lab, LabPrefix: "fd12:3456:789a:1::/64"}
	return plan
}

func validNativePlan() Plan {
	plan := validTwoNICPlan()
	plan.IPv6 = IPv6Configuration{
		Strategy:       IPv6NativeRouted,
		LabPrefix:      "2a01:4f8:1c1c:a001::/64",
		GatewayAddress: "2a01:4f8:1c1c:a001::fe",
		DNSAddresses:   []string{"2a01:4f8:1c1c:a001::fe", "2606:4700:4700::1111"},
	}
	return plan
}

// assertGolden compares rendered output with testdata/ipv6/<name>. Set
// SHAKERPROXY_UPDATE_GOLDEN=1 to rewrite the files after reviewing a change.
func assertGolden(t *testing.T, name, actual string) {
	t.Helper()
	path := filepath.Join("testdata", "ipv6", name)
	if os.Getenv("SHAKERPROXY_UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(actual), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	expected, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(expected) != actual {
		t.Fatalf("%s differs from golden file:\n--- expected\n%s\n--- actual\n%s", name, expected, actual)
	}
}

func TestULANAT66PlanRendersGoldenArtifacts(t *testing.T) {
	preview := BuildPreview(validULAPlan(), time.Unix(100, 0))
	if !preview.Validation.Valid {
		t.Fatalf("valid ULA plan was rejected: %+v", preview.Validation.Errors)
	}
	for _, code := range []string{"NAT66_LAB_COMPROMISE", "IPV6_ULA_PREFERS_IPV4", "IPV6_ROUTER_MODE"} {
		if !hasIssue(preview.Validation.Warnings, code) {
			t.Fatalf("ULA plan is missing warning %s: %+v", code, preview.Validation.Warnings)
		}
	}
	assertGolden(t, "ula-netplan.yaml", preview.NetplanYAML)
	assertGolden(t, "ula-ip6tables.rules", preview.FirewallRestoreIPv6)
	assertGolden(t, "ula-radvd.conf", preview.RadvdConf)
	for _, expected := range []string{RadvdConfigPath, RadvdUnit, "ip6tables filter/SHAKERPROXY-FORWARD", "ip6tables filter/SHAKERPROXY-INPUT", "ip6tables nat/SHAKERPROXY-POSTROUTING", "net.ipv6.conf.all.forwarding", "net.ipv6.conf.enp1s0.accept_ra"} {
		if !containsString(preview.ChangedObjects, expected) {
			t.Fatalf("changed objects are missing %q: %+v", expected, preview.ChangedObjects)
		}
	}
	commands := []string{}
	for _, command := range preview.AttachmentCommands {
		if command.Executable == "/usr/sbin/ip6tables" {
			commands = append(commands, strings.Join(command.Arguments, " "))
		}
	}
	expected := []string{
		"-w 5 -C DOCKER-USER -j SHAKERPROXY-FORWARD", "-w 5 -I DOCKER-USER 1 -j SHAKERPROXY-FORWARD",
		"-w 5 -C INPUT -j SHAKERPROXY-INPUT", "-w 5 -I INPUT 1 -j SHAKERPROXY-INPUT",
		"-w 5 -t nat -C POSTROUTING -j SHAKERPROXY-POSTROUTING", "-w 5 -t nat -I POSTROUTING 1 -j SHAKERPROXY-POSTROUTING",
	}
	if strings.Join(commands, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("unexpected ip6tables attachments:\n%s", strings.Join(commands, "\n"))
	}
}

func TestNativeRoutedPlanRendersWithoutNAT66(t *testing.T) {
	preview := BuildPreview(validNativePlan(), time.Unix(100, 0))
	if !preview.Validation.Valid {
		t.Fatalf("valid native plan was rejected: %+v", preview.Validation.Errors)
	}
	if hasIssue(preview.Validation.Warnings, "NAT66_LAB_COMPROMISE") || !hasIssue(preview.Validation.Warnings, "IPV6_NATIVE_UPSTREAM_ROUTE") {
		t.Fatalf("native plan warnings are inaccurate: %+v", preview.Validation.Warnings)
	}
	assertGolden(t, "native-netplan.yaml", preview.NetplanYAML)
	assertGolden(t, "native-ip6tables.rules", preview.FirewallRestoreIPv6)
	assertGolden(t, "native-radvd.conf", preview.RadvdConf)
	if strings.Contains(preview.FirewallRestoreIPv6, "*nat") || containsString(preview.ChangedObjects, "ip6tables nat/SHAKERPROXY-POSTROUTING") {
		t.Fatalf("native routing must not translate addresses:\n%s", preview.FirewallRestoreIPv6)
	}
}

func TestDisabledIPv6ActivelyDropsForwardedLabTraffic(t *testing.T) {
	preview := BuildPreview(validTwoNICPlan(), time.Unix(100, 0))
	if !preview.Validation.Valid {
		t.Fatalf("valid plan was rejected: %+v", preview.Validation.Errors)
	}
	assertGolden(t, "disabled-ip6tables.rules", preview.FirewallRestoreIPv6)
	if preview.RadvdConf != "" || strings.Contains(preview.NetplanYAML, "fd") {
		t.Fatalf("disabled IPv6 advertised a prefix: radvd=%q netplan=%s", preview.RadvdConf, preview.NetplanYAML)
	}
	for _, expected := range []string{"dhcp6: false", "accept-ra: false", "link-local: []"} {
		if !strings.Contains(preview.NetplanYAML, expected) {
			t.Fatalf("disabled lab IPv6 missing %q:\n%s", expected, preview.NetplanYAML)
		}
	}
	if !containsString(preview.ChangedObjects, "ip6tables filter/SHAKERPROXY-FORWARD") || containsString(preview.ChangedObjects, RadvdUnit) {
		t.Fatalf("unexpected disabled IPv6 changed objects: %+v", preview.ChangedObjects)
	}
}

func TestObserveOnlyKeepsIPv6FirewallUntouched(t *testing.T) {
	plan := validTwoNICPlan()
	plan.IPv6.Strategy = IPv6ObserveOnly
	preview := BuildPreview(plan, time.Unix(100, 0))
	if !preview.Validation.Valid || preview.FirewallRestoreIPv6 != "" || preview.RadvdConf != "" {
		t.Fatalf("observe-only changed IPv6 state: %+v", preview)
	}
	for _, command := range preview.AttachmentCommands {
		if command.Executable != "/usr/sbin/iptables" {
			t.Fatalf("observe-only attached IPv6 chains: %+v", command)
		}
	}
	if !strings.Contains(preview.NetplanYAML, "link-local: []") {
		t.Fatalf("observe-only lab interface can acquire IPv6:\n%s", preview.NetplanYAML)
	}
}

func TestSingleArmAndPassiveKeepAccurateIPv6Boundaries(t *testing.T) {
	single := validSingleArmPlan()
	preview := BuildPreview(single, time.Unix(100, 0))
	if !preview.Validation.Valid || preview.FirewallRestoreIPv6 != "" || !hasIssue(preview.Validation.Warnings, "SINGLE_ARM_IPV6_BYPASS") {
		t.Fatalf("single-arm DISABLED must keep the bypass warning and no IPv6 state: %+v", preview)
	}
	for _, strategy := range []IPv6Strategy{IPv6ULANAT66Lab, IPv6NativeRouted} {
		single.IPv6 = IPv6Configuration{Strategy: strategy, LabPrefix: "fd12:3456:789a:1::/64"}
		if strategy == IPv6NativeRouted {
			single.IPv6.LabPrefix = "2a01:4f8:1c1c:a001::/64"
		}
		result := Validate(single)
		if result.Valid || !hasIssue(result.Errors, "IPV6_ROUTING_NEEDS_LAB_INTERFACE") {
			t.Fatalf("single-arm %s routing was accepted: %+v", strategy, result.Errors)
		}
	}
	passive := Plan{Schema: 1, Name: "mirror", Topology: TopologyPassiveSensor, Interfaces: []Interface{{StableID: "usb-1", CurrentName: "enxmirror", Role: RoleMirror}}, Management: Management{PreserveActiveSSH: true}, IPv6: IPv6Configuration{Strategy: IPv6ULANAT66Lab, LabPrefix: "fd12:3456:789a:1::/64"}}
	if result := Validate(passive); result.Valid || !hasIssue(result.Errors, "IPV6_ROUTING_PASSIVE") {
		t.Fatalf("passive routing was accepted: %+v", result.Errors)
	}
	passive.IPv6 = IPv6Configuration{Strategy: IPv6Disabled}
	if preview := BuildPreview(passive, time.Unix(100, 0)); !preview.Validation.Valid || preview.FirewallRestoreIPv6 != "" {
		t.Fatalf("passive DISABLED must not add IPv6 firewall state: %+v", preview)
	}
}

func TestIPv6ValidationRejectsUnsafeOrMistypedConfiguration(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Plan)
		code string
		path string
	}{
		{name: "prefix missing", edit: func(plan *Plan) { plan.IPv6.LabPrefix = "" }, code: "IPV6_LAB_PREFIX_REQUIRED", path: "ipv6.lab_prefix"},
		{name: "prefix garbage", edit: func(plan *Plan) { plan.IPv6.LabPrefix = "not-a-prefix" }, code: "IPV6_LAB_PREFIX_INVALID", path: "ipv6.lab_prefix"},
		{name: "IPv4 prefix", edit: func(plan *Plan) { plan.IPv6.LabPrefix = "10.0.0.0/24" }, code: "IPV6_LAB_PREFIX_INVALID", path: "ipv6.lab_prefix"},
		{name: "prefix /56", edit: func(plan *Plan) { plan.IPv6.LabPrefix = "fd12:3456:789a::/56" }, code: "IPV6_LAB_PREFIX_SIZE_INVALID", path: "ipv6.lab_prefix"},
		{name: "prefix /80", edit: func(plan *Plan) { plan.IPv6.LabPrefix = "fd12:3456:789a:1::/80" }, code: "IPV6_LAB_PREFIX_SIZE_INVALID", path: "ipv6.lab_prefix"},
		{name: "ULA outside fd00::/8", edit: func(plan *Plan) { plan.IPv6.LabPrefix = "fc00:1:2:3::/64" }, code: "IPV6_ULA_PREFIX_INVALID", path: "ipv6.lab_prefix"},
		{name: "ULA global prefix", edit: func(plan *Plan) { plan.IPv6.LabPrefix = "2a01:4f8:1c1c:a001::/64" }, code: "IPV6_ULA_PREFIX_INVALID", path: "ipv6.lab_prefix"},
		{name: "native ULA prefix", edit: func(plan *Plan) { plan.IPv6.Strategy, plan.IPv6.LabPrefix = IPv6NativeRouted, "fd12:3456:789a:1::/64" }, code: "IPV6_NATIVE_PREFIX_INVALID", path: "ipv6.lab_prefix"},
		{name: "native documentation prefix", edit: func(plan *Plan) { plan.IPv6.Strategy, plan.IPv6.LabPrefix = IPv6NativeRouted, "2001:db8:1:2::/64" }, code: "IPV6_NATIVE_PREFIX_INVALID", path: "ipv6.lab_prefix"},
		{name: "native link-local prefix", edit: func(plan *Plan) { plan.IPv6.Strategy, plan.IPv6.LabPrefix = IPv6NativeRouted, "fe80::/64" }, code: "IPV6_NATIVE_PREFIX_INVALID", path: "ipv6.lab_prefix"},
		{name: "native overlaps static WAN", edit: func(plan *Plan) {
			plan.IPv6.Strategy, plan.IPv6.LabPrefix = IPv6NativeRouted, "2a01:4f8:1c1c:a001::/64"
			plan.WAN.IPv6Mode, plan.WAN.IPv6Address, plan.WAN.IPv6Gateway = WANIPv6Static, "2a01:4f8:1c1c::10/48", "2a01:4f8:1c1c::1"
			plan.WAN.AllowWorkingWANChange = true
		}, code: "IPV6_LAB_PREFIX_OVERLAPS_WAN", path: "ipv6.lab_prefix"},
		{name: "gateway outside prefix", edit: func(plan *Plan) { plan.IPv6.GatewayAddress = "fd99::1" }, code: "IPV6_GATEWAY_INVALID", path: "ipv6.gateway_address"},
		{name: "gateway anycast", edit: func(plan *Plan) { plan.IPv6.GatewayAddress = "fd12:3456:789a:1::" }, code: "IPV6_GATEWAY_INVALID", path: "ipv6.gateway_address"},
		{name: "gateway garbage", edit: func(plan *Plan) { plan.IPv6.GatewayAddress = "gateway" }, code: "IPV6_GATEWAY_INVALID", path: "ipv6.gateway_address"},
		{name: "DNS IPv4", edit: func(plan *Plan) { plan.IPv6.DNSAddresses = []string{"10.77.0.1"} }, code: "IPV6_DNS_ADDRESS_INVALID", path: "ipv6.dns_addresses[0]"},
		{name: "DNS multicast", edit: func(plan *Plan) { plan.IPv6.DNSAddresses = []string{"ff02::1"} }, code: "IPV6_DNS_ADDRESS_INVALID", path: "ipv6.dns_addresses[0]"},
		{name: "DNS link-local", edit: func(plan *Plan) { plan.IPv6.DNSAddresses = []string{"fe80::1"} }, code: "IPV6_DNS_ADDRESS_INVALID", path: "ipv6.dns_addresses[0]"},
		{name: "DNS duplicate", edit: func(plan *Plan) { plan.IPv6.DNSAddresses = []string{"fd12:3456:789a:1::1", "fd12:3456:789a:1::1"} }, code: "IPV6_DNS_ADDRESS_DUPLICATE", path: "ipv6.dns_addresses[1]"},
		{name: "DNS too many", edit: func(plan *Plan) {
			plan.IPv6.DNSAddresses = []string{"fd12:3456:789a:1::1", "fd12:3456:789a:1::2", "fd12:3456:789a:1::3", "fd12:3456:789a:1::4"}
		}, code: "IPV6_DNS_TOO_MANY", path: "ipv6.dns_addresses"},
		{name: "WAN without IPv6", edit: func(plan *Plan) { plan.WAN.IPv6Mode = WANIPv6None; plan.WAN.AllowWorkingWANChange = true }, code: "IPV6_WAN_REQUIRED", path: "wan.ipv6_mode"},
		{name: "disabled with prefix", edit: func(plan *Plan) { plan.IPv6.Strategy = IPv6Disabled }, code: "IPV6_FIELDS_UNUSED", path: "ipv6"},
		{name: "observe with DNS", edit: func(plan *Plan) {
			plan.IPv6 = IPv6Configuration{Strategy: IPv6ObserveOnly, DNSAddresses: []string{"fd12:3456:789a:1::1"}}
		}, code: "IPV6_FIELDS_UNUSED", path: "ipv6"},
		{name: "prefix delegation", edit: func(plan *Plan) { plan.IPv6.Strategy = IPv6PrefixDelegation }, code: "IPV6_PREFIX_DELEGATION_UNAVAILABLE", path: "ipv6.strategy"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			plan := validULAPlan()
			test.edit(&plan)
			result := Validate(plan)
			if result.Valid || !hasIssueAt(result.Errors, test.code, test.path) {
				t.Fatalf("expected %s at %s, got %+v", test.code, test.path, result.Errors)
			}
			for _, issue := range result.Errors {
				if strings.HasPrefix(issue.Code, "IPV6") && (!strings.HasSuffix(issue.Message, ".") || strings.Contains(issue.Message, "ROUTING_UNAVAILABLE")) {
					t.Fatalf("IPv6 error is not a plain sentence: %+v", issue)
				}
			}
		})
	}
}

func TestPrefixDelegationMessageSaysWhatToDoNext(t *testing.T) {
	plan := validTwoNICPlan()
	plan.IPv6.Strategy = IPv6PrefixDelegation
	result := Validate(plan)
	for _, issue := range result.Errors {
		if issue.Code == "IPV6_PREFIX_DELEGATION_UNAVAILABLE" && strings.Contains(issue.Message, "ULA_NAT66_LAB") && strings.Contains(issue.Message, "NATIVE_ROUTED_PREFIX") {
			return
		}
	}
	t.Fatalf("prefix delegation error is not actionable: %+v", result.Errors)
}

func TestLabIPv6RoutingAppliesDefaults(t *testing.T) {
	labIPv6, ok := LabIPv6Routing(validULAPlan())
	if !ok || labIPv6.Interface != "enp2s0" || labIPv6.Prefix.String() != "fd12:3456:789a:1::/64" || labIPv6.Gateway.String() != "fd12:3456:789a:1::1" || len(labIPv6.DNS) != 1 || labIPv6.DNS[0] != labIPv6.Gateway || !labIPv6.NAT66 {
		t.Fatalf("unexpected ULA defaults: %+v ok=%v", labIPv6, ok)
	}
	plan := validULAPlan()
	plan.IPv6.LabPrefix = "fd12:3456:789a:1::9/64"
	if labIPv6, ok := LabIPv6Routing(plan); !ok || labIPv6.Prefix.String() != "fd12:3456:789a:1::/64" {
		t.Fatalf("host bits were not masked: %+v", labIPv6)
	}
	native, ok := LabIPv6Routing(validNativePlan())
	if !ok || native.NAT66 || native.Gateway.String() != "2a01:4f8:1c1c:a001::fe" || len(native.DNS) != 2 || native.DNS[1].String() != "2606:4700:4700::1111" {
		t.Fatalf("unexpected native addressing: %+v", native)
	}
	for _, plan := range []Plan{validTwoNICPlan(), validSingleArmPlan()} {
		if _, ok := LabIPv6Routing(plan); ok {
			t.Fatalf("non-routing plan reported lab IPv6: %+v", plan.IPv6)
		}
	}
}

func TestVLANTrunkRendersLabIPv6OnTheLabSubinterface(t *testing.T) {
	wanVLAN, labVLAN := 10, 20
	plan := validULAPlan()
	plan.Topology = TopologyVLANTrunk
	plan.Interfaces = []Interface{
		{StableID: "pci-0000:01:00.0", CurrentName: "enp1s0.10", Role: RoleWAN, VLANID: &wanVLAN},
		{StableID: "pci-0000:01:00.0", CurrentName: "enp1s0.20", Role: RoleLab, VLANID: &labVLAN},
	}
	plan.WAN = WANConfiguration{IPv4Mode: WANIPv4DHCP, IPv6Mode: WANIPv6SLAAC}
	preview := BuildPreview(plan, time.Unix(100, 0))
	if !preview.Validation.Valid {
		t.Fatalf("VLAN IPv6 plan rejected: %+v", preview.Validation.Errors)
	}
	if !strings.Contains(preview.NetplanYAML, "    enp1s0.20:\n      id: 20\n      link: enp1s0\n      addresses: [10.77.0.1/24, \"fd12:3456:789a:1::1/64\"]\n      dhcp6: false\n      accept-ra: false\n") {
		t.Fatalf("VLAN lab IPv6 address missing:\n%s", preview.NetplanYAML)
	}
	if !strings.Contains(preview.NetplanYAML, "    enp1s0.10:\n      id: 10\n      link: enp1s0\n      dhcp4: true\n      accept-ra: true\n") {
		t.Fatalf("VLAN WAN must keep accepting router advertisements:\n%s", preview.NetplanYAML)
	}
	if !strings.Contains(preview.RadvdConf, "interface enp1s0.20\n") || !strings.Contains(preview.FirewallRestoreIPv6, "-o enp1s0.10 -j MASQUERADE") {
		t.Fatalf("VLAN IPv6 artifacts use the wrong interfaces:\n%s\n%s", preview.RadvdConf, preview.FirewallRestoreIPv6)
	}
}

func TestIPv6FirewallMirrorsClientIsolationAndMSSClamp(t *testing.T) {
	plan := validULAPlan()
	plan.IPv4.ClientIsolation = true
	plan.WAN.ClampMSS = true
	labIPv6, _ := LabIPv6Routing(plan)
	wan, _ := WANInterface(plan)
	rules := renderRoutedIPv6Firewall(plan, labIPv6, wan)
	if !strings.Contains(rules, "-A SHAKERPROXY-FORWARD -i enp2s0 -o enp2s0 -s fd12:3456:789a:1::/64 -d fd12:3456:789a:1::/64 -j DROP\n") {
		t.Fatalf("client isolation was not mirrored:\n%s", rules)
	}
	if !strings.HasPrefix(rules, "*filter\n:SHAKERPROXY-FORWARD - [0:0]\n:SHAKERPROXY-INPUT - [0:0]\n-A SHAKERPROXY-FORWARD -o enp1s0 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu\n") {
		t.Fatalf("MSS clamping was not mirrored first:\n%s", rules)
	}
}

func TestIPv6ObservedHostPrefixConflictsAndWANWarning(t *testing.T) {
	plan := validULAPlan()
	observed := []ObservedInterface{
		{CurrentName: "enp1s0", StableID: "pci-0000:01:00.0", Addresses: []string{"192.0.2.10/24", "fd12:3456:789a:1::50/64", "fe80::1/64"}, DefaultIPv4: true},
		{CurrentName: "enp2s0", StableID: "pci-0000:02:00.0", Addresses: []string{}},
	}
	result := ValidateWithObserved(plan, observed)
	if result.Valid || !hasIssue(result.Errors, "IPV6_LAB_PREFIX_HOST_CONFLICT") || result.PlanHash != "" {
		t.Fatalf("host prefix conflict was accepted: %+v", result)
	}
	if !hasIssue(result.Warnings, "IPV6_WAN_NO_DEFAULT_ROUTE") {
		t.Fatalf("missing WAN IPv6 route warning: %+v", result.Warnings)
	}
	observed[0].Addresses = []string{"192.0.2.10/24", "2a01:4f8:1c1c:9::10/64"}
	observed[0].DefaultIPv6 = true
	observed[1].Addresses = []string{"fd12:3456:789a:1::1/64"}
	result = ValidateWithObserved(plan, observed)
	if !result.Valid || hasIssue(result.Warnings, "IPV6_WAN_NO_DEFAULT_ROUTE") {
		t.Fatalf("existing lab gateway address or healthy WAN was rejected: %+v", result)
	}
}

func TestBindIPv6HostEvidenceFollowsTheInspectedHost(t *testing.T) {
	ready := firewall.Inspection{IptablesPath: "/usr/bin/iptables", IPv6Available: true, Ip6tablesPath: "/usr/bin/ip6tables", IPv6DockerUserChain: true, IPv6FirewallReady: true}

	preview := BuildPreview(validULAPlan(), time.Unix(100, 0))
	preview.FirewallEnvironment = ready
	BindIPv6HostEvidence(&preview)
	for _, command := range preview.AttachmentCommands {
		if strings.Contains(command.Executable, "ip6tables") && command.Executable != "/usr/bin/ip6tables" {
			t.Fatalf("ip6tables path was not bound: %+v", command)
		}
	}
	if err := CheckIPv6Artifacts(validULAPlan(), preview); err != nil {
		t.Fatal(err)
	}

	noDocker := ready
	noDocker.IPv6DockerUserChain = false
	preview = BuildPreview(validULAPlan(), time.Unix(100, 0))
	preview.FirewallEnvironment = noDocker
	BindIPv6HostEvidence(&preview)
	found := false
	for _, command := range preview.AttachmentCommands {
		joined := strings.Join(command.Arguments, " ")
		if strings.Contains(command.Executable, "ip6tables") && strings.Contains(joined, "DOCKER-USER") {
			t.Fatalf("ip6tables attachment kept DOCKER-USER without Docker IPv6: %+v", command)
		}
		found = found || joined == "-w 5 -I FORWARD 1 -j SHAKERPROXY-FORWARD"
	}
	if !found || IPv6ForwardParent(noDocker) != "FORWARD" {
		t.Fatalf("FORWARD fallback attachment missing: %+v", preview.AttachmentCommands)
	}

	kernelOff := firewall.Inspection{IptablesPath: "/usr/sbin/iptables"}
	disabled := BuildPreview(validTwoNICPlan(), time.Unix(100, 0))
	disabled.FirewallEnvironment = kernelOff
	BindIPv6HostEvidence(&disabled)
	if disabled.FirewallRestoreIPv6 != "" || containsString(disabled.ChangedObjects, "ip6tables filter/SHAKERPROXY-FORWARD") {
		t.Fatalf("DISABLED kept IPv6 firewall on a kernel without IPv6: %+v", disabled)
	}
	for _, command := range disabled.AttachmentCommands {
		if strings.Contains(command.Executable, "ip6tables") {
			t.Fatalf("DISABLED kept ip6tables attachments: %+v", disabled.AttachmentCommands)
		}
	}
	if err := CheckIPv6Artifacts(validTwoNICPlan(), disabled); err != nil {
		t.Fatalf("kernel without IPv6 must accept an empty IPv6 firewall: %v", err)
	}

	routed := BuildPreview(validULAPlan(), time.Unix(100, 0))
	routed.FirewallEnvironment = kernelOff
	BindIPv6HostEvidence(&routed)
	if err := CheckIPv6Artifacts(validULAPlan(), routed); err == nil || !strings.Contains(strings.Join(routed.Impact, "\n"), "Host apply remains blocked") {
		t.Fatalf("IPv6 routing on a kernel without IPv6 was not blocked: err=%v impact=%v", err, routed.Impact)
	}
}

func TestCheckIPv6ArtifactsFailsClosed(t *testing.T) {
	ready := firewall.Inspection{IptablesPath: "/usr/sbin/iptables", IPv6Available: true, Ip6tablesPath: "/usr/sbin/ip6tables", IPv6FirewallReady: true}
	disabled := BuildPreview(validTwoNICPlan(), time.Unix(100, 0))
	disabled.FirewallEnvironment = ready
	if err := CheckIPv6Artifacts(validTwoNICPlan(), disabled); err != nil {
		t.Fatal(err)
	}
	missing := disabled
	missing.FirewallRestoreIPv6 = ""
	if err := CheckIPv6Artifacts(validTwoNICPlan(), missing); err == nil {
		t.Fatal("DISABLED preview without the IPv6 drop rules was accepted")
	}
	notReady := disabled
	notReady.FirewallEnvironment.IPv6FirewallReady = false
	if err := CheckIPv6Artifacts(validTwoNICPlan(), notReady); err == nil {
		t.Fatal("IPv6 firewall apply without a readable ip6tables was accepted")
	}
	observe := validTwoNICPlan()
	observe.IPv6.Strategy = IPv6ObserveOnly
	if err := CheckIPv6Artifacts(observe, disabled); err == nil {
		t.Fatal("observe-only plan accepted IPv6 firewall artifacts")
	}
	routed := BuildPreview(validULAPlan(), time.Unix(100, 0))
	routed.FirewallEnvironment = ready
	routed.RadvdConf = ""
	if err := CheckIPv6Artifacts(validULAPlan(), routed); err == nil {
		t.Fatal("routed preview without radvd configuration was accepted")
	}
	if LabIPv6FirewallMode(disabled) != "BLOCK" || LabIPv6FirewallMode(BuildPreview(validULAPlan(), time.Unix(100, 0))) != "ROUTE" || LabIPv6FirewallMode(Preview{}) != "" {
		t.Fatal("IPv6 firewall mode is inconsistent with the preview")
	}
}

func TestIPv6ManagementCIDRsMatchIPv6SSHSessions(t *testing.T) {
	plan := validULAPlan()
	plan.Management.AllowedCIDRs = []string{"192.0.2.0/24", "2001:db8:aaaa::/48"}
	observed := []ObservedInterface{
		{CurrentName: "enp1s0", StableID: "pci-0000:01:00.0", DefaultIPv6: true},
		{CurrentName: "enp2s0", StableID: "pci-0000:02:00.0"},
	}
	allowed := ValidateWithObservedSSH(plan, observed, []ActiveSSHSession{{SourceAddress: "2001:db8:aaaa::10", SourcePort: 49152, DestinationAddress: "2001:db8:ffff::2", DestinationPort: 22, DestinationInterface: "enp1s0"}})
	if !allowed.Valid {
		t.Fatalf("IPv6 SSH source inside an IPv6 management CIDR was rejected: %+v", allowed.Errors)
	}
	denied := ValidateWithObservedSSH(plan, observed, []ActiveSSHSession{{SourceAddress: "2001:db8:bbbb::10", SourcePort: 49152, DestinationAddress: "2001:db8:ffff::2", DestinationPort: 22, DestinationInterface: "enp1s0"}})
	if denied.Valid || !hasIssue(denied.Errors, "ACTIVE_SSH_SOURCE_NOT_ALLOWED") {
		t.Fatalf("IPv6 SSH source outside the management CIDRs was accepted: %+v", denied.Errors)
	}
	plan.Management.AllowedCIDRs = []string{"2001:db8:aaaa::/129"}
	if result := Validate(plan); result.Valid || !hasIssue(result.Errors, "MANAGEMENT_CIDR_INVALID") {
		t.Fatalf("invalid IPv6 management CIDR was accepted: %+v", result.Errors)
	}
}

func hasIssueAt(issues []Issue, code, path string) bool {
	for _, issue := range issues {
		if issue.Code == code && issue.Path == path {
			return true
		}
	}
	return false
}
