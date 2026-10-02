package trafficpolicy

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const (
	renderDeviceA = "device-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	renderDeviceB = "device-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func renderPolicy(mutate func(*Policy)) Policy {
	policy := LegacyDefaultPolicy()
	policy.Revision = 2
	policy.Name = "Render test"
	mutate(&policy)
	return policy
}

func renderContext() RenderContext {
	return RenderContext{
		LabInterface:   "lab0",
		LabCIDR:        "10.77.0.0/24",
		LabGatewayIPv4: "10.77.0.1",
		LabIPv6Prefix:  "fd12:3456:789a:1::/64",
		LabGatewayIPv6: "fd12:3456:789a:1::1",
		IPv6Listeners:  true,
		Devices: map[string]DeviceMatch{
			renderDeviceA: {HardwareAddresses: []string{"aa:bb:cc:dd:ee:01"}, IPv4: []string{"10.77.0.23"}},
			renderDeviceB: {IPv4: []string{"10.77.0.24"}, IPv6: []string{"fd12:3456:789a:1::24"}},
		},
	}
}

func mustRender(t *testing.T, policy Policy, context RenderContext) FirewallRules {
	t.Helper()
	rules, err := RenderFirewall(policy, context)
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func indexOf(t *testing.T, rules []string, fragment string) int {
	t.Helper()
	for index, rule := range rules {
		if strings.Contains(rule, fragment) {
			return index
		}
	}
	t.Fatalf("no rule contains %q:\n%s", fragment, strings.Join(rules, "\n"))
	return -1
}

func assertAbsent(t *testing.T, rules []string, fragment string) {
	t.Helper()
	for _, rule := range rules {
		if strings.Contains(rule, fragment) {
			t.Fatalf("unexpected rule %q", rule)
		}
	}
}

func TestInterceptionBlocksQUICAndSkipsPrivateDestinationsByDefault(t *testing.T) {
	rules := mustRender(t, renderPolicy(func(p *Policy) { p.TLS.Enabled = true }), renderContext())
	reject := indexOf(t, rules.FilterRules, "-i lab0 -s 10.77.0.0/24 ! -d 10.77.0.0/24 -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable")
	if exempt := indexOf(t, rules.FilterRules, "-d 192.168.0.0/16 -p udp --dport 443 -j RETURN"); exempt > reject {
		t.Fatal("private QUIC exemption must precede the QUIC reject")
	}
	redirect := indexOf(t, rules.NATRules, "-p tcp --dport 443 -j REDIRECT --to-ports 8085")
	for _, private := range []string{"10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16"} {
		if index := indexOf(t, rules.NATRules, "-d "+private+" -p tcp --dport 443 -j RETURN"); index > redirect {
			t.Fatalf("private destination %s is not exempt before the redirect", private)
		}
	}
	indexOf(t, rules.FilterRulesIPv6, "-i lab0 -s fd12:3456:789a:1::/64 ! -d fd12:3456:789a:1::/64 -p udp --dport 443 -j REJECT --reject-with icmp6-port-unreachable")
	indexOf(t, rules.NATRulesIPv6, "-d fc00::/7 -p tcp --dport 443 -j RETURN")
	assertAbsent(t, rules.NATRules, "--dport 80 -j REDIRECT")

	rules = mustRender(t, renderPolicy(func(p *Policy) {
		p.TLS.Enabled = true
		p.TLS.AllowQUIC = true
		p.TLS.InterceptPrivateDestinations = true
		p.TLS.InterceptHTTP = true
	}), renderContext())
	assertAbsent(t, rules.FilterRules, "--dport 443 -j REJECT")
	assertAbsent(t, rules.NATRules, "-d 10.0.0.0/8")
	indexOf(t, rules.NATRules, "-i lab0 -s 10.77.0.0/24 ! -d 10.77.0.0/24 -p tcp --dport 80 -j REDIRECT --to-ports 8085")
	indexOf(t, rules.NATRulesIPv6, "-i lab0 -s fd12:3456:789a:1::/64 ! -d fd12:3456:789a:1::/64 -p tcp --dport 80 -j REDIRECT --to-ports 8085")
}

func TestOnboardingDNATPrecedesInterceptionAndOpensOnlyLabPort(t *testing.T) {
	rules := mustRender(t, renderPolicy(func(p *Policy) {
		p.TLS.Enabled = true
		p.TLS.InterceptHTTP = true
	}), renderContext())
	if !rules.NeedsOnboarding {
		t.Fatal("interception policy did not request the onboarding page")
	}
	if rules.NATRules[0] != "-A SHAKERPROXY-PREROUTING -i lab0 -s 10.77.0.0/24 -d 10.77.0.1 -p tcp --dport 80 -j DNAT --to-destination 10.77.0.1:8086" {
		t.Fatalf("onboarding DNAT must be first (before the private-destination exemption):\n%s", strings.Join(rules.NATRules, "\n"))
	}
	if rules.NATRulesIPv6[0] != "-A SHAKERPROXY-PREROUTING -i lab0 -s fd12:3456:789a:1::/64 -d fd12:3456:789a:1::1 -p tcp --dport 80 -j DNAT --to-destination [fd12:3456:789a:1::1]:8086" {
		t.Fatalf("IPv6 onboarding DNAT is wrong: %s", rules.NATRulesIPv6[0])
	}
	accept := indexOf(t, rules.FilterRules, "-A SHAKERPROXY-INPUT -i lab0 -s 10.77.0.0/24 -d 10.77.0.1 -p tcp --dport 8086 -m conntrack --ctstate DNAT -j ACCEPT")
	if drop := indexOf(t, rules.FilterRules, "-A SHAKERPROXY-INPUT -p tcp --dport 8086 -j DROP"); drop < accept {
		t.Fatal("onboarding port drop precedes the lab accept")
	}

	rules = mustRender(t, renderPolicy(func(p *Policy) { p.EncryptedDNS.BlockDoT = true }), renderContext())
	if rules.NeedsOnboarding {
		t.Fatal("onboarding page published without interception")
	}
	assertAbsent(t, rules.NATRules, "DNAT")
}

func TestDeviceControlsMatchByMACThenIPAndKeepBlockedDevicesOffTheProxy(t *testing.T) {
	policy := renderPolicy(func(p *Policy) {
		p.TLS.Enabled = true
		p.TLS.SelectedDeviceIDs = []string{renderDeviceA, renderDeviceB}
		p.DeviceControls = []DeviceControl{
			{DeviceID: renderDeviceA, HardwareAddresses: []string{"aa:bb:cc:dd:ee:01"}, BlockInternet: true},
			{DeviceID: renderDeviceB, Addresses: []string{"10.77.0.24"}, BlockedDomains: []string{"ads.example"}},
		}
	})
	rules := mustRender(t, policy, renderContext())
	indexOf(t, rules.FilterRules, "-A SHAKERPROXY-FORWARD -i lab0 -m mac --mac-source aa:bb:cc:dd:ee:01 ! -d 10.77.0.0/24 -j DROP")
	indexOf(t, rules.FilterRulesIPv6, "-A SHAKERPROXY-FORWARD -i lab0 -m mac --mac-source aa:bb:cc:dd:ee:01 ! -d fd12:3456:789a:1::/64 -j DROP")
	assertAbsent(t, rules.FilterRules, "-s 10.77.0.23 ")
	blockedReturn := indexOf(t, rules.NATRules, "-i lab0 -m mac --mac-source aa:bb:cc:dd:ee:01 -p tcp --dport 443 -j RETURN")
	if redirect := indexOf(t, rules.NATRules, "-p tcp --dport 443 -j REDIRECT"); redirect < blockedReturn {
		t.Fatal("internet-blocked device reaches the proxy before its exemption")
	}
	indexOf(t, rules.NATRules, "-i lab0 -s 10.77.0.24 ! -d 10.77.0.0/24 -p udp --dport 53 -j REDIRECT --to-ports 1053")
	indexOf(t, rules.NATRules, "-i lab0 -s 10.77.0.0/24 -d 10.77.0.1 -p udp --dport 53 -j REDIRECT --to-ports 1053")
	indexOf(t, rules.NATRulesIPv6, "-i lab0 -s fd12:3456:789a:1::24 ! -d fd12:3456:789a:1::/64 -p tcp --dport 53 -j REDIRECT --to-ports 1053")
	indexOf(t, rules.NATRulesIPv6, "-i lab0 -s fd12:3456:789a:1::/64 -d fd12:3456:789a:1::1 -p tcp --dport 53 -j REDIRECT --to-ports 1053")
	indexOf(t, rules.FilterRules, "-i lab0 -s 10.77.0.24 ! -d 10.77.0.0/24 -p tcp --dport 853 -j REJECT --reject-with tcp-reset")
	indexOf(t, rules.FilterRules, "-i lab0 -s 10.77.0.24 ! -d 10.77.0.0/24 -p udp --dport 443 -j REJECT")
	// Every selected device has an identity, so interception is narrowed.
	indexOf(t, rules.NATRules, "-i lab0 -s 10.77.0.24 ! -d 10.77.0.0/24 -p tcp --dport 443 -j REDIRECT --to-ports 8085")
	assertAbsent(t, rules.NATRules, "-i lab0 -s 10.77.0.0/24 ! -d 10.77.0.0/24 -p tcp --dport 443 -j REDIRECT")
	if !rules.NeedsDNSService || len(rules.UnmatchedDevices) != 0 {
		t.Fatalf("unexpected requirements: %#v", rules)
	}

	context := renderContext()
	delete(context.Devices, renderDeviceB)
	rules = mustRender(t, policy, context)
	if len(rules.UnmatchedDevices) != 1 || rules.UnmatchedDevices[0] != renderDeviceB {
		t.Fatalf("device without identity not reported: %#v", rules.UnmatchedDevices)
	}
	// A selected device without identity falls back to whole-lab redirect
	// with mitmproxy deciding by device ID, as before device controls.
	indexOf(t, rules.NATRules, "-i lab0 -s 10.77.0.0/24 ! -d 10.77.0.0/24 -p tcp --dport 443 -j REDIRECT --to-ports 8085")
}

func TestEncryptedDNSLogPrecedesReject(t *testing.T) {
	rules := mustRender(t, renderPolicy(func(p *Policy) {
		p.EncryptedDNS.Mode = EncryptedDNSBlockKnown
		p.EncryptedDNS.BlockDoT = true
	}), renderContext())
	log := indexOf(t, rules.FilterRules, `--dport 853 -m limit --limit 10/second --limit-burst 20 -j NFLOG --nflog-group 853 --nflog-prefix "SHAKERPROXY_EDNS_DOT " --nflog-size 128`)
	reject := indexOf(t, rules.FilterRules, "-s 10.77.0.0/24 ! -d 10.77.0.0/24 -p tcp --dport 853 -j REJECT")
	if log > reject {
		t.Fatal("LOG rule is unreachable after its REJECT")
	}
	indexOf(t, rules.FilterRulesIPv6, "-i lab0 -s fd12:3456:789a:1::/64 ! -d fd12:3456:789a:1::/64 -p tcp --dport 853 -j REJECT")
}

func TestBaselineProtectsListenersInBothFamilies(t *testing.T) {
	rules := mustRender(t, DefaultPolicy(), RenderContext{})
	for _, family := range [][]string{rules.FilterRules, rules.FilterRulesIPv6} {
		for _, port := range []string{"1053", "8085", "8086"} {
			indexOf(t, family, "-A SHAKERPROXY-INPUT -p tcp --dport "+port+" -j DROP")
		}
		indexOf(t, family, "-A SHAKERPROXY-INPUT -p udp --dport 1053 -j DROP")
		indexOf(t, family, "-A SHAKERPROXY-INPUT -i lo -p tcp --dport 8085 -j ACCEPT")
	}
	if len(rules.NATRules) != 0 || len(rules.NATRulesIPv6) != 0 {
		t.Fatal("baseline installs NAT rules")
	}
}

func TestConfirmedLabAlwaysAnswersDNSSentToShakerProxy(t *testing.T) {
	// DHCP hands out ShakerProxy's lab address as the resolver, and
	// single-arm clients are told to use it, so even the default
	// observe-only policy must answer those queries.
	context := renderContext()
	context.Devices = nil
	rules := mustRender(t, LegacyDefaultPolicy(), context)
	for _, protocol := range []string{"udp", "tcp"} {
		indexOf(t, rules.NATRules, "-A SHAKERPROXY-PREROUTING -i lab0 -s 10.77.0.0/24 -d 10.77.0.1 -p "+protocol+" --dport 53 -j REDIRECT --to-ports 1053")
		indexOf(t, rules.FilterRules, "-A SHAKERPROXY-INPUT -i lab0 -s 10.77.0.0/24 -p "+protocol+" --dport 1053 -m conntrack --ctstate DNAT -j ACCEPT")
	}
	if !rules.NeedsDNSService || !rules.NeedsNATHook {
		t.Fatalf("the lab resolver needs the DNS service and the NAT hook: %+v", rules)
	}
	// Observe-only never redirects DNS addressed to other resolvers.
	assertAbsent(t, rules.NATRules, "! -d 10.77.0.0/24 -p udp --dport 53")
	assertAbsent(t, rules.NATRules, "--dport 443")
}

func TestIPv6RedirectsRequireIPv6Listeners(t *testing.T) {
	context := renderContext()
	context.IPv6Listeners = false
	rules := mustRender(t, renderPolicy(func(p *Policy) {
		p.TLS.Enabled = true
		p.EncryptedDNS.Mode = EncryptedDNSEnforceLocal
		p.EncryptedDNS.RedirectPlainDNS = true
		p.EncryptedDNS.UpstreamServers = []string{"192.0.2.53:53"}
	}), context)
	assertAbsent(t, rules.NATRulesIPv6, "REDIRECT")
	indexOf(t, rules.NATRules, "-p udp --dport 53 -j REDIRECT --to-ports 1053")
	indexOf(t, rules.FilterRulesIPv6, "-p udp --dport 443 -j REJECT")
}

// With a bridged wired + Wi-Fi lab and br_netfilter, lab-to-lab frames pass
// the same hooks; only traffic leaving the lab may be redirected or blocked.
func TestClientRulesLeaveLabToLabTrafficAlone(t *testing.T) {
	context := renderContext()
	context.LabInterface = "lgbr0"
	rules := mustRender(t, renderPolicy(func(p *Policy) {
		p.TLS.Enabled = true
		p.TLS.InterceptHTTP = true
		p.TLS.InterceptPrivateDestinations = true
		p.EncryptedDNS.Mode = EncryptedDNSEnforceLocal
		p.EncryptedDNS.RedirectPlainDNS = true
		p.EncryptedDNS.UpstreamServers = []string{"192.0.2.53:53"}
		p.EncryptedDNS.BlockDoT = true
		p.DeviceControls = []DeviceControl{{DeviceID: renderDeviceA, BlockInternet: true}}
	}), context)
	for _, family := range []struct {
		lab    string
		filter []string
		nat    []string
	}{{"10.77.0.0/24", rules.FilterRules, rules.NATRules}, {"fd12:3456:789a:1::/64", rules.FilterRulesIPv6, rules.NATRulesIPv6}} {
		for _, rule := range append(append([]string{}, family.filter...), family.nat...) {
			client := strings.Contains(rule, "-j REDIRECT") || strings.Contains(rule, "--dport 443 -j REJECT") || strings.Contains(rule, "--dport 853 -j REJECT")
			gatewayDNS := strings.Contains(rule, "--dport 53") && (strings.Contains(rule, "-d 10.77.0.1 ") || strings.Contains(rule, "-d fd12:3456:789a:1::1 "))
			if client && !gatewayDNS && !strings.Contains(rule, "! -d "+family.lab+" ") {
				t.Fatalf("rule would act on lab-to-lab traffic: %s", rule)
			}
			if strings.Contains(rule, "-j DROP") && strings.HasPrefix(rule, "-A SHAKERPROXY-FORWARD") && !strings.Contains(rule, "! -o lgbr0") && !strings.Contains(rule, "! -d "+family.lab+" ") {
				t.Fatalf("internet block would act on lab-to-lab traffic: %s", rule)
			}
		}
	}
	indexOf(t, rules.NATRules, "-i lgbr0 -s 10.77.0.0/24 -d 10.77.0.1 -p udp --dport 53 -j REDIRECT --to-ports 1053")
}

func TestRenderRejectsUnsafeContext(t *testing.T) {
	policy := renderPolicy(func(p *Policy) { p.TLS.Enabled = true })
	for name, mutate := range map[string]func(*RenderContext){
		"interface":    func(c *RenderContext) { c.LabInterface = "lab0 -j ACCEPT" },
		"gateway":      func(c *RenderContext) { c.LabGatewayIPv4 = "192.0.2.1" },
		"ipv6 prefix":  func(c *RenderContext) { c.LabIPv6Prefix = "10.0.0.0/8" },
		"ipv6 gateway": func(c *RenderContext) { c.LabGatewayIPv6 = "2001:db8::1" },
		"mac": func(c *RenderContext) {
			c.Devices[renderDeviceA] = DeviceMatch{HardwareAddresses: []string{"aa:bb:cc:dd:ee:01 -j ACCEPT"}}
		},
		"device ip": func(c *RenderContext) { c.Devices[renderDeviceA] = DeviceMatch{IPv4: []string{"10.0.0.1/8"}} },
		"device id": func(c *RenderContext) { c.Devices["device-x"] = DeviceMatch{} },
	} {
		context := renderContext()
		mutate(&context)
		if _, err := RenderFirewall(policy, context); err == nil {
			t.Fatalf("%s: unsafe render context accepted", name)
		}
	}
}

func TestDeviceControlsNormalizeAndValidate(t *testing.T) {
	policy := renderPolicy(func(p *Policy) {
		p.DeviceControls = []DeviceControl{{
			DeviceID:          renderDeviceB,
			HardwareAddresses: []string{"AA-BB-CC-DD-EE-02", "aa:bb:cc:dd:ee:02"},
			Addresses:         []string{"::ffff:10.77.0.9"},
			BlockedDomains:    []string{"*.Ads.Example.", "ads.example"},
			BypassHosts:       []string{"Pinned.Example"},
		}, {DeviceID: renderDeviceA, BlockInternet: true}}
	})
	normalized, err := Normalize(policy)
	if err != nil {
		t.Fatal(err)
	}
	control := normalized.DeviceControls[1]
	if normalized.DeviceControls[0].DeviceID != renderDeviceA || len(control.HardwareAddresses) != 1 || control.HardwareAddresses[0] != "aa:bb:cc:dd:ee:02" || control.Addresses[0] != "10.77.0.9" || len(control.BlockedDomains) != 1 || control.BlockedDomains[0] != "ads.example" || control.BypassHosts[0] != "pinned.example" {
		t.Fatalf("unexpected normalization: %#v", normalized.DeviceControls)
	}
	tooMany := make([]string, MaxBlockedDomainsPerDevice+1)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("d%d.example", index)
	}
	for name, control := range map[string]DeviceControl{
		"device id":   {DeviceID: "device-1"},
		"multicast":   {DeviceID: renderDeviceA, HardwareAddresses: []string{"01:00:5e:00:00:01"}},
		"domain":      {DeviceID: renderDeviceA, BlockedDomains: []string{"not a domain"}},
		"single":      {DeviceID: renderDeviceA, BlockedDomains: []string{"localhost"}},
		"too many":    {DeviceID: renderDeviceA, BlockedDomains: tooMany},
		"bad address": {DeviceID: renderDeviceA, Addresses: []string{"224.0.0.1"}},
	} {
		invalid := renderPolicy(func(p *Policy) { p.DeviceControls = []DeviceControl{control} })
		if _, err := Normalize(invalid); err == nil {
			t.Fatalf("%s: invalid device control accepted", name)
		}
	}
	duplicate := renderPolicy(func(p *Policy) {
		p.DeviceControls = []DeviceControl{{DeviceID: renderDeviceA}, {DeviceID: renderDeviceA}}
	})
	if _, err := Normalize(duplicate); err == nil {
		t.Fatal("duplicate device control accepted")
	}
}

// Documents written before these fields existed must keep their digest.
func TestNewPolicyFieldsAreOmittedWhenUnset(t *testing.T) {
	normalized, err := Normalize(renderPolicy(func(p *Policy) { p.TLS.Enabled = true }))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"device_controls", "allow_quic", "intercept_http", "intercept_private_destinations"} {
		if strings.Contains(string(encoded), field) {
			t.Fatalf("unset field %q changes legacy digests: %s", field, encoded)
		}
	}
}

func TestResolveDeviceMatchesPrefersLiveNeighborsAndDropsAmbiguity(t *testing.T) {
	renderDeviceC := "device-cccccccccccccccccccccccccccccccc"
	policy := renderPolicy(func(p *Policy) {
		p.DeviceControls = []DeviceControl{
			// A's saved lease 10.77.0.50 has since been handed to B.
			{DeviceID: renderDeviceA, HardwareAddresses: []string{"aa:bb:cc:dd:ee:01"}, Addresses: []string{"10.77.0.50"}},
			{DeviceID: renderDeviceB, HardwareAddresses: []string{"aa:bb:cc:dd:ee:02"}},
			// C has no MAC; its saved address collides with A's live one.
			{DeviceID: renderDeviceC, Addresses: []string{"10.77.0.23"}},
		}
	})
	normalized, err := Normalize(policy)
	if err != nil {
		t.Fatal(err)
	}
	neighbors := []Neighbor{
		{Address: "10.77.0.23", HardwareAddress: "AA:BB:CC:DD:EE:01"},
		{Address: "10.77.0.50", HardwareAddress: "aa:bb:cc:dd:ee:02"},
		{Address: "fe80::1%lab0", HardwareAddress: "aa:bb:cc:dd:ee:02"},
	}
	matches := ResolveDeviceMatches(normalized, neighbors, true)
	if got := matches[renderDeviceA].IPv4; len(got) != 0 {
		t.Fatalf("device A kept a stale or ambiguous address: %v", got)
	}
	if got := matches[renderDeviceB].IPv4; len(got) != 1 || got[0] != "10.77.0.50" {
		t.Fatalf("device B addresses = %v", got)
	}
	if got := matches[renderDeviceC].IPv4; len(got) != 0 {
		t.Fatalf("ambiguous address was attributed to C: %v", got)
	}
	// Without a readable neighbor table the saved evidence is all there is.
	matches = ResolveDeviceMatches(normalized, nil, false)
	if got := matches[renderDeviceA].IPv4; len(got) != 1 || got[0] != "10.77.0.50" {
		t.Fatalf("saved address not used when neighbors are unknown: %v", got)
	}
}

// Regression from a single-arm EC2 lab: the lab and the internet share one
// interface, so an internet block keyed on "! -o <lab>" never dropped anything.
func TestInternetBlockWorksWhenTheLabAndInternetShareAnInterface(t *testing.T) {
	context := RenderContext{LabInterface: "ens5", LabCIDR: "172.31.32.0/20", LabGatewayIPv4: "172.31.47.80",
		Devices: map[string]DeviceMatch{renderDeviceA: {HardwareAddresses: []string{"0e:ff:c0:be:18:05"}}}}
	rules := mustRender(t, renderPolicy(func(p *Policy) {
		p.DeviceControls = []DeviceControl{{DeviceID: renderDeviceA, HardwareAddresses: []string{"0e:ff:c0:be:18:05"}, BlockInternet: true}}
	}), context)
	indexOf(t, rules.FilterRules, "-A SHAKERPROXY-FORWARD -i ens5 -m mac --mac-source 0e:ff:c0:be:18:05 ! -d 172.31.32.0/20 -j DROP")
	assertAbsent(t, rules.FilterRules, "! -o ens5")
}

func TestVPNDevicesGetTheLabRulesByAddress(t *testing.T) {
	context := renderContext()
	context.VPN = &Segment{
		Interface: "wg-lab", IPv4CIDR: "10.89.0.0/24", GatewayIPv4: "10.89.0.1", IPv6Prefix: "fd89::/64", GatewayIPv6: "fd89::1",
		Devices: map[string]DeviceMatch{renderDeviceB: {IPv4: []string{"10.89.0.2"}, IPv6: []string{"fd89::2"}}},
	}
	policy := renderPolicy(func(p *Policy) {
		p.TLS.Enabled = true
		p.EncryptedDNS.BlockDoT = true
		p.DeviceControls = []DeviceControl{{DeviceID: renderDeviceB, BlockInternet: true}}
	})
	rules := mustRender(t, policy, context)
	indexOf(t, rules.NATRules, "-A SHAKERPROXY-PREROUTING -i wg-lab -s 10.89.0.0/24 -d 10.89.0.1 -p udp --dport 53 -j REDIRECT --to-ports 1053")
	indexOf(t, rules.FilterRules, "-A SHAKERPROXY-INPUT -i wg-lab -s 10.89.0.0/24 -p udp --dport 1053 -m conntrack --ctstate DNAT -j ACCEPT")
	indexOf(t, rules.FilterRules, "-A SHAKERPROXY-FORWARD -i wg-lab -s 10.89.0.0/24 ! -d 10.89.0.0/24 -p tcp --dport 853")
	indexOf(t, rules.FilterRules, "-A SHAKERPROXY-FORWARD -i wg-lab -s 10.89.0.2 ! -d 10.89.0.0/24 -j DROP")
	indexOf(t, rules.FilterRulesIPv6, "-A SHAKERPROXY-FORWARD -i wg-lab -s fd89::2 ! -d fd89::/64 -j DROP")
	// The lab keeps its own rules; the CA onboarding page stays lab-only.
	indexOf(t, rules.NATRules, "-i lab0 -s 10.77.0.0/24 -d 10.77.0.1 -p tcp --dport 80 -j DNAT")
	assertAbsent(t, rules.NATRules, "-i wg-lab -s 10.89.0.0/24 -d 10.89.0.1 -p tcp --dport 80 -j DNAT")
	if len(rules.UnmatchedDevices) != 0 {
		t.Fatalf("a VPN device was reported unmatched: %v", rules.UnmatchedDevices)
	}
	// One listener protection block for both segments.
	if count := strings.Count(strings.Join(rules.FilterRules, "\n"), "-A SHAKERPROXY-INPUT -p udp --dport 1053 -j DROP"); count != 1 {
		t.Fatalf("listener drop appears %d times", count)
	}
	// A VPN-only appliance renders the VPN alone.
	vpnOnly := mustRender(t, renderPolicy(func(p *Policy) {}), RenderContext{VPN: context.VPN, IPv6Listeners: true})
	indexOf(t, vpnOnly.NATRules, "-i wg-lab -s 10.89.0.0/24 -d 10.89.0.1 -p tcp --dport 53 -j REDIRECT --to-ports 1053")
	assertAbsent(t, vpnOnly.NATRules, "lab0")
}
