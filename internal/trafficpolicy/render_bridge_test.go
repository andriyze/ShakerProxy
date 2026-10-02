package trafficpolicy

import (
	"strings"
	"testing"
)

// On an inline bridge the lab is "frames that entered through the device
// port"; plain DNS to the network's own router is answered by ShakerProxy.
func TestInlineBridgeRulesMatchTheDevicePort(t *testing.T) {
	context := RenderContext{LabInterface: "spbr0", LabCIDR: "192.0.2.0/24", LabGatewayIPv4: "192.0.2.20", LabBridgePort: "eth1", IPv6Listeners: true,
		Devices: map[string]DeviceMatch{renderDeviceA: {HardwareAddresses: []string{"aa:bb:cc:dd:ee:01"}}}}
	rules := mustRender(t, renderPolicy(func(p *Policy) {
		p.EncryptedDNS.Mode = EncryptedDNSEnforceLocal
		p.EncryptedDNS.RedirectPlainDNS = true
		p.EncryptedDNS.UpstreamServers = []string{"192.0.2.1:53"}
		p.EncryptedDNS.BlockDoT = true
		p.DeviceControls = []DeviceControl{{DeviceID: renderDeviceA, BlockInternet: true}}
	}), context)
	for _, protocol := range []string{"udp", "tcp"} {
		indexOf(t, rules.NATRules, "-A SHAKERPROXY-PREROUTING -i spbr0 -m physdev --physdev-in eth1 -p "+protocol+" --dport 53 -j REDIRECT --to-ports 1053")
		indexOf(t, rules.FilterRules, "-A SHAKERPROXY-INPUT -i spbr0 -m physdev --physdev-in eth1 -p "+protocol+" --dport 1053 -m conntrack --ctstate DNAT -j ACCEPT")
	}
	indexOf(t, rules.FilterRules, "-i spbr0 -m physdev --physdev-in eth1 -p tcp --dport 853")
	indexOf(t, rules.FilterRules, "-i spbr0 -m mac --mac-source aa:bb:cc:dd:ee:01 ! -d 192.0.2.0/24 -j DROP")
	indexOf(t, rules.FilterRulesIPv6, "-i spbr0 -m mac --mac-source aa:bb:cc:dd:ee:01 ! -d fe80::/10 -j DROP")
	assertAbsent(t, rules.NATRules, "! -d 192.0.2.0/24 -p udp --dport 53")
	assertAbsent(t, rules.NATRulesIPv6, "REDIRECT")

	context.LabBridgePort = "spbr0"
	if _, err := RenderFirewall(LegacyDefaultPolicy(), context); err == nil {
		t.Fatal("the bridge itself was accepted as its device port")
	}
}

// The Wi-Fi access point joins the inline bridge as a second device-side
// port: every rule the device port gets, the access point gets right after
// it, so both see the same order; the router's port gets none.
func TestInlineBridgeRulesMatchTheAccessPointToo(t *testing.T) {
	context := RenderContext{LabInterface: "spbr0", LabCIDR: "192.0.2.0/24", LabGatewayIPv4: "192.0.2.20", LabBridgePort: "eth1", LabBridgeAPPort: "wlan0", LabBridgeIPv6: true, IPv6Listeners: true}
	rules := mustRender(t, renderPolicy(func(p *Policy) {
		p.EncryptedDNS.Mode = EncryptedDNSEnforceLocal
		p.EncryptedDNS.RedirectPlainDNS = true
		p.EncryptedDNS.UpstreamServers = []string{"192.0.2.1:53"}
		p.EncryptedDNS.BlockDoT = true
		p.TLS.Enabled = true
	}), context)
	for _, port := range []string{"eth1", "wlan0"} {
		scope := "-i spbr0 -m physdev --physdev-in " + port
		for _, protocol := range []string{"udp", "tcp"} {
			indexOf(t, rules.NATRules, "-A SHAKERPROXY-PREROUTING "+scope+" -p "+protocol+" --dport 53 -j REDIRECT --to-ports 1053")
			indexOf(t, rules.NATRulesIPv6, "-A SHAKERPROXY-PREROUTING "+scope+" -p "+protocol+" --dport 53 -j REDIRECT --to-ports 1053")
			indexOf(t, rules.FilterRules, "-A SHAKERPROXY-INPUT "+scope+" -p "+protocol+" --dport 1053 -m conntrack --ctstate DNAT -j ACCEPT")
		}
		indexOf(t, rules.NATRules, "-A SHAKERPROXY-PREROUTING "+scope+" -p tcp --dport 443 -j REDIRECT")
		// The CA onboarding page is reached before any interception
		// exemption can return a lab client from the chain.
		if onboarding, exemption := indexOf(t, rules.NATRules, scope+" -d 192.0.2.20 -p tcp --dport 80 -j DNAT"), indexOf(t, rules.NATRules, "-j RETURN"); onboarding > exemption {
			t.Fatalf("%s: onboarding DNAT follows an exemption:\n%s", port, strings.Join(rules.NATRules, "\n"))
		}
	}
	wired := indexOf(t, rules.FilterRules, "-i spbr0 -m physdev --physdev-in eth1 -p tcp --dport 853 -j REJECT")
	if wifi := indexOf(t, rules.FilterRules, "-i spbr0 -m physdev --physdev-in wlan0 -p tcp --dport 853 -m limit"); wifi != wired+1 {
		t.Fatalf("the access point's DoT block does not follow the device port's:\n%s", strings.Join(rules.FilterRules, "\n"))
	}
	for _, list := range [][]string{rules.FilterRules, rules.NATRules, rules.FilterRulesIPv6, rules.NATRulesIPv6} {
		assertAbsent(t, list, "! --physdev-in")
		assertAbsent(t, list, "--physdev-in eth0")
	}

	for name, invalid := range map[string]RenderContext{
		"access point is the device port": {LabInterface: "spbr0", LabCIDR: "192.0.2.0/24", LabBridgePort: "eth1", LabBridgeAPPort: "eth1"},
		"access point is the bridge":      {LabInterface: "spbr0", LabCIDR: "192.0.2.0/24", LabBridgePort: "eth1", LabBridgeAPPort: "spbr0"},
		"access point without a bridge":   {LabInterface: "spbr0", LabCIDR: "192.0.2.0/24", LabBridgeAPPort: "wlan0"},
		"unsafe name":                     {LabInterface: "spbr0", LabCIDR: "192.0.2.0/24", LabBridgePort: "eth1", LabBridgeAPPort: "wlan0 -j ACCEPT"},
	} {
		if _, err := RenderFirewall(LegacyDefaultPolicy(), invalid); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// With its own IPv6 address on the bridge, ShakerProxy answers DNS that
// devices send over IPv6 too; without one, or without IPv6 listeners, it
// only records it.
func TestInlineBridgeRedirectsIPv6DNSOnlyWithAnAddress(t *testing.T) {
	policy := renderPolicy(func(p *Policy) {
		p.EncryptedDNS.Mode = EncryptedDNSEnforceLocal
		p.EncryptedDNS.RedirectPlainDNS = true
		p.EncryptedDNS.UpstreamServers = []string{"192.0.2.1:53"}
		p.EncryptedDNS.BlockDoT = true
	})
	context := RenderContext{LabInterface: "spbr0", LabCIDR: "192.0.2.0/24", LabGatewayIPv4: "192.0.2.20", LabBridgePort: "eth1", LabBridgeIPv6: true, IPv6Listeners: true}
	rules := mustRender(t, policy, context)
	for _, protocol := range []string{"udp", "tcp"} {
		indexOf(t, rules.NATRulesIPv6, "-A SHAKERPROXY-PREROUTING -i spbr0 -m physdev --physdev-in eth1 -p "+protocol+" --dport 53 -j REDIRECT --to-ports 1053")
		indexOf(t, rules.FilterRulesIPv6, "-A SHAKERPROXY-INPUT -i spbr0 -m physdev --physdev-in eth1 -p "+protocol+" --dport 1053 -m conntrack --ctstate DNAT -j ACCEPT")
	}
	indexOf(t, rules.FilterRulesIPv6, "-i spbr0 -m physdev --physdev-in eth1 -p tcp --dport 853")
	assertAbsent(t, rules.NATRulesIPv6, "-d fe80")

	for name, without := range map[string]RenderContext{
		"no address":   {LabInterface: "spbr0", LabCIDR: "192.0.2.0/24", LabGatewayIPv4: "192.0.2.20", LabBridgePort: "eth1", IPv6Listeners: true},
		"no listeners": {LabInterface: "spbr0", LabCIDR: "192.0.2.0/24", LabGatewayIPv4: "192.0.2.20", LabBridgePort: "eth1", LabBridgeIPv6: true},
	} {
		rules := mustRender(t, policy, without)
		if len(rules.NATRulesIPv6) != 0 {
			t.Fatalf("%s: IPv6 DNS was redirected: %v", name, rules.NATRulesIPv6)
		}
		indexOf(t, rules.FilterRulesIPv6, "-i spbr0 -m physdev --physdev-in eth1 -p tcp --dport 853")
	}
}
