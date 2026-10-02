package trafficpolicy

import "testing"

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
