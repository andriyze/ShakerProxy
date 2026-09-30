package networkplan

import (
	"strings"
	"testing"
	"time"
)

func withULA(plan Plan) Plan {
	plan.IPv6 = IPv6Configuration{Strategy: IPv6ULANAT66Lab, LabPrefix: "fd12:3456:789a:1::/64"}
	return plan
}

func TestIPv6RoutesOverAWiFiOnlyLabOnEveryWiFiTopology(t *testing.T) {
	for _, topology := range []Topology{TopologyTwoNIC, TopologyThreeInterface, TopologyExistingRoutedVLAN, TopologyAdvancedCustom} {
		t.Run(string(topology), func(t *testing.T) {
			plan := withULA(validWiFiPlan())
			plan.Topology = topology
			preview := BuildPreview(plan, time.Unix(100, 0))
			if !preview.Validation.Valid {
				t.Fatalf("Wi-Fi IPv6 plan rejected: %+v", preview.Validation.Errors)
			}
			labIPv6, ok := LabIPv6Routing(plan)
			if !ok || labIPv6.Interface != "wlan0" {
				t.Fatalf("lab IPv6 must use the access point: %+v", labIPv6)
			}
			if !strings.Contains(preview.NetplanYAML, "    wlan0:\n      renderer: networkd\n      addresses: [10.77.0.1/24, \"fd12:3456:789a:1::1/64\"]\n      dhcp6: false\n      accept-ra: false\n") {
				t.Fatalf("access point lacks the IPv6 gateway address:\n%s", preview.NetplanYAML)
			}
			if !strings.Contains(preview.RadvdConf, "interface wlan0\n") {
				t.Fatalf("radvd does not serve the access point:\n%s", preview.RadvdConf)
			}
			for _, expected := range []string{
				"-A SHAKERPROXY-FORWARD -i wlan0 ! -s fd12:3456:789a:1::/64 -j DROP\n",
				"-A SHAKERPROXY-FORWARD -i wlan0 -o enp1s0 -s fd12:3456:789a:1::/64 -j ACCEPT\n",
				"-A SHAKERPROXY-INPUT -i wlan0 -p ipv6-icmp -m icmp6 --icmpv6-type router-solicitation -m hl --hl-eq 255 -j ACCEPT\n",
			} {
				if !strings.Contains(preview.FirewallRestoreIPv6, expected) {
					t.Fatalf("IPv6 firewall missing %q:\n%s", expected, preview.FirewallRestoreIPv6)
				}
			}
			if strings.Contains(preview.FirewallRestoreIPv6, LabBridgeName) {
				t.Fatalf("Wi-Fi-only lab rendered a bridge rule:\n%s", preview.FirewallRestoreIPv6)
			}
		})
	}
}

func TestIPv6RoutesOverTheBridgedWiredAndWiFiLab(t *testing.T) {
	plan := withULA(validBridgedWiFiPlan())
	preview := BuildPreview(plan, time.Unix(100, 0))
	if !preview.Validation.Valid {
		t.Fatalf("bridged IPv6 plan rejected: %+v", preview.Validation.Errors)
	}
	assertGolden(t, "wifi-bridge-ula-netplan.yaml", preview.NetplanYAML)
	assertGolden(t, "wifi-bridge-ula-ip6tables.rules", preview.FirewallRestoreIPv6)
	if labIPv6, ok := LabIPv6Routing(plan); !ok || labIPv6.Interface != LabBridgeName {
		t.Fatalf("lab IPv6 must use the bridge: %+v", labIPv6)
	}
	if !strings.Contains(preview.RadvdConf, "interface lgbr0\n") || strings.Contains(preview.RadvdConf, "enp2s0") || strings.Contains(preview.RadvdConf, "wlan0") {
		t.Fatalf("radvd must advertise on the bridge only:\n%s", preview.RadvdConf)
	}
	if strings.Contains(preview.FirewallRestoreIPv6, "enp2s0") || strings.Contains(preview.FirewallRestoreIPv6, "wlan0") {
		t.Fatalf("bridged IPv6 firewall must match only the bridge:\n%s", preview.FirewallRestoreIPv6)
	}

	isolated := plan
	isolated.IPv4.ClientIsolation = true
	isolatedWiFi := *plan.WiFi
	isolatedWiFi.ClientIsolation = true
	isolated.WiFi = &isolatedWiFi
	rules := BuildPreview(isolated, time.Unix(100, 0)).FirewallRestoreIPv6
	if strings.Contains(rules, "-A SHAKERPROXY-FORWARD -i lgbr0 -o lgbr0 -j ACCEPT") || !strings.Contains(rules, "-A SHAKERPROXY-FORWARD -i lgbr0 -o lgbr0 -s fd12:3456:789a:1::/64 -d fd12:3456:789a:1::/64 -j DROP") {
		t.Fatalf("lab isolation was weakened by the IPv6 bridge rule:\n%s", rules)
	}
}

func TestDisabledIPv6KeepsTheBridgedLabOneSegment(t *testing.T) {
	plan := validBridgedWiFiPlan()
	rules := BuildPreview(plan, time.Unix(100, 0)).FirewallRestoreIPv6
	expected := "*filter\n:SHAKERPROXY-FORWARD - [0:0]\n-A SHAKERPROXY-FORWARD -i lgbr0 -o lgbr0 -j ACCEPT\n-A SHAKERPROXY-FORWARD -i lgbr0 -j DROP\n-A SHAKERPROXY-FORWARD -o lgbr0 -j DROP\nCOMMIT\n"
	if rules != expected {
		t.Fatalf("unexpected bridged DISABLED IPv6 firewall:\n%s", rules)
	}
	wifiOnly := BuildPreview(validWiFiPlan(), time.Unix(100, 0)).FirewallRestoreIPv6
	if wifiOnly != "*filter\n:SHAKERPROXY-FORWARD - [0:0]\n-A SHAKERPROXY-FORWARD -i wlan0 -j DROP\n-A SHAKERPROXY-FORWARD -o wlan0 -j DROP\nCOMMIT\n" {
		t.Fatalf("unexpected Wi-Fi-only DISABLED IPv6 firewall:\n%s", wifiOnly)
	}
}

func TestBridgeIPv6GatewayAddressIsNotAHostConflict(t *testing.T) {
	plan := withULA(validBridgedWiFiPlan())
	result := ValidateWithObserved(plan, []ObservedInterface{
		{CurrentName: "enp1s0", StableID: "pci-0000:01:00.0", DefaultIPv6: true},
		{CurrentName: "enp2s0", StableID: "pci-0000:02:00.0"},
		{CurrentName: "wlan0", StableID: plan.Interfaces[2].StableID},
		{CurrentName: LabBridgeName, StableID: "path:virtual:lgbr0|mac:02:00:00:00:00:09", Addresses: []string{"10.77.0.1/24", "fd12:3456:789a:1::1/64"}},
	})
	if !result.Valid {
		t.Fatalf("existing ShakerProxy bridge IPv6 address was treated as a conflict: %+v", result.Errors)
	}
}
