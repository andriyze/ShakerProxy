package coverage

import (
	"strings"
	"testing"
)

func findingsByID(list []Finding) map[string]Finding {
	out := map[string]Finding{}
	for _, finding := range list {
		out[finding.ID] = finding
	}
	return out
}

// The test VM: a single-arm lab on a home network without IPv6, encrypted
// DNS allowed.
func TestRoutingFindingsForASingleArmLab(t *testing.T) {
	got := findingsByID(InspectRouting(RoutingInput{Routing: true, Topology: "SINGLE_ARM", IPv6Strategy: "DISABLED", GatewayIPv4: "192.168.10.177", LabInterface: "ens18", PolicyAvailable: true, RouterAdvertsSearched: true}))
	for id, status := range map[string]FindingStatus{
		FindingIPv6: FindingOK, FindingDHCP: FindingGap, FindingPeerToPeer: FindingGap,
		FindingEncryptedDNS: FindingGap, FindingPlainDNS: FindingGap, FindingLocalDiscovery: FindingOK,
	} {
		if got[id].Status != status {
			t.Fatalf("%s = %s (%s), want %s", id, got[id].Status, got[id].Detail, status)
		}
		if got[id].Status == FindingGap && got[id].Fix == "" {
			t.Fatalf("gap %s has no fix", id)
		}
	}
	if !strings.Contains(got[FindingDHCP].Detail, "192.168.10.177") {
		t.Fatalf("DHCP finding should name the gateway: %s", got[FindingDHCP].Detail)
	}
	if !strings.Contains(got[FindingEncryptedDNS].Detail, "DNS over TLS, DNS over QUIC and DNS over HTTPS is allowed") {
		t.Fatalf("encrypted DNS detail = %s", got[FindingEncryptedDNS].Detail)
	}
}

func TestIPv6FromAnotherRouterIsAGap(t *testing.T) {
	got := findingsByID(InspectRouting(RoutingInput{Routing: true, Topology: "SINGLE_ARM", IPv6Strategy: "DISABLED", LabIPv6: true, LabInterface: "ens18"}))
	if got[FindingIPv6].Status != FindingGap || !strings.Contains(got[FindingIPv6].Detail, "ens18") {
		t.Fatalf("IPv6 = %+v", got[FindingIPv6])
	}
	advertised := findingsByID(InspectRouting(RoutingInput{Routing: true, Topology: "TWO_NIC", IPv6Strategy: "ULA_NAT66_LAB", ForeignRouterAdverts: []string{"fe80::1", "fe80::1"}, RouterAdvertsSearched: true}))
	if advertised[FindingIPv6].Status != FindingGap || !strings.Contains(advertised[FindingIPv6].Detail, "also advertises IPv6 on the lab network (fe80::1)") {
		t.Fatalf("a foreign router advertisement is a gap even when ShakerProxy routes IPv6: %+v", advertised[FindingIPv6])
	}
	routed := findingsByID(InspectRouting(RoutingInput{Routing: true, Topology: "TWO_NIC", IPv6Strategy: "ULA_NAT66_LAB", RouterAdvertsSearched: true}))
	if routed[FindingIPv6].Status != FindingOK {
		t.Fatalf("routed IPv6 = %+v", routed[FindingIPv6])
	}
}

// The home router on a single-arm lab advertises IPv6 while ShakerProxy
// routes only IPv4: every IPv6 connection bypasses it.
func TestARouterAdvertisementOnASingleArmLabIsAGap(t *testing.T) {
	got := findingsByID(InspectRouting(RoutingInput{Routing: true, Topology: "SINGLE_ARM", IPv6Strategy: "DISABLED", LabInterface: "ens18",
		ForeignRouterAdverts: []string{"fe80::be24:11ff:fe00:1"}, RouterAdvertsSearched: true}))
	finding := got[FindingIPv6]
	if finding.Status != FindingGap || !strings.Contains(finding.Detail, "(fe80::be24:11ff:fe00:1), and ShakerProxy does not route IPv6") || finding.Fix == "" {
		t.Fatalf("IPv6 = %+v", finding)
	}
}

func TestUnsearchedRecordingLeavesIPv6Unknown(t *testing.T) {
	for _, strategy := range []string{"DISABLED", "ULA_NAT66_LAB"} {
		got := findingsByID(InspectRouting(RoutingInput{Routing: true, Topology: "SINGLE_ARM", IPv6Strategy: strategy, LabInterface: "ens18"}))
		if got[FindingIPv6].Status != FindingUnknown || got[FindingIPv6].Fix == "" {
			t.Fatalf("%s: IPv6 = %+v", strategy, got[FindingIPv6])
		}
	}
	// What the host itself shows still decides without a recording.
	hostEvidence := findingsByID(InspectRouting(RoutingInput{Routing: true, Topology: "SINGLE_ARM", IPv6Strategy: "DISABLED", LabIPv6: true, LabInterface: "ens18"}))
	if hostEvidence[FindingIPv6].Status != FindingGap {
		t.Fatalf("IPv6 = %+v", hostEvidence[FindingIPv6])
	}
}

func TestAWiFiLabWithEncryptedDNSBlockedHasNoGaps(t *testing.T) {
	list := InspectRouting(RoutingInput{Routing: true, Topology: "TWO_NIC", IPv6Strategy: "DISABLED", WirelessAccessPoint: true, WirelessClients: "BRIDGED", RouterAdvertsSearched: true,
		PolicyAvailable: true, BlockDoT: true, BlockDoQ: true, BlockKnownDoH: true, RedirectPlainDNS: true})
	if gaps := CountGaps(list); gaps != 0 {
		t.Fatalf("gaps = %d: %+v", gaps, list)
	}
	other := findingsByID(InspectRouting(RoutingInput{Routing: true, Topology: "TWO_NIC", ForeignDHCPServers: []string{"10.77.0.5"}}))
	if other[FindingDHCP].Status != FindingGap || !strings.Contains(other[FindingDHCP].Detail, "10.77.0.5") {
		t.Fatalf("another DHCP server = %+v", other[FindingDHCP])
	}
}

func TestNothingRoutingIsOneGap(t *testing.T) {
	list := InspectRouting(RoutingInput{})
	if len(list) != 1 || list[0].ID != FindingNotRouting || list[0].Status != FindingGap {
		t.Fatalf("findings = %+v", list)
	}
}

// A VPN device has no other router, DHCP server or IPv6 path.
func TestVPNDevicesHaveNoBypass(t *testing.T) {
	vpnOnly := findingsByID(InspectRouting(RoutingInput{VPN: true, VPNDevices: 2, PolicyAvailable: true, RedirectPlainDNS: true}))
	if _, gap := vpnOnly[FindingNotRouting]; gap || vpnOnly[FindingVPN].Status != FindingOK || vpnOnly[FindingPlainDNS].Status != FindingOK {
		t.Fatalf("VPN-only findings = %+v", vpnOnly)
	}
	if !strings.Contains(vpnOnly[FindingVPN].Detail, "2 VPN device(s)") || !strings.Contains(vpnOnly[FindingVPN].Detail, "cannot reach each other") {
		t.Fatalf("VPN finding = %+v", vpnOnly[FindingVPN])
	}
	withLab := findingsByID(InspectRouting(RoutingInput{Routing: true, Topology: "SINGLE_ARM", VPN: true, VPNPeerToPeer: true, VPNIPv6Routed: true}))
	if withLab[FindingDHCP].Status != FindingGap || withLab[FindingVPN].Status != FindingUnknown || withLab[FindingVPN].Fix == "" || !strings.Contains(withLab[FindingVPN].Detail, "IPv6 is routed") {
		t.Fatalf("lab and VPN findings = %+v", withLab)
	}
}

// Traffic between two Wi-Fi devices is recorded only when the access point
// hands it to a bridge; Wi-Fi as the whole lab switches it inside the adapter.
func TestWiFiDeviceToDeviceFindingFollowsHowClientTrafficTravels(t *testing.T) {
	for _, test := range []struct {
		topology, clients string
		status            FindingStatus
		detail            string
	}{
		{"TWO_NIC", "BRIDGED", FindingOK, "hands their traffic to the bridge"},
		{"TWO_NIC", "ISOLATED", FindingOK, "cannot reach each other"},
		{"TWO_NIC", "INSIDE_ACCESS_POINT", FindingGap, "switched inside ShakerProxy's access point and is not recorded"},
		{"TWO_NIC", "", FindingGap, "switched inside ShakerProxy's access point and is not recorded"},
		{"TRANSPARENT_BRIDGE", "BRIDGED", FindingOK, "hands traffic between two Wi-Fi devices to the bridge"},
		{"TRANSPARENT_BRIDGE", "ISOLATED", FindingOK, "client isolation is on"},
		{"TRANSPARENT_BRIDGE", "", FindingOK, "forwarded inside the access point"},
	} {
		peer := findingsByID(InspectRouting(RoutingInput{Routing: true, Topology: test.topology, IPv6Strategy: "DISABLED", WirelessAccessPoint: true, WirelessClients: test.clients}))[FindingPeerToPeer]
		if peer.Status != test.status || !strings.Contains(peer.Detail, test.detail) {
			t.Errorf("%s %q: %+v", test.topology, test.clients, peer)
		}
		if test.status == FindingGap && peer.Fix == "" {
			t.Errorf("%s %q: a gap without a fix", test.topology, test.clients)
		}
	}
}

// The test VM after the owner joined an iPhone to the lab Wi-Fi: it took the
// router's DHCP and none of its traffic reached ShakerProxy.
func TestBypassingDevicesAreNamedWithTheFix(t *testing.T) {
	in := RoutingInput{Routing: true, Topology: "SINGLE_ARM", IPv6Strategy: "DISABLED", GatewayIPv4: "192.168.10.177", LabInterface: "ens18",
		LabPresenceChecked: true, BypassingDevices: []string{"iPhone · 192.168.10.130"}, ShakerProxyIPv4: "192.168.10.177", RouterIPv4: "192.168.10.1"}
	finding := findingsByID(InspectRouting(in))[FindingBypassing]
	if finding.Status != FindingGap || finding.Detail != "iPhone · 192.168.10.130 is on the lab network, but its traffic goes straight to the router (192.168.10.1), so ShakerProxy cannot see it." ||
		!strings.Contains(finding.Fix, "gateway and DNS to 192.168.10.177") || !strings.Contains(finding.Fix, "VPN mode") {
		t.Fatalf("finding = %+v", finding)
	}
	if InspectRouting(in)[0].ID != FindingBypassing {
		t.Fatal("bypassing devices are not the first finding")
	}
	in.BypassingDevices = nil
	if finding := findingsByID(InspectRouting(in))[FindingBypassing]; finding.Status != FindingOK {
		t.Fatalf("no bypassing devices = %+v", finding)
	}
	in.LabPresenceChecked = false
	if _, ok := findingsByID(InspectRouting(in))[FindingBypassing]; ok {
		t.Fatal("a finding was made without presence evidence")
	}
}
