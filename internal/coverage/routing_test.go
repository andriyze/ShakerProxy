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
	got := findingsByID(InspectRouting(RoutingInput{Routing: true, Topology: "SINGLE_ARM", IPv6Strategy: "DISABLED", GatewayIPv4: "192.168.10.177", LabInterface: "ens18", PolicyAvailable: true}))
	for id, status := range map[string]FindingStatus{
		FindingIPv6: FindingOK, FindingDHCP: FindingGap, FindingPeerToPeer: FindingGap,
		FindingEncryptedDNS: FindingGap, FindingPlainDNS: FindingGap, FindingLocalDiscovery: FindingGap,
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
	advertised := findingsByID(InspectRouting(RoutingInput{Routing: true, Topology: "TWO_NIC", IPv6Strategy: "ULA_NAT66_LAB", ForeignRouterAdverts: []string{"fe80::1", "fe80::1"}}))
	if advertised[FindingIPv6].Status != FindingGap || !strings.Contains(advertised[FindingIPv6].Detail, "(fe80::1)") {
		t.Fatalf("a foreign router advertisement is a gap even when ShakerProxy routes IPv6: %+v", advertised[FindingIPv6])
	}
	routed := findingsByID(InspectRouting(RoutingInput{Routing: true, Topology: "TWO_NIC", IPv6Strategy: "ULA_NAT66_LAB"}))
	if routed[FindingIPv6].Status != FindingOK {
		t.Fatalf("routed IPv6 = %+v", routed[FindingIPv6])
	}
}

func TestAWiFiLabWithEncryptedDNSBlockedHasNoGaps(t *testing.T) {
	list := InspectRouting(RoutingInput{Routing: true, Topology: "TWO_NIC", IPv6Strategy: "DISABLED", WirelessAccessPoint: true,
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
