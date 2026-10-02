package coverage

import (
	"strings"
	"testing"
)

// On an inline bridge the router's DHCP and IPv6 advertisements cross
// ShakerProxy, so they are not bypasses even when seen in the recording.
func TestInlineBridgeHasNoRoutingBypass(t *testing.T) {
	findings := InspectRouting(RoutingInput{
		Routing: true, Topology: "TRANSPARENT_BRIDGE", IPv6Strategy: "OBSERVE_ONLY", GatewayIPv4: "192.0.2.20", LabInterface: "spbr0",
		ForeignRouterAdverts: []string{"fe80::1"}, ForeignDHCPServers: []string{"192.0.2.1"}, RouterAdvertsSearched: true,
		PolicyAvailable: true, BlockDoT: true, BlockDoQ: true, BlockKnownDoH: true, RedirectPlainDNS: true,
	})
	seen := map[string]bool{}
	for _, finding := range findings {
		seen[finding.ID] = true
		if finding.Status != FindingOK {
			t.Fatalf("inline bridge finding %s is %s: %s", finding.ID, finding.Status, finding.Detail)
		}
	}
	for _, id := range []string{FindingIPv6, FindingDHCP, FindingPeerToPeer, FindingLocalDiscovery, FindingEncryptedDNS, FindingPlainDNS} {
		if !seen[id] {
			t.Fatalf("finding %s missing from %+v", id, findings)
		}
	}
}

// With ShakerProxy's Wi-Fi access point in the bridge, Wi-Fi devices cross
// ShakerProxy too: their DHCP comes from the router through the bridge and
// their device-to-device traffic is recorded.
func TestInlineBridgeWithAccessPointHasNoWiFiBypass(t *testing.T) {
	findings := InspectRouting(RoutingInput{
		Routing: true, Topology: "TRANSPARENT_BRIDGE", IPv6Strategy: "OBSERVE_ONLY", GatewayIPv4: "192.0.2.20", LabInterface: "spbr0", WirelessAccessPoint: true,
		PolicyAvailable: true, BlockDoT: true, BlockDoQ: true, BlockKnownDoH: true, RedirectPlainDNS: true,
	})
	byID := map[string]Finding{}
	for _, finding := range findings {
		byID[finding.ID] = finding
		if finding.Status != FindingOK {
			t.Fatalf("finding %s is %s: %s", finding.ID, finding.Status, finding.Detail)
		}
	}
	if peer := byID[FindingPeerToPeer]; !containsText(peer.Detail, "Wi-Fi devices on ShakerProxy's access point reach the wired device") || !containsText(peer.Detail, "forwarded inside the access point") || !containsText(peer.Fix, "one on Wi-Fi and the other on the device port") {
		t.Fatalf("device-to-device finding = %+v", peer)
	}
	if dhcp := byID[FindingDHCP]; !containsText(dhcp.Detail, "Wi-Fi devices on ShakerProxy's access point") {
		t.Fatalf("DHCP finding = %+v", dhcp)
	}
}

func containsText(value, fragment string) bool {
	return strings.Contains(value, fragment)
}
