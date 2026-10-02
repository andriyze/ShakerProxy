package coverage

import "testing"

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
