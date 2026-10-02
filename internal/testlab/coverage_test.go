package testlab

import (
	"net/netip"
	"testing"

	"shakerproxy.dev/shakerproxy/internal/coverage"
)

// The coverage evaluator matches evidence by the test lab's addresses, so
// both packages must agree on them.
func TestCoverageUsesTheTestLabAddresses(t *testing.T) {
	for _, pair := range [][2]string{
		{coverage.ClientCIDR, DefaultClientCIDR},
		{coverage.GatewayIPv4, DefaultGatewayIPv4},
		{coverage.NormalClient, DefaultNormalClient},
		{coverage.DNSClient, DefaultDNSClient},
		{coverage.ClientIPv6CIDR, DefaultClientIPv6CIDR},
		{coverage.GatewayIPv6, DefaultGatewayIPv6},
		{coverage.NormalClientIPv6, DefaultNormalClientIPv6},
	} {
		if pair[0] != pair[1] {
			t.Fatalf("coverage uses %s, the test lab %s", pair[0], pair[1])
		}
	}
	prefix := netip.MustParsePrefix(DefaultClientIPv6CIDR)
	for _, value := range []string{DefaultGatewayIPv6, DefaultNormalClientIPv6, DefaultBypassClientIPv6, DefaultDNSClientIPv6} {
		address := netip.MustParseAddr(value)
		if !prefix.Contains(address) || !address.IsPrivate() {
			t.Fatalf("%s is not a unique-local address on the client bridge", value)
		}
	}
	target := netip.MustParseAddr(coverage.TargetIPv6)
	if prefix.Contains(target) || !target.IsPrivate() {
		t.Fatalf("the IPv6 target %s must be routed, on its own unique-local subnet", target)
	}
}
