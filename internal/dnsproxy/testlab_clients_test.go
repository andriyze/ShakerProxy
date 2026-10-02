package dnsproxy

import (
	"net/netip"
	"testing"

	"shakerproxy.dev/shakerproxy/internal/testlab"
)

// The visibility coverage check's virtual clients must reach the forwarder;
// the rest of the benchmarking range stays an open-resolver refusal.
func TestTheVirtualTestLabClientsMayUseTheForwarder(t *testing.T) {
	if testLabClients != netip.MustParsePrefix(testlab.DefaultClientCIDR) {
		t.Fatalf("dnsd allows %s, the test lab uses %s", testLabClients, testlab.DefaultClientCIDR)
	}
	var runtime *Runtime
	if !runtime.AllowedClient(netip.MustParseAddr(testlab.DefaultNormalClient)) {
		t.Fatal("a virtual test-lab client was refused")
	}
	// The IPv6 probes come from a unique-local address, a private client.
	if !runtime.AllowedClient(netip.MustParseAddr(testlab.DefaultNormalClientIPv6)) {
		t.Fatal("a virtual test-lab client's IPv6 lookup was refused")
	}
	if runtime.AllowedClient(netip.MustParseAddr("198.18.241.254")) || runtime.AllowedClient(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("addresses outside the lab and the test-lab clients must be refused")
	}
}
