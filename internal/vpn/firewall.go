package vpn

import (
	"errors"
	"fmt"
	"strings"
)

// The VPN owns three chains per address family. gatewayd hooks them in
// below the traffic policy's security chains, so per-device blocks and
// encrypted-DNS rules apply to VPN devices exactly as to lab devices.
const (
	ForwardChain     = "SHAKERPROXY-VPN-FORWARD"
	InputChain       = "SHAKERPROXY-VPN-INPUT"
	PostroutingChain = "SHAKERPROXY-VPN-POSTROUTING"
)

// FirewallRules is one address family's iptables-restore input: Filter for
// the filter table, NAT for the nat table. Both flush and refill only the
// VPN chains (load them with --noflush).
type FirewallRules struct {
	Filter string `json:"filter"`
	NAT    string `json:"nat"`
}

// RenderFirewall renders the VPN's rules for one family:
//
//   - The WireGuard port is accepted even on hosts whose firewall drops
//     everything else (ufw), so turning the VPN on is enough.
//   - VPN devices reach the internet and the networks behind ShakerProxy,
//     NATed to ShakerProxy's address on the way out.
//   - They do not reach ShakerProxy itself: not the management UI, SSH or
//     any other host or container service. The DNS and HTTPS the traffic
//     policy redirects to ShakerProxy's own listeners are the exception;
//     the security chains decide those.
//   - They do not reach each other unless AllowPeerToPeer is on, and
//     nothing outside opens connections to them.
func RenderFirewall(state State, ipv6 bool) (FirewallRules, error) {
	settings, err := state.Settings.Normalize()
	if err != nil {
		return FirewallRules{}, err
	}
	prefix, echo := state.IPv4Prefix(), "-p icmp --icmp-type echo-request"
	if ipv6 {
		prefix, echo = state.IPv6PrefixValue(), "-p ipv6-icmp --icmpv6-type echo-request"
	}
	if !prefix.IsValid() {
		return FirewallRules{}, errors.New("the VPN network is not configured")
	}
	source := prefix.Masked().String()
	iface := InterfaceName

	var filter strings.Builder
	filter.WriteString(chainHeader("filter", ForwardChain, InputChain))
	rule := func(format string, arguments ...any) {
		filter.WriteString(fmt.Sprintf(format, arguments...))
		filter.WriteByte('\n')
	}
	rule("-A %s -p udp --dport %d -j ACCEPT", InputChain, settings.ListenPort)
	rule("-A %s -i %s -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", InputChain, iface)
	rule("-A %s -i %s -m conntrack --ctstate DNAT -j RETURN", InputChain, iface)
	rule("-A %s -i %s %s -j ACCEPT", InputChain, iface, echo)
	rule("-A %s -i %s -j DROP", InputChain, iface)
	rule("-A %s -j RETURN", InputChain)

	rule("-A %s -i %s ! -s %s -j DROP", ForwardChain, iface, source)
	// Docker publishes the management UI and other services with DNAT;
	// a VPN device must not reach them through any of ShakerProxy's
	// addresses, nor the container networks directly.
	rule("-A %s -i %s -m conntrack --ctstate DNAT -j DROP", ForwardChain, iface)
	rule("-A %s -i %s -o docker0 -j DROP", ForwardChain, iface)
	rule("-A %s -i %s -o br-+ -j DROP", ForwardChain, iface)
	if settings.AllowPeerToPeer {
		rule("-A %s -i %s -o %s -j ACCEPT", ForwardChain, iface, iface)
	} else {
		rule("-A %s -i %s -o %s -j DROP", ForwardChain, iface, iface)
	}
	rule("-A %s -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu", ForwardChain, iface)
	rule("-A %s -i %s -j ACCEPT", ForwardChain, iface)
	rule("-A %s -o %s -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", ForwardChain, iface)
	rule("-A %s -o %s -j DROP", ForwardChain, iface)
	rule("-A %s -j RETURN", ForwardChain)
	filter.WriteString("COMMIT\n")

	var nat strings.Builder
	nat.WriteString(chainHeader("nat", PostroutingChain))
	fmt.Fprintf(&nat, "-A %s -s %s ! -o %s -j MASQUERADE\n", PostroutingChain, source, iface)
	fmt.Fprintf(&nat, "-A %s -j RETURN\nCOMMIT\n", PostroutingChain)
	return FirewallRules{Filter: filter.String(), NAT: nat.String()}, nil
}

// EmptyFirewall flushes the VPN chains to a bare RETURN, which is what
// remains while VPN mode is off (the hooks are detached as well).
func EmptyFirewall() FirewallRules {
	filter := chainHeader("filter", ForwardChain, InputChain) + fmt.Sprintf("-A %s -j RETURN\n-A %s -j RETURN\nCOMMIT\n", ForwardChain, InputChain)
	nat := chainHeader("nat", PostroutingChain) + fmt.Sprintf("-A %s -j RETURN\nCOMMIT\n", PostroutingChain)
	return FirewallRules{Filter: filter, NAT: nat}
}

func chainHeader(table string, chains ...string) string {
	var b strings.Builder
	b.WriteString("*" + table + "\n")
	for _, chain := range chains {
		fmt.Fprintf(&b, ":%s - [0:0]\n-F %s\n", chain, chain)
	}
	return b.String()
}
