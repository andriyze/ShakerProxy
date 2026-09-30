package firewall

import (
	"context"
	"strings"
)

// IPv6 firewall chains owned by ShakerProxy. They live in ip6tables, which has
// tables separate from iptables, so they reuse the IPv4 chain names.
var shakerProxyIPv6Chains = []string{"SHAKERPROXY-FORWARD", "SHAKERPROXY-INPUT"}

const shakerProxyIPv6NATChain = "SHAKERPROXY-POSTROUTING"

// Ip6tablesPathFor returns the ip6tables executable that sits next to an
// approved iptables executable, or "" when the iptables path is not approved.
func Ip6tablesPathFor(iptablesPath string) string {
	switch iptablesPath {
	case "/usr/sbin/iptables":
		return "/usr/sbin/ip6tables"
	case "/usr/bin/iptables":
		return "/usr/bin/ip6tables"
	default:
		return ""
	}
}

// inspectIPv6 records whether the kernel has IPv6, whether ip6tables can be
// read, whether Docker created its IPv6 DOCKER-USER hook, and whether stale
// ShakerProxy IPv6 chains exist. A missing kernel IPv6 stack or an unreadable
// ip6tables ruleset only blocks plans that need the IPv6 firewall; stale
// ShakerProxy chains block every apply, exactly like the IPv4 chains.
func (i Inspector) inspectIPv6(ctx context.Context, iptablesPath string, result *Inspection, add func(string, string, bool)) {
	if _, err := i.ReadFile("/proc/sys/net/ipv6/conf/all/forwarding"); err != nil {
		add("IPV6_KERNEL_DISABLED", "IPv6 is turned off in this host's kernel; ShakerProxy cannot route or filter lab IPv6", false)
		return
	}
	result.IPv6Available = true
	path := Ip6tablesPathFor(iptablesPath)
	if path == "" {
		add("IP6TABLES_UNAVAILABLE", "ip6tables could not be located next to the approved iptables executable", false)
		return
	}
	filterRules, filterErr := i.Runner.Run(ctx, path, "-w", "2", "-S")
	natRules, natErr := i.Runner.Run(ctx, path, "-w", "2", "-t", "nat", "-S")
	if filterErr != nil || natErr != nil {
		add("IP6TABLES_RULESET_UNREADABLE", "the IPv6 filter and NAT rulesets could not be inspected; IPv6 lab plans cannot be applied", false)
		return
	}
	result.Ip6tablesPath = path
	result.IPv6DockerUserChain = ruleDeclaresChain(filterRules, "DOCKER-USER")
	for _, chain := range shakerProxyIPv6Chains {
		if ruleDeclaresChain(filterRules, chain) {
			result.ShakerProxyIPv6Chains = true
		}
	}
	if ruleDeclaresChain(natRules, shakerProxyIPv6NATChain) {
		result.ShakerProxyIPv6Chains = true
	}
	if result.ShakerProxyIPv6Chains {
		add("SHAKERPROXY_IPV6_CHAIN_CONFLICT", "reserved ShakerProxy IPv6 firewall chains already exist", true)
		return
	}
	result.IPv6FirewallReady = true
}

func allowedIPv6InspectionCommand(args []string) bool {
	joined := strings.Join(args, "\x00")
	return joined == "-w\x002\x00-S" || joined == "-w\x002\x00-t\x00nat\x00-S"
}
