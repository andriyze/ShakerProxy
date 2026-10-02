package networkplan

import (
	"errors"
	"fmt"
	"net/netip"

	"shakerproxy.dev/shakerproxy/internal/firewall"
)

// IPv6 lab routing.
//
// ULA_NAT66_LAB and NATIVE_ROUTED_PREFIX give the lab a /64 announced by
// radvd (SLAAC + RDNSS). ULA prefixes are translated to the WAN address with
// NAT66; native prefixes are routed unchanged and must be routed to ShakerProxy by
// the upstream network. DISABLED actively drops forwarded lab IPv6 so devices
// cannot bypass ShakerProxy. OBSERVE_ONLY keeps the lab interface free of IPv6
// addressing without adding firewall state. PREFIX_DELEGATION is not
// implemented.

const (
	IPv6LabPrefixBits      = 64
	MaxIPv6DNSAddresses    = 3
	IPv6ForwardParentUser  = "DOCKER-USER"
	IPv6ForwardParentChain = "FORWARD"
)

var (
	ulaLabRange         = netip.MustParsePrefix("fd00::/8")
	globalUnicastRange  = netip.MustParsePrefix("2000::/3")
	nonRoutableGlobalV6 = []netip.Prefix{
		netip.MustParsePrefix("2001::/23"),     // IETF protocol assignments (Teredo, ORCHID, benchmarking)
		netip.MustParsePrefix("2001:db8::/32"), // documentation
		netip.MustParsePrefix("2002::/16"),     // deprecated 6to4
		netip.MustParsePrefix("3fff::/20"),     // documentation (RFC 9637)
	}
)

// LabIPv6 is the effective IPv6 addressing of a plan that routes lab IPv6.
// Other components (traffic policy, inventory, capture) should use
// LabIPv6Routing rather than reading the raw plan fields, because it applies
// the documented defaults.
type LabIPv6 struct {
	Strategy  IPv6Strategy
	Interface string
	VLANID    *int
	Prefix    netip.Prefix
	Gateway   netip.Addr
	DNS       []netip.Addr
	NAT66     bool
}

// RoutesIPv6 reports whether the plan asks ShakerProxy to route lab IPv6.
func RoutesIPv6(plan Plan) bool {
	return (plan.IPv6.Strategy == IPv6ULANAT66Lab || plan.IPv6.Strategy == IPv6NativeRouted) && ipv6CapableTopology(plan.Topology)
}

// BlocksLabIPv6 reports whether the plan asks ShakerProxy to drop forwarded lab
// IPv6 (the DISABLED strategy on a topology with a dedicated lab segment).
func BlocksLabIPv6(plan Plan) bool {
	return plan.IPv6.Strategy == IPv6Disabled && ipv6CapableTopology(plan.Topology)
}

func ipv6CapableTopology(topology Topology) bool {
	return topology != TopologyPassiveSensor && topology != TopologySingleArm && topology != TopologyTransparentBridge
}

// LabIPv6Routing returns the effective lab IPv6 addressing (with defaults
// applied) for a plan that routes IPv6. It returns false for any other plan or
// for fields that do not parse; callers must only rely on it for valid plans.
func LabIPv6Routing(plan Plan) (LabIPv6, bool) {
	if !RoutesIPv6(plan) {
		return LabIPv6{}, false
	}
	lab, ok := LabInterface(plan)
	if !ok {
		return LabIPv6{}, false
	}
	prefix, err := netip.ParsePrefix(plan.IPv6.LabPrefix)
	if err != nil || !prefix.Addr().Is6() || prefix.Addr().Is4In6() || prefix.Bits() != IPv6LabPrefixBits || prefix.Addr().Zone() != "" {
		return LabIPv6{}, false
	}
	prefix = prefix.Masked()
	gateway := defaultIPv6Gateway(prefix)
	if plan.IPv6.GatewayAddress != "" {
		gateway, err = netip.ParseAddr(plan.IPv6.GatewayAddress)
		if err != nil || !validIPv6LabGateway(prefix, gateway) {
			return LabIPv6{}, false
		}
	}
	dns := []netip.Addr{gateway}
	if len(plan.IPv6.DNSAddresses) != 0 {
		dns = make([]netip.Addr, 0, len(plan.IPv6.DNSAddresses))
		for _, raw := range plan.IPv6.DNSAddresses {
			address, parseErr := netip.ParseAddr(raw)
			if parseErr != nil || !validIPv6DNSAddress(address) {
				return LabIPv6{}, false
			}
			dns = append(dns, address)
		}
	}
	return LabIPv6{
		Strategy:  plan.IPv6.Strategy,
		Interface: lab.CurrentName,
		VLANID:    cloneIntPointer(lab.VLANID),
		Prefix:    prefix,
		Gateway:   gateway,
		DNS:       dns,
		NAT66:     plan.IPv6.Strategy == IPv6ULANAT66Lab,
	}, true
}

// IPv6ForwardParent returns the chain that the ShakerProxy IPv6 forward chain is
// attached to: Docker's DOCKER-USER hook when Docker manages ip6tables,
// otherwise the built-in FORWARD chain. The IPv6 traffic-policy chain must use
// the same parent so its rules stay in front of ShakerProxy's accept rules.
func IPv6ForwardParent(inspection firewall.Inspection) string {
	if inspection.IPv6DockerUserChain {
		return IPv6ForwardParentUser
	}
	return IPv6ForwardParentChain
}

// CheckIPv6Artifacts verifies that the rendered IPv6 artifacts in a preview
// agree with the plan and the bound host inspection. The apply pipeline calls
// it at every stage so a preview can never silently skip the IPv6 firewall.
func CheckIPv6Artifacts(plan Plan, preview Preview) error {
	env := preview.FirewallEnvironment
	switch {
	case RoutesIPv6(plan):
		if preview.FirewallRestoreIPv6 == "" || preview.RadvdConf == "" {
			return errors.New("IPv6 lab routing preview is missing its firewall or router advertisement configuration")
		}
		if !env.IPv6Available {
			return errors.New("IPv6 is turned off in this host's kernel; ShakerProxy cannot route lab IPv6")
		}
		if !env.IPv6FirewallReady || firewall.Ip6tablesPathFor(env.IptablesPath) != env.Ip6tablesPath {
			return errors.New("the IPv6 firewall (ip6tables) is not ready on this host")
		}
	case InlineBridge(plan) && env.IPv6Available:
		// The bridge's IPv6 forward chain only lets bridged frames pass.
		if preview.FirewallRestoreIPv6 == "" || preview.RadvdConf != "" {
			return errors.New("inline bridge preview must contain only the bridged IPv6 forward rule")
		}
		if !env.IPv6FirewallReady || firewall.Ip6tablesPathFor(env.IptablesPath) != env.Ip6tablesPath {
			return errors.New("the IPv6 firewall (ip6tables) is not ready on this host")
		}
	case BlocksLabIPv6(plan) && env.IPv6Available:
		if preview.FirewallRestoreIPv6 == "" || preview.RadvdConf != "" {
			return errors.New("disabled-IPv6 preview must contain only the IPv6 lab drop rules")
		}
		if !env.IPv6FirewallReady || firewall.Ip6tablesPathFor(env.IptablesPath) != env.Ip6tablesPath {
			return errors.New("the IPv6 firewall (ip6tables) is not ready on this host")
		}
	default:
		if preview.FirewallRestoreIPv6 != "" || preview.RadvdConf != "" {
			return errors.New("preview contains IPv6 artifacts that this plan does not use")
		}
	}
	return nil
}

func defaultIPv6Gateway(prefix netip.Prefix) netip.Addr {
	bytes := prefix.Masked().Addr().As16()
	bytes[15] = 1
	return netip.AddrFrom16(bytes)
}

func validIPv6LabGateway(prefix netip.Prefix, gateway netip.Addr) bool {
	if !gateway.Is6() || gateway.Is4In6() || gateway.Zone() != "" || !prefix.Contains(gateway) {
		return false
	}
	// The all-zero interface identifier is the subnet-router anycast address.
	return gateway != prefix.Masked().Addr()
}

func validIPv6DNSAddress(address netip.Addr) bool {
	return address.Is6() && !address.Is4In6() && address.Zone() == "" && !address.IsUnspecified() && !address.IsLoopback() && !address.IsMulticast() && !address.IsLinkLocalUnicast()
}

func nativeGlobalPrefix(prefix netip.Prefix) bool {
	if !globalUnicastRange.Contains(prefix.Addr()) {
		return false
	}
	for _, reserved := range nonRoutableGlobalV6 {
		if prefixesOverlap(reserved, prefix) {
			return false
		}
	}
	return true
}

func validateIPv6(plan Plan, addError, addWarning func(string, string, string)) {
	strategy := plan.IPv6.Strategy
	config := plan.IPv6
	hasFields := config.LabPrefix != "" || config.GatewayAddress != "" || len(config.DNSAddresses) != 0
	switch strategy {
	case IPv6PrefixDelegation:
		addError("IPV6_PREFIX_DELEGATION_UNAVAILABLE", "ipv6.strategy", "Prefix delegation (DHCPv6-PD) is not supported yet. Choose ULA_NAT66_LAB for a private lab prefix, NATIVE_ROUTED_PREFIX if your network routes a /64 to ShakerProxy, or DISABLED.")
		return
	case IPv6Disabled, IPv6ObserveOnly:
		if hasFields {
			addError("IPV6_FIELDS_UNUSED", "ipv6", "The IPv6 lab prefix, gateway and DNS servers are only used by ULA_NAT66_LAB and NATIVE_ROUTED_PREFIX. Remove them or choose one of those strategies.")
		}
		return
	case IPv6ULANAT66Lab, IPv6NativeRouted:
	default:
		return
	}
	switch plan.Topology {
	case TopologyPassiveSensor:
		addError("IPV6_ROUTING_PASSIVE", "ipv6.strategy", "A passive sensor never routes traffic. Choose DISABLED or OBSERVE_ONLY.")
		return
	case TopologySingleArm:
		addError("IPV6_ROUTING_NEEDS_LAB_INTERFACE", "ipv6.strategy", "IPv6 routing needs a separate lab interface: on a single-arm gateway ShakerProxy's router advertisements would reach every host on the upstream network. Choose DISABLED or OBSERVE_ONLY, or use a two-NIC topology.")
		return
	}
	if effectiveWANIPv6Mode(plan.WAN.IPv6Mode) == WANIPv6None {
		addError("IPV6_WAN_REQUIRED", "wan.ipv6_mode", "Lab IPv6 needs IPv6 on the WAN. Set wan.ipv6_mode to KEEP_EXISTING, SLAAC, DHCPV6 or STATIC.")
	}
	example := "fd12:3456:789a:1::/64"
	if strategy == IPv6NativeRouted {
		example = "a /64 from your organisation's IPv6 allocation"
	}
	if config.LabPrefix == "" {
		addError("IPV6_LAB_PREFIX_REQUIRED", "ipv6.lab_prefix", "Enter the /64 lab prefix, for example "+example+".")
		return
	}
	prefix, err := netip.ParsePrefix(config.LabPrefix)
	if err != nil || !prefix.Addr().Is6() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
		addError("IPV6_LAB_PREFIX_INVALID", "ipv6.lab_prefix", "The lab prefix must be an IPv6 prefix such as fd12:3456:789a:1::/64.")
		return
	}
	if prefix.Bits() != IPv6LabPrefixBits {
		addError("IPV6_LAB_PREFIX_SIZE_INVALID", "ipv6.lab_prefix", "The lab prefix must be exactly /64 so phones, TVs and IoT devices can configure themselves (SLAAC). Use a /64 such as "+example+".")
		return
	}
	prefix = prefix.Masked()
	switch strategy {
	case IPv6ULANAT66Lab:
		if !ulaLabRange.Contains(prefix.Addr()) {
			addError("IPV6_ULA_PREFIX_INVALID", "ipv6.lab_prefix", "A ULA lab prefix must start with fd (inside fd00::/8). Generate a random one as described in docs/ipv6.md, for example fd12:3456:789a:1::/64.")
		}
		addWarning("NAT66_LAB_COMPROMISE", "ipv6.strategy", "NAT66 hides every lab device behind ShakerProxy's WAN address. This is fine for testing, but it is not how production IPv6 networks work.")
		addWarning("IPV6_ULA_PREFERS_IPV4", "ipv6.strategy", "Devices that only have a ULA address usually prefer IPv4 for Internet destinations, so you may see less IPv6 traffic than on a real network. Use NATIVE_ROUTED_PREFIX to test production IPv6 behaviour.")
	case IPv6NativeRouted:
		if !nativeGlobalPrefix(prefix) {
			addError("IPV6_NATIVE_PREFIX_INVALID", "ipv6.lab_prefix", "NATIVE_ROUTED_PREFIX needs a public (global unicast) /64 that your upstream router sends to ShakerProxy. For a private lab prefix choose ULA_NAT66_LAB instead.")
		} else {
			addWarning("IPV6_NATIVE_UPSTREAM_ROUTE", "ipv6.lab_prefix", fmt.Sprintf("Your upstream router must route %s to ShakerProxy's WAN address; ShakerProxy does not announce or request it.", prefix))
		}
		if effectiveWANIPv6Mode(plan.WAN.IPv6Mode) == WANIPv6Static {
			if wanPrefix, wanErr := netip.ParsePrefix(plan.WAN.IPv6Address); wanErr == nil && wanPrefix.Addr().Is6() && prefixesOverlap(wanPrefix.Masked(), prefix) {
				addError("IPV6_LAB_PREFIX_OVERLAPS_WAN", "ipv6.lab_prefix", "The lab prefix overlaps the WAN's IPv6 network (wan.ipv6_address). Ask your network team for a separate /64 routed to ShakerProxy.")
			}
		}
	}
	gateway := defaultIPv6Gateway(prefix)
	if config.GatewayAddress != "" {
		parsed, parseErr := netip.ParseAddr(config.GatewayAddress)
		if parseErr != nil || !validIPv6LabGateway(prefix, parsed) {
			addError("IPV6_GATEWAY_INVALID", "ipv6.gateway_address", fmt.Sprintf("The IPv6 gateway must be an address inside the lab prefix other than its first address, for example %s.", gateway))
		}
	}
	if len(config.DNSAddresses) > MaxIPv6DNSAddresses {
		addError("IPV6_DNS_TOO_MANY", "ipv6.dns_addresses", "Advertise at most three IPv6 DNS servers.")
	}
	seen := map[netip.Addr]bool{}
	for index, raw := range config.DNSAddresses {
		path := fmt.Sprintf("ipv6.dns_addresses[%d]", index)
		address, parseErr := netip.ParseAddr(raw)
		if parseErr != nil || !validIPv6DNSAddress(address) {
			addError("IPV6_DNS_ADDRESS_INVALID", path, fmt.Sprintf("Each IPv6 DNS server must be a unicast IPv6 address, for example the lab gateway %s.", gateway))
			continue
		}
		if seen[address] {
			addError("IPV6_DNS_ADDRESS_DUPLICATE", path, "List each IPv6 DNS server only once.")
		}
		seen[address] = true
	}
	addWarning("IPV6_ROUTER_MODE", "ipv6.strategy", "Turning on IPv6 forwarding makes this host an IPv6 router. ShakerProxy keeps SLAAC working on the WAN, but a management interface that gets its IPv6 address from router advertisements may lose it; give it a static IPv6 address or manage ShakerProxy over IPv4.")
}

// validateIPv6Observed rejects a lab prefix that overlaps an address already
// configured on the host (for example the WAN's own /64) and warns when the
// WAN has no IPv6 default route to carry lab traffic.
func validateIPv6Observed(plan Plan, observed []ObservedInterface, result *ValidationResult) {
	labIPv6, ok := LabIPv6Routing(plan)
	if !ok {
		return
	}
	for _, iface := range observed {
		for _, rawAddress := range iface.Addresses {
			current, err := netip.ParsePrefix(rawAddress)
			if err != nil || !current.Addr().Is6() || current.Addr().IsLinkLocalUnicast() || !prefixesOverlap(labIPv6.Prefix, current.Masked()) {
				continue
			}
			if iface.CurrentName == labIPv6.Interface && current.Addr().WithZone("") == labIPv6.Gateway {
				continue
			}
			result.Errors = append(result.Errors, Issue{Code: "IPV6_LAB_PREFIX_HOST_CONFLICT", Path: "ipv6.lab_prefix", Message: fmt.Sprintf("The lab prefix overlaps address %s on %s. Choose a different /64 for the lab.", rawAddress, iface.CurrentName)})
		}
	}
	wan, hasWAN := WANInterface(plan)
	if !hasWAN || wanConfigurationChangesHost(plan.WAN, wan) {
		return
	}
	for _, iface := range observed {
		if iface.CurrentName == wan.CurrentName && !iface.DefaultIPv6 {
			result.Warnings = append(result.Warnings, Issue{Code: "IPV6_WAN_NO_DEFAULT_ROUTE", Path: "wan.ipv6_mode", Message: fmt.Sprintf("The WAN (%s) has no IPv6 default route right now, so lab devices will not reach the Internet over IPv6 until it gets one.", wan.CurrentName)})
		}
	}
	sortIssues(result.Warnings)
}

func cloneIntPointer(value *int) *int {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
