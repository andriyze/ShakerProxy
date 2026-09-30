package trafficpolicy

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// DefaultOnboardingPort is the unprivileged local port of the lab-side CA
// onboarding service. Lab clients reach it as http://<lab gateway>/ through a
// DNAT rule that exists only while interception is configured.
const DefaultOnboardingPort = 8086

var (
	privateIPv4Destinations = []string{"10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16"}
	privateIPv6Destinations = []string{"fc00::/7", "fe80::/10"}
)

// RenderContext is the host-bound scope the privileged gateway derives from
// the confirmed network plan and the lab neighbor table.
type RenderContext struct {
	LabInterface string
	LabCIDR      string
	// LabGatewayIPv4 is ShakerProxy's own address on the lab segment. With an
	// interception policy it enables http://<LabGatewayIPv4>/ CA onboarding.
	LabGatewayIPv4 string
	// LabIPv6Prefix and LabGatewayIPv6 are set only when the confirmed plan
	// routes lab IPv6 (ULA_NAT66_LAB or NATIVE_ROUTED_PREFIX).
	LabIPv6Prefix  string
	LabGatewayIPv6 string
	// IPv6Listeners reports that the DNS and TLS listeners accept IPv6. IPv6
	// redirects are rendered only when true so an IPv4-only listener cannot
	// blackhole lab IPv6 traffic; IPv6 blocking rules are rendered regardless.
	IPv6Listeners bool
	// Devices maps device IDs to their current packet identity.
	Devices map[string]DeviceMatch
	// OnboardingPort defaults to DefaultOnboardingPort.
	OnboardingPort int
}

type FirewallRules struct {
	FilterRules      []string `json:"filter_rules"`
	NATRules         []string `json:"nat_rules"`
	FilterRulesIPv6  []string `json:"filter_rules_ipv6,omitempty"`
	NATRulesIPv6     []string `json:"nat_rules_ipv6,omitempty"`
	NeedsInputHook   bool     `json:"needs_input_hook"`
	NeedsNATHook     bool     `json:"needs_nat_prerouting_hook"`
	NeedsDNSService  bool     `json:"needs_dns_service"`
	NeedsMITMService bool     `json:"needs_mitm_service"`
	NeedsOnboarding  bool     `json:"needs_onboarding_service,omitempty"`
	// UnmatchedDevices lists devices whose controls cannot be enforced yet
	// because no MAC or current IP address is known for them.
	UnmatchedDevices []string `json:"unmatched_devices,omitempty"`
}

type familyRenderer struct {
	ipv6        bool
	iface       string
	source      string
	gateway     string
	unreachable string
	private     []string
	redirects   bool
	devices     map[string]DeviceMatch
}

// outbound restricts a client rule to traffic leaving the lab. When the lab
// is a bridge (wired + Wi-Fi) with br_netfilter, lab-to-lab frames traverse
// the same hooks and must not be redirected, blocked or proxied.
func (f familyRenderer) outbound() string {
	if f.source == "" {
		return ""
	}
	return " ! -d " + f.source
}

// leavingLab matches a lab client's packet bound for somewhere outside the
// lab. It goes by destination: in a single-arm lab the internet is reached
// through the lab interface itself, so "! -o <lab>" never matches there.
func (f familyRenderer) leavingLab() string {
	if f.source == "" {
		return "! -o " + f.iface
	}
	return "! -d " + f.source
}

func (f familyRenderer) scope() string {
	if f.source == "" {
		return "-i " + f.iface
	}
	return "-i " + f.iface + " -s " + f.source
}

// selectors returns one match fragment per identity: MACs when known (they
// cover both address families and survive DHCP changes), otherwise the
// device's current addresses in this family.
func (f familyRenderer) selectors(deviceID string) []string {
	match := f.devices[deviceID]
	result := []string{}
	if len(match.HardwareAddresses) != 0 {
		for _, mac := range match.HardwareAddresses {
			result = append(result, "-i "+f.iface+" -m mac --mac-source "+mac)
		}
		return result
	}
	addresses := match.IPv4
	if f.ipv6 {
		addresses = match.IPv6
	}
	for _, address := range addresses {
		result = append(result, "-i "+f.iface+" -s "+address)
	}
	return result
}

func RenderFirewall(policy Policy, context RenderContext) (FirewallRules, error) {
	normalized, err := Normalize(policy)
	if err != nil {
		return FirewallRules{}, err
	}
	onboardingPort := context.OnboardingPort
	if onboardingPort == 0 {
		onboardingPort = DefaultOnboardingPort
	}
	if !validUnprivilegedPort(onboardingPort) || onboardingPort == normalized.EncryptedDNS.LocalListenPort || onboardingPort == normalized.TLS.TransparentPort {
		return FirewallRules{}, fmt.Errorf("onboarding port must be an unprivileged port distinct from the DNS and TLS listeners")
	}
	ports := listenerPorts{dns: normalized.EncryptedDNS.LocalListenPort, tls: normalized.TLS.TransparentPort, onboarding: onboardingPort}
	rules := FirewallRules{NeedsInputHook: true}
	// A confirmed lab always gets its resolver (see renderFamily), so only a
	// policy without client rules and without a lab stays baseline-only.
	if !needsLabContext(normalized) && context.LabInterface == "" {
		rules.FilterRules = baselineInput(false, ports)
		rules.FilterRulesIPv6 = baselineInput(true, ports)
		rules.NATRules = []string{}
		return rules, nil
	}

	prefix, parseErr := netip.ParsePrefix(context.LabCIDR)
	if parseErr != nil || !prefix.Addr().Is4() {
		return FirewallRules{}, fmt.Errorf("traffic policy requires an IPv4 lab CIDR")
	}
	if !enforcementInterfacePattern.MatchString(context.LabInterface) {
		return FirewallRules{}, fmt.Errorf("traffic policy requires a safe lab interface name")
	}
	if err := validateDeviceMatches(context.Devices); err != nil {
		return FirewallRules{}, err
	}
	v4 := familyRenderer{ipv6: false, iface: context.LabInterface, source: prefix.Masked().String(), unreachable: "icmp-port-unreachable", private: privateIPv4Destinations, redirects: true, devices: context.Devices}
	if context.LabGatewayIPv4 != "" {
		gateway, err := netip.ParseAddr(context.LabGatewayIPv4)
		if err != nil || !gateway.Is4() || !prefix.Contains(gateway) {
			return FirewallRules{}, fmt.Errorf("lab IPv4 gateway address must be inside the lab CIDR")
		}
		v4.gateway = gateway.String()
	}
	v6 := familyRenderer{ipv6: true, iface: context.LabInterface, unreachable: "icmp6-port-unreachable", private: privateIPv6Destinations, redirects: context.IPv6Listeners, devices: context.Devices}
	if context.LabIPv6Prefix != "" {
		prefix6, err := netip.ParsePrefix(context.LabIPv6Prefix)
		if err != nil || !prefix6.Addr().Is6() || prefix6.Addr().Is4In6() || prefix6.Bits() < 16 {
			return FirewallRules{}, fmt.Errorf("lab IPv6 prefix is invalid")
		}
		v6.source = prefix6.Masked().String()
		if context.LabGatewayIPv6 != "" {
			gateway, err := netip.ParseAddr(context.LabGatewayIPv6)
			if err != nil || !gateway.Is6() || gateway.Zone() != "" || !prefix6.Contains(gateway) {
				return FirewallRules{}, fmt.Errorf("lab IPv6 gateway address must be inside the lab IPv6 prefix")
			}
			v6.gateway = gateway.String()
		}
	}

	for _, control := range normalized.DeviceControls {
		if control.Effective() && context.Devices[control.DeviceID].Empty() {
			rules.UnmatchedDevices = append(rules.UnmatchedDevices, control.DeviceID)
		}
	}

	filter4, nat4, needs4 := renderFamily(normalized, v4, ports)
	filter6, nat6, _ := renderFamily(normalized, v6, ports)
	rules.FilterRules = filter4
	rules.NATRules = nat4
	rules.FilterRulesIPv6 = filter6
	rules.NATRulesIPv6 = nat6
	rules.NeedsNATHook = len(nat4) != 0
	rules.NeedsDNSService = needs4.dns
	rules.NeedsMITMService = normalized.TLS.Enabled
	rules.NeedsOnboarding = needs4.onboarding || (v6.gateway != "" && normalized.TLS.Enabled)
	return rules, nil
}

type listenerPorts struct {
	dns, tls, onboarding int
}

type familyNeeds struct {
	dns        bool
	onboarding bool
}

func renderFamily(policy Policy, f familyRenderer, ports listenerPorts) ([]string, []string, familyNeeds) {
	var needs familyNeeds
	forward := []string{}
	nat := []string{}
	inputLab := []string{}

	// 1. Device internet blocks. Only traffic leaving the lab segment is
	// dropped, so LAN peers and ShakerProxy's own DNS/DHCP/onboarding still work.
	blocked := map[string]bool{}
	for _, control := range policy.DeviceControls {
		if !control.BlockInternet {
			continue
		}
		blocked[control.DeviceID] = true
		for _, selector := range f.selectors(control.DeviceID) {
			forward = append(forward, fmt.Sprintf("-A SHAKERPROXY-FORWARD %s %s -j DROP", selector, f.leavingLab()))
		}
	}

	// 2. Devices with blocked domains must use ShakerProxy DNS: reject DNS over
	// TLS/QUIC so the device falls back to plain DNS that ShakerProxy answers.
	dnsDevices := []string{}
	for _, control := range policy.DeviceControls {
		if len(control.BlockedDomains) == 0 || blocked[control.DeviceID] {
			continue
		}
		dnsDevices = append(dnsDevices, control.DeviceID)
		for _, selector := range f.selectors(control.DeviceID) {
			forward = append(forward,
				fmt.Sprintf("-A SHAKERPROXY-FORWARD %s%s -p tcp --dport 853 -j REJECT --reject-with tcp-reset", selector, f.outbound()),
				fmt.Sprintf("-A SHAKERPROXY-FORWARD %s%s -p udp --dport 853 -j REJECT --reject-with %s", selector, f.outbound(), f.unreachable),
			)
		}
	}

	// 3. Policy-wide encrypted DNS blocks with bounded kernel logging. Each
	// LOG rule must precede its REJECT rule, so this list is never sorted.
	dns := policy.EncryptedDNS
	if dns.BlockDoT {
		forward = appendLoggedEncryptedDNSBlock(forward, fmt.Sprintf("-A SHAKERPROXY-FORWARD %s%s -p tcp --dport 853", f.scope(), f.outbound()), "SHAKERPROXY_EDNS_DOT ", "REJECT --reject-with tcp-reset")
	}
	if dns.BlockDoQ {
		forward = appendLoggedEncryptedDNSBlock(forward, fmt.Sprintf("-A SHAKERPROXY-FORWARD %s%s -p udp --dport 853", f.scope(), f.outbound()), "SHAKERPROXY_EDNS_DOQ ", "REJECT --reject-with "+f.unreachable)
	}
	known := BlockSafeAddresses(policy, f.ipv6)
	if dns.BlockKnownDoH {
		for _, address := range known {
			forward = appendLoggedEncryptedDNSBlock(forward, fmt.Sprintf("-A SHAKERPROXY-FORWARD %s -d %s -p tcp --dport 443", f.scope(), address), "SHAKERPROXY_EDNS_DOH_TCP ", "REJECT --reject-with tcp-reset")
		}
	}
	if dns.BlockKnownDoH3 {
		for _, address := range known {
			forward = appendLoggedEncryptedDNSBlock(forward, fmt.Sprintf("-A SHAKERPROXY-FORWARD %s -d %s -p udp --dport 443", f.scope(), address), "SHAKERPROXY_EDNS_DOH_UDP ", "REJECT --reject-with "+f.unreachable)
		}
	}

	tls := policy.TLS
	selective := len(tls.SelectedDeviceIDs) != 0
	// Selective interception is narrowed to the selected devices' packets
	// when every selected device has a known identity. Otherwise the whole
	// lab is redirected and mitmproxy passes unselected clients through, as
	// before device identities existed.
	narrow := selective
	for _, deviceID := range tls.SelectedDeviceIDs {
		if len(f.selectors(deviceID)) == 0 {
			narrow = false
		}
	}

	// 4. QUIC: reject UDP/443 from the interception scope so HTTP/3 clients
	// fall back to TCP. This block is last in the chain because the private
	// destination exemptions RETURN from it.
	if tls.Enabled && !tls.AllowQUIC {
		quicScope := []string{f.scope()}
		if selective {
			quicScope = []string{}
			for _, deviceID := range tls.SelectedDeviceIDs {
				if !blocked[deviceID] {
					quicScope = append(quicScope, f.selectors(deviceID)...)
				}
			}
		}
		if len(quicScope) != 0 {
			if !tls.InterceptPrivateDestinations {
				for _, destination := range f.private {
					forward = append(forward, fmt.Sprintf("-A SHAKERPROXY-FORWARD -i %s -d %s -p udp --dport 443 -j RETURN", f.iface, destination))
				}
			}
			for _, scope := range quicScope {
				forward = append(forward, fmt.Sprintf("-A SHAKERPROXY-FORWARD %s%s -p udp --dport 443 -j REJECT --reject-with %s", scope, f.outbound(), f.unreachable))
			}
		}
	}

	// NAT order: onboarding DNAT, interception exemptions (RETURN), DNS
	// redirects, then interception redirects.
	onboarding := tls.Enabled && f.gateway != ""
	if onboarding {
		needs.onboarding = true
		target := f.gateway
		if f.ipv6 {
			target = "[" + f.gateway + "]"
		}
		nat = append(nat, fmt.Sprintf("-A SHAKERPROXY-PREROUTING %s -d %s -p tcp --dport 80 -j DNAT --to-destination %s:%d", f.scope(), f.gateway, target, ports.onboarding))
		inputLab = append(inputLab, fmt.Sprintf("-A SHAKERPROXY-INPUT %s -d %s -p tcp --dport %d -m conntrack --ctstate DNAT -j ACCEPT", f.scope(), f.gateway, ports.onboarding))
	}

	interceptPorts := []int{443}
	if tls.InterceptHTTP {
		interceptPorts = append(interceptPorts, 80)
	}
	if tls.Enabled && f.redirects {
		returns := []string{}
		// Resolver addresses selected for blocking must remain in FORWARD
		// instead of being swallowed by the transparent TLS redirect.
		if dns.BlockKnownDoH {
			for _, address := range known {
				returns = append(returns, fmt.Sprintf("-A SHAKERPROXY-PREROUTING %s -d %s -p tcp --dport 443 -j RETURN", f.scope(), address))
			}
		}
		for _, cidr := range tls.ExcludeCIDRs {
			if parsed, err := netip.ParsePrefix(cidr); err == nil && parsed.Addr().Is6() == f.ipv6 {
				for _, port := range interceptPorts {
					returns = append(returns, fmt.Sprintf("-A SHAKERPROXY-PREROUTING %s -d %s -p tcp --dport %d -j RETURN", f.scope(), cidr, port))
				}
			}
		}
		if !tls.InterceptPrivateDestinations {
			for _, destination := range f.private {
				for _, port := range interceptPorts {
					returns = append(returns, fmt.Sprintf("-A SHAKERPROXY-PREROUTING -i %s -d %s -p tcp --dport %d -j RETURN", f.iface, destination, port))
				}
			}
		}
		// Internet-blocked devices must not reach the WAN through the proxy.
		for _, control := range policy.DeviceControls {
			if !control.BlockInternet {
				continue
			}
			for _, selector := range f.selectors(control.DeviceID) {
				for _, port := range interceptPorts {
					returns = append(returns, fmt.Sprintf("-A SHAKERPROXY-PREROUTING %s -p tcp --dport %d -j RETURN", selector, port))
				}
			}
		}
		sort.Strings(returns)
		nat = append(nat, returns...)
	}

	if f.redirects {
		// ShakerProxy's own lab address is the resolver DHCP hands out and
		// the one single-arm clients are told to use, so queries to it are
		// always answered locally, whatever the policy mode.
		type dnsRedirect struct{ scope, destination string }
		redirects := []dnsRedirect{}
		if f.gateway != "" {
			redirects = append(redirects, dnsRedirect{f.scope(), " -d " + f.gateway})
		}
		// Enforcement also answers queries sent to resolvers outside the
		// lab; DNS between two lab devices is left alone.
		dnsScopes := []string{}
		if dns.Mode == EncryptedDNSEnforceLocal && dns.RedirectPlainDNS {
			dnsScopes = append(dnsScopes, f.scope())
		} else {
			for _, deviceID := range dnsDevices {
				dnsScopes = append(dnsScopes, f.selectors(deviceID)...)
			}
		}
		for _, scope := range dnsScopes {
			redirects = append(redirects, dnsRedirect{scope, f.outbound()})
		}
		for _, redirect := range redirects {
			nat = append(nat,
				fmt.Sprintf("-A SHAKERPROXY-PREROUTING %s%s -p udp --dport 53 -j REDIRECT --to-ports %d", redirect.scope, redirect.destination, ports.dns),
				fmt.Sprintf("-A SHAKERPROXY-PREROUTING %s%s -p tcp --dport 53 -j REDIRECT --to-ports %d", redirect.scope, redirect.destination, ports.dns),
			)
		}
		if len(redirects) != 0 {
			needs.dns = true
			inputLab = append(inputLab,
				fmt.Sprintf("-A SHAKERPROXY-INPUT %s -p udp --dport %d -m conntrack --ctstate DNAT -j ACCEPT", f.scope(), ports.dns),
				fmt.Sprintf("-A SHAKERPROXY-INPUT %s -p tcp --dport %d -m conntrack --ctstate DNAT -j ACCEPT", f.scope(), ports.dns),
			)
		}
	}

	if tls.Enabled && f.redirects {
		for _, port := range interceptPorts {
			scopes := []string{f.scope()}
			if narrow || (selective && port != 443) {
				scopes = []string{}
				for _, deviceID := range tls.SelectedDeviceIDs {
					scopes = append(scopes, f.selectors(deviceID)...)
				}
			}
			for _, scope := range scopes {
				nat = append(nat, fmt.Sprintf("-A SHAKERPROXY-PREROUTING %s%s -p tcp --dport %d -j REDIRECT --to-ports %d", scope, f.outbound(), port, ports.tls))
			}
		}
		inputLab = append(inputLab, fmt.Sprintf("-A SHAKERPROXY-INPUT %s -p tcp --dport %d -m conntrack --ctstate DNAT -j ACCEPT", f.scope(), ports.tls))
	}

	filter := append([]string{}, forward...)
	baseline := baselineInput(f.ipv6, ports)
	loopback, drops := baseline[:4], baseline[4:]
	sort.Strings(inputLab)
	filter = append(filter, loopback...)
	filter = append(filter, inputLab...)
	filter = append(filter, drops...)
	return filter, nat, needs
}

// baselineInput keeps the local DNS, TLS and onboarding listeners reachable
// only from loopback. It is installed even when no policy is active so the
// listeners are never exposed on WAN or management interfaces.
func baselineInput(_ bool, ports listenerPorts) []string {
	return []string{
		fmt.Sprintf("-A SHAKERPROXY-INPUT -i lo -p tcp --dport %d -j ACCEPT", ports.dns),
		fmt.Sprintf("-A SHAKERPROXY-INPUT -i lo -p tcp --dport %d -j ACCEPT", ports.onboarding),
		fmt.Sprintf("-A SHAKERPROXY-INPUT -i lo -p tcp --dport %d -j ACCEPT", ports.tls),
		fmt.Sprintf("-A SHAKERPROXY-INPUT -i lo -p udp --dport %d -j ACCEPT", ports.dns),
		fmt.Sprintf("-A SHAKERPROXY-INPUT -p tcp --dport %d -j DROP", ports.dns),
		fmt.Sprintf("-A SHAKERPROXY-INPUT -p tcp --dport %d -j DROP", ports.onboarding),
		fmt.Sprintf("-A SHAKERPROXY-INPUT -p tcp --dport %d -j DROP", ports.tls),
		fmt.Sprintf("-A SHAKERPROXY-INPUT -p udp --dport %d -j DROP", ports.dns),
	}
}

func appendLoggedEncryptedDNSBlock(rules []string, match, prefix, verdict string) []string {
	rules = append(rules, fmt.Sprintf(`%s -m limit --limit 10/second --limit-burst 20 -j LOG --log-prefix %q`, match, prefix))
	return append(rules, fmt.Sprintf("%s -j %s", match, verdict))
}

func needsLabContext(policy Policy) bool {
	for _, control := range policy.DeviceControls {
		if control.Effective() {
			return true
		}
	}
	return policy.EncryptedDNS.BlockDoT ||
		policy.EncryptedDNS.BlockDoQ ||
		policy.EncryptedDNS.BlockKnownDoH ||
		policy.EncryptedDNS.BlockKnownDoH3 ||
		policy.EncryptedDNS.Mode == EncryptedDNSEnforceLocal ||
		policy.TLS.Enabled
}

// NeedsLabContext reports whether a policy installs any client packet rule
// and therefore requires a confirmed routed lab interface.
func NeedsLabContext(policy Policy) bool { return needsLabContext(policy) }

// HasRuleForChain reports whether any rule appends to chain.
func HasRuleForChain(rules []string, chain string) bool {
	needle := "-A " + chain + " "
	for _, rule := range rules {
		if strings.HasPrefix(rule, needle) {
			return true
		}
	}
	return false
}
