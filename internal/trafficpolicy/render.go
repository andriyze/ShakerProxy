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
	// LabBridgePort is the device-side port of an inline bridge (topology
	// TRANSPARENT_BRIDGE, LabInterface spbr0). Client rules then match frames
	// that entered through that port, and plain DNS to any resolver, the
	// network's router included, is answered by ShakerProxy.
	LabBridgePort string
	// LabBridgeAPPort is ShakerProxy's Wi-Fi access point when it joins the
	// inline bridge: a second device-side port whose frames get the same
	// rules as the wired device port's.
	LabBridgeAPPort string
	// LabBridgeIPv6 reports that ShakerProxy has its own IPv6 address on the
	// inline bridge (from the router's advertisements). Only then is DNS that
	// devices send over IPv6 redirected: the kernel redirects a query to an
	// address of the bridge with the query's scope, and drops it without one.
	LabBridgeIPv6 bool
	// IPv6Listeners reports that the DNS and TLS listeners accept IPv6. IPv6
	// redirects are rendered only when true so an IPv4-only listener cannot
	// blackhole lab IPv6 traffic; IPv6 blocking rules are rendered regardless.
	IPv6Listeners bool
	// Devices maps device IDs to their current packet identity.
	Devices map[string]DeviceMatch
	// OnboardingPort defaults to DefaultOnboardingPort.
	OnboardingPort int
	// VPN is the WireGuard VPN segment while VPN mode is up. Its devices get
	// the lab's DNS, encrypted-DNS, TLS and device rules. It may be the only
	// segment (a VPN-only install has no LabInterface).
	VPN *Segment
}

// Segment is a client network beside the lab, such as the WireGuard VPN.
type Segment struct {
	Interface   string
	IPv4CIDR    string
	GatewayIPv4 string
	IPv6Prefix  string
	GatewayIPv6 string
	// BridgePort is the device-side port when Interface is an inline bridge.
	BridgePort string
	// BridgeAPPort is the inline bridge's Wi-Fi access point, a second
	// device-side port.
	BridgeAPPort string
	// BridgeIPv6 reports ShakerProxy's own IPv6 address on that bridge.
	BridgeIPv6 bool
	// Devices maps device IDs to their addresses on this segment. VPN
	// addresses are bound to the device's key, so no MAC is needed.
	Devices map[string]DeviceMatch
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
	// noOnboarding leaves out the CA onboarding page; it is served on the
	// lab gateway only.
	noOnboarding bool
	// physIns are the device-side ports of an inline bridge (the wired
	// device port, then the Wi-Fi access point when it joins): the lab is
	// then "frames that entered through these ports", whatever their address.
	physIns []string
}

// outbound restricts a client rule to traffic leaving the lab. When the lab
// is a bridge (wired + Wi-Fi) with br_netfilter, lab-to-lab frames traverse
// the same hooks and must not be redirected, blocked or proxied.
func (f familyRenderer) outbound() string {
	if f.source == "" || len(f.physIns) != 0 {
		// On an inline bridge every destination is outside the device port,
		// the network's router included.
		return ""
	}
	return " ! -d " + f.source
}

// leavingLab matches a lab client's packet bound for somewhere outside the
// lab. It goes by destination: in a single-arm lab the internet is reached
// through the lab interface itself, so "! -o <lab>" never matches there.
func (f familyRenderer) leavingLab() string {
	if len(f.physIns) != 0 && f.source == "" {
		// A bridged IPv6 lab has no prefix of its own: everything but
		// link-local leaves the device.
		return "! -d fe80::/10"
	}
	if f.source == "" {
		return "! -o " + f.iface
	}
	return "! -d " + f.source
}

// scopes returns the match fragments for "a lab client's packet": one per
// device-side port of an inline bridge (iptables cannot match either of
// two physdev ports in one rule), otherwise one. Every caller emits a rule's
// copies back to back, so each port sees the rules in the same order as a
// lab with one port would.
func (f familyRenderer) scopes() []string {
	if len(f.physIns) != 0 {
		scopes := make([]string, 0, len(f.physIns))
		for _, port := range f.physIns {
			scopes = append(scopes, "-i "+f.iface+" -m physdev --physdev-in "+port)
		}
		return scopes
	}
	if f.source == "" {
		return []string{"-i " + f.iface}
	}
	return []string{"-i " + f.iface + " -s " + f.source}
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
	if !needsLabContext(normalized) && context.LabInterface == "" && context.VPN == nil {
		rules.FilterRules = baselineInput(false, ports)
		rules.FilterRulesIPv6 = baselineInput(true, ports)
		rules.NATRules = []string{}
		return rules, nil
	}

	segments := []Segment{}
	if context.LabInterface != "" || context.VPN == nil {
		segments = append(segments, Segment{
			Interface: context.LabInterface, IPv4CIDR: context.LabCIDR, GatewayIPv4: context.LabGatewayIPv4,
			IPv6Prefix: context.LabIPv6Prefix, GatewayIPv6: context.LabGatewayIPv6, BridgePort: context.LabBridgePort, BridgeAPPort: context.LabBridgeAPPort, BridgeIPv6: context.LabBridgeIPv6, Devices: context.Devices,
		})
	}
	if context.VPN != nil {
		segments = append(segments, *context.VPN)
	}
	var v4s, v6s []familyRenderer
	for index, segment := range segments {
		v4, v6, err := segmentRenderers(segment, context.IPv6Listeners)
		if err != nil {
			return FirewallRules{}, err
		}
		if context.VPN != nil && index == len(segments)-1 {
			v4.noOnboarding, v6.noOnboarding = true, true
		}
		v4s, v6s = append(v4s, v4), append(v6s, v6)
	}

	for _, control := range normalized.DeviceControls {
		if !control.Effective() {
			continue
		}
		matched := false
		for _, segment := range segments {
			if !segment.Devices[control.DeviceID].Empty() {
				matched = true
			}
		}
		if !matched {
			rules.UnmatchedDevices = append(rules.UnmatchedDevices, control.DeviceID)
		}
	}

	filter4, nat4, needs4 := renderFamilies(normalized, v4s, ports)
	filter6, nat6, needs6 := renderFamilies(normalized, v6s, ports)
	rules.FilterRules = filter4
	rules.NATRules = nat4
	rules.FilterRulesIPv6 = filter6
	rules.NATRulesIPv6 = nat6
	rules.NeedsNATHook = len(nat4) != 0
	rules.NeedsDNSService = needs4.dns
	rules.NeedsMITMService = normalized.TLS.Enabled
	rules.NeedsOnboarding = needs4.onboarding || needs6.onboarding
	return rules, nil
}

// segmentRenderers validates one client segment and returns its IPv4 and
// IPv6 renderers.
func segmentRenderers(segment Segment, ipv6Listeners bool) (familyRenderer, familyRenderer, error) {
	prefix, parseErr := netip.ParsePrefix(segment.IPv4CIDR)
	if parseErr != nil || !prefix.Addr().Is4() {
		return familyRenderer{}, familyRenderer{}, fmt.Errorf("traffic policy requires an IPv4 lab CIDR")
	}
	if !enforcementInterfacePattern.MatchString(segment.Interface) {
		return familyRenderer{}, familyRenderer{}, fmt.Errorf("traffic policy requires a safe lab interface name")
	}
	if err := validateDeviceMatches(segment.Devices); err != nil {
		return familyRenderer{}, familyRenderer{}, err
	}
	v4 := familyRenderer{ipv6: false, iface: segment.Interface, source: prefix.Masked().String(), unreachable: "icmp-port-unreachable", private: privateIPv4Destinations, redirects: true, devices: segment.Devices}
	if segment.GatewayIPv4 != "" {
		gateway, err := netip.ParseAddr(segment.GatewayIPv4)
		if err != nil || !gateway.Is4() || !prefix.Contains(gateway) {
			return familyRenderer{}, familyRenderer{}, fmt.Errorf("lab IPv4 gateway address must be inside the lab CIDR")
		}
		v4.gateway = gateway.String()
	}
	v6 := familyRenderer{ipv6: true, iface: segment.Interface, unreachable: "icmp6-port-unreachable", private: privateIPv6Destinations, redirects: ipv6Listeners, devices: segment.Devices}
	if segment.BridgeAPPort != "" && segment.BridgePort == "" {
		return familyRenderer{}, familyRenderer{}, fmt.Errorf("a bridge access point needs the bridge's device port")
	}
	if segment.BridgePort != "" {
		if !enforcementInterfacePattern.MatchString(segment.BridgePort) || segment.BridgePort == segment.Interface {
			return familyRenderer{}, familyRenderer{}, fmt.Errorf("traffic policy requires a safe bridge port name")
		}
		ports := []string{segment.BridgePort}
		if segment.BridgeAPPort != "" {
			if !enforcementInterfacePattern.MatchString(segment.BridgeAPPort) || segment.BridgeAPPort == segment.Interface || segment.BridgeAPPort == segment.BridgePort {
				return familyRenderer{}, familyRenderer{}, fmt.Errorf("traffic policy requires a safe bridge access point name")
			}
			ports = append(ports, segment.BridgeAPPort)
		}
		v4.physIns, v6.physIns = ports, ports
		// DNS over IPv6 is answered only when ShakerProxy has its own IPv6
		// address on the bridge; otherwise it is recorded, not redirected.
		v6.redirects = ipv6Listeners && segment.BridgeIPv6
	}
	if segment.IPv6Prefix != "" {
		prefix6, err := netip.ParsePrefix(segment.IPv6Prefix)
		if err != nil || !prefix6.Addr().Is6() || prefix6.Addr().Is4In6() || prefix6.Bits() < 16 {
			return familyRenderer{}, familyRenderer{}, fmt.Errorf("lab IPv6 prefix is invalid")
		}
		v6.source = prefix6.Masked().String()
		if segment.GatewayIPv6 != "" {
			gateway, err := netip.ParseAddr(segment.GatewayIPv6)
			if err != nil || !gateway.Is6() || gateway.Zone() != "" || !prefix6.Contains(gateway) {
				return familyRenderer{}, familyRenderer{}, fmt.Errorf("lab IPv6 gateway address must be inside the lab IPv6 prefix")
			}
			v6.gateway = gateway.String()
		}
	}
	return v4, v6, nil
}

// renderFamilies renders every segment of one family into a single filter
// and NAT list: each segment's forward rules in turn (every rule names its
// interface, so segments never match each other's packets), then the
// listener protection with all segments' accepts.
func renderFamilies(policy Policy, renderers []familyRenderer, ports listenerPorts) ([]string, []string, familyNeeds) {
	var needs familyNeeds
	forward, nat, inputLab := []string{}, []string{}, []string{}
	ipv6 := false
	for _, renderer := range renderers {
		segmentForward, segmentNAT, segmentInput, segmentNeeds := renderFamily(policy, renderer, ports)
		forward = append(forward, segmentForward...)
		nat = append(nat, segmentNAT...)
		inputLab = append(inputLab, segmentInput...)
		needs.dns = needs.dns || segmentNeeds.dns
		needs.onboarding = needs.onboarding || segmentNeeds.onboarding
		ipv6 = renderer.ipv6
	}
	filter := append([]string{}, forward...)
	baseline := baselineInput(ipv6, ports)
	loopback, drops := baseline[:4], baseline[4:]
	sort.Strings(inputLab)
	filter = append(filter, loopback...)
	filter = append(filter, inputLab...)
	filter = append(filter, drops...)
	return filter, nat, needs
}

type listenerPorts struct {
	dns, tls, onboarding int
}

type familyNeeds struct {
	dns        bool
	onboarding bool
}

func renderFamily(policy Policy, f familyRenderer, ports listenerPorts) ([]string, []string, []string, familyNeeds) {
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
			forward = appendLoggedEncryptedDNSBlock(forward, fmt.Sprintf("-A SHAKERPROXY-FORWARD %s%s -p tcp --dport 853", selector, f.outbound()), "SHAKERPROXY_EDNS_DOT ", "REJECT --reject-with tcp-reset")
			forward = appendLoggedEncryptedDNSBlock(forward, fmt.Sprintf("-A SHAKERPROXY-FORWARD %s%s -p udp --dport 853", selector, f.outbound()), "SHAKERPROXY_EDNS_DOQ ", "REJECT --reject-with "+f.unreachable)
		}
	}

	// 3. Policy-wide encrypted DNS blocks, each attempt reported to the
	// gateway through NFLOG (bounded per rule). Each NFLOG rule must precede
	// its REJECT rule, so this list is never sorted.
	dns := policy.EncryptedDNS
	if dns.BlockDoT {
		for _, scope := range f.scopes() {
			forward = appendLoggedEncryptedDNSBlock(forward, fmt.Sprintf("-A SHAKERPROXY-FORWARD %s%s -p tcp --dport 853", scope, f.outbound()), "SHAKERPROXY_EDNS_DOT ", "REJECT --reject-with tcp-reset")
		}
	}
	if dns.BlockDoQ {
		for _, scope := range f.scopes() {
			forward = appendLoggedEncryptedDNSBlock(forward, fmt.Sprintf("-A SHAKERPROXY-FORWARD %s%s -p udp --dport 853", scope, f.outbound()), "SHAKERPROXY_EDNS_DOQ ", "REJECT --reject-with "+f.unreachable)
		}
	}
	known := BlockSafeAddresses(policy, f.ipv6)
	if dns.BlockKnownDoH {
		for _, address := range known {
			for _, scope := range f.scopes() {
				forward = appendLoggedEncryptedDNSBlock(forward, fmt.Sprintf("-A SHAKERPROXY-FORWARD %s -d %s -p tcp --dport 443", scope, address), "SHAKERPROXY_EDNS_DOH_TCP ", "REJECT --reject-with tcp-reset")
			}
		}
	}
	if dns.BlockKnownDoH3 {
		for _, address := range known {
			for _, scope := range f.scopes() {
				forward = appendLoggedEncryptedDNSBlock(forward, fmt.Sprintf("-A SHAKERPROXY-FORWARD %s -d %s -p udp --dport 443", scope, address), "SHAKERPROXY_EDNS_DOH_UDP ", "REJECT --reject-with "+f.unreachable)
			}
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
		quicScope := f.scopes()
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
	onboarding := tls.Enabled && f.gateway != "" && !f.noOnboarding
	if onboarding {
		needs.onboarding = true
		target := f.gateway
		if f.ipv6 {
			target = "[" + f.gateway + "]"
		}
		for _, scope := range f.scopes() {
			nat = append(nat, fmt.Sprintf("-A SHAKERPROXY-PREROUTING %s -d %s -p tcp --dport 80 -j DNAT --to-destination %s:%d", scope, f.gateway, target, ports.onboarding))
			inputLab = append(inputLab, fmt.Sprintf("-A SHAKERPROXY-INPUT %s -d %s -p tcp --dport %d -m conntrack --ctstate DNAT -j ACCEPT", scope, f.gateway, ports.onboarding))
		}
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
				for _, scope := range f.scopes() {
					returns = append(returns, fmt.Sprintf("-A SHAKERPROXY-PREROUTING %s -d %s -p tcp --dport 443 -j RETURN", scope, address))
				}
			}
		}
		for _, cidr := range tls.ExcludeCIDRs {
			if parsed, err := netip.ParsePrefix(cidr); err == nil && parsed.Addr().Is6() == f.ipv6 {
				for _, port := range interceptPorts {
					for _, scope := range f.scopes() {
						returns = append(returns, fmt.Sprintf("-A SHAKERPROXY-PREROUTING %s -d %s -p tcp --dport %d -j RETURN", scope, cidr, port))
					}
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
			for _, scope := range f.scopes() {
				redirects = append(redirects, dnsRedirect{scope, " -d " + f.gateway})
			}
		}
		// Enforcement also answers queries sent to resolvers outside the
		// lab; DNS between two lab devices is left alone.
		dnsScopes := []string{}
		if dns.RedirectPlainDNS {
			dnsScopes = append(dnsScopes, f.scopes()...)
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
			for _, scope := range f.scopes() {
				inputLab = append(inputLab,
					fmt.Sprintf("-A SHAKERPROXY-INPUT %s -p udp --dport %d -m conntrack --ctstate DNAT -j ACCEPT", scope, ports.dns),
					fmt.Sprintf("-A SHAKERPROXY-INPUT %s -p tcp --dport %d -m conntrack --ctstate DNAT -j ACCEPT", scope, ports.dns),
				)
			}
		}
	}

	if tls.Enabled && f.redirects {
		for _, port := range interceptPorts {
			scopes := f.scopes()
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
		for _, scope := range f.scopes() {
			inputLab = append(inputLab, fmt.Sprintf("-A SHAKERPROXY-INPUT %s -p tcp --dport %d -m conntrack --ctstate DNAT -j ACCEPT", scope, ports.tls))
		}
	}

	return forward, nat, inputLab, needs
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

// appendLoggedEncryptedDNSBlock reports each blocked attempt to the gateway
// over NFLOG (group EncryptedDNSLogGroup, the prefix names what was blocked,
// at most 10 a second per rule), then applies the verdict.
func appendLoggedEncryptedDNSBlock(rules []string, match, prefix, verdict string) []string {
	rules = append(rules, fmt.Sprintf(`%s -m limit --limit 10/second --limit-burst 20 -j NFLOG --nflog-group %d --nflog-prefix %q --nflog-size 128`, match, EncryptedDNSLogGroup, prefix))
	return append(rules, fmt.Sprintf("%s -j %s", match, verdict))
}

// needsLabContext reports client packet rules that make no sense without a
// confirmed lab: device controls and TLS interception. The DNS visibility
// switches (plain DNS redirection, encrypted DNS blocking) are lab-wide
// defaults instead: they apply as soon as a lab is confirmed and install
// nothing before.
func needsLabContext(policy Policy) bool {
	for _, control := range policy.DeviceControls {
		if control.Effective() {
			return true
		}
	}
	return policy.TLS.Enabled
}

// NeedsLabContext reports whether a policy installs client packet rules
// that require a confirmed routed lab interface.
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
