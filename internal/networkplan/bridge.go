package networkplan

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// TopologyTransparentBridge puts ShakerProxy inline between test devices and
// the rest of the network as a Linux bridge over two ports. Devices keep the
// network's own DHCP, gateway and DNS and need no setup; every frame between
// the device side and the router side crosses ShakerProxy.
const TopologyTransparentBridge Topology = "TRANSPARENT_BRIDGE"

// InlineBridgeName is the bridge over the upstream (router side) and device
// side ports of a transparent-bridge plan. It takes over the host's address on
// the upstream network.
const InlineBridgeName = "spbr0"

// inlineBridgeStableID identifies the synthetic bridge returned by
// LabInterface for a transparent-bridge plan; like lgbr0 it is matched by its
// fixed name, never by host evidence.
const inlineBridgeStableID = "shakerproxy-bridge:" + InlineBridgeName

// InlineBridgeForwardDelaySeconds is the spanning-tree forward delay. STP is
// always on so that cabling both ports to the same switch cannot loop; the
// bridge forwards about twice this long after it comes up.
const InlineBridgeForwardDelaySeconds = 4

// InlineBridge reports whether the plan is a transparent bridge.
func InlineBridge(plan Plan) bool {
	return plan.Topology == TopologyTransparentBridge
}

// InlineBridgeIPv6Address reports whether ShakerProxy configures its own IPv6
// address on the bridge from the router's advertisements (wan.ipv6_mode
// SLAAC). DNS a device sends over IPv6 can then be answered by ShakerProxy;
// without one it can only be recorded, because the kernel redirects a query
// to an address of the bridge with the query's scope.
func InlineBridgeIPv6Address(plan Plan) bool {
	return InlineBridge(plan) && effectiveWANIPv6Mode(plan.WAN.IPv6Mode) == WANIPv6SLAAC
}

// BridgePorts returns the upstream (router side, role WAN) and device side
// (role LAB) ports of a transparent-bridge plan.
func BridgePorts(plan Plan) (upstream, device Interface, ok bool) {
	if !InlineBridge(plan) {
		return Interface{}, Interface{}, false
	}
	upstream, upstreamOK := InterfaceForRole(plan, RoleWAN)
	device, deviceOK := InterfaceForRole(plan, RoleLab)
	return upstream, device, upstreamOK && deviceOK
}

// UplinkInterface returns the interface that carries the host's own address
// and default route once the plan is applied: the bridge for a transparent
// bridge, the WAN (or single-arm interface) otherwise.
func UplinkInterface(plan Plan) (Interface, bool) {
	if InlineBridge(plan) {
		upstream, _, ok := BridgePorts(plan)
		if !ok {
			return Interface{}, false
		}
		return Interface{StableID: inlineBridgeStableID, CurrentName: InlineBridgeName, Role: RoleWAN, MTU: upstream.MTU}, true
	}
	return WANInterface(plan)
}

func inlineBridgeInterface(plan Plan) (Interface, bool) {
	upstream, _, ok := BridgePorts(plan)
	if !ok {
		return Interface{}, false
	}
	return Interface{StableID: inlineBridgeStableID, CurrentName: InlineBridgeName, Role: RoleLab, MTU: upstream.MTU}, true
}

// inlineBridgeAddress returns the host's own address on the bridge (the
// static WAN address) and the network's router.
func inlineBridgeAddress(plan Plan) (netip.Prefix, netip.Addr, bool) {
	prefix, prefixErr := netip.ParsePrefix(plan.WAN.IPv4Address)
	router, routerErr := netip.ParseAddr(plan.WAN.IPv4Gateway)
	if prefixErr != nil || routerErr != nil || !prefix.Addr().Is4() || !router.Is4() {
		return netip.Prefix{}, netip.Addr{}, false
	}
	return prefix, router, true
}

func validateInlineBridge(plan Plan, roles map[InterfaceRole]int, addError, addWarning func(string, string, string)) {
	if roles[RoleWAN] != 1 || roles[RoleLab] != 1 || roles[RoleWANLab] != 0 || roles[RoleMirror] != 0 || roles[RoleWiFiAP] != 0 {
		addError("BRIDGE_ROLES_INVALID", "interfaces", "an inline bridge needs exactly one upstream port (role WAN, toward the router) and one device port (role LAB)")
	}
	for _, port := range []InterfaceRole{RoleWAN, RoleLab} {
		if iface, ok := InterfaceForRole(plan, port); ok && len(iface.CurrentName) > maxLinuxInterfaceName {
			addError("BRIDGE_PORT_NAME_INVALID", "interfaces", "bridge ports need Linux interface names of at most 15 characters")
		}
	}
	if WiFiEnabled(plan) {
		addError("BRIDGE_WIFI_UNAVAILABLE", "wifi", "ShakerProxy's Wi-Fi access point cannot join an inline bridge yet; use a two-port or Wi-Fi lab for it")
	}
	if !plan.IPv4.Enabled {
		addError("IPV4_REQUIRED_FOR_ROUTED_V1", "ipv4.enabled", "an inline bridge needs ShakerProxy's own IPv4 address on the network")
	}
	if plan.IPv4.NAT44 {
		addError("BRIDGE_NAT_FORBIDDEN", "ipv4.nat44", "an inline bridge forwards frames unchanged; NAT is not used")
	}
	if plan.IPv4.ClientIsolation {
		addError("BRIDGE_CLIENT_ISOLATION_UNAVAILABLE", "ipv4.client_isolation", "client isolation is not available on an inline bridge")
	}
	if plan.IPv4.DHCPStart != "" || plan.IPv4.DHCPEnd != "" || plan.IPv4.DHCPLeaseSeconds != 0 || len(plan.IPv4.DNSAddresses) != 0 || plan.IPv4.SearchDomain != "" || len(plan.IPv4.Reservations) != 0 {
		addError("BRIDGE_DHCP_FORBIDDEN", "ipv4", "on an inline bridge the network's own router keeps handing out addresses; ShakerProxy runs no DHCP")
	}
	if effectiveWANIPv4Mode(plan.WAN.IPv4Mode) != WANIPv4Static {
		addError("BRIDGE_STATIC_ADDRESS_REQUIRED", "wan.ipv4_mode", "the bridge takes over ShakerProxy's address on the network; set wan.ipv4_mode to STATIC with the address it has now and the router as wan.ipv4_gateway")
	} else if address, router, ok := inlineBridgeAddress(plan); ok {
		if plan.IPv4.LabCIDR != address.Masked().String() {
			addError("BRIDGE_LAB_CIDR_MISMATCH", "ipv4.lab_cidr", fmt.Sprintf("on an inline bridge the lab is the network itself: ipv4.lab_cidr must be %s", address.Masked()))
		}
		if plan.IPv4.GatewayAddress != address.Addr().String() {
			addError("BRIDGE_GATEWAY_MISMATCH", "ipv4.gateway_address", fmt.Sprintf("on an inline bridge ipv4.gateway_address is ShakerProxy's own address, %s", address.Addr()))
		}
		if router == address.Addr() {
			addError("BRIDGE_ROUTER_INVALID", "wan.ipv4_gateway", "wan.ipv4_gateway must be the network's router, not ShakerProxy")
		}
	}
	switch effectiveWANIPv6Mode(plan.WAN.IPv6Mode) {
	case WANIPv6None, WANIPv6SLAAC:
	default:
		addError("BRIDGE_IPV6_MODE_INVALID", "wan.ipv6_mode", "set wan.ipv6_mode to NONE or SLAAC for ShakerProxy's own IPv6 on the bridge")
	}
	if effectiveWANDNSMode(plan.WAN.DNSMode) != WANDNSUseDHCP {
		addError("BRIDGE_DNS_MODE_INVALID", "wan.dns_mode", "an inline bridge uses the router as ShakerProxy's own DNS server")
	}
	if plan.WAN.UpstreamNAT {
		addError("BRIDGE_NAT_FORBIDDEN", "wan.upstream_nat", "an inline bridge forwards frames unchanged; NAT is not used")
	}
	if plan.IPv6.Strategy != IPv6ObserveOnly {
		addError("BRIDGE_IPV6_STRATEGY_INVALID", "ipv6.strategy", "IPv6 crosses an inline bridge from the network's own router and is recorded; choose OBSERVE_ONLY")
	}
	if effectiveWANIPv6Mode(plan.WAN.IPv6Mode) != WANIPv6SLAAC {
		addWarning("BRIDGE_IPV6_DNS_NOT_FORCED", "wan.ipv6_mode", "with wan.ipv6_mode NONE, DNS that devices send over IPv6 is recorded but not answered by ShakerProxy; choose SLAAC so ShakerProxy takes an IPv6 address from the router's advertisements")
	}
	addWarning("BRIDGE_STP", "topology", fmt.Sprintf("spanning tree is on, so cabling both ports to the same switch cannot loop; the bridge forwards about %d seconds after it comes up", 2*InlineBridgeForwardDelaySeconds))
	addWarning("BRIDGE_FAIL_CLOSED_POWER", "topology", "devices behind the bridge lose their network while ShakerProxy is off or rebooting; emergency bypass keeps bridging without inspection")
	addWarning("BRIDGE_EXISTING_NETPLAN", "wan", "if another Netplan file gives the upstream port a static address, that address stays on the port; the health check then fails and ShakerProxy rolls back")
}

// inlineBridgeObservedConflict reports whether an observed address is the
// host's own address on a port the bridge takes over (which moves to the
// bridge rather than conflicting with the lab CIDR).
func inlineBridgeObservedConflict(plan Plan, interfaceName string, address netip.Addr) bool {
	if !InlineBridge(plan) {
		return false
	}
	upstream, device, ok := BridgePorts(plan)
	if !ok || (interfaceName != upstream.CurrentName && interfaceName != device.CurrentName && interfaceName != InlineBridgeName) {
		return false
	}
	gateway, err := netip.ParseAddr(plan.IPv4.GatewayAddress)
	return err == nil && gateway == address
}

// validateInlineBridgeSSH keeps the active SSH path: a session that arrives on
// the upstream port survives only when the bridge keeps the address it
// connected to; a session on the device port is refused (that port carries
// test devices).
func validateInlineBridgeSSH(plan Plan, index int, session ActiveSSHSession, role InterfaceRole, result *ValidationResult) bool {
	if !InlineBridge(plan) {
		return false
	}
	path := fmt.Sprintf("active_ssh[%d]", index)
	switch role {
	case RoleWAN:
		destination, err := netip.ParseAddr(session.DestinationAddress)
		gateway, gatewayErr := netip.ParseAddr(plan.IPv4.GatewayAddress)
		if err != nil || gatewayErr != nil || destination.WithZone("").Unmap() != gateway {
			result.Errors = append(result.Errors, Issue{Code: "BRIDGE_SSH_ADDRESS_CHANGE", Path: path + ".destination_address", Message: fmt.Sprintf("this SSH session uses %s on the upstream port; the bridge must keep that address (set wan.ipv4_address and ipv4.gateway_address to it) or the session drops", session.DestinationAddress)})
		}
		return true
	case RoleLab:
		result.Errors = append(result.Errors, Issue{Code: "ACTIVE_SSH_ON_LAB_INTERFACE", Path: path + ".destination_interface", Message: "this SSH session arrives on the device port; connect through the upstream port or a management port before bridging"})
		return true
	}
	return false
}

func buildInlineBridgePreview(plan Plan, preview *Preview) {
	upstream, device, _ := BridgePorts(plan)
	address, router, _ := inlineBridgeAddress(plan)
	preview.NetplanYAML = renderInlineBridgeNetplan(plan)
	preview.FirewallRestoreIPv4 = renderInlineBridgeFirewall()
	// Bridged IPv6 meets ip6tables FORWARD too (bridge-nf-call-ip6tables),
	// where Docker may set a DROP policy: the same accept rule keeps it
	// crossing, and the traffic policy's IPv6 rules apply to it.
	preview.FirewallRestoreIPv6 = renderInlineBridgeFirewall()
	preview.ChangedObjects = []string{"/etc/netplan/90-shakerproxy.yaml", "bridge " + InlineBridgeName, "iptables filter/SHAKERPROXY-FORWARD", labIPv6ChangedForward, "net.bridge.bridge-nf-call-iptables", BridgeNFCallIP6TablesSysctl}
	preview.AttachmentCommands = []CommandPreview{
		{Executable: "/usr/sbin/iptables", Arguments: []string{"-w", "5", "-C", "DOCKER-USER", "-j", "SHAKERPROXY-FORWARD"}},
		{Executable: "/usr/sbin/iptables", Arguments: []string{"-w", "5", "-I", "DOCKER-USER", "1", "-j", "SHAKERPROXY-FORWARD"}},
	}
	preview.AttachmentCommands = append(preview.AttachmentCommands, ipv6AttachmentPreview(defaultIp6tablesPath, "filter", IPv6ForwardParentUser, "SHAKERPROXY-FORWARD")...)
	ipv6DNS := "IPv6 crosses the bridge from the network's own router and is recorded; DNS sent over IPv6 is not answered by ShakerProxy because it takes no IPv6 address (set wan.ipv6_mode to SLAAC)"
	if InlineBridgeIPv6Address(plan) {
		ipv6DNS = "ShakerProxy takes an IPv6 address on the bridge from the router's advertisements, so plain DNS devices send over IPv6 is answered by ShakerProxy too"
	}
	preview.Impact = []string{
		fmt.Sprintf("Ports %s (toward the router) and %s (toward the test devices) would join bridge %s; devices keep the network's own DHCP, gateway and DNS and need no setup", upstream.CurrentName, device.CurrentName, InlineBridgeName),
		fmt.Sprintf("ShakerProxy's address %s would move from %s to %s, with %s as its router and DNS server", address, upstream.CurrentName, InlineBridgeName, router),
		"Every frame between the two sides is recorded, including DHCP, ARP, router advertisements, multicast and device-to-device traffic that crosses the bridge",
		"Bridged IPv4 and IPv6 pass through the host firewall (br_netfilter), so plain DNS can be redirected to ShakerProxy and connections are reported as they open",
		ipv6DNS,
		"Spanning tree is on, so cabling both ports to the same switch cannot loop",
		"Active SSH preservation remains mandatory, and an independent rollback deadline is armed before the bridge is created",
	}
}

func renderInlineBridgeNetplan(plan Plan) string {
	upstream, device, _ := BridgePorts(plan)
	address, router, _ := inlineBridgeAddress(plan)
	var b strings.Builder
	b.WriteString("network:\n  version: 2\n  ethernets:\n")
	for _, port := range []Interface{upstream, device} {
		// Ports carry no address of their own: the bridge holds the host's.
		fmt.Fprintf(&b, "    %s:\n      dhcp4: false\n      dhcp6: false\n      accept-ra: false\n      link-local: []\n", port.CurrentName)
		if port.MTU != 0 {
			fmt.Fprintf(&b, "      mtu: %d\n", port.MTU)
		}
	}
	b.WriteString("  bridges:\n")
	fmt.Fprintf(&b, "    %s:\n", InlineBridgeName)
	fmt.Fprintf(&b, "      interfaces: [%s, %s]\n", upstream.CurrentName, device.CurrentName)
	if mac, err := net.ParseMAC(upstream.PermanentMAC); err == nil && len(mac) == 6 {
		// The router keeps seeing the MAC it knew this host by.
		fmt.Fprintf(&b, "      macaddress: %s\n", mac)
	}
	b.WriteString("      dhcp4: false\n")
	if effectiveWANIPv6Mode(plan.WAN.IPv6Mode) == WANIPv6SLAAC {
		b.WriteString("      dhcp6: false\n      accept-ra: true\n")
	} else {
		b.WriteString("      dhcp6: false\n      accept-ra: false\n")
	}
	fmt.Fprintf(&b, "      addresses: [%s]\n", address)
	fmt.Fprintf(&b, "      routes:\n        - to: 0.0.0.0/0\n          via: %s\n", router)
	fmt.Fprintf(&b, "      nameservers:\n        addresses: [%s]\n", router)
	fmt.Fprintf(&b, "      parameters:\n        stp: true\n        forward-delay: %d\n", InlineBridgeForwardDelaySeconds)
	if upstream.MTU != 0 {
		fmt.Fprintf(&b, "      mtu: %d\n", upstream.MTU)
	}
	return b.String()
}

// BridgeNFCallIP6TablesSysctl is the switch that sends bridged IPv6 through
// ip6tables.
const BridgeNFCallIP6TablesSysctl = "net.bridge.bridge-nf-call-ip6tables"

// renderInlineBridgeFirewall lets bridged frames past the host's FORWARD
// policy: with br_netfilter, frames crossing the bridge traverse iptables
// and ip6tables FORWARD, and Docker sets their policy to DROP. The same batch
// serves both families. ShakerProxy's security chain (device blocks,
// encrypted-DNS blocks) is hooked ahead of this chain.
func renderInlineBridgeFirewall() string {
	return fmt.Sprintf("*filter\n:SHAKERPROXY-FORWARD - [0:0]\n-A SHAKERPROXY-FORWARD -i %[1]s -o %[1]s -j ACCEPT\nCOMMIT\n", InlineBridgeName)
}
