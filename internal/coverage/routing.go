package coverage

import (
	"fmt"
	"sort"
	"strings"
)

// RoutingInput is the live configuration and recorded evidence the routing
// inspection judges. control-api fills it from gatewayd (state, host
// inspection, traffic policy) and from stored events.
type RoutingInput struct {
	// Routing is true when a confirmed lab plan routes traffic.
	Routing      bool
	Topology     string // networkplan.Topology
	IPv6Strategy string // networkplan.IPv6Strategy
	GatewayIPv4  string
	LabInterface string
	// LabIPv6 is set when the lab interface holds a global IPv6 address or
	// an IPv6 default route, which another router's advertisements provide.
	LabIPv6 bool
	// ForeignRouterAdverts and ForeignDHCPServers are sources seen in
	// recorded traffic that are not ShakerProxy.
	ForeignRouterAdverts []string
	ForeignDHCPServers   []string
	// RouterAdvertsSearched is set when recorded lab traffic could be
	// searched for IPv6 router advertisements; without it, finding none
	// proves nothing.
	RouterAdvertsSearched bool
	// WirelessAccessPoint is set when the plan runs ShakerProxy's own Wi-Fi.
	WirelessAccessPoint bool
	// Encrypted DNS policy (trafficpolicy.EncryptedDNSPolicy).
	PolicyAvailable  bool
	BlockDoT         bool
	BlockDoQ         bool
	BlockKnownDoH    bool
	RedirectPlainDNS bool
	// VPN is true while VPN mode is up (and no emergency bypass): devices
	// on the WireGuard VPN send everything through ShakerProxy.
	VPN           bool
	VPNDevices    int
	VPNPeerToPeer bool
	VPNIPv6Routed bool
}

const (
	FindingNotRouting     = "not-routing"
	FindingIPv6           = "ipv6-bypass"
	FindingDHCP           = "other-dhcp-server"
	FindingPeerToPeer     = "device-to-device"
	FindingEncryptedDNS   = "encrypted-dns"
	FindingPlainDNS       = "outside-dns"
	FindingLocalDiscovery = "local-discovery"
	FindingVPN            = "vpn-full-tunnel"
)

// InspectRouting names every way a real device could bypass ShakerProxy.
func InspectRouting(in RoutingInput) []Finding {
	if !in.Routing {
		if in.VPN {
			// A VPN-only appliance: the VPN is the whole lab.
			return append([]Finding{vpnFinding(in)}, encryptedDNSFindings(in)...)
		}
		return []Finding{{
			ID:     FindingNotRouting,
			Title:  "No lab is routing",
			Status: FindingGap,
			Detail: "No confirmed lab network routes devices through ShakerProxy, so nothing devices do is visible.",
			Fix:    "Set up and confirm a lab on the Network page, or turn on VPN mode and add a device.",
		}}
	}
	if in.Topology == "TRANSPARENT_BRIDGE" {
		findings := inlineBridgeFindings(in)
		findings = append(findings, encryptedDNSFindings(in)...)
		if in.VPN {
			findings = append(findings, vpnFinding(in))
		}
		return findings
	}
	singleArm := in.Topology == "SINGLE_ARM"
	findings := []Finding{ipv6Finding(in, singleArm), dhcpFinding(in, singleArm), peerFinding(in, singleArm)}
	findings = append(findings, encryptedDNSFindings(in)...)
	findings = append(findings, discoveryFinding(singleArm))
	if in.VPN {
		findings = append(findings, vpnFinding(in))
	}
	return findings
}

// inlineBridgeFindings judges an inline bridge: devices keep the network's
// own router, DHCP and IPv6, but every frame between the device port and the
// rest of the network crosses ShakerProxy, so none of them is a way around.
// ShakerProxy's Wi-Fi access point, when it joins the bridge, is a second
// device-side port: Wi-Fi devices cross the bridge the same way.
func inlineBridgeFindings(in RoutingInput) []Finding {
	dhcp := "Inline bridge: the network's router hands out addresses through ShakerProxy, so devices need no setup and have no other way to their gateway than across the bridge."
	peer := Finding{ID: FindingPeerToPeer, Title: "Device-to-device traffic (AirPlay, casting, local SSH)", Status: FindingOK,
		Detail: "Traffic between a device on the device port and anything on the router's side crosses the bridge and is recorded. Two devices behind the same switch on the device port still talk directly.",
		Fix:    "Connect one test device to the device port, or add ShakerProxy's Wi-Fi access point to the bridge for several."}
	if in.WirelessAccessPoint {
		dhcp = "Inline bridge: the network's router hands out addresses through ShakerProxy, to wired devices on the device port and to Wi-Fi devices on ShakerProxy's access point, so they need no setup and have no other way to their gateway than across the bridge."
		peer.Detail = "Wi-Fi devices on ShakerProxy's access point reach the wired device and the rest of the network across the bridge, so that traffic is recorded, as is traffic between the device port and the router's side. Traffic sent directly between two Wi-Fi devices is forwarded inside the access point, and two devices behind the same switch on the device port still talk directly."
		peer.Fix = "To see two devices talk to each other, put one on Wi-Fi and the other on the device port."
	}
	return []Finding{
		{ID: FindingIPv6, Title: "IPv6", Status: FindingOK,
			Detail: "The network's router advertises IPv6 through the bridge, so a device's IPv6 crosses ShakerProxy and is recorded. DNS forcing and device blocks apply to IPv4, and to IPv6 when ShakerProxy takes its own IPv6 address from the router (SLAAC)."},
		{ID: FindingDHCP, Title: "Address assignment (DHCP)", Status: FindingOK, Detail: dhcp},
		peer,
		{ID: FindingLocalDiscovery, Title: "Local discovery (mDNS/Bonjour, SSDP)", Status: FindingOK,
			Detail: "Every multicast and broadcast frame crossing the bridge is recorded, including the discovery AirPlay, Chromecast and smart-home apps use."},
	}
}

// vpnFinding describes the WireGuard VPN path: a full tunnel leaves a
// device no other router, DHCP server or IPv6 path, so the lab's bypass
// findings do not apply to VPN devices.
func vpnFinding(in RoutingInput) Finding {
	finding := Finding{ID: FindingVPN, Title: "VPN devices (WireGuard)", Status: FindingOK}
	ipv6 := "IPv6 stays inside the tunnel, so they use IPv4."
	if in.VPNIPv6Routed {
		ipv6 = "IPv6 is routed through ShakerProxy too."
	}
	peers := "They cannot reach each other."
	if in.VPNPeerToPeer {
		peers = "Traffic between two VPN devices also crosses ShakerProxy."
	}
	finding.Detail = fmt.Sprintf("%d VPN device(s) send all their traffic through ShakerProxy, local-network destinations included: no other router, DHCP server or IPv6 path can take it around ShakerProxy. %s %s Local discovery (mDNS, SSDP) of the device's own network does not cross the tunnel.", in.VPNDevices, ipv6, peers)
	if in.VPNDevices == 0 {
		finding.Status = FindingUnknown
		finding.Fix = "Add a device under VPN devices on the Network page and scan its QR code with the WireGuard app."
	}
	return finding
}

func routesIPv6(strategy string) bool {
	switch strategy {
	case "NATIVE_ROUTED_PREFIX", "PREFIX_DELEGATION", "ULA_NAT66_LAB":
		return true
	default:
		return false
	}
}

// ipv6Finding judges IPv6 from router advertisements in recorded lab traffic
// and the appliance's own lab interface: a device takes its IPv6 default
// route from whichever router advertises one.
func ipv6Finding(in RoutingInput, singleArm bool) Finding {
	finding := Finding{ID: FindingIPv6, Title: "IPv6"}
	routers := uniqueSorted(in.ForeignRouterAdverts)
	routed := routesIPv6(in.IPv6Strategy)
	switch {
	case len(routers) > 0 && routed:
		finding.Status = FindingGap
		finding.Detail = fmt.Sprintf("Another router also advertises IPv6 on the lab network (%s). Devices may send IPv6 traffic to it instead of ShakerProxy.", strings.Join(routers, ", "))
		finding.Fix = "Turn off IPv6 router advertisements on that router for the lab network, so ShakerProxy is the only IPv6 router."
	case len(routers) > 0:
		finding.Status = FindingGap
		finding.Detail = fmt.Sprintf("Another router advertises IPv6 on the lab network (%s), and ShakerProxy does not route IPv6. Devices send every IPv6 connection straight to it, past ShakerProxy.", strings.Join(routers, ", "))
		finding.Fix = "Turn off IPv6 router advertisements on that router for the lab network, or give the lab its own network (two ports or ShakerProxy's Wi-Fi)."
	case in.LabIPv6 && !routed:
		finding.Status = FindingGap
		finding.Detail = fmt.Sprintf("The lab network (%s) has IPv6 from another router, and ShakerProxy does not route IPv6. Devices with IPv6 bypass ShakerProxy for every IPv6 destination.", in.LabInterface)
		finding.Fix = "Turn off IPv6 on the network's router, or use a two-port or Wi-Fi lab where ShakerProxy is the only router."
	case !in.RouterAdvertsSearched:
		finding.Status = FindingUnknown
		finding.Detail = "Recorded lab traffic could not be searched for IPv6 router advertisements, so another IPv6 router on the lab network cannot be ruled out."
		finding.Fix = "Keep the automatic lab recording on, then check again."
	case routed:
		finding.Status = FindingOK
		finding.Detail = "ShakerProxy routes the lab's IPv6, and no other router advertised IPv6 in the last 24 hours of recorded lab traffic."
	case singleArm:
		finding.Status = FindingOK
		finding.Detail = "No router advertised IPv6 in the last 24 hours of recorded lab traffic, so devices have no IPv6 path around ShakerProxy."
	default:
		finding.Status = FindingOK
		finding.Detail = "ShakerProxy is the lab network's only router, and no other router advertised IPv6 in the last 24 hours of recorded lab traffic."
	}
	return finding
}

func dhcpFinding(in RoutingInput, singleArm bool) Finding {
	finding := Finding{ID: FindingDHCP, Title: "Address assignment (DHCP)"}
	servers := uniqueSorted(in.ForeignDHCPServers)
	switch {
	case len(servers) > 0:
		finding.Status = FindingGap
		finding.Detail = fmt.Sprintf("Another DHCP server answers on the lab network (%s). Devices it configures may use another gateway and bypass ShakerProxy.", strings.Join(servers, ", "))
		finding.Fix = "Turn off that DHCP server for the lab network, or move the lab onto its own network."
	case singleArm:
		finding.Status = FindingGap
		finding.Detail = fmt.Sprintf("Single-arm lab: the network's own router hands out addresses. Only devices set by hand to use %s as their gateway go through ShakerProxy; a device that reconnects with DHCP bypasses it.", orUnknown(in.GatewayIPv4))
		finding.Fix = "Give each test device a static IP with ShakerProxy as gateway and DNS, or use a two-port or Wi-Fi lab where ShakerProxy hands out addresses."
	default:
		finding.Status = FindingOK
		finding.Detail = "ShakerProxy hands out the lab's addresses and no other DHCP server was seen."
	}
	return finding
}

func peerFinding(in RoutingInput, singleArm bool) Finding {
	finding := Finding{ID: FindingPeerToPeer, Title: "Device-to-device traffic (AirPlay, casting, local SSH)"}
	switch {
	case singleArm:
		finding.Status = FindingGap
		finding.Detail = "Devices on the shared network talk to each other directly. ShakerProxy only sees traffic devices send to it as their gateway, so AirPlay, Chromecast, local file sharing and SSH between lab devices are invisible."
		finding.Fix = "Use ShakerProxy's Wi-Fi access point, which forwards device-to-device traffic through the appliance."
	case in.WirelessAccessPoint:
		finding.Status = FindingOK
		finding.Detail = "Wi-Fi clients reach each other through ShakerProxy's access point, so their device-to-device traffic is recorded."
	default:
		finding.Status = FindingUnknown
		finding.Detail = "Devices that share a switch on the lab side talk to each other directly; ShakerProxy sees only traffic that crosses it."
		finding.Fix = "Connect one test device per lab port, or use ShakerProxy's Wi-Fi access point."
	}
	return finding
}

func encryptedDNSFindings(in RoutingInput) []Finding {
	if !in.PolicyAvailable {
		return []Finding{{ID: FindingEncryptedDNS, Title: "Encrypted DNS (DoH, DoT, DoQ)", Status: FindingUnknown,
			Detail: "The DNS policy could not be read, so it is unknown whether encrypted DNS is blocked."}}
	}
	missing := []string{}
	if !in.BlockDoT {
		missing = append(missing, "DNS over TLS")
	}
	if !in.BlockDoQ {
		missing = append(missing, "DNS over QUIC")
	}
	if !in.BlockKnownDoH {
		missing = append(missing, "DNS over HTTPS")
	}
	encrypted := Finding{ID: FindingEncryptedDNS, Title: "Encrypted DNS (DoH, DoT, DoQ)"}
	if len(missing) == 0 {
		encrypted.Status = FindingOK
		encrypted.Detail = "Encrypted DNS to known resolvers is blocked, so devices fall back to DNS that ShakerProxy records."
	} else {
		encrypted.Status = FindingGap
		encrypted.Detail = fmt.Sprintf("%s is allowed and shown in Traffic as DoH, DoT or DoQ: ShakerProxy sees which resolver a device uses, but not the names it looks up.", joinWords(missing))
		encrypted.Fix = "To see those names, turn on Block encrypted DNS on DNS & HTTPS; devices then fall back to plain DNS."
	}
	plain := Finding{ID: FindingPlainDNS, Title: "DNS sent to other resolvers"}
	if in.RedirectPlainDNS {
		plain.Status = FindingOK
		plain.Detail = "Plain DNS sent to any resolver is redirected to ShakerProxy's DNS forwarder, so every lookup is answered and recorded in real time."
	} else {
		plain.Status = FindingGap
		plain.Detail = "Plain DNS sent to resolvers other than ShakerProxy (for example 8.8.8.8) is not redirected; those lookups appear only once the recording is analyzed, and only while a recording runs."
		plain.Fix = "On DNS & HTTPS, turn on redirecting plain DNS to ShakerProxy."
	}
	return []Finding{encrypted, plain}
}

func discoveryFinding(singleArm bool) Finding {
	finding := Finding{ID: FindingLocalDiscovery, Title: "Local discovery (mDNS/Bonjour, SSDP)"}
	if singleArm {
		finding.Status = FindingOK
		finding.Detail = "The recording keeps every device's multicast and broadcast on the shared network (mDNS/Bonjour, SSDP, LLMNR, NetBIOS, DHCP), the discovery AirPlay, Chromecast and smart-home apps use. Unicast traffic between two devices still does not cross ShakerProxy."
	} else {
		finding.Status = FindingOK
		finding.Detail = "The lab segment is recorded in full, including multicast discovery."
	}
	return finding
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	if len(out) > 8 {
		out = append(out[:8], fmt.Sprintf("and %d more", len(out)-8))
	}
	return out
}

func joinWords(values []string) string {
	switch len(values) {
	case 0:
		return ""
	case 1:
		return values[0]
	default:
		return strings.Join(values[:len(values)-1], ", ") + " and " + values[len(values)-1]
	}
}

func orUnknown(value string) string {
	if value == "" {
		return "ShakerProxy"
	}
	return value
}
