package networkplan

import (
	"fmt"
	"net/netip"
	"strings"
)

const (
	// RadvdConfigPath is the ShakerProxy-owned radvd configuration. It is written
	// only by a guarded apply and restored byte-for-byte on rollback.
	RadvdConfigPath = "/etc/shakerproxy/radvd/shakerproxy.conf"
	// RadvdUnit is the hardened systemd unit that runs radvd for the lab.
	RadvdUnit = "shakerproxy-radvd.service"

	defaultIp6tablesPath = "/usr/sbin/ip6tables"

	// Router advertisement timing. Short intervals let devices notice a
	// rollback quickly; lifetimes follow RFC 4861 and RFC 8106 bounds
	// (MaxRtrAdvInterval <= RDNSS lifetime <= 2 * MaxRtrAdvInterval).
	radvdMinInterval       = 30
	radvdMaxInterval       = 120
	radvdRouterLifetime    = 600
	radvdPrefixValid       = 3600
	radvdPrefixPreferred   = 1800
	radvdDNSLifetime       = 240
	ip6tablesAttachWait    = "5"
	labIPv6ChangedForward  = "ip6tables filter/SHAKERPROXY-FORWARD"
	labIPv6ChangedInput    = "ip6tables filter/SHAKERPROXY-INPUT"
	labIPv6ChangedNAT      = "ip6tables nat/SHAKERPROXY-POSTROUTING"
	ipv6ForwardingSysctl   = "net.ipv6.conf.all.forwarding"
	ipv6AcceptRASysctlBase = "net.ipv6.conf."
)

// labNetplanAddresses returns the flow-sequence body of the lab interface's
// Netplan addresses: the IPv4 gateway and, when IPv6 is routed, the quoted
// IPv6 gateway address.
func labNetplanAddresses(plan Plan) string {
	addresses := fmt.Sprintf("%s/%d", plan.IPv4.GatewayAddress, netip.MustParsePrefix(plan.IPv4.LabCIDR).Bits())
	if labIPv6, ok := LabIPv6Routing(plan); ok {
		addresses += fmt.Sprintf(", %q", netip.PrefixFrom(labIPv6.Gateway, IPv6LabPrefixBits).String())
	}
	return addresses
}

func addIPv6Preview(preview *Preview, plan Plan, wan, lab Interface) {
	switch {
	case BlocksLabIPv6(plan):
		preview.FirewallRestoreIPv6 = renderDisabledIPv6Firewall(plan, lab)
		preview.ChangedObjects = append(preview.ChangedObjects, labIPv6ChangedForward)
		preview.AttachmentCommands = append(preview.AttachmentCommands, ipv6AttachmentPreview(defaultIp6tablesPath, "filter", IPv6ForwardParentUser, "SHAKERPROXY-FORWARD")...)
		preview.Impact = append(preview.Impact, "Forwarded lab IPv6 would be dropped by the ShakerProxy IPv6 firewall, so devices cannot bypass ShakerProxy over IPv6")
	case RoutesIPv6(plan):
		labIPv6, ok := LabIPv6Routing(plan)
		if !ok {
			return
		}
		preview.FirewallRestoreIPv6 = renderRoutedIPv6Firewall(plan, labIPv6, wan)
		preview.RadvdConf = renderRadvdConf(plan, labIPv6, lab)
		preview.ChangedObjects = append(preview.ChangedObjects, labIPv6ChangedForward, labIPv6ChangedInput)
		preview.AttachmentCommands = append(preview.AttachmentCommands, ipv6AttachmentPreview(defaultIp6tablesPath, "filter", IPv6ForwardParentUser, "SHAKERPROXY-FORWARD")...)
		preview.AttachmentCommands = append(preview.AttachmentCommands, ipv6AttachmentPreview(defaultIp6tablesPath, "filter", "INPUT", "SHAKERPROXY-INPUT")...)
		if labIPv6.NAT66 {
			preview.ChangedObjects = append(preview.ChangedObjects, labIPv6ChangedNAT)
			preview.AttachmentCommands = append(preview.AttachmentCommands, ipv6AttachmentPreview(defaultIp6tablesPath, "nat", "POSTROUTING", "SHAKERPROXY-POSTROUTING")...)
		}
		preview.ChangedObjects = append(preview.ChangedObjects, RadvdConfigPath, RadvdUnit, ipv6ForwardingSysctl, ipv6AcceptRASysctlBase+wan.CurrentName+".accept_ra")
		dns := make([]string, 0, len(labIPv6.DNS))
		for _, address := range labIPv6.DNS {
			dns = append(dns, address.String())
		}
		preview.Impact = append(preview.Impact,
			fmt.Sprintf("Lab devices would configure IPv6 addresses in %s from ShakerProxy router advertisements (SLAAC), with gateway %s and DNS %s", labIPv6.Prefix, labIPv6.Gateway, strings.Join(dns, ", ")),
			"IPv6 forwarding would be enabled only during confirmed apply; the WAN keeps accepting router advertisements so its own SLAAC address survives",
		)
		if labIPv6.NAT66 {
			preview.Impact = append(preview.Impact, fmt.Sprintf("Lab IPv6 traffic would leave through %s behind NAT66 (the WAN's IPv6 address)", wan.CurrentName))
		} else {
			preview.Impact = append(preview.Impact, fmt.Sprintf("Lab IPv6 addresses would be routed without NAT; your upstream router must route %s to ShakerProxy", labIPv6.Prefix))
		}
	}
}

func ipv6AttachmentPreview(path, table, parent, chain string) []CommandPreview {
	check := []string{"-w", ip6tablesAttachWait}
	insert := []string{"-w", ip6tablesAttachWait}
	if table == "nat" {
		check = append(check, "-t", "nat")
		insert = append(insert, "-t", "nat")
	}
	check = append(check, "-C", parent, "-j", chain)
	insert = append(insert, "-I", parent, "1", "-j", chain)
	return []CommandPreview{{Executable: path, Arguments: check}, {Executable: path, Arguments: insert}}
}

// BindIPv6HostEvidence adjusts the IPv6 part of a preview to the bound host
// inspection: it selects the ip6tables executable and forward-chain parent,
// drops the DISABLED firewall when the kernel has no IPv6 at all, and states
// plainly when the host blocks an IPv6 apply.
func BindIPv6HostEvidence(preview *Preview) {
	if preview.FirewallRestoreIPv6 == "" {
		return
	}
	env := preview.FirewallEnvironment
	if !env.IPv6Available {
		if preview.RadvdConf != "" {
			preview.Impact = append(preview.Impact, "Host apply remains blocked: IPv6 is turned off in this host's kernel, so ShakerProxy cannot route lab IPv6")
			return
		}
		preview.FirewallRestoreIPv6 = ""
		preview.ChangedObjects = removeStrings(preview.ChangedObjects, labIPv6ChangedForward)
		preview.AttachmentCommands = removeIPv6Attachments(preview.AttachmentCommands)
		preview.Impact = append(preview.Impact, "IPv6 is turned off in this host's kernel, so lab devices cannot use ShakerProxy for IPv6 and no IPv6 firewall is needed")
		return
	}
	if !env.IPv6FirewallReady {
		preview.Impact = append(preview.Impact, "Host apply remains blocked: the IPv6 firewall (ip6tables) could not be inspected")
		return
	}
	parent := IPv6ForwardParent(env)
	for index, command := range preview.AttachmentCommands {
		if !isIp6tablesPath(command.Executable) {
			continue
		}
		preview.AttachmentCommands[index].Executable = env.Ip6tablesPath
		arguments := append([]string(nil), command.Arguments...)
		for position := range arguments {
			if position > 0 && arguments[position] == IPv6ForwardParentUser && (arguments[position-1] == "-C" || arguments[position-1] == "-I") {
				arguments[position] = parent
			}
		}
		preview.AttachmentCommands[index].Arguments = arguments
	}
	if parent == IPv6ForwardParentChain {
		preview.Impact = append(preview.Impact, "Docker does not manage IPv6 firewall rules on this host, so ShakerProxy attaches its IPv6 rules directly to FORWARD")
	}
}

func isIp6tablesPath(path string) bool {
	return path == "/usr/sbin/ip6tables" || path == "/usr/bin/ip6tables"
}

func removeIPv6Attachments(commands []CommandPreview) []CommandPreview {
	kept := make([]CommandPreview, 0, len(commands))
	for _, command := range commands {
		if !isIp6tablesPath(command.Executable) {
			kept = append(kept, command)
		}
	}
	return kept
}

func removeStrings(values []string, remove string) []string {
	kept := make([]string, 0, len(values))
	for _, value := range values {
		if value != remove {
			kept = append(kept, value)
		}
	}
	return kept
}

// renderDisabledIPv6Firewall drops every forwarded IPv6 packet entering or
// leaving the lab. It is the active part of the DISABLED strategy.
func renderDisabledIPv6Firewall(plan Plan, lab Interface) string {
	var b strings.Builder
	b.WriteString("*filter\n:SHAKERPROXY-FORWARD - [0:0]\n")
	// A bridged wired/Wi-Fi lab still behaves like one switch for IPv6
	// (link-local, neighbor discovery, mDNS); only forwarding is blocked.
	b.WriteString(wifiBridgeForwardRules(plan, lab))
	fmt.Fprintf(&b, "-A SHAKERPROXY-FORWARD -i %s -j DROP\n", lab.CurrentName)
	fmt.Fprintf(&b, "-A SHAKERPROXY-FORWARD -o %s -j DROP\n", lab.CurrentName)
	b.WriteString("COMMIT\n")
	return b.String()
}

// renderRoutedIPv6Firewall mirrors the IPv4 ShakerProxy chains for a routed lab
// prefix and adds the ICMPv6 that RFC 4890 says must not be filtered.
func renderRoutedIPv6Firewall(plan Plan, labIPv6 LabIPv6, wan Interface) string {
	lab := labIPv6.Interface
	prefix := labIPv6.Prefix.String()
	var b strings.Builder
	b.WriteString("*filter\n:SHAKERPROXY-FORWARD - [0:0]\n:SHAKERPROXY-INPUT - [0:0]\n")
	if plan.WAN.ClampMSS {
		fmt.Fprintf(&b, "-A SHAKERPROXY-FORWARD -o %s -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu\n", wan.CurrentName)
	}
	// Mirrors the IPv4 bridge rule: Docker's br_netfilter sends frames bridged
	// between the wired port and the access point through FORWARD, including
	// link-local neighbor discovery and mDNS that the anti-spoof rule drops.
	if labInterface, ok := LabInterface(plan); ok {
		b.WriteString(wifiBridgeForwardRules(plan, labInterface))
	}
	fmt.Fprintf(&b, "-A SHAKERPROXY-FORWARD -i %s ! -s %s -j DROP\n", lab, prefix)
	b.WriteString("-A SHAKERPROXY-FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")
	fmt.Fprintf(&b, "-A SHAKERPROXY-FORWARD -i %s -o %s -s %s -j ACCEPT\n", lab, wan.CurrentName, prefix)
	if !plan.IPv4.ClientIsolation {
		fmt.Fprintf(&b, "-A SHAKERPROXY-FORWARD -i %s -o %s -s %s -d %s -j ACCEPT\n", lab, lab, prefix, prefix)
	} else {
		fmt.Fprintf(&b, "-A SHAKERPROXY-FORWARD -i %s -o %s -s %s -d %s -j DROP\n", lab, lab, prefix, prefix)
	}
	for _, icmpType := range []string{"destination-unreachable", "packet-too-big", "time-exceeded", "parameter-problem"} {
		fmt.Fprintf(&b, "-A SHAKERPROXY-FORWARD -o %s -d %s -p ipv6-icmp -m icmp6 --icmpv6-type %s -j ACCEPT\n", lab, prefix, icmpType)
	}
	fmt.Fprintf(&b, "-A SHAKERPROXY-FORWARD -i %s -o %s -d %s -j DROP\n", wan.CurrentName, lab, prefix)
	fmt.Fprintf(&b, "-A SHAKERPROXY-FORWARD -i %s -j DROP\n", lab)
	fmt.Fprintf(&b, "-A SHAKERPROXY-FORWARD -o %s -j DROP\n", lab)
	for _, icmpType := range []string{"router-solicitation", "neighbour-solicitation", "neighbour-advertisement"} {
		fmt.Fprintf(&b, "-A SHAKERPROXY-INPUT -i %s -p ipv6-icmp -m icmp6 --icmpv6-type %s -m hl --hl-eq 255 -j ACCEPT\n", lab, icmpType)
	}
	for _, mldType := range []string{"130", "131", "132", "143"} {
		fmt.Fprintf(&b, "-A SHAKERPROXY-INPUT -i %s -s fe80::/10 -p ipv6-icmp -m icmp6 --icmpv6-type %s -j ACCEPT\n", lab, mldType)
	}
	for _, icmpType := range []string{"echo-request", "destination-unreachable", "packet-too-big", "time-exceeded", "parameter-problem"} {
		fmt.Fprintf(&b, "-A SHAKERPROXY-INPUT -i %s -p ipv6-icmp -m icmp6 --icmpv6-type %s -j ACCEPT\n", lab, icmpType)
	}
	for _, protocol := range []string{"udp", "tcp"} {
		fmt.Fprintf(&b, "-A SHAKERPROXY-INPUT -i %s -s %s -p %s -m %s --dport 53 -j ACCEPT\n", lab, prefix, protocol, protocol)
	}
	b.WriteString("COMMIT\n")
	if labIPv6.NAT66 {
		b.WriteString("*nat\n:SHAKERPROXY-POSTROUTING - [0:0]\n")
		fmt.Fprintf(&b, "-A SHAKERPROXY-POSTROUTING -s %s -o %s -j MASQUERADE\n", prefix, wan.CurrentName)
		b.WriteString("COMMIT\n")
	}
	return b.String()
}

// renderRadvdConf announces the lab /64 for SLAAC with RDNSS. On shutdown or
// rollback radvd withdraws itself as default router and deprecates the prefix.
func renderRadvdConf(plan Plan, labIPv6 LabIPv6, lab Interface) string {
	var b strings.Builder
	b.WriteString("# ShakerProxy router advertisements for the lab network.\n")
	b.WriteString("# Generated from the confirmed network plan; manual edits are overwritten.\n")
	fmt.Fprintf(&b, "interface %s\n{\n", labIPv6.Interface)
	b.WriteString("\tAdvSendAdvert on;\n\tIgnoreIfMissing on;\n")
	fmt.Fprintf(&b, "\tMinRtrAdvInterval %d;\n\tMaxRtrAdvInterval %d;\n\tAdvDefaultLifetime %d;\n", radvdMinInterval, radvdMaxInterval, radvdRouterLifetime)
	b.WriteString("\tAdvManagedFlag off;\n\tAdvOtherConfigFlag off;\n")
	if lab.MTU != 0 {
		fmt.Fprintf(&b, "\tAdvLinkMTU %d;\n", lab.MTU)
	}
	fmt.Fprintf(&b, "\tprefix %s\n\t{\n", labIPv6.Prefix)
	b.WriteString("\t\tAdvOnLink on;\n\t\tAdvAutonomous on;\n\t\tAdvRouterAddr off;\n")
	fmt.Fprintf(&b, "\t\tAdvValidLifetime %d;\n\t\tAdvPreferredLifetime %d;\n", radvdPrefixValid, radvdPrefixPreferred)
	b.WriteString("\t\tDeprecatePrefix on;\n\t};\n")
	dns := make([]string, 0, len(labIPv6.DNS))
	for _, address := range labIPv6.DNS {
		dns = append(dns, address.String())
	}
	fmt.Fprintf(&b, "\tRDNSS %s\n\t{\n\t\tAdvRDNSSLifetime %d;\n\t};\n", strings.Join(dns, " "), radvdDNSLifetime)
	if plan.IPv4.SearchDomain != "" {
		fmt.Fprintf(&b, "\tDNSSL %s\n\t{\n\t\tAdvDNSSLLifetime %d;\n\t};\n", plan.IPv4.SearchDomain, radvdDNSLifetime)
	}
	b.WriteString("};\n")
	return b.String()
}

// LabIPv6FirewallMode names the ShakerProxy ip6tables state a preview installs:
// "" (none), "BLOCK" (DISABLED drop rules) or "ROUTE" (routed lab prefix).
func LabIPv6FirewallMode(preview Preview) string {
	switch {
	case preview.FirewallRestoreIPv6 == "":
		return ""
	case preview.RadvdConf != "":
		return "ROUTE"
	default:
		return "BLOCK"
	}
}
