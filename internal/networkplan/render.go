package networkplan

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

func BuildPreview(plan Plan, now time.Time) Preview {
	return BuildPreviewWithValidation(plan, Validate(plan), now)
}

func BuildPreviewWithValidation(plan Plan, validation ValidationResult, now time.Time) Preview {
	preview := Preview{Validation: validation, GeneratedAt: now.UTC(), FirewallBackend: "iptables", ChangedObjects: []string{}, Impact: []string{}}
	if !validation.Valid {
		return preview
	}
	preview.ChangedObjects = []string{"/etc/netplan/90-shakerproxy.yaml", "iptables filter/SHAKERPROXY-FORWARD"}
	preview.Impact = []string{"IPv4 forwarding would be enabled only during confirmed apply", "Active SSH preservation remains mandatory", "An independent rollback deadline is required before loading this plan"}
	if plan.Topology == TopologyPassiveSensor {
		preview.NetplanYAML = renderPassiveNetplan(plan)
		preview.ChangedObjects = []string{"/etc/netplan/90-shakerproxy.yaml"}
		preview.Impact = []string{"No routing, NAT, DHCP, DNS redirection, or interception would be enabled", "The passive interface would accept no IPv4 or IPv6 address configuration"}
		return preview
	}
	wan, _ := WANInterface(plan)
	lab, _ := LabInterface(plan)
	preview.NetplanYAML = renderRoutedNetplan(plan, wan, lab)
	if UsesManagedDHCP4(plan) {
		preview.KeaDHCP4JSON = renderKeaDHCP4(plan, lab)
		preview.ChangedObjects = append(preview.ChangedObjects, "/etc/kea/kea-dhcp4.conf")
		preview.Impact = append(preview.Impact, "DHCPv4 would start on the lab interface only after the rollback deadline is armed")
	} else {
		preview.Impact = append(preview.Impact, "ShakerProxy DHCPv4 would remain disabled; clients must be configured manually")
	}
	if wanConfigurationChangesHost(plan.WAN, wan) {
		preview.Impact = append(preview.Impact, "WAN addressing or MTU would be changed only because the reviewed plan explicitly selected it")
	} else {
		preview.Impact = append(preview.Impact, "Existing WAN addressing, routes, MTU, and DNS ownership would remain untouched")
	}
	if plan.WAN.UpstreamNAT && plan.IPv4.NAT44 {
		preview.Impact = append(preview.Impact, "The lab would operate behind deliberate double NAT")
	}
	if plan.Topology == TopologySingleArm {
		preview.ChangedObjects = append(preview.ChangedObjects, "net.ipv4.conf."+wan.CurrentName+".send_redirects")
		preview.Impact = append(preview.Impact,
			"The existing interface address, route, DNS, VLAN, and MTU would remain untouched",
			"IPv4 ICMP redirects would be disabled transactionally so clients keep using ShakerProxy",
			"Same-subnet client-to-client traffic cannot be isolated or forced through ShakerProxy",
		)
	}
	if plan.Topology != TopologySingleArm && plan.IPv6.Strategy == IPv6Disabled {
		preview.Impact = append(preview.Impact, "IPv6 RA, DHCPv6, and link-local addressing would be disabled on the ShakerProxy lab interface")
	} else if plan.Topology != TopologySingleArm && plan.IPv6.Strategy == IPv6ObserveOnly {
		preview.Impact = append(preview.Impact, "The ShakerProxy lab interface would receive no IPv6 address or route; raw capture may still observe IPv6 frames")
	}
	preview.FirewallRestoreIPv4 = renderIPv4Firewall(plan, wan, lab)
	preview.AttachmentCommands = []CommandPreview{
		{Executable: "/usr/sbin/iptables", Arguments: []string{"-w", "5", "-C", "DOCKER-USER", "-j", "SHAKERPROXY-FORWARD"}},
		{Executable: "/usr/sbin/iptables", Arguments: []string{"-w", "5", "-I", "DOCKER-USER", "1", "-j", "SHAKERPROXY-FORWARD"}},
	}
	if plan.IPv4.NAT44 {
		preview.ChangedObjects = append(preview.ChangedObjects, "iptables nat/SHAKERPROXY-POSTROUTING")
		preview.AttachmentCommands = append(preview.AttachmentCommands,
			CommandPreview{Executable: "/usr/sbin/iptables", Arguments: []string{"-w", "5", "-t", "nat", "-C", "POSTROUTING", "-j", "SHAKERPROXY-POSTROUTING"}},
			CommandPreview{Executable: "/usr/sbin/iptables", Arguments: []string{"-w", "5", "-t", "nat", "-I", "POSTROUTING", "1", "-j", "SHAKERPROXY-POSTROUTING"}},
		)
	}
	addWiFiPreview(&preview, plan)
	addIPv6Preview(&preview, plan, wan, lab)
	return preview
}

type keaDHCP4Config struct {
	DHCP4 keaDHCP4 `json:"Dhcp4"`
}

type keaDHCP4 struct {
	Interfaces    keaInterfaces `json:"interfaces-config"`
	LeaseDatabase keaLeaseDB    `json:"lease-database"`
	RenewTimer    int           `json:"renew-timer"`
	RebindTimer   int           `json:"rebind-timer"`
	ValidLifetime int           `json:"valid-lifetime"`
	Subnet4       []keaSubnet4  `json:"subnet4"`
}

type keaInterfaces struct {
	Interfaces     []string `json:"interfaces"`
	DHCPSocketType string   `json:"dhcp-socket-type"`
}

type keaLeaseDB struct {
	Type        string `json:"type"`
	Persist     bool   `json:"persist"`
	Name        string `json:"name"`
	LFCInterval int    `json:"lfc-interval"`
}

type keaSubnet4 struct {
	ID           int              `json:"id"`
	Subnet       string           `json:"subnet"`
	Pools        []keaPool        `json:"pools"`
	OptionData   []keaOption      `json:"option-data"`
	Reservations []keaReservation `json:"reservations,omitempty"`
}

type keaPool struct {
	Pool string `json:"pool"`
}

type keaOption struct {
	Name string `json:"name"`
	Data string `json:"data"`
}

type keaReservation struct {
	HardwareAddress string `json:"hw-address"`
	IPAddress       string `json:"ip-address"`
	Hostname        string `json:"hostname,omitempty"`
}

func renderKeaDHCP4(plan Plan, lab Interface) string {
	leaseSeconds := normalizedDHCPLeaseSeconds(plan.IPv4.DHCPLeaseSeconds)
	dnsAddresses := append([]string(nil), plan.IPv4.DNSAddresses...)
	if len(dnsAddresses) == 0 {
		dnsAddresses = []string{plan.IPv4.GatewayAddress}
	}
	options := []keaOption{
		{Name: "routers", Data: plan.IPv4.GatewayAddress},
		{Name: "domain-name-servers", Data: strings.Join(dnsAddresses, ", ")},
	}
	if plan.IPv4.SearchDomain != "" {
		options = append(options, keaOption{Name: "domain-name", Data: plan.IPv4.SearchDomain})
	}
	reservations := make([]keaReservation, 0, len(plan.IPv4.Reservations))
	for _, reservation := range plan.IPv4.Reservations {
		hardwareAddress, _ := net.ParseMAC(reservation.HardwareAddress)
		reservations = append(reservations, keaReservation{
			HardwareAddress: hardwareAddress.String(),
			IPAddress:       reservation.IPAddress,
			Hostname:        reservation.Hostname,
		})
	}
	sort.Slice(reservations, func(i, j int) bool {
		if reservations[i].IPAddress == reservations[j].IPAddress {
			return reservations[i].HardwareAddress < reservations[j].HardwareAddress
		}
		return reservations[i].IPAddress < reservations[j].IPAddress
	})
	config := keaDHCP4Config{DHCP4: keaDHCP4{
		Interfaces: keaInterfaces{Interfaces: []string{lab.CurrentName}, DHCPSocketType: "raw"},
		LeaseDatabase: keaLeaseDB{
			Type: "memfile", Persist: true, Name: "/var/lib/kea/kea-leases4.csv", LFCInterval: 3600,
		},
		RenewTimer:    leaseSeconds / 2,
		RebindTimer:   leaseSeconds * 7 / 8,
		ValidLifetime: leaseSeconds,
		Subnet4: []keaSubnet4{{
			ID:           1,
			Subnet:       netip.MustParsePrefix(plan.IPv4.LabCIDR).Masked().String(),
			Pools:        []keaPool{{Pool: plan.IPv4.DHCPStart + " - " + plan.IPv4.DHCPEnd}},
			OptionData:   options,
			Reservations: reservations,
		}},
	}}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		panic("networkplan: static Kea configuration cannot be encoded: " + err.Error())
	}
	return string(encoded) + "\n"
}

func renderIPv4Firewall(plan Plan, wan, lab Interface) string {
	prefix := netip.MustParsePrefix(plan.IPv4.LabCIDR).Masked().String()
	var b strings.Builder
	b.WriteString("*filter\n:SHAKERPROXY-FORWARD - [0:0]\n")
	if plan.Topology == TopologySingleArm {
		b.WriteString("-A SHAKERPROXY-FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")
		fmt.Fprintf(&b, "-A SHAKERPROXY-FORWARD -i %s -o %s -s %s -j ACCEPT\n", lab.CurrentName, wan.CurrentName, prefix)
		fmt.Fprintf(&b, "-A SHAKERPROXY-FORWARD -i %s -o %s -d %s -j DROP\n", wan.CurrentName, lab.CurrentName, prefix)
		b.WriteString("COMMIT\n")
		if plan.IPv4.NAT44 {
			b.WriteString("*nat\n:SHAKERPROXY-POSTROUTING - [0:0]\n")
			fmt.Fprintf(&b, "-A SHAKERPROXY-POSTROUTING -s %s -o %s -j MASQUERADE\n", prefix, wan.CurrentName)
			b.WriteString("COMMIT\n")
		}
		return b.String()
	}
	b.WriteString(wifiBridgeForwardRules(plan, lab))
	fmt.Fprintf(&b, "-A SHAKERPROXY-FORWARD -i %s ! -s %s -j DROP\n", lab.CurrentName, prefix)
	b.WriteString("-A SHAKERPROXY-FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")
	fmt.Fprintf(&b, "-A SHAKERPROXY-FORWARD -i %s -o %s -s %s -j ACCEPT\n", lab.CurrentName, wan.CurrentName, prefix)
	if !plan.IPv4.ClientIsolation {
		fmt.Fprintf(&b, "-A SHAKERPROXY-FORWARD -i %s -o %s -s %s -d %s -j ACCEPT\n", lab.CurrentName, lab.CurrentName, prefix, prefix)
	} else {
		fmt.Fprintf(&b, "-A SHAKERPROXY-FORWARD -i %s -o %s -s %s -d %s -j DROP\n", lab.CurrentName, lab.CurrentName, prefix, prefix)
	}
	fmt.Fprintf(&b, "-A SHAKERPROXY-FORWARD -i %s -o %s -d %s -j DROP\n", wan.CurrentName, lab.CurrentName, prefix)
	b.WriteString("COMMIT\n")
	if plan.IPv4.NAT44 {
		b.WriteString("*nat\n:SHAKERPROXY-POSTROUTING - [0:0]\n")
		fmt.Fprintf(&b, "-A SHAKERPROXY-POSTROUTING -s %s -o %s -j MASQUERADE\n", prefix, wan.CurrentName)
		b.WriteString("COMMIT\n")
	}
	return b.String()
}

func renderRoutedNetplan(plan Plan, wan, lab Interface) string {
	// KEEP_EXISTING deliberately omits the WAN. Netplan merges this dedicated
	// file with the administrator/cloud-init definition; explicit WAN modes are
	// rendered only after host-aware validation and acknowledgement.
	var b strings.Builder
	b.WriteString("network:\n  version: 2\n")
	if plan.Topology == TopologySingleArm {
		return b.String()
	}
	if plan.Topology == TopologyVLANTrunk {
		parent := vlanParentName(wan.CurrentName)
		b.WriteString("  ethernets:\n")
		fmt.Fprintf(&b, "    %s: {}\n", parent)
		b.WriteString("  vlans:\n")
		renderVLANNetplan(&b, wan, parent, plan.WAN, "", "")
		renderVLANNetplan(&b, lab, parent, WANConfiguration{}, labNetplanAddresses(plan), plan.IPv6.Strategy)
		return b.String()
	}
	b.WriteString("  ethernets:\n")
	if wanConfigurationChangesHost(plan.WAN, wan) {
		fmt.Fprintf(&b, "    %s:\n", wan.CurrentName)
		renderWANNetplan(&b, plan.WAN, wan.MTU, 6)
	}
	if WiFiEnabled(plan) {
		renderWiFiLabNetplan(&b, plan, lab)
		return b.String()
	}
	fmt.Fprintf(&b, "    %s:\n", lab.CurrentName)
	fmt.Fprintf(&b, "      addresses: [%s]\n", labNetplanAddresses(plan))
	renderLabIPv6Netplan(&b, plan.IPv6.Strategy, 6)
	if lab.MTU != 0 {
		fmt.Fprintf(&b, "      mtu: %d\n", lab.MTU)
	}
	return b.String()
}

func renderVLANNetplan(b *strings.Builder, iface Interface, parent string, wan WANConfiguration, labAddress string, labIPv6 IPv6Strategy) {
	fmt.Fprintf(b, "    %s:\n", iface.CurrentName)
	fmt.Fprintf(b, "      id: %d\n      link: %s\n", *iface.VLANID, parent)
	if labAddress != "" {
		fmt.Fprintf(b, "      addresses: [%s]\n", labAddress)
		renderLabIPv6Netplan(b, labIPv6, 6)
		if iface.MTU != 0 {
			fmt.Fprintf(b, "      mtu: %d\n", iface.MTU)
		}
		return
	}
	renderWANNetplan(b, wan, iface.MTU, 6)
}

func renderLabIPv6Netplan(b *strings.Builder, strategy IPv6Strategy, indent int) {
	spaces := strings.Repeat(" ", indent)
	switch strategy {
	case IPv6Disabled, IPv6ObserveOnly:
		fmt.Fprintf(b, "%sdhcp6: false\n%saccept-ra: false\n%slink-local: []\n", spaces, spaces, spaces)
	case IPv6ULANAT66Lab, IPv6NativeRouted:
		// ShakerProxy is the lab's IPv6 router: it keeps its link-local address
		// for router advertisements and never learns routes from the lab.
		fmt.Fprintf(b, "%sdhcp6: false\n%saccept-ra: false\n", spaces, spaces)
	}
}

func renderWANNetplan(b *strings.Builder, config WANConfiguration, mtu, indent int) {
	spaces := strings.Repeat(" ", indent)
	addresses := []string{}
	type route struct{ to, via string }
	routes := []route{}
	switch effectiveWANIPv4Mode(config.IPv4Mode) {
	case WANIPv4DHCP:
		fmt.Fprintf(b, "%sdhcp4: true\n", spaces)
		if effectiveWANDNSMode(config.DNSMode) == WANDNSIgnoreDHCP {
			fmt.Fprintf(b, "%sdhcp4-overrides:\n%s  use-dns: false\n", spaces, spaces)
		}
	case WANIPv4Static:
		fmt.Fprintf(b, "%sdhcp4: false\n", spaces)
		addresses = append(addresses, config.IPv4Address)
		routes = append(routes, route{to: "0.0.0.0/0", via: config.IPv4Gateway})
	}
	switch effectiveWANIPv6Mode(config.IPv6Mode) {
	case WANIPv6SLAAC:
		fmt.Fprintf(b, "%saccept-ra: true\n%sdhcp6: false\n", spaces, spaces)
	case WANIPv6DHCP:
		fmt.Fprintf(b, "%saccept-ra: true\n%sdhcp6: true\n", spaces, spaces)
	case WANIPv6Static:
		fmt.Fprintf(b, "%saccept-ra: false\n%sdhcp6: false\n", spaces, spaces)
		addresses = append(addresses, config.IPv6Address)
		routes = append(routes, route{to: "::/0", via: config.IPv6Gateway})
	case WANIPv6None:
		fmt.Fprintf(b, "%saccept-ra: false\n%sdhcp6: false\n", spaces, spaces)
	}
	if len(addresses) > 0 {
		fmt.Fprintf(b, "%saddresses: [%s]\n", spaces, strings.Join(addresses, ", "))
	}
	if len(routes) > 0 {
		fmt.Fprintf(b, "%sroutes:\n", spaces)
		for _, route := range routes {
			fmt.Fprintf(b, "%s  - to: %s\n%s    via: %s\n", spaces, route.to, spaces, route.via)
		}
	}
	if mtu != 0 {
		fmt.Fprintf(b, "%smtu: %d\n", spaces, mtu)
	}
}

func vlanParentName(name string) string {
	if index := strings.LastIndex(name, "."); index > 0 {
		return name[:index]
	}
	return name
}

func renderPassiveNetplan(plan Plan) string {
	mirror, _ := InterfaceForRole(plan, RoleMirror)
	mtu := ""
	if mirror.MTU != 0 {
		mtu = fmt.Sprintf("      mtu: %d\n", mirror.MTU)
	}
	return fmt.Sprintf("network:\n  version: 2\n  ethernets:\n    %s:\n      dhcp4: false\n      dhcp6: false\n      accept-ra: false\n      link-local: []\n      optional: true\n%s", mirror.CurrentName, mtu)
}
