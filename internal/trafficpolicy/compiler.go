package trafficpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

const OwnedNFTTable = "shakerproxy_dynamic_policy"

type CompileOptions struct {
	ReplaceExisting     bool
	TLSBackendAvailable bool
}

type Compiled struct {
	NFTables       []byte `json:"-"`
	ProxyPolicy    []byte `json:"-"`
	PolicyDigest   string `json:"policy_digest"`
	ResolverIPv4   int    `json:"resolver_ipv4"`
	ResolverIPv6   int    `json:"resolver_ipv6"`
	TLSBypassRules int    `json:"tls_bypass_rules"`
	TLSDegraded    bool   `json:"tls_degraded"`
}

type ProxySnapshot struct {
	SchemaVersion     int                   `json:"schema_version"`
	PolicyID          string                `json:"policy_id"`
	Revision          uint64                `json:"revision"`
	Digest            string                `json:"digest"`
	Enabled           bool                  `json:"enabled"`
	TLS               TLSInterceptionPolicy `json:"tls"`
	EncryptedDNS      EnforcementDNSPolicy  `json:"encrypted_dns"`
	ResolverHostnames []string              `json:"resolver_hostnames"`
	ResolverAddresses []string              `json:"resolver_addresses"`
	DeviceByIP        map[string]string     `json:"device_by_ip,omitempty"`
	DevicePlatforms   map[string]string     `json:"device_platforms,omitempty"`
	GeneratedAt       time.Time             `json:"generated_at"`
}

func Compile(request ApplyRequest, options CompileOptions, now time.Time) (Compiled, error) {
	if err := request.NormalizeAndValidate(now); err != nil {
		return Compiled{}, err
	}
	resolverIPv4, resolverIPv6, resolverHostnames := resolverBlockTargets(request.Policy)
	proxyAddresses := append(append([]string{}, resolverIPv4...), resolverIPv6...)
	proxySnapshot := ProxySnapshot{
		SchemaVersion:     SchemaVersion,
		PolicyID:          request.PolicyID,
		Revision:          request.Revision,
		Digest:            request.Digest,
		Enabled:           request.Policy.Enabled,
		TLS:               request.Policy.TLS,
		EncryptedDNS:      request.Policy.EncryptedDNS,
		ResolverHostnames: resolverHostnames,
		ResolverAddresses: proxyAddresses,
		DeviceByIP:        unambiguousDeviceAddresses(request.Runtime),
		DevicePlatforms:   request.Runtime.DevicePlatforms,
		GeneratedAt:       now.UTC(),
	}
	proxyPolicy, err := json.MarshalIndent(proxySnapshot, "", "  ")
	if err != nil {
		return Compiled{}, fmt.Errorf("encode MITM policy snapshot: %w", err)
	}
	proxyPolicy = append(proxyPolicy, '\n')

	compiled := Compiled{
		ProxyPolicy:    proxyPolicy,
		PolicyDigest:   request.Digest,
		ResolverIPv4:   len(resolverIPv4),
		ResolverIPv6:   len(resolverIPv6),
		TLSBypassRules: enabledBypassCount(request.Policy.TLS.BypassRules, now),
	}
	if !request.Policy.Enabled {
		if options.ReplaceExisting {
			compiled.NFTables = []byte("delete table inet " + OwnedNFTTable + "\n")
		}
		return compiled, nil
	}

	var script bytes.Buffer
	if options.ReplaceExisting {
		script.WriteString("delete table inet ")
		script.WriteString(OwnedNFTTable)
		script.WriteByte('\n')
	}
	script.WriteString("table inet ")
	script.WriteString(OwnedNFTTable)
	script.WriteString(" {\n")
	writeAddressSet(&script, "scope4", "ipv4_addr", request.Runtime.ScopeIPv4)
	writeAddressSet(&script, "scope6", "ipv6_addr", request.Runtime.ScopeIPv6)
	writeAddressSet(&script, "resolver_doh4", "ipv4_addr", resolverIPv4)
	writeAddressSet(&script, "resolver_doh6", "ipv6_addr", resolverIPv6)
	dnsSelected4, dnsSelected6 := selectedDeviceAddresses(request.Policy.EncryptedDNS.SelectedDeviceIDs, request.Runtime)
	tlsSelected4, tlsSelected6 := selectedDeviceAddresses(request.Policy.TLS.SelectedDeviceIDs, request.Runtime)
	writeAddressSet(&script, "dns_selected4", "ipv4_addr", dnsSelected4)
	writeAddressSet(&script, "dns_selected6", "ipv6_addr", dnsSelected6)
	writeAddressSet(&script, "tls_selected4", "ipv4_addr", tlsSelected4)
	writeAddressSet(&script, "tls_selected6", "ipv6_addr", tlsSelected6)

	script.WriteString("  chain enforce_prerouting {\n")
	script.WriteString("    type filter hook prerouting priority -120; policy accept;\n")
	writeEnforcementRules(&script, request, resolverIPv4, resolverIPv6, dnsSelected4, dnsSelected6, tlsSelected4, tlsSelected6, options)
	script.WriteString("  }\n")

	script.WriteString("  chain redirect_prerouting {\n")
	script.WriteString("    type nat hook prerouting priority -110; policy accept;\n")
	writeRedirectRules(&script, request, dnsSelected4, dnsSelected6, tlsSelected4, tlsSelected6, options)
	script.WriteString("  }\n")
	script.WriteString("}\n")

	compiled.NFTables = InstrumentDetectionLogs(script.Bytes())
	compiled.TLSDegraded = request.Policy.TLS.Mode != "off" && !options.TLSBackendAvailable
	return compiled, nil
}

func writeEnforcementRules(script *bytes.Buffer, request ApplyRequest, resolverIPv4, resolverIPv6, dnsSelected4, dnsSelected6, tlsSelected4, tlsSelected6 []string, options CompileOptions) {
	dns := request.Policy.EncryptedDNS
	blocking := dns.Mode == "block" || dns.Mode == "strict"
	for _, interfaceName := range request.Runtime.TestInterfaces {
		interfaceExpr := "iifname " + nftQuote(interfaceName)
		if blocking && dns.BlockDoT {
			writeSelectedDualFamilyRule(script, interfaceExpr, request.Runtime, dns.SelectedDeviceIDs, dnsSelected4, dnsSelected6, "dns_selected", "tcp dport 853", "reject with tcp reset comment \"ShakerProxy block DoT\"")
		}
		if blocking && dns.BlockDoQ {
			writeSelectedDualFamilyRule(script, interfaceExpr, request.Runtime, dns.SelectedDeviceIDs, dnsSelected4, dnsSelected6, "dns_selected", "udp dport 853", "reject comment \"ShakerProxy block DoQ\"")
		}
		if blocking && dns.BlockKnownDoH {
			if len(resolverIPv4) != 0 {
				writeSelectedFamilyRule(script, interfaceExpr, request.Runtime.ScopeIPv4, true, dns.SelectedDeviceIDs, dnsSelected4, "dns_selected4", "ip daddr @resolver_doh4 tcp dport 443", "reject with tcp reset comment \"ShakerProxy block known DoH\"")
				writeSelectedFamilyRule(script, interfaceExpr, request.Runtime.ScopeIPv4, true, dns.SelectedDeviceIDs, dnsSelected4, "dns_selected4", "ip daddr @resolver_doh4 udp dport 443", "reject comment \"ShakerProxy block known DoH3\"")
			}
			if len(resolverIPv6) != 0 {
				writeSelectedFamilyRule(script, interfaceExpr, request.Runtime.ScopeIPv6, false, dns.SelectedDeviceIDs, dnsSelected6, "dns_selected6", "ip6 daddr @resolver_doh6 tcp dport 443", "reject with tcp reset comment \"ShakerProxy block known DoH\"")
				writeSelectedFamilyRule(script, interfaceExpr, request.Runtime.ScopeIPv6, false, dns.SelectedDeviceIDs, dnsSelected6, "dns_selected6", "ip6 daddr @resolver_doh6 udp dport 443", "reject comment \"ShakerProxy block known DoH3\"")
			}
		}
		if dns.Mode == "strict" && dns.BlockQUICForScope {
			writeSelectedDualFamilyRule(script, interfaceExpr, request.Runtime, dns.SelectedDeviceIDs, dnsSelected4, dnsSelected6, "dns_selected", "udp dport 443", "reject comment \"ShakerProxy strict block all QUIC\"")
		}
		if request.Policy.TLS.Mode != "off" && !options.TLSBackendAvailable && request.Policy.TLS.FailMode == "block" {
			ports := nftPortSet(request.Runtime.TLSInterceptPorts)
			writeSelectedDualFamilyRule(script, interfaceExpr, request.Runtime, request.Policy.TLS.SelectedDeviceIDs, tlsSelected4, tlsSelected6, "tls_selected", "tcp dport "+ports, "reject with tcp reset comment \"ShakerProxy TLS fail closed\"")
		}
	}
}

func writeRedirectRules(script *bytes.Buffer, request ApplyRequest, dnsSelected4, dnsSelected6, tlsSelected4, tlsSelected6 []string, options CompileOptions) {
	for _, interfaceName := range request.Runtime.TestInterfaces {
		interfaceExpr := "iifname " + nftQuote(interfaceName)
		if request.Policy.EncryptedDNS.RedirectPlainDNS {
			action := "redirect to :" + strconv.Itoa(request.Runtime.LocalDNSPort) + " comment \"ShakerProxy redirect DNS\""
			writeSelectedDualFamilyRule(script, interfaceExpr, request.Runtime, request.Policy.EncryptedDNS.SelectedDeviceIDs, dnsSelected4, dnsSelected6, "dns_selected", "udp dport 53", action)
			writeSelectedDualFamilyRule(script, interfaceExpr, request.Runtime, request.Policy.EncryptedDNS.SelectedDeviceIDs, dnsSelected4, dnsSelected6, "dns_selected", "tcp dport 53", action)
		}
		if request.Policy.TLS.Mode != "off" && options.TLSBackendAvailable {
			ports := nftPortSet(request.Runtime.TLSInterceptPorts)
			action := "redirect to :" + strconv.Itoa(request.Runtime.MITMPort) + " comment \"ShakerProxy TLS interception\""
			writeSelectedDualFamilyRule(script, interfaceExpr, request.Runtime, request.Policy.TLS.SelectedDeviceIDs, tlsSelected4, tlsSelected6, "tls_selected", "tcp dport "+ports, action)
		}
	}
}

func writeSelectedDualFamilyRule(script *bytes.Buffer, interfaceExpr string, runtime Runtime, selectedIDs, selected4, selected6 []string, setPrefix, match, action string) {
	writeSelectedFamilyRule(script, interfaceExpr, runtime.ScopeIPv4, true, selectedIDs, selected4, setPrefix+"4", match, action)
	writeSelectedFamilyRule(script, interfaceExpr, runtime.ScopeIPv6, false, selectedIDs, selected6, setPrefix+"6", match, action)
}

func writeSelectedFamilyRule(script *bytes.Buffer, interfaceExpr string, scope []string, ipv4 bool, selectedIDs, selectedAddresses []string, setName, match, action string) {
	if len(selectedIDs) != 0 {
		if len(selectedAddresses) == 0 {
			return
		}
		family := "ip"
		if !ipv4 {
			family = "ip6"
		}
		match = family + " saddr @" + setName + " " + match
	}
	writeFamilyRule(script, interfaceExpr, scope, ipv4, match, action)
}

func writeFamilyRule(script *bytes.Buffer, interfaceExpr string, scope []string, ipv4 bool, match, action string) {
	script.WriteString("    ")
	script.WriteString(interfaceExpr)
	script.WriteByte(' ')
	if ipv4 {
		script.WriteString("meta nfproto ipv4 ")
		if len(scope) != 0 {
			script.WriteString("ip saddr @scope4 ")
		}
	} else {
		script.WriteString("meta nfproto ipv6 ")
		if len(scope) != 0 {
			script.WriteString("ip6 saddr @scope6 ")
		}
	}
	script.WriteString(match)
	script.WriteByte(' ')
	script.WriteString(action)
	script.WriteByte('\n')
}

func writeAddressSet(script *bytes.Buffer, name, valueType string, values []string) {
	script.WriteString("  set ")
	script.WriteString(name)
	script.WriteString(" {\n")
	script.WriteString("    type ")
	script.WriteString(valueType)
	script.WriteString("; flags interval;\n")
	if len(values) != 0 {
		script.WriteString("    elements = { ")
		script.WriteString(strings.Join(values, ", "))
		script.WriteString(" }\n")
	}
	script.WriteString("  }\n")
}

func resolverBlockTargets(document EnforcementDocument) ([]string, []string, []string) {
	ipv4 := make([]string, 0)
	ipv6 := make([]string, 0)
	hostnames := make([]string, 0)
	for _, resolver := range document.Resolvers {
		hostnames = append(hostnames, resolver.Hostnames...)
		if resolver.Dedicated && resolver.SafeToBlockByIP {
			ipv4 = append(ipv4, resolver.IPv4...)
			ipv6 = append(ipv6, resolver.IPv6...)
		}
	}
	return uniqueSorted(ipv4), uniqueSorted(ipv6), uniqueSorted(hostnames)
}

func selectedDeviceAddresses(deviceIDs []string, runtime Runtime) ([]string, []string) {
	return selectedDeviceAddressesForFamily(deviceIDs, runtime.DeviceIPv4), selectedDeviceAddressesForFamily(deviceIDs, runtime.DeviceIPv6)
}

func selectedDeviceAddressesForFamily(deviceIDs []string, addresses map[string][]string) []string {
	values := make([]string, 0)
	for _, deviceID := range deviceIDs {
		values = append(values, addresses[deviceID]...)
	}
	return uniqueSorted(values)
}

func unambiguousDeviceAddresses(runtime Runtime) map[string]string {
	owners := make(map[string]string)
	ambiguous := make(map[string]bool)
	add := func(deviceID string, addresses []string) {
		for _, address := range addresses {
			if ambiguous[address] {
				continue
			}
			if previous, exists := owners[address]; exists && previous != deviceID {
				delete(owners, address)
				ambiguous[address] = true
				continue
			}
			owners[address] = deviceID
		}
	}
	for deviceID, addresses := range runtime.DeviceIPv4 {
		add(deviceID, addresses)
	}
	for deviceID, addresses := range runtime.DeviceIPv6 {
		add(deviceID, addresses)
	}
	return owners
}

func enabledBypassCount(rules []TLSBypassRule, now time.Time) int {
	count := 0
	for _, rule := range rules {
		if !rule.Enabled || (rule.ExpiresAt != nil && !rule.ExpiresAt.After(now)) {
			continue
		}
		count++
	}
	return count
}

func uniqueSorted(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func nftPortSet(ports []int) string {
	if len(ports) == 1 {
		return strconv.Itoa(ports[0])
	}
	values := make([]string, len(ports))
	for index, port := range ports {
		values[index] = strconv.Itoa(port)
	}
	return "{ " + strings.Join(values, ", ") + " }"
}

func nftQuote(value string) string {
	return strconv.Quote(value)
}

func MatchTLSBypass(document EnforcementDocument, deviceID, platform, hostname, destinationIP string, now time.Time) (*TLSBypassRule, error) {
	platform = strings.ToLower(strings.TrimSpace(platform))
	hostname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	ip := net.ParseIP(strings.TrimSpace(destinationIP))
	for index := range document.TLS.BypassRules {
		rule := &document.TLS.BypassRules[index]
		if !rule.Enabled || (rule.ExpiresAt != nil && !rule.ExpiresAt.After(now)) {
			continue
		}
		if rule.DeviceID != "" && rule.DeviceID != deviceID {
			continue
		}
		if rule.Platform != "any" && rule.Platform != "unknown" && rule.Platform != platform {
			continue
		}
		matched := false
		switch rule.MatchType {
		case "exact-host":
			matched = hostname != "" && hostname == rule.Pattern
		case "host-suffix":
			matched = hostname != "" && (hostname == rule.Pattern || strings.HasSuffix(hostname, "."+rule.Pattern))
		case "ip":
			matched = ip != nil && ip.Equal(net.ParseIP(rule.Pattern))
		case "cidr":
			_, network, err := net.ParseCIDR(rule.Pattern)
			if err != nil {
				return nil, err
			}
			matched = ip != nil && network.Contains(ip)
		default:
			return nil, errors.New("TLS bypass policy contains an unsupported matcher")
		}
		if matched {
			copy := *rule
			return &copy, nil
		}
	}
	return nil, nil
}
