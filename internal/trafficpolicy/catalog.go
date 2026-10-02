package trafficpolicy

import (
	"net/netip"
	"sort"
	"strings"
	"time"
)

// BuiltinCatalog returns the reviewed, versioned resolver seed used for
// detection and conservative dedicated-IP blocking. Hostnames remain useful
// for classification even when an address is not safe to block globally.
func BuiltinCatalog() Catalog {
	return Catalog{
		Schema:      SchemaVersion,
		Revision:    BuiltinCatalogRevision,
		GeneratedAt: time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC),
		Resolvers: []Resolver{
			{
				ID: "cloudflare", Provider: "Cloudflare Public DNS",
				Hostnames:    []string{"cloudflare-dns.com", "one.one.one.one"},
				IPv4:         []string{"1.0.0.1", "1.1.1.1"},
				IPv6:         []string{"2606:4700:4700::1001", "2606:4700:4700::1111"},
				DoHPaths:     []string{"/dns-query"},
				Transports:   []ResolverTransport{TransportDoH, TransportDoH3, TransportDoT},
				DedicatedIPs: true, SafeForIPBlock: true,
				Source: "https://developers.cloudflare.com/1.1.1.1/",
			},
			{
				ID: "google", Provider: "Google Public DNS",
				Hostnames:    []string{"dns.google"},
				IPv4:         []string{"8.8.4.4", "8.8.8.8"},
				IPv6:         []string{"2001:4860:4860::8844", "2001:4860:4860::8888"},
				DoHPaths:     []string{"/dns-query", "/resolve"},
				Transports:   []ResolverTransport{TransportDoH, TransportDoH3, TransportDoT},
				DedicatedIPs: true, SafeForIPBlock: true,
				Source: "https://developers.google.com/speed/public-dns/docs/doh",
			},
			{
				ID: "quad9-secure", Provider: "Quad9",
				Hostnames:    []string{"dns.quad9.net"},
				IPv4:         []string{"9.9.9.9", "149.112.112.112"},
				IPv6:         []string{"2620:fe::9", "2620:fe::fe"},
				DoHPaths:     []string{"/dns-query"},
				Transports:   []ResolverTransport{TransportDoH, TransportDoH3, TransportDoT, TransportDoQ},
				DedicatedIPs: true, SafeForIPBlock: true,
				Source: "https://docs.quad9.net/services/addresses-and-features/",
			},
			{
				ID: "adguard-default", Provider: "AdGuard DNS",
				Hostnames:    []string{"dns.adguard-dns.com"},
				IPv4:         []string{"94.140.14.14", "94.140.15.15"},
				IPv6:         []string{"2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"},
				DoHPaths:     []string{"/dns-query"},
				Transports:   []ResolverTransport{TransportDoH, TransportDoH3, TransportDoT, TransportDoQ},
				DedicatedIPs: true, SafeForIPBlock: true,
				Source: "https://adguard-dns.io/kb/general/dns-providers/",
			},
			{
				ID: "adguard-family", Provider: "AdGuard DNS Family",
				Hostnames:    []string{"family.adguard-dns.com"},
				IPv4:         []string{"94.140.14.15", "94.140.15.16"},
				IPv6:         []string{"2a10:50c0::bad1:ff", "2a10:50c0::bad2:ff"},
				DoHPaths:     []string{"/dns-query"},
				Transports:   []ResolverTransport{TransportDoH, TransportDoH3, TransportDoT, TransportDoQ},
				DedicatedIPs: true, SafeForIPBlock: true,
				Source: "https://adguard-dns.io/kb/general/dns-providers/",
			},
			{
				ID: "adguard-unfiltered", Provider: "AdGuard DNS Unfiltered",
				Hostnames:    []string{"unfiltered.adguard-dns.com"},
				IPv4:         []string{"94.140.14.140", "94.140.14.141"},
				IPv6:         []string{"2a10:50c0::1:ff", "2a10:50c0::2:ff"},
				DoHPaths:     []string{"/dns-query"},
				Transports:   []ResolverTransport{TransportDoH, TransportDoH3, TransportDoT, TransportDoQ},
				DedicatedIPs: true, SafeForIPBlock: true,
				Source: "https://adguard-dns.io/kb/general/dns-providers/",
			},
			{
				ID: "opendns", Provider: "Cisco OpenDNS",
				Hostnames:    []string{"doh.opendns.com", "dns.opendns.com"},
				IPv4:         []string{"208.67.220.220", "208.67.222.222"},
				IPv6:         []string{"2620:119:35::35", "2620:119:53::53"},
				DoHPaths:     []string{"/dns-query"},
				Transports:   []ResolverTransport{TransportDoH, TransportDoT},
				DedicatedIPs: true, SafeForIPBlock: true,
				Source: "https://support.opendns.com/",
			},
			{
				ID: "nextdns", Provider: "NextDNS",
				Hostnames: []string{"dns.nextdns.io", "*.dns.nextdns.io"},
				// The anycast resolver addresses; configuration-specific
				// addresses are reached through these names.
				IPv4:         []string{"45.90.28.0", "45.90.30.0"},
				IPv6:         []string{"2a07:a8c0::", "2a07:a8c1::"},
				DoHPaths:     []string{"/dns-query", "/"},
				Transports:   []ResolverTransport{TransportDoH, TransportDoH3, TransportDoT, TransportDoQ},
				DedicatedIPs: true, SafeForIPBlock: true,
				Source: "https://github.com/nextdns/nextdns/wiki",
			},
			{
				ID: "cloudflare-security", Provider: "Cloudflare for Families (malware)",
				Hostnames:    []string{"security.cloudflare-dns.com"},
				IPv4:         []string{"1.0.0.2", "1.1.1.2"},
				IPv6:         []string{"2606:4700:4700::1002", "2606:4700:4700::1112"},
				DoHPaths:     []string{"/dns-query"},
				Transports:   []ResolverTransport{TransportDoH, TransportDoH3, TransportDoT},
				DedicatedIPs: true, SafeForIPBlock: true,
				Source: "https://developers.cloudflare.com/1.1.1.1/setup/#1111-for-families",
			},
			{
				ID: "cloudflare-family", Provider: "Cloudflare for Families (malware and adult)",
				Hostnames:    []string{"family.cloudflare-dns.com"},
				IPv4:         []string{"1.0.0.3", "1.1.1.3"},
				IPv6:         []string{"2606:4700:4700::1003", "2606:4700:4700::1113"},
				DoHPaths:     []string{"/dns-query"},
				Transports:   []ResolverTransport{TransportDoH, TransportDoH3, TransportDoT},
				DedicatedIPs: true, SafeForIPBlock: true,
				Source: "https://developers.cloudflare.com/1.1.1.1/setup/#1111-for-families",
			},
			{
				ID: "quad9-unsecured", Provider: "Quad9 (unsecured)",
				Hostnames:    []string{"dns10.quad9.net"},
				IPv4:         []string{"9.9.9.10", "149.112.112.10"},
				IPv6:         []string{"2620:fe::10", "2620:fe::fe:10"},
				DoHPaths:     []string{"/dns-query"},
				Transports:   []ResolverTransport{TransportDoH, TransportDoH3, TransportDoT, TransportDoQ},
				DedicatedIPs: true, SafeForIPBlock: true,
				Source: "https://docs.quad9.net/services/addresses-and-features/",
			},
			{
				ID: "quad9-ecs", Provider: "Quad9 (with ECS)",
				Hostnames:    []string{"dns11.quad9.net"},
				IPv4:         []string{"9.9.9.11", "149.112.112.11"},
				IPv6:         []string{"2620:fe::11", "2620:fe::fe:11"},
				DoHPaths:     []string{"/dns-query"},
				Transports:   []ResolverTransport{TransportDoH, TransportDoH3, TransportDoT, TransportDoQ},
				DedicatedIPs: true, SafeForIPBlock: true,
				Source: "https://docs.quad9.net/services/addresses-and-features/",
			},
			{
				ID: "opendns-familyshield", Provider: "Cisco OpenDNS FamilyShield",
				Hostnames:    []string{"doh.familyshield.opendns.com", "familyshield.opendns.com"},
				IPv4:         []string{"208.67.220.123", "208.67.222.123"},
				IPv6:         []string{"2620:119:35::123", "2620:119:53::123"},
				DoHPaths:     []string{"/dns-query"},
				Transports:   []ResolverTransport{TransportDoH, TransportDoT},
				DedicatedIPs: true, SafeForIPBlock: true,
				Source: "https://support.opendns.com/",
			},
			{
				ID: "cleanbrowsing", Provider: "CleanBrowsing",
				Hostnames:    []string{"doh.cleanbrowsing.org", "security-filter-dns.cleanbrowsing.org", "family-filter-dns.cleanbrowsing.org", "adult-filter-dns.cleanbrowsing.org"},
				IPv4:         []string{"185.228.168.9", "185.228.169.9", "185.228.168.168", "185.228.169.168", "185.228.168.10", "185.228.169.11"},
				IPv6:         []string{"2a0d:2a00:1::2", "2a0d:2a00:2::2", "2a0d:2a00:1::", "2a0d:2a00:2::", "2a0d:2a00:1::1", "2a0d:2a00:2::1"},
				DoHPaths:     []string{"/doh/security-filter/", "/doh/family-filter/", "/doh/adult-filter/"},
				Transports:   []ResolverTransport{TransportDoH, TransportDoT},
				DedicatedIPs: true, SafeForIPBlock: true,
				Source: "https://cleanbrowsing.org/filters/",
			},
			{
				ID: "mullvad", Provider: "Mullvad DNS",
				Hostnames:    []string{"dns.mullvad.net", "adblock.dns.mullvad.net", "base.dns.mullvad.net", "extended.dns.mullvad.net", "family.dns.mullvad.net", "all.dns.mullvad.net"},
				IPv4:         []string{"194.242.2.2", "194.242.2.3", "194.242.2.4", "194.242.2.5", "194.242.2.6", "194.242.2.9"},
				IPv6:         []string{"2a07:e340::2", "2a07:e340::3", "2a07:e340::4", "2a07:e340::5", "2a07:e340::6", "2a07:e340::9"},
				DoHPaths:     []string{"/dns-query"},
				Transports:   []ResolverTransport{TransportDoH, TransportDoT},
				DedicatedIPs: true, SafeForIPBlock: true,
				Source: "https://mullvad.net/en/help/dns-over-https-and-dns-over-tls",
			},
			{
				ID: "controld", Provider: "Control D free DNS",
				Hostnames:    []string{"freedns.controld.com", "dns.controld.com"},
				IPv4:         []string{"76.76.2.0", "76.76.2.1", "76.76.2.2", "76.76.2.3", "76.76.2.4", "76.76.2.5", "76.76.10.0", "76.76.10.1", "76.76.10.2", "76.76.10.3", "76.76.10.4", "76.76.10.5"},
				IPv6:         []string{"2606:1a40::", "2606:1a40:1::"},
				DoHPaths:     []string{"/p0", "/p1", "/p2", "/p3", "/family", "/uncensored"},
				Transports:   []ResolverTransport{TransportDoH, TransportDoH3, TransportDoT, TransportDoQ},
				DedicatedIPs: true, SafeForIPBlock: true,
				Source: "https://controld.com/free-dns",
			},
			{
				ID: "dnssb", Provider: "DNS.SB",
				Hostnames:    []string{"doh.dns.sb", "dot.sb", "dns.sb"},
				IPv4:         []string{"45.11.45.11", "185.222.222.222"},
				IPv6:         []string{"2a09::", "2a11::"},
				DoHPaths:     []string{"/dns-query"},
				Transports:   []ResolverTransport{TransportDoH, TransportDoT},
				DedicatedIPs: true, SafeForIPBlock: true,
				Source: "https://dns.sb/doh/",
			},
			{
				ID: "alidns", Provider: "AliDNS",
				Hostnames:    []string{"dns.alidns.com"},
				IPv4:         []string{"223.5.5.5", "223.6.6.6"},
				IPv6:         []string{"2400:3200::1", "2400:3200:baba::1"},
				DoHPaths:     []string{"/dns-query", "/resolve"},
				Transports:   []ResolverTransport{TransportDoH, TransportDoH3, TransportDoT, TransportDoQ},
				DedicatedIPs: true, SafeForIPBlock: true,
				Source: "https://www.alidns.com/knowledge?type=SETTING_DOCS",
			},
			{
				ID: "dnspod", Provider: "DNSPod Public DNS",
				Hostnames:    []string{"doh.pub", "dot.pub"},
				IPv4:         []string{"1.12.12.12", "120.53.53.53"},
				DoHPaths:     []string{"/dns-query"},
				Transports:   []ResolverTransport{TransportDoH, TransportDoT},
				DedicatedIPs: true, SafeForIPBlock: true,
				Source: "https://www.dnspod.cn/products/publicdns",
			},
			{
				ID: "yandex", Provider: "Yandex DNS",
				Hostnames:    []string{"common.dot.dns.yandex.net", "safe.dot.dns.yandex.net", "family.dot.dns.yandex.net"},
				IPv4:         []string{"77.88.8.1", "77.88.8.8"},
				IPv6:         []string{"2a02:6b8::feed:0ff", "2a02:6b8:0:1::feed:0ff"},
				DoHPaths:     []string{"/dns-query"},
				Transports:   []ResolverTransport{TransportDoH, TransportDoT},
				DedicatedIPs: true, SafeForIPBlock: true,
				Source: "https://dns.yandex.com/advanced/",
			},
			{
				ID: "mozilla-canary", Provider: "Mozilla DoH canary",
				Hostnames:  []string{"use-application-dns.net"},
				Transports: []ResolverTransport{}, DedicatedIPs: false, SafeForIPBlock: false,
				Source: "https://support.mozilla.org/kb/canary-domain-use-application-dnsnet",
			},
		},
	}
}

// EncryptedDNSCanaries are names whose NXDOMAIN answer tells clients the
// network wants them to use its own DNS: Firefox turns off its default DoH
// (use-application-dns.net) and Apple devices turn off iCloud Private Relay
// (mask.icloud.com, mask-h2.icloud.com).
var EncryptedDNSCanaries = []string{"mask-h2.icloud.com", "mask.icloud.com", "use-application-dns.net"}

// MaxBlockedResolverNames bounds the names the forwarder refuses.
const MaxBlockedResolverNames = 512

// Why ShakerProxy blocked a lookup or a connection, as recorded in Traffic
// events (blocked_reason).
const (
	BlockReasonDeviceDomain = "device-domain" // a domain blocked for one device
	BlockReasonDoHName      = "doh-name"      // a DNS-over-HTTPS/TLS resolver hostname
	BlockReasonCanary       = "canary"        // an encrypted-DNS opt-out canary name
	BlockReasonDoT          = "dot"           // DNS over TLS, TCP 853
	BlockReasonDoQ          = "doq"           // DNS over QUIC, UDP 853
	BlockReasonDoHAddress   = "doh-ip"        // a catalog DoH resolver address, TCP 443
	BlockReasonDoH3Address  = "doh3-ip"       // a catalog DoH resolver address, UDP 443 (HTTP/3)
)

// BlockedResolverNames lists the names the forwarder answers with NXDOMAIN
// while "Block encrypted DNS" is on: every catalog DoH/DoT hostname (each
// name also covers its subdomains, so cloudflare-dns.com covers
// mozilla.cloudflare-dns.com) of resolvers that are not excluded, plus the
// canaries. Sorted and de-duplicated.
func BlockedResolverNames(policy Policy) []string {
	excluded := make(map[string]bool, len(policy.EncryptedDNS.ResolverExclusions))
	for _, id := range policy.EncryptedDNS.ResolverExclusions {
		excluded[id] = true
	}
	seen := map[string]bool{}
	names := []string{}
	add := func(raw string) {
		name := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(raw)), "*.")
		if name != "" && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	for _, resolver := range BuiltinCatalog().Resolvers {
		if excluded[resolver.ID] {
			continue
		}
		for _, hostname := range resolver.Hostnames {
			add(hostname)
		}
	}
	for _, canary := range EncryptedDNSCanaries {
		add(canary)
	}
	sort.Strings(names)
	return names
}

// DoHHostnames lists the catalog's DNS-over-HTTPS hostnames (wildcard
// entries without their "*."), sorted. Each also covers its subdomains, so
// cloudflare-dns.com covers mozilla.cloudflare-dns.com.
func DoHHostnames() []string {
	seen := map[string]bool{}
	names := []string{}
	for _, resolver := range BuiltinCatalog().Resolvers {
		if !resolverSupportsTransport(resolver, TransportDoH) && !resolverSupportsTransport(resolver, TransportDoH3) {
			continue
		}
		for _, hostname := range resolver.Hostnames {
			name := strings.TrimPrefix(strings.ToLower(hostname), "*.")
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)
	return names
}

// IsDoHHostname reports a catalog DNS-over-HTTPS hostname or a subdomain of
// one.
func IsDoHHostname(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" {
		return false
	}
	for _, host := range DoHHostnames() {
		if name == host || strings.HasSuffix(name, "."+host) {
			return true
		}
	}
	return false
}

// IsDoHResolverAddress reports an address of a catalog resolver that serves
// DNS over HTTPS (TCP or UDP 443 to it is encrypted DNS).
func IsDoHResolverAddress(raw string) bool {
	address, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	address = address.Unmap()
	for _, resolver := range BuiltinCatalog().Resolvers {
		if !resolverSupportsTransport(resolver, TransportDoH) && !resolverSupportsTransport(resolver, TransportDoH3) {
			continue
		}
		for _, candidate := range append(append([]string(nil), resolver.IPv4...), resolver.IPv6...) {
			if parsed, err := netip.ParseAddr(candidate); err == nil && parsed == address {
				return true
			}
		}
	}
	return false
}

// IsEncryptedDNSCanary reports one of EncryptedDNSCanaries.
func IsEncryptedDNSCanary(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	for _, canary := range EncryptedDNSCanaries {
		if name == canary {
			return true
		}
	}
	return false
}

func resolverIDSet(catalog Catalog) map[string]bool {
	result := make(map[string]bool, len(catalog.Resolvers))
	for _, resolver := range catalog.Resolvers {
		result[resolver.ID] = true
	}
	return result
}

func BlockSafeAddresses(policy Policy, ipv6 bool) []string {
	excluded := make(map[string]bool, len(policy.EncryptedDNS.ResolverExclusions))
	for _, id := range policy.EncryptedDNS.ResolverExclusions {
		excluded[id] = true
	}
	seen := map[string]bool{}
	result := []string{}
	for _, resolver := range BuiltinCatalog().Resolvers {
		if excluded[resolver.ID] || !resolver.SafeForIPBlock || !resolver.DedicatedIPs {
			continue
		}
		addresses := resolver.IPv4
		if ipv6 {
			addresses = resolver.IPv6
		}
		for _, raw := range addresses {
			address, err := netip.ParseAddr(raw)
			if err != nil || address.Is6() != ipv6 {
				continue
			}
			value := address.String()
			if !seen[value] {
				seen[value] = true
				result = append(result, value)
			}
		}
	}
	sort.Strings(result)
	return result
}

func Classify(destinationIP, hostname string, port int, udp bool, httpPath string) Classification {
	hostname = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname)), ".")
	httpPath = strings.TrimSpace(httpPath)
	address, _ := netip.ParseAddr(strings.TrimSpace(destinationIP))
	for _, resolver := range BuiltinCatalog().Resolvers {
		hostMatch := false
		for _, pattern := range resolver.Hostnames {
			if hostnameMatches(pattern, hostname) {
				hostMatch = true
				break
			}
		}
		ipMatch := false
		if address.IsValid() {
			addresses := resolver.IPv4
			if address.Is6() {
				addresses = resolver.IPv6
			}
			for _, raw := range addresses {
				if candidate, err := netip.ParseAddr(raw); err == nil && candidate == address {
					ipMatch = true
					break
				}
			}
		}
		transport := transportFor(port, udp, httpPath)
		if transport == "" || (!hostMatch && !ipMatch) || !resolverSupportsTransport(resolver, transport) {
			continue
		}
		confidence := 70
		evidence := []string{}
		if hostMatch {
			confidence += 20
			evidence = append(evidence, "hostname_catalog_match")
		}
		if ipMatch {
			confidence += 10
			evidence = append(evidence, "dedicated_resolver_ip_match")
		}
		if httpPath != "" && pathMatches(resolver.DoHPaths, httpPath) {
			confidence = 100
			evidence = append(evidence, "doh_path_match")
		}
		return Classification{Detected: true, ResolverID: resolver.ID, Provider: resolver.Provider, Transport: transport, Confidence: confidence, Evidence: evidence, BlockSafe: resolver.SafeForIPBlock && resolver.DedicatedIPs}
	}
	if port == 853 {
		transport := TransportDoT
		if udp {
			transport = TransportDoQ
		}
		return Classification{Detected: true, Transport: transport, Confidence: 80, Evidence: []string{"standard_encrypted_dns_port"}, BlockSafe: true}
	}
	return Classification{}
}

func transportFor(port int, udp bool, path string) ResolverTransport {
	switch {
	case port == 853 && udp:
		return TransportDoQ
	case port == 853:
		return TransportDoT
	case port == 443 && udp:
		return TransportDoH3
	case port == 443 && path != "":
		return TransportDoH
	case port == 443:
		return TransportDoH
	default:
		return ""
	}
}

func hostnameMatches(pattern, hostname string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(hostname, suffix) && hostname != strings.TrimPrefix(suffix, ".")
	}
	return pattern == hostname
}

func pathMatches(patterns []string, path string) bool {
	for _, pattern := range patterns {
		if pattern == path || (pattern == "/" && strings.HasPrefix(path, "/")) {
			return true
		}
	}
	return false
}

func resolverSupportsTransport(resolver Resolver, transport ResolverTransport) bool {
	for _, candidate := range resolver.Transports {
		if candidate == transport {
			return true
		}
	}
	return false
}
