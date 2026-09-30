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
				Hostnames:    []string{"dns.nextdns.io", "*.dns.nextdns.io"},
				DoHPaths:     []string{"/dns-query", "/"},
				Transports:   []ResolverTransport{TransportDoH, TransportDoH3, TransportDoT, TransportDoQ},
				DedicatedIPs: false, SafeForIPBlock: false,
				Source: "https://github.com/nextdns/nextdns/wiki",
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
