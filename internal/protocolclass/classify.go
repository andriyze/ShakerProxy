package protocolclass

import "strings"

// Observation is the analyzer-neutral evidence for one flow or event.
type Observation struct {
	// Transport is the IP transport, e.g. "tcp", "udp", "icmp".
	Transport string
	// Service is what an analyzer identified: a Zeek conn.log service
	// (possibly comma-separated, e.g. "quic,ssl") or a Suricata app_proto.
	Service string
	// ServerPort is the responder/destination port, 0 when unknown.
	ServerPort int
	// ClientPort is the originator/source port, 0 when unknown.
	ClientPort int
	// Intercepted is true when ShakerProxy decrypted this flow.
	Intercepted bool
	// ToBroadcast is true when the destination is a broadcast or multicast
	// address.
	ToBroadcast bool
}

// Classification is the result of Classify.
type Classification struct {
	Protocol   string     `json:"protocol"`
	Label      string     `json:"label"`
	Category   Category   `json:"category"`
	Evidence   Evidence   `json:"evidence"`
	Visibility Visibility `json:"visibility"`
	Exotic     bool       `json:"exotic"`
}

// analyzerAliases maps Zeek service names and Suricata app_proto values onto
// catalog IDs. Names already equal to a catalog ID need no entry.
var analyzerAliases = map[string]string{
	"ssl": "tls", "dtls": "tls", "http1": "http", "https": "tls",
	"doh2": "doh", "krb": "kerberos", "krb_tcp": "kerberos", "krb5": "kerberos",
	"dce_rpc": "dce-rpc", "dcerpc": "dce-rpc", "rfb": "vnc", "ike": "ipsec", "ikev2": "ipsec",
	"pgsql": "postgresql", "ldap_tcp": "ldap", "ldap_udp": "ldap", "ftp-data": "ftp", "ftp_data": "ftp",
	"smb1": "smb", "smb2": "smb", "netbios": "netbios-ns", "nbns": "netbios-ns", "nbss": "smb",
	"bittorrent-dht": "bittorrent-dht", "bittorrent_dht": "bittorrent-dht", "bittorrenttracker": "bittorrent",
	"mqtt": "mqtt", "modbus": "modbus", "dnp3": "dnp3", "enip": "enip", "cip": "enip", "bacnet": "bacnet",
	"s7comm": "s7comm", "s7comm_plus": "s7comm", "opcua_binary": "opcua", "sip": "sip", "rtp": "rtp",
	"stun": "stun", "teredo": "ipv6-tunnel", "ayiya": "ipv6-tunnel", "gtpv1": "overlay-tunnel", "vxlan": "overlay-tunnel", "geneve": "overlay-tunnel", "gre": "gre",
	"wireguard": "wireguard", "openvpn": "openvpn", "spicy_openvpn": "openvpn", "spicy_wireguard": "wireguard",
	"websocket": "websocket", "http2": "http2", "quic": "quic", "dhcp": "dhcp", "dhcpv6": "dhcpv6",
	"ntp": "ntp", "dns": "dns", "mdns": "mdns", "llmnr": "llmnr", "ssdp": "ssdp",
}

// generic analyzer names describe a transport wrapper rather than the
// application. When a Zeek service lists several analyzers, a specific one
// wins over these.
var generic = map[string]int{"http": 1, "tls": 2}

// NormalizeService canonicalizes an analyzer service string into a catalog
// protocol ID. It returns "" when the service is empty, unknown, or reports
// a failed/violating analyzer.
func NormalizeService(service string) string {
	best, bestRank := "", 1<<30
	for _, raw := range strings.Split(service, ",") {
		name := strings.ToLower(strings.TrimSpace(raw))
		// Zeek prefixes analyzers removed after a protocol violation with "-".
		if name == "" || strings.HasPrefix(name, "-") || name == "failed" || name == "unknown" {
			continue
		}
		name = strings.TrimPrefix(name, "spicy::")
		id, ok := analyzerAliases[name]
		if !ok {
			if _, known := byID[name]; known {
				id = name
			} else {
				continue
			}
		}
		rank := 0
		if id == "quic" {
			rank = -1 // QUIC's embedded TLS handshake must not hide the transport.
		} else if value, isGeneric := generic[id]; isGeneric {
			rank = value
		}
		if rank < bestRank {
			best, bestRank = id, rank
		}
	}
	return best
}

// carriers maps protocols that ride inside a generic analyzer-visible carrier
// (TLS, QUIC, DNS wire format, or HTTP) to that carrier. When an analyzer only
// names the carrier, a matching well-known port identifies the application:
// TLS on TCP/853 is DNS over TLS, DNS wire format on UDP/5353 is mDNS.
var carriers = map[string]string{
	"dot": "tls", "mqtts": "tls", "amqps": "tls", "fcm": "tls", "apns": "tls",
	"smtps": "tls", "imaps": "tls", "pop3s": "tls", "ldaps": "tls", "sips": "tls",
	"turn-tls": "tls", "syslog-tls": "tls", "chromecast": "tls", "coaps": "tls",
	"lwm2m": "tls", "hue": "tls",
	"doq":  "quic",
	"mdns": "dns", "llmnr": "dns", "netbios-ns": "dns",
	"roku-ecp": "http", "sonos": "http", "ipp": "http",
}

// Classify identifies the application protocol for an observation. Analyzer
// evidence is preferred over well-known ports; flows matching neither are
// reported in an unidentified bucket so they stay visible as coverage gaps.
func Classify(observation Observation) Classification {
	transport := strings.ToLower(strings.TrimSpace(observation.Transport))
	if id := NormalizeService(observation.Service); id != "" {
		if specific := portProtocol(transport, observation.ServerPort); specific != "" && carriers[specific] == id {
			return classification(specific, EvidenceAnalyzer, observation.Intercepted)
		}
		return classification(id, EvidenceAnalyzer, observation.Intercepted)
	}
	switch transport {
	case "icmp":
		return classification("icmp", EvidenceAnalyzer, false)
	case "icmpv6", "ipv6-icmp", "icmp6":
		return classification("icmpv6", EvidenceAnalyzer, false)
	}
	if id := portProtocol(transport, observation.ServerPort); id != "" {
		return classification(id, EvidencePort, observation.Intercepted)
	}
	// Some analyzers report a response direction; fall back to the client port
	// only for privileged ports so ephemeral ports are not misread.
	if observation.ClientPort > 0 && observation.ClientPort < 1024 {
		if id := portProtocol(transport, observation.ClientPort); id != "" {
			return classification(id, EvidencePort, observation.Intercepted)
		}
	}
	if observation.ToBroadcast {
		return classification(LocalBroadcast, EvidencePort, false)
	}
	switch transport {
	case "tcp":
		return classification(UnknownTCP, EvidenceUnclassified, false)
	case "udp":
		return classification(UnknownUDP, EvidenceUnclassified, false)
	default:
		return classification(UnknownIP, EvidenceUnclassified, false)
	}
}

func portProtocol(transport string, port int) string {
	if port <= 0 || port > 65535 {
		return ""
	}
	return byPort[Port{Transport: transport, Number: port}]
}

func classification(id string, evidence Evidence, intercepted bool) Classification {
	protocol := byID[id]
	visibility := protocol.Visibility
	if intercepted && (visibility == VisibilityEncryptedMetadata || id == "http") {
		visibility = VisibilityDecrypted
	}
	return Classification{
		Protocol:   protocol.ID,
		Label:      protocol.Label,
		Category:   protocol.Category,
		Evidence:   evidence,
		Visibility: visibility,
		Exotic:     protocol.Exotic,
	}
}

// ValidID reports whether id is a catalog protocol ID.
func ValidID(id string) bool {
	_, ok := byID[id]
	return ok
}

// ValidCategory reports whether value is a known category.
func ValidCategory(value string) bool {
	for _, category := range Categories() {
		if string(category) == value {
			return true
		}
	}
	return false
}

// ValidVisibility reports whether value is a known visibility.
func ValidVisibility(value string) bool {
	switch Visibility(value) {
	case VisibilityDecrypted, VisibilityCleartext, VisibilityEncryptedMetadata, VisibilityOpaque:
		return true
	}
	return false
}
