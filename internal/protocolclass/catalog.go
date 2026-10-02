// Package protocolclass maps analyzer-identified services and well-known
// ports onto a bounded catalog of application protocols. It is the single
// source of protocol names, categories, and visibility used by protocol
// discovery, fleet demand summaries, and the query language.
package protocolclass

import "sort"

// Category groups protocols by what they are used for.
type Category string

const (
	CategoryWeb               Category = "web"
	CategoryDNS               Category = "dns"
	CategoryEncryptedDNS      Category = "encrypted-dns"
	CategoryVPNTunnel         Category = "vpn-tunnel"
	CategoryIoTMessaging      Category = "iot-messaging"
	CategorySmartHome         Category = "smart-home"
	CategoryLocalDiscovery    Category = "local-discovery"
	CategoryCasting           Category = "casting"
	CategoryMediaStreaming    Category = "media-streaming"
	CategoryRealtimeMedia     Category = "realtime-media"
	CategoryPush              Category = "push-messaging"
	CategoryRemoteAccess      Category = "remote-access"
	CategoryFileTransfer      Category = "file-transfer"
	CategoryPrinting          Category = "printing"
	CategoryEmail             Category = "email"
	CategoryIndustrial        Category = "industrial"
	CategoryDatabase          Category = "database"
	CategoryDirectoryAuth     Category = "directory-auth"
	CategoryNetworkManagement Category = "network-management"
	CategoryPeerToPeer        Category = "peer-to-peer"
	CategoryUnknown           Category = "unknown"
)

// Categories returns every category in display order.
func Categories() []Category {
	return []Category{
		CategoryWeb, CategoryDNS, CategoryEncryptedDNS, CategoryVPNTunnel, CategoryIoTMessaging,
		CategorySmartHome, CategoryLocalDiscovery, CategoryCasting, CategoryMediaStreaming,
		CategoryRealtimeMedia, CategoryPush, CategoryRemoteAccess, CategoryFileTransfer,
		CategoryPrinting, CategoryEmail, CategoryIndustrial, CategoryDatabase,
		CategoryDirectoryAuth, CategoryNetworkManagement, CategoryPeerToPeer, CategoryUnknown,
	}
}

// Evidence states how a protocol was identified.
type Evidence string

const (
	// EvidenceAnalyzer means Zeek dynamic protocol detection or a Suricata
	// app-layer parser recognized the protocol from payload.
	EvidenceAnalyzer Evidence = "ANALYZER"
	// EvidencePort means only a well-known port matched; the payload was not
	// confirmed and may be something else.
	EvidencePort Evidence = "PORT_HEURISTIC"
	// EvidenceUnclassified means neither an analyzer nor a port matched.
	EvidenceUnclassified Evidence = "UNCLASSIFIED"
)

// Visibility states how much of a flow ShakerProxy can see into.
type Visibility string

const (
	// VisibilityDecrypted means ShakerProxy intercepted and decrypted the flow.
	VisibilityDecrypted Visibility = "DECRYPTED"
	// VisibilityCleartext means the application protocol is not encrypted.
	VisibilityCleartext Visibility = "CLEARTEXT"
	// VisibilityEncryptedMetadata means the payload is encrypted but the
	// handshake exposes useful metadata such as SNI or ALPN.
	VisibilityEncryptedMetadata Visibility = "ENCRYPTED_METADATA"
	// VisibilityOpaque means ShakerProxy cannot see what the flow carries: VPN
	// tunnels, proprietary binary protocols, or unclassified traffic.
	VisibilityOpaque Visibility = "OPAQUE"
)

// Protocol is one catalog entry.
type Protocol struct {
	ID          string     `json:"id"`
	Label       string     `json:"label"`
	Category    Category   `json:"category"`
	Visibility  Visibility `json:"visibility"`
	Exotic      bool       `json:"exotic"`
	Description string     `json:"description"`
	Ports       []Port     `json:"ports,omitempty"`
}

// Port is a well-known server port used for heuristic classification.
type Port struct {
	Transport string `json:"transport"`
	Number    int    `json:"port"`
}

const (
	UnknownTCP = "unknown-tcp"
	UnknownUDP = "unknown-udp"
	// LocalBroadcast is unrecognized traffic to a broadcast or multicast
	// address: local network chatter, not a connection to a server.
	LocalBroadcast = "local-broadcast"
	UnknownIP      = "unknown"
)

// mainstream protocols are expected on almost every network and are
// therefore not flagged as exotic.
var mainstream = map[string]bool{
	"http": true, "tls": true, "quic": true, "dns": true, "ntp": true, "dhcp": true,
	"dhcpv6": true, "icmp": true, "icmpv6": true, "mdns": true, "ssdp": true, "llmnr": true,
	"netbios-ns": true,
}

func tcp(ports ...int) []Port { return portsFor("tcp", ports...) }
func udp(ports ...int) []Port { return portsFor("udp", ports...) }
func portsFor(transport string, ports ...int) []Port {
	out := make([]Port, 0, len(ports))
	for _, port := range ports {
		out = append(out, Port{Transport: transport, Number: port})
	}
	return out
}
func join(groups ...[]Port) []Port {
	var out []Port
	for _, group := range groups {
		out = append(out, group...)
	}
	return out
}

const (
	cleartext = VisibilityCleartext
	encrypted = VisibilityEncryptedMetadata
	opaque    = VisibilityOpaque
)

var catalog = []Protocol{
	// Web and baseline infrastructure.
	{ID: "http", Label: "HTTP", Category: CategoryWeb, Visibility: cleartext, Description: "Plaintext web and API traffic.", Ports: tcp(80, 8080, 8000, 8888)},
	{ID: "tls", Label: "TLS", Category: CategoryWeb, Visibility: encrypted, Description: "TLS-encrypted TCP; SNI and certificate metadata are visible.", Ports: tcp(443, 8443)},
	{ID: "quic", Label: "QUIC / HTTP/3", Category: CategoryWeb, Visibility: encrypted, Description: "UDP-based encrypted transport; cannot be intercepted, block UDP/443 to force TCP fallback.", Ports: udp(443)},
	{ID: "http2", Label: "HTTP/2 (cleartext)", Category: CategoryWeb, Visibility: cleartext, Description: "Cleartext HTTP/2 (h2c)."},
	{ID: "websocket", Label: "WebSocket", Category: CategoryWeb, Visibility: cleartext, Description: "Long-lived bidirectional channel upgraded from HTTP."},
	{ID: "dns", Label: "DNS", Category: CategoryDNS, Visibility: cleartext, Description: "Plain DNS lookups.", Ports: join(udp(53), tcp(53))},
	{ID: "dot", Label: "DNS over TLS", Category: CategoryEncryptedDNS, Visibility: encrypted, Description: "Encrypted DNS that bypasses the lab resolver unless blocked.", Ports: tcp(853)},
	{ID: "doq", Label: "DNS over QUIC", Category: CategoryEncryptedDNS, Visibility: encrypted, Description: "Encrypted DNS over QUIC.", Ports: udp(853)},
	{ID: "doh", Label: "DNS over HTTPS", Category: CategoryEncryptedDNS, Visibility: encrypted, Description: "Encrypted DNS carried inside HTTPS."},
	{ID: "ntp", Label: "NTP", Category: CategoryNetworkManagement, Visibility: cleartext, Description: "Network time.", Ports: udp(123)},
	{ID: "dhcp", Label: "DHCP", Category: CategoryNetworkManagement, Visibility: cleartext, Description: "IPv4 address assignment.", Ports: udp(67, 68)},
	{ID: "dhcpv6", Label: "DHCPv6", Category: CategoryNetworkManagement, Visibility: cleartext, Description: "IPv6 address assignment.", Ports: udp(546, 547)},
	{ID: "icmp", Label: "ICMP", Category: CategoryNetworkManagement, Visibility: cleartext, Description: "IPv4 control messages (ping, unreachable)."},
	{ID: "icmpv6", Label: "ICMPv6", Category: CategoryNetworkManagement, Visibility: cleartext, Description: "IPv6 control messages including neighbor discovery."},
	{ID: "snmp", Label: "SNMP", Category: CategoryNetworkManagement, Visibility: cleartext, Description: "Device management and monitoring.", Ports: udp(161, 162)},
	{ID: "syslog", Label: "Syslog", Category: CategoryNetworkManagement, Visibility: cleartext, Description: "Log shipping.", Ports: join(udp(514), tcp(514, 601))},
	{ID: "syslog-tls", Label: "Syslog over TLS", Category: CategoryNetworkManagement, Visibility: encrypted, Description: "Encrypted log shipping.", Ports: tcp(6514)},
	{ID: "nat-pmp", Label: "NAT-PMP / PCP", Category: CategoryNetworkManagement, Visibility: cleartext, Description: "Device asks the router to open inbound ports.", Ports: udp(5351)},
	{ID: "socks", Label: "SOCKS proxy", Category: CategoryVPNTunnel, Visibility: cleartext, Description: "Generic proxy tunnel; inner traffic may evade policy.", Ports: tcp(1080)},

	// Local discovery.
	{ID: "mdns", Label: "mDNS / Bonjour", Category: CategoryLocalDiscovery, Visibility: cleartext, Description: "Local service discovery (AirPlay, Chromecast, printers, HomeKit).", Ports: udp(5353)},
	{ID: "ssdp", Label: "SSDP / UPnP", Category: CategoryLocalDiscovery, Visibility: cleartext, Description: "UPnP discovery used by TVs, media renderers, and routers.", Ports: udp(1900)},
	{ID: "llmnr", Label: "LLMNR", Category: CategoryLocalDiscovery, Visibility: cleartext, Description: "Windows link-local name resolution.", Ports: udp(5355)},
	{ID: "netbios-ns", Label: "NetBIOS name service", Category: CategoryLocalDiscovery, Visibility: cleartext, Description: "Legacy Windows name resolution.", Ports: udp(137, 138)},
	{ID: "ws-discovery", Label: "WS-Discovery", Category: CategoryLocalDiscovery, Visibility: cleartext, Description: "Discovery used by printers and ONVIF cameras.", Ports: udp(3702)},
	{ID: "ubnt-discovery", Label: "Ubiquiti discovery", Category: CategoryLocalDiscovery, Visibility: cleartext, Description: "UniFi and other Ubiquiti devices announcing themselves on the network.", Ports: udp(10001)},
	{ID: LocalBroadcast, Label: "Broadcast or multicast", Category: CategoryLocalDiscovery, Visibility: cleartext, Description: "Sent to every device on the network or to a multicast group, on a port no known protocol uses."},

	// IoT messaging.
	{ID: "mqtt", Label: "MQTT", Category: CategoryIoTMessaging, Visibility: cleartext, Description: "Lightweight IoT publish/subscribe messaging.", Ports: tcp(1883)},
	{ID: "mqtts", Label: "MQTT over TLS", Category: CategoryIoTMessaging, Visibility: encrypted, Description: "Encrypted IoT publish/subscribe messaging.", Ports: tcp(8883)},
	{ID: "coap", Label: "CoAP", Category: CategoryIoTMessaging, Visibility: cleartext, Description: "Constrained-device REST over UDP.", Ports: udp(5683)},
	{ID: "coaps", Label: "CoAP over DTLS", Category: CategoryIoTMessaging, Visibility: encrypted, Description: "Encrypted constrained-device REST.", Ports: udp(5684)},
	{ID: "amqp", Label: "AMQP", Category: CategoryIoTMessaging, Visibility: cleartext, Description: "Message-queue protocol used by some IoT backends.", Ports: tcp(5672)},
	{ID: "amqps", Label: "AMQP over TLS", Category: CategoryIoTMessaging, Visibility: encrypted, Description: "Encrypted message-queue protocol.", Ports: tcp(5671)},
	{ID: "xmpp", Label: "XMPP", Category: CategoryIoTMessaging, Visibility: encrypted, Description: "Chat and device messaging (used by some IoT clouds).", Ports: tcp(5222)},
	{ID: "lwm2m", Label: "LwM2M", Category: CategoryIoTMessaging, Visibility: encrypted, Description: "OMA device-management over CoAP/DTLS.", Ports: udp(5685)},

	// Smart home.
	{ID: "matter", Label: "Matter", Category: CategorySmartHome, Visibility: encrypted, Description: "Cross-vendor smart-home standard over IPv6 UDP.", Ports: udp(5540)},
	{ID: "tuya", Label: "Tuya local", Category: CategorySmartHome, Visibility: opaque, Description: "Proprietary Tuya/Smart Life local control and discovery.", Ports: join(udp(6666, 6667), tcp(6668))},
	{ID: "hue", Label: "Philips Hue entertainment", Category: CategorySmartHome, Visibility: encrypted, Description: "Hue bridge DTLS entertainment streaming.", Ports: udp(2100)},
	{ID: "homekit", Label: "HomeKit Accessory Protocol", Category: CategorySmartHome, Visibility: opaque, Description: "Apple HomeKit accessory control (encrypted session over HTTP)."},

	// Casting and TV control.
	{ID: "chromecast", Label: "Google Cast", Category: CategoryCasting, Visibility: encrypted, Description: "Chromecast / Google Cast control channel.", Ports: tcp(8008, 8009)},
	{ID: "airplay", Label: "AirPlay", Category: CategoryCasting, Visibility: opaque, Description: "Apple AirPlay screen and audio streaming.", Ports: tcp(7000, 7100)},
	{ID: "roku-ecp", Label: "Roku ECP", Category: CategoryCasting, Visibility: cleartext, Description: "Roku External Control Protocol.", Ports: tcp(8060)},
	{ID: "sonos", Label: "Sonos control", Category: CategoryCasting, Visibility: cleartext, Description: "Sonos speaker UPnP control.", Ports: tcp(1400)},
	{ID: "dial", Label: "DIAL", Category: CategoryCasting, Visibility: cleartext, Description: "Discovery-and-launch protocol for TV apps (YouTube, Netflix)."},

	// Media streaming and real-time media.
	{ID: "rtsp", Label: "RTSP", Category: CategoryMediaStreaming, Visibility: cleartext, Description: "Camera and media stream control.", Ports: tcp(554, 8554)},
	{ID: "rtmp", Label: "RTMP", Category: CategoryMediaStreaming, Visibility: cleartext, Description: "Live video ingest.", Ports: tcp(1935)},
	{ID: "rtp", Label: "RTP", Category: CategoryRealtimeMedia, Visibility: cleartext, Description: "Real-time audio/video packets."},
	{ID: "stun", Label: "STUN / TURN", Category: CategoryRealtimeMedia, Visibility: cleartext, Description: "NAT traversal for WebRTC calls and P2P video.", Ports: join(udp(3478, 19302, 19303, 19304, 19305, 19306, 19307, 19308, 19309), tcp(3478))},
	{ID: "turn-tls", Label: "TURN over TLS", Category: CategoryRealtimeMedia, Visibility: encrypted, Description: "Relayed WebRTC media over TLS.", Ports: tcp(5349)},
	{ID: "sip", Label: "SIP", Category: CategoryRealtimeMedia, Visibility: cleartext, Description: "VoIP call signalling.", Ports: join(udp(5060), tcp(5060))},
	{ID: "sips", Label: "SIP over TLS", Category: CategoryRealtimeMedia, Visibility: encrypted, Description: "Encrypted VoIP call signalling.", Ports: tcp(5061)},

	// Push messaging.
	{ID: "fcm", Label: "Google push (FCM)", Category: CategoryPush, Visibility: encrypted, Description: "Firebase Cloud Messaging persistent connection used by Android devices.", Ports: tcp(5228, 5229, 5230)},
	{ID: "apns", Label: "Apple push (APNs)", Category: CategoryPush, Visibility: encrypted, Description: "Apple Push Notification service persistent connection.", Ports: tcp(5223)},

	// VPNs and tunnels.
	{ID: "wireguard", Label: "WireGuard", Category: CategoryVPNTunnel, Visibility: opaque, Description: "VPN tunnel; inner traffic bypasses ShakerProxy inspection.", Ports: udp(51820)},
	{ID: "openvpn", Label: "OpenVPN", Category: CategoryVPNTunnel, Visibility: opaque, Description: "VPN tunnel; inner traffic bypasses ShakerProxy inspection.", Ports: join(udp(1194), tcp(1194))},
	{ID: "ipsec", Label: "IPsec / IKE", Category: CategoryVPNTunnel, Visibility: opaque, Description: "VPN key exchange and tunnels.", Ports: udp(500, 4500)},
	{ID: "tailscale", Label: "Tailscale", Category: CategoryVPNTunnel, Visibility: opaque, Description: "WireGuard-based mesh VPN.", Ports: udp(41641)},
	{ID: "pptp", Label: "PPTP", Category: CategoryVPNTunnel, Visibility: opaque, Description: "Legacy, insecure VPN.", Ports: tcp(1723)},
	{ID: "gre", Label: "GRE", Category: CategoryVPNTunnel, Visibility: opaque, Description: "Generic routing encapsulation tunnel."},
	{ID: "ipv6-tunnel", Label: "IPv6 tunnel (Teredo/AYIYA)", Category: CategoryVPNTunnel, Visibility: opaque, Description: "IPv6-in-IPv4 tunnel; the client reaches IPv6 destinations around the lab gateway.", Ports: udp(3544)},
	{ID: "overlay-tunnel", Label: "Overlay tunnel (VXLAN/Geneve/GTP)", Category: CategoryVPNTunnel, Visibility: opaque, Description: "Encapsulated overlay network traffic.", Ports: udp(4789, 6081, 2152)},
	{ID: "tor", Label: "Tor", Category: CategoryVPNTunnel, Visibility: opaque, Description: "Onion-routing anonymity network.", Ports: tcp(9001, 9030)},

	// Remote access.
	{ID: "ssh", Label: "SSH", Category: CategoryRemoteAccess, Visibility: encrypted, Description: "Encrypted remote shell and tunnels.", Ports: tcp(22)},
	{ID: "telnet", Label: "Telnet", Category: CategoryRemoteAccess, Visibility: cleartext, Description: "Plaintext remote shell; credentials visible on the wire.", Ports: tcp(23, 2323)},
	{ID: "rdp", Label: "RDP", Category: CategoryRemoteAccess, Visibility: encrypted, Description: "Windows remote desktop.", Ports: tcp(3389)},
	{ID: "vnc", Label: "VNC (RFB)", Category: CategoryRemoteAccess, Visibility: cleartext, Description: "Remote framebuffer desktop sharing.", Ports: tcp(5900, 5901)},
	{ID: "teamviewer", Label: "TeamViewer", Category: CategoryRemoteAccess, Visibility: opaque, Description: "Proprietary remote-support tunnel.", Ports: tcp(5938)},
	{ID: "anydesk", Label: "AnyDesk", Category: CategoryRemoteAccess, Visibility: opaque, Description: "Proprietary remote-support tunnel.", Ports: tcp(6568)},

	// File transfer and printing.
	{ID: "ftp", Label: "FTP", Category: CategoryFileTransfer, Visibility: cleartext, Description: "Plaintext file transfer.", Ports: tcp(21)},
	{ID: "tftp", Label: "TFTP", Category: CategoryFileTransfer, Visibility: cleartext, Description: "Trivial file transfer, common for firmware and PXE.", Ports: udp(69)},
	{ID: "smb", Label: "SMB", Category: CategoryFileTransfer, Visibility: cleartext, Description: "Windows file sharing.", Ports: tcp(445, 139)},
	{ID: "nfs", Label: "NFS", Category: CategoryFileTransfer, Visibility: cleartext, Description: "Unix network file system.", Ports: tcp(2049)},
	{ID: "afp", Label: "AFP", Category: CategoryFileTransfer, Visibility: cleartext, Description: "Apple Filing Protocol.", Ports: tcp(548)},
	{ID: "rsync", Label: "rsync", Category: CategoryFileTransfer, Visibility: cleartext, Description: "File synchronization daemon.", Ports: tcp(873)},
	{ID: "ipp", Label: "IPP", Category: CategoryPrinting, Visibility: cleartext, Description: "Internet Printing Protocol.", Ports: tcp(631)},
	{ID: "jetdirect", Label: "JetDirect / RAW print", Category: CategoryPrinting, Visibility: cleartext, Description: "Raw port 9100 printing.", Ports: tcp(9100)},
	{ID: "lpd", Label: "LPD", Category: CategoryPrinting, Visibility: cleartext, Description: "Legacy line printer daemon.", Ports: tcp(515)},

	// Email.
	{ID: "smtp", Label: "SMTP", Category: CategoryEmail, Visibility: cleartext, Description: "Mail submission and relay.", Ports: tcp(25, 587)},
	{ID: "smtps", Label: "SMTP over TLS", Category: CategoryEmail, Visibility: encrypted, Description: "Implicit-TLS mail submission.", Ports: tcp(465)},
	{ID: "imap", Label: "IMAP", Category: CategoryEmail, Visibility: cleartext, Description: "Mailbox access.", Ports: tcp(143)},
	{ID: "imaps", Label: "IMAP over TLS", Category: CategoryEmail, Visibility: encrypted, Description: "Encrypted mailbox access.", Ports: tcp(993)},
	{ID: "pop3", Label: "POP3", Category: CategoryEmail, Visibility: cleartext, Description: "Mail download.", Ports: tcp(110)},
	{ID: "pop3s", Label: "POP3 over TLS", Category: CategoryEmail, Visibility: encrypted, Description: "Encrypted mail download.", Ports: tcp(995)},

	// Industrial and building automation.
	{ID: "modbus", Label: "Modbus/TCP", Category: CategoryIndustrial, Visibility: cleartext, Description: "Industrial control; no authentication.", Ports: tcp(502)},
	{ID: "dnp3", Label: "DNP3", Category: CategoryIndustrial, Visibility: cleartext, Description: "Utility SCADA protocol.", Ports: tcp(20000)},
	{ID: "bacnet", Label: "BACnet/IP", Category: CategoryIndustrial, Visibility: cleartext, Description: "Building automation (HVAC, lighting, access control).", Ports: udp(47808)},
	{ID: "s7comm", Label: "Siemens S7", Category: CategoryIndustrial, Visibility: cleartext, Description: "Siemens PLC communication (ISO-TSAP).", Ports: tcp(102)},
	{ID: "enip", Label: "EtherNet/IP (CIP)", Category: CategoryIndustrial, Visibility: cleartext, Description: "Rockwell/ODVA industrial protocol.", Ports: join(tcp(44818), udp(44818, 2222))},
	{ID: "opcua", Label: "OPC UA", Category: CategoryIndustrial, Visibility: encrypted, Description: "Industrial interoperability protocol.", Ports: tcp(4840)},
	{ID: "iec104", Label: "IEC 60870-5-104", Category: CategoryIndustrial, Visibility: cleartext, Description: "Power-grid telecontrol.", Ports: tcp(2404)},

	// Databases.
	{ID: "mysql", Label: "MySQL", Category: CategoryDatabase, Visibility: cleartext, Description: "MySQL/MariaDB client protocol.", Ports: tcp(3306)},
	{ID: "postgresql", Label: "PostgreSQL", Category: CategoryDatabase, Visibility: cleartext, Description: "PostgreSQL client protocol.", Ports: tcp(5432)},
	{ID: "redis", Label: "Redis", Category: CategoryDatabase, Visibility: cleartext, Description: "Redis key-value protocol.", Ports: tcp(6379)},
	{ID: "mongodb", Label: "MongoDB", Category: CategoryDatabase, Visibility: cleartext, Description: "MongoDB wire protocol.", Ports: tcp(27017)},
	{ID: "memcached", Label: "Memcached", Category: CategoryDatabase, Visibility: cleartext, Description: "Memcached cache protocol.", Ports: join(tcp(11211), udp(11211))},

	// Directory and authentication.
	{ID: "kerberos", Label: "Kerberos", Category: CategoryDirectoryAuth, Visibility: encrypted, Description: "Ticket-based authentication.", Ports: join(tcp(88), udp(88))},
	{ID: "ldap", Label: "LDAP", Category: CategoryDirectoryAuth, Visibility: cleartext, Description: "Directory lookups.", Ports: join(tcp(389), udp(389))},
	{ID: "ldaps", Label: "LDAP over TLS", Category: CategoryDirectoryAuth, Visibility: encrypted, Description: "Encrypted directory lookups.", Ports: tcp(636)},
	{ID: "radius", Label: "RADIUS", Category: CategoryDirectoryAuth, Visibility: cleartext, Description: "Network access authentication.", Ports: udp(1812, 1813)},
	{ID: "ntlm", Label: "NTLM", Category: CategoryDirectoryAuth, Visibility: cleartext, Description: "Legacy Windows challenge-response authentication."},
	{ID: "dce-rpc", Label: "DCE/RPC", Category: CategoryDirectoryAuth, Visibility: cleartext, Description: "Windows remote procedure calls.", Ports: tcp(135)},

	// Peer to peer.
	{ID: "bittorrent", Label: "BitTorrent", Category: CategoryPeerToPeer, Visibility: cleartext, Description: "Peer-to-peer file sharing.", Ports: tcp(6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889)},
	{ID: "bittorrent-dht", Label: "BitTorrent DHT", Category: CategoryPeerToPeer, Visibility: cleartext, Description: "Peer discovery for BitTorrent.", Ports: udp(6881)},

	// Chat.
	{ID: "irc", Label: "IRC", Category: CategoryIoTMessaging, Visibility: cleartext, Description: "Internet Relay Chat; also used by botnet command channels.", Ports: tcp(6667, 6697)},

	// Unclassified buckets.
	{ID: UnknownTCP, Label: "Unidentified TCP", Category: CategoryUnknown, Visibility: opaque, Description: "TCP traffic no analyzer or well-known port recognized."},
	{ID: UnknownUDP, Label: "Unidentified UDP", Category: CategoryUnknown, Visibility: opaque, Description: "UDP traffic no analyzer or well-known port recognized."},
	{ID: UnknownIP, Label: "Unidentified", Category: CategoryUnknown, Visibility: opaque, Description: "Traffic whose transport and application protocol are unknown."},
}

var (
	byID   = map[string]Protocol{}
	byPort = map[Port]string{}
)

func init() {
	for index, protocol := range catalog {
		if _, duplicate := byID[protocol.ID]; duplicate {
			panic("protocolclass: duplicate protocol " + protocol.ID)
		}
		protocol.Exotic = !mainstream[protocol.ID]
		catalog[index] = protocol
		byID[protocol.ID] = protocol
		for _, port := range protocol.Ports {
			if owner, duplicate := byPort[port]; duplicate {
				panic("protocolclass: port " + port.Transport + " claimed by " + owner + " and " + protocol.ID)
			}
			byPort[port] = protocol.ID
		}
	}
}

// Lookup returns the catalog entry for a canonical protocol ID.
func Lookup(id string) (Protocol, bool) {
	protocol, ok := byID[id]
	if !ok {
		return Protocol{}, false
	}
	return clone(protocol), true
}

// Catalog returns a copy of every protocol, sorted by category order then label.
func Catalog() []Protocol {
	order := make(map[Category]int, len(Categories()))
	for index, category := range Categories() {
		order[category] = index
	}
	out := make([]Protocol, 0, len(catalog))
	for _, protocol := range catalog {
		out = append(out, clone(protocol))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if order[out[i].Category] != order[out[j].Category] {
			return order[out[i].Category] < order[out[j].Category]
		}
		return out[i].Label < out[j].Label
	})
	return out
}

func clone(protocol Protocol) Protocol {
	protocol.Ports = append([]Port(nil), protocol.Ports...)
	return protocol
}
