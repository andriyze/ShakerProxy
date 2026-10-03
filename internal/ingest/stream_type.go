package ingest

import (
	"strconv"
	"strings"
)

// Stream types are the kinds of traffic the live Traffic view groups events
// into. docs/traffic-stream-types.md is the specification; StreamType (Go),
// streamTypeSQL (PostgreSQL) and the web UI's streamKind
// (apps/web-ui/src/lib/liveTraffic.ts) implement it, and
// testdata/stream_types.json checks that all three agree.
const (
	StreamDNS       = "dns"
	StreamTLS       = "tls"
	StreamQUIC      = "quic"
	StreamHTTP      = "http"
	StreamDiscovery = "discovery"
	StreamAlert     = "alert"
	StreamOther     = "other"
	StreamBlocked   = "blocked"
	StreamWiFi      = "wifi"
)

// StreamTypes lists the stream types in display order.
var StreamTypes = []string{StreamDNS, StreamTLS, StreamQUIC, StreamHTTP, StreamDiscovery, StreamWiFi, StreamAlert, StreamOther, StreamBlocked}

// discoveryPorts are destination ports of local discovery: mDNS, LLMNR,
// SSDP, NetBIOS, DHCP, DHCPv6, WS-Discovery and Ubiquiti discovery.
var discoveryPorts = []int{5353, 5355, 1900, 137, 138, 67, 68, 546, 547, 3702, 10001}

// discoveryApps are application protocols the classifier names for local
// discovery and address assignment.
var discoveryApps = []string{"mdns", "ssdp", "llmnr", "netbios-ns", "ws-discovery", "dhcp", "dhcpv6"}

var encryptedDNSApps = []string{"doh", "dot", "doq"}

// StreamType classifies one event; the order of the rules matters and
// matches docs/traffic-stream-types.md.
func StreamType(event RecentEvent) string {
	protocol := strings.ToLower(event.Protocol)
	switch {
	case event.Blocked:
		return StreamBlocked
	case event.Source == SourceNetworkGear:
		if stream, ok := streamTypeNetworkGear(event.Kind); ok {
			return stream
		}
		return StreamOther
	case isHostWiFi(event.Source, event.Kind):
		return StreamWiFi
	case contains(encryptedDNSApps, event.AppProtocol):
		return StreamDNS
	case event.Kind == HostConnKind:
		switch {
		case protocol == "udp" && (event.DestinationPort == 443 || event.TLSServerName != ""):
			return StreamQUIC
		case protocol == "tcp" && (event.DestinationPort == 443 || event.TLSServerName != ""):
			return StreamTLS
		case protocol == "tcp" && event.DestinationPort == 80:
			return StreamHTTP
		}
		return StreamOther
	case event.AlertSignature != "" || event.Kind == "suricata.alert":
		return StreamAlert
	case containsPort(discoveryPorts, event.DestinationPort) || event.Kind == "zeek.dhcp" || event.ProtocolCategory == "local-discovery" || contains(discoveryApps, event.AppProtocol):
		return StreamDiscovery
	case event.DNSQuery != "":
		return StreamDNS
	case event.HTTPMethod != "" || event.HTTPHost != "" || strings.HasSuffix(event.Kind, ".http"):
		return StreamHTTP
	case strings.HasSuffix(event.Kind, ".quic") || event.TLSServerName != "" && protocol == "udp":
		return StreamQUIC
	case event.TLSServerName != "" || strings.HasSuffix(event.Kind, ".ssl") || strings.HasSuffix(event.Kind, ".tls"):
		return StreamTLS
	}
	return StreamOther
}

// streamTypeSQL is StreamType as a PostgreSQL expression over the
// normalized_events columns.
var streamTypeSQL = `CASE
 WHEN ` + blockedFlagSQL + ` THEN '` + StreamBlocked + `'
 WHEN source = 'NETWORK_GEAR' THEN CASE
   WHEN kind = '` + NetworkGearWiFiKind + `' THEN '` + StreamWiFi + `'
   WHEN kind = '` + NetworkGearIDSKind + `' THEN '` + StreamAlert + `'
   WHEN kind = '` + NetworkGearDHCPKind + `' THEN '` + StreamDiscovery + `'
   ELSE '` + StreamOther + `' END
 WHEN source = 'HOST' AND starts_with(kind, 'wifi.') THEN '` + StreamWiFi + `'
 WHEN COALESCE(app_protocol, '') IN (` + sqlStrings(encryptedDNSApps) + `) THEN '` + StreamDNS + `'
 WHEN kind = '` + HostConnKind + `' THEN CASE
   WHEN lower(COALESCE(protocol, '')) = 'udp' AND (destination_port = 443 OR COALESCE(tls_server_name, '') <> '') THEN '` + StreamQUIC + `'
   WHEN lower(COALESCE(protocol, '')) = 'tcp' AND (destination_port = 443 OR COALESCE(tls_server_name, '') <> '') THEN '` + StreamTLS + `'
   WHEN lower(COALESCE(protocol, '')) = 'tcp' AND destination_port = 80 THEN '` + StreamHTTP + `'
   ELSE '` + StreamOther + `' END
 WHEN COALESCE(alert_signature, '') <> '' OR kind = 'suricata.alert' THEN '` + StreamAlert + `'
 WHEN destination_port IN (` + sqlPorts(discoveryPorts) + `) OR kind = 'zeek.dhcp' OR COALESCE(protocol_category, '') = 'local-discovery' OR COALESCE(app_protocol, '') IN (` + sqlStrings(discoveryApps) + `) THEN '` + StreamDiscovery + `'
 WHEN COALESCE(dns_query, '') <> '' THEN '` + StreamDNS + `'
 WHEN COALESCE(http_method, '') <> '' OR COALESCE(http_host, '') <> '' OR kind LIKE '%.http' THEN '` + StreamHTTP + `'
 WHEN kind LIKE '%.quic' OR (COALESCE(tls_server_name, '') <> '' AND lower(COALESCE(protocol, '')) = 'udp') THEN '` + StreamQUIC + `'
 WHEN COALESCE(tls_server_name, '') <> '' OR kind LIKE '%.ssl' OR kind LIKE '%.tls' THEN '` + StreamTLS + `'
 ELSE '` + StreamOther + `' END`

// analyzerDuplicatesFilter leaves out the analyzers' duplicate records of
// traffic another event already shows: Suricata's flow and app-layer records
// next to Zeek's, Zeek's TLS and QUIC handshakes next to their connection,
// its bookkeeping logs, and the connection records of DNS and mDNS lookups.
// It is the web UI's EVERYTHING_QUERY.
const analyzerDuplicatesFilter = "NOT (kind:suricata.flow OR kind:suricata.dns OR kind:suricata.mdns OR kind:suricata.quic OR kind:suricata.tls OR kind:suricata.http OR kind:suricata.anomaly OR kind:zeek.ssl OR kind:zeek.quic OR kind:zeek.weird OR kind:zeek.known_services OR kind:zeek.software OR kind:zeek.reporter OR (kind:zeek.conn AND (dst.port:53 OR dst.port:5353 OR dst.port:5355)))"

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func containsPort(ports []int, port int) bool {
	for _, candidate := range ports {
		if candidate == port {
			return true
		}
	}
	return false
}

func sqlStrings(values []string) string {
	quoted := make([]string, len(values))
	for index, value := range values {
		quoted[index] = "'" + value + "'"
	}
	return strings.Join(quoted, ", ")
}

func sqlPorts(ports []int) string {
	values := make([]string, len(ports))
	for index, port := range ports {
		values[index] = strconv.Itoa(port)
	}
	return strings.Join(values, ", ")
}
