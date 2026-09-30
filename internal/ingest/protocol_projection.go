package ingest

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"

	"shakerproxy.dev/shakerproxy/internal/protocolclass"
)

// ProtocolProjection is the protocolclass result stored with an event.
type ProtocolProjection struct {
	AppProtocol string
	Category    string
	Visibility  string
	Evidence    string
	Exotic      bool
}

// Present reports whether the event was classified.
func (p ProtocolProjection) Present() bool { return p.AppProtocol != "" }

// zeekLogServices maps Zeek protocol logs to the analyzer service they
// describe. Records in these logs carry no "service" field of their own, so
// without this mapping "service:dns" would miss every dns.log record. Logs
// that are not about one application protocol (weird, notice, files, x509,
// known_*, software, analyzer) are deliberately absent: they are evidence
// about traffic, not traffic.
var zeekLogServices = map[string]string{
	"dns": "dns", "http": "http", "ssl": "ssl", "quic": "quic", "ssh": "ssh", "ftp": "ftp",
	"smtp": "smtp", "dhcp": "dhcp", "ntp": "ntp", "snmp": "snmp", "sip": "sip", "rdp": "rdp",
	"rfb": "rfb", "mysql": "mysql", "radius": "radius", "irc": "irc", "kerberos": "krb",
	"ntlm": "ntlm", "dce_rpc": "dce_rpc", "smb_files": "smb", "smb_mapping": "smb",
	"modbus": "modbus", "modbus_register_change": "modbus", "dnp3": "dnp3", "syslog": "syslog",
	"socks": "socks", "ldap": "ldap", "ldap_search": "ldap", "postgresql": "postgresql",
	"websocket": "websocket", "mqtt_connect": "mqtt", "mqtt_publish": "mqtt",
	"mqtt_subscribe": "mqtt", "tftp": "tftp", "bacnet": "bacnet", "enip": "enip", "cip": "enip",
	"s7comm": "s7comm", "opcua_binary": "opcua_binary", "stun": "stun", "wireguard": "wireguard",
	"openvpn": "openvpn", "ipsec": "ike", "redis": "redis",
}

// suricataNonProtocolEvents are EVE records that describe the engine or a
// packet anomaly rather than an application protocol.
var suricataNonProtocolEvents = map[string]bool{"stats": true, "anomaly": true, "engine": true}

// zeekLogPath returns the log name of a Zeek kind ("zeek.conn" -> "conn").
func zeekLogPath(kind string) string {
	return strings.TrimPrefix(kind, "zeek.")
}

// suricataEventType returns the EVE event_type of a Suricata kind.
func suricataEventType(kind string) string {
	return strings.TrimPrefix(kind, "suricata.")
}

// projectedService returns the service stored for an event. It prefers the
// analyzer's own service field and falls back to the protocol a Zeek log or
// Suricata app-layer record describes.
func projectedService(envelope Envelope, network NetworkProjection) string {
	if network.Service != "" {
		return network.Service
	}
	switch envelope.Source {
	case SourceZeek:
		return zeekLogServices[zeekLogPath(envelope.Kind)]
	case SourceSuricata:
		eventType := strings.ToLower(suricataEventType(envelope.Kind))
		if !suricataNonProtocolEvents[eventType] && protocolclass.NormalizeService(eventType) != "" && projectionTextPattern.MatchString(eventType) {
			return eventType
		}
	}
	return ""
}

// classifiableEvent reports whether an event describes network traffic that
// protocol discovery should classify.
func classifiableEvent(envelope Envelope, network NetworkProjection) bool {
	switch envelope.Source {
	case SourceZeek:
		path := zeekLogPath(envelope.Kind)
		if path == "conn" {
			return true
		}
		_, known := zeekLogServices[path]
		return known
	case SourceSuricata:
		if suricataNonProtocolEvents[strings.ToLower(suricataEventType(envelope.Kind))] {
			return false
		}
		return network.Protocol != "" || network.Service != ""
	case SourceMitmproxy:
		return network.Protocol != "" || network.Service != ""
	}
	return false
}

// ProjectProtocolFields classifies one event with protocolclass using the
// projected transport, service, and ports plus ShakerProxy's TLS interception
// state. Unclassifiable events (host detections, engine statistics, meta
// logs) return an empty projection.
func ProjectProtocolFields(envelope Envelope, network NetworkProjection, tls TLSProjection) ProtocolProjection {
	if !classifiableEvent(envelope, network) {
		return ProtocolProjection{}
	}
	classification := protocolclass.Classify(protocolclass.Observation{
		Transport:   network.Protocol,
		Service:     classificationService(envelope, network),
		ServerPort:  network.DestinationPort,
		ClientPort:  network.SourcePort,
		Intercepted: mitmproxyDecrypted(envelope, tls),
	})
	return protocolProjection(classification)
}

// classificationService gives protocolclass Zeek's full analyzer list. The
// stored service column keeps only the first analyzer, but the classifier
// must see all of them: in "http,websocket" the WebSocket upgrade is the
// application protocol, and in "ssl,quic" QUIC is the transport.
func classificationService(envelope Envelope, network NetworkProjection) string {
	if envelope.Source != SourceZeek || zeekLogPath(envelope.Kind) != "conn" {
		return network.Service
	}
	var record struct {
		Service any `json:"service"`
	}
	if json.Unmarshal(envelope.Payload, &record) != nil {
		return network.Service
	}
	services, ok := record.Service.(string)
	if !ok || len(services) > 512 || protocolclass.NormalizeService(services) == "" {
		return network.Service
	}
	return services
}

func protocolProjection(classification protocolclass.Classification) ProtocolProjection {
	if classification.Protocol == "" {
		return ProtocolProjection{}
	}
	return ProtocolProjection{
		AppProtocol: classification.Protocol,
		Category:    string(classification.Category),
		Visibility:  string(classification.Visibility),
		Evidence:    string(classification.Evidence),
		Exotic:      classification.Exotic,
	}
}

// mitmproxyDecrypted reports whether ShakerProxy itself decrypted the event.
// Passive analyzers cannot know this at ingest time; aggregation upgrades
// their flows when a matching interception event exists.
func mitmproxyDecrypted(envelope Envelope, tls TLSProjection) bool {
	if envelope.Source != SourceMitmproxy {
		return false
	}
	if tls.InterceptionState == "INTERCEPTED" {
		return true
	}
	var payload struct {
		Decrypted any `json:"decrypted"`
	}
	decoder := json.NewDecoder(bytes.NewReader(envelope.Payload))
	if decoder.Decode(&payload) != nil {
		return false
	}
	decrypted, ok := payload.Decrypted.(bool)
	return ok && decrypted
}

var storedProtocolIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// validProtocolProjection checks stored classification values syntactically.
// It deliberately does not require them to match today's catalog: rows keep
// the classification they were ingested with when the catalog evolves.
func validProtocolProjection(event RecentEvent) bool {
	if event.AppProtocol == "" {
		return event.ProtocolCategory == "" && event.ProtocolVisibility == "" && event.ProtocolEvidence == "" && !event.ProtocolExotic
	}
	if !storedProtocolIDPattern.MatchString(event.AppProtocol) || !storedProtocolIDPattern.MatchString(event.ProtocolCategory) || !protocolclass.ValidVisibility(event.ProtocolVisibility) {
		return false
	}
	switch protocolclass.Evidence(event.ProtocolEvidence) {
	case protocolclass.EvidenceAnalyzer, protocolclass.EvidencePort, protocolclass.EvidenceUnclassified:
		return true
	}
	return false
}
