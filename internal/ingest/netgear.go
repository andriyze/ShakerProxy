package ingest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// Network gear (the lab router/gateway and its access points) sends ShakerProxy
// its own logs over syslog. In single-arm and inline-bridge labs the router
// serves DHCP and terminates Wi-Fi, so it sees bindings and associations
// ShakerProxy never does on the wire; its firewall and IDS see traffic that
// never reaches ShakerProxy at all. The syslog collector turns those lines
// into these events, which flow through the normal ingest pipeline and appear
// in the Live view, API and MCP alongside captured traffic.
//
// Every field here comes from a device log line, which is untrusted input and
// may be spoofed on UDP; the collector restricts senders to an allowlist and
// bounds volume, and these events carry a confidence below first-hand capture.

const (
	// SourceNetworkGear marks events derived from a network device's own
	// logs, distinct from first-hand capture (ZEEK/SURICATA) and from
	// ShakerProxy's own services (HOST).
	SourceNetworkGear Source = "NETWORK_GEAR"

	// NetworkGearParserVersion identifies the collector's normalization.
	NetworkGearParserVersion = "shakerproxy-netgear-syslog-v1"

	// NetworkGearDHCPKind is a DHCP lease the router granted (DHCPACK): a
	// strong MAC-to-address-to-hostname binding.
	NetworkGearDHCPKind = "netgear.dhcp_lease"
	// NetworkGearWiFiKind is a Wi-Fi client associating, roaming or leaving
	// an access point the router manages.
	NetworkGearWiFiKind = "netgear.wifi_client"
	// NetworkGearFirewallKind is a firewall accept or drop the router logged.
	NetworkGearFirewallKind = "netgear.firewall"
	// NetworkGearIDSKind is an intrusion-detection/prevention alert.
	NetworkGearIDSKind = "netgear.ids"
	// NetworkGearSystemKind is a WAN or system event (link up/down, reboot).
	NetworkGearSystemKind = "netgear.system"

	// NetworkGearConfidence ranks these events below first-hand capture
	// (Zeek 80, Suricata 85). The gear is reporting what it did, which is
	// reliable, but the channel is a log line from an allowlisted but
	// unauthenticated source.
	NetworkGearConfidence = 75
)

// networkGearKinds is the closed set of kinds the collector may emit.
var networkGearKinds = map[string]bool{
	NetworkGearDHCPKind:     true,
	NetworkGearWiFiKind:     true,
	NetworkGearFirewallKind: true,
	NetworkGearIDSKind:      true,
	NetworkGearSystemKind:   true,
}

// ValidNetworkGearKind reports whether kind is one the collector may emit.
func ValidNetworkGearKind(kind string) bool { return networkGearKinds[kind] }

// NormalizeNetworkGearEvent builds a normalized envelope from a collector
// record. payload is marshaled, compacted and bounded like any adapter input;
// kind must be one of the NetworkGear* kinds. The event ID is derived from the
// kind, time and payload so an identical line delivered twice deduplicates.
func NormalizeNetworkGearEvent(kind string, occurredAt time.Time, payload any) (Envelope, error) {
	if !networkGearKinds[kind] {
		return Envelope{}, errors.New("network gear event kind is unsupported")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, errors.New("network gear payload is not serializable")
	}
	compactBuffer := bytes.NewBuffer(make([]byte, 0, len(raw)))
	if json.Compact(compactBuffer, raw) != nil || compactBuffer.Len() == 0 || compactBuffer.Len() > MaxPayloadBytes {
		return Envelope{}, errors.New("network gear payload is invalid or exceeds its byte limit")
	}
	compact := append(json.RawMessage(nil), compactBuffer.Bytes()...)
	occurred := occurredAt.UTC()
	seed := append([]byte("NETWORK_GEAR\x00"+kind+"\x00"+occurred.Format(time.RFC3339Nano)+"\x00"), compact...)
	digest := sha256.Sum256(seed)
	envelope := Envelope{
		Schema:        SchemaVersion,
		EventID:       "netgear-" + hex.EncodeToString(digest[:]),
		Source:        SourceNetworkGear,
		Kind:          kind,
		OccurredAt:    occurred,
		SourceVersion: NetworkGearParserVersion,
		ParserVersion: NetworkGearParserVersion,
		Confidence:    NetworkGearConfidence,
		Payload:       compact,
	}
	if err := envelope.Validate(); err != nil {
		return Envelope{}, err
	}
	return envelope, nil
}

// projectNetworkGear fills the network fields shown in the Live view from a
// network gear payload's flat fields. A DHCP lease is shown as coming from the
// device that now holds the address.
func projectNetworkGear(envelope Envelope, fields map[string]json.RawMessage) NetworkProjection {
	projection := NetworkProjection{
		SourceIP:        projectionIP(fields["source_ip"]),
		DestinationIP:   projectionIP(fields["destination_ip"]),
		SourcePort:      projectionPort(fields["source_port"]),
		DestinationPort: projectionPort(fields["destination_port"]),
		Protocol:        projectionText(fields["protocol"]),
		Service:         projectionText(fields["service"]),
	}
	if envelope.Kind == NetworkGearDHCPKind && projection.SourceIP == "" {
		projection.SourceIP = projectionIP(fields["assigned_addr"])
	}
	return projection
}

// streamTypeNetworkGear classifies a network gear event into a Live view
// stream type. It must match the netgear arm of streamTypeSQL and the web
// UI's streamKind.
func streamTypeNetworkGear(kind string) (string, bool) {
	switch kind {
	case NetworkGearWiFiKind:
		return StreamWiFi, true
	case NetworkGearIDSKind:
		return StreamAlert, true
	case NetworkGearDHCPKind:
		return StreamDiscovery, true
	case NetworkGearFirewallKind, NetworkGearSystemKind:
		return StreamOther, true
	}
	return "", false
}

// parseNetgearDHCP reads a netgear.dhcp_lease payload into the shared DHCP
// exchange shape, so the router's logged leases enrich the inventory through
// the same path as DHCP exchanges ShakerProxy captures itself. The collector
// emits only acknowledged leases, so acknowledged is always true here.
func parseNetgearDHCP(payload []byte, occurredAt time.Time) (dhcpExchange, bool) {
	var record struct {
		MAC           string `json:"mac"`
		HostName      string `json:"host_name"`
		ClientFQDN    string `json:"client_fqdn"`
		VendorClass   string `json:"vendor_class"`
		AssignedAddr  string `json:"assigned_addr"`
		RequestedAddr string `json:"requested_addr"`
		Server        string `json:"server"`
		Router        string `json:"router"`
		LeaseSeconds  int64  `json:"lease_seconds"`
	}
	if json.Unmarshal(payload, &record) != nil {
		return dhcpExchange{}, false
	}
	exchange := dhcpExchange{at: occurredAt.UTC()}
	if exchange.mac = dhcpClientMAC(record.MAC); exchange.mac == "" {
		return dhcpExchange{}, false
	}
	// The router's own acknowledgement is the authoritative binding, so the
	// address it granted must be present and usable in the lab.
	assigned := dhcpAddress(record.AssignedAddr)
	if !assigned.IsValid() {
		return dhcpExchange{}, false
	}
	exchange.acknowledged, exchange.assigned = true, assigned
	exchange.hostName = dhcpText(record.HostName, 253)
	exchange.fqdn = dhcpText(record.ClientFQDN, 253)
	exchange.vendorClass = dhcpText(record.VendorClass, 255)
	exchange.requested = dhcpAddress(record.RequestedAddr)
	exchange.server = dhcpAddress(record.Server)
	exchange.router = dhcpAddress(record.Router)
	if record.LeaseSeconds > 0 && record.LeaseSeconds <= maxDHCPLeaseSeconds {
		exchange.leaseSeconds = record.LeaseSeconds
	}
	return exchange, true
}
