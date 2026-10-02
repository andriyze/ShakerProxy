package ingest

import (
	"encoding/json"
	"math"
	"net"
	"regexp"
	"strings"
)

type NetworkProjection struct {
	SourceIP        string
	DestinationIP   string
	SourcePort      int
	DestinationPort int
	Protocol        string
	Service         string
	NetworkBytes    int64
}

var projectionTextPattern = regexp.MustCompile(`^[A-Za-z0-9_.+-]{1,64}$`)

func ProjectNetworkFields(envelope Envelope) NetworkProjection {
	var fields map[string]json.RawMessage
	if json.Unmarshal(envelope.Payload, &fields) != nil {
		return NetworkProjection{}
	}
	projection := NetworkProjection{}
	switch envelope.Source {
	case SourceZeek:
		projection.SourceIP = projectionIP(fields["id.orig_h"])
		projection.DestinationIP = projectionIP(fields["id.resp_h"])
		projection.SourcePort = projectionPort(fields["id.orig_p"])
		projection.DestinationPort = projectionPort(fields["id.resp_p"])
		projection.Protocol = projectionText(fields["proto"])
		projection.Service = projectionZeekService(fields["service"])
		if networkBytes, ok := projectionBytes(fields["orig_ip_bytes"], fields["resp_ip_bytes"]); ok {
			projection.NetworkBytes = networkBytes
		} else if networkBytes, ok := projectionBytes(fields["orig_bytes"], fields["resp_bytes"]); ok {
			projection.NetworkBytes = networkBytes
		}
	case SourceSuricata:
		projection.SourceIP = projectionIP(fields["src_ip"])
		projection.DestinationIP = projectionIP(fields["dest_ip"])
		projection.SourcePort = projectionPort(fields["src_port"])
		projection.DestinationPort = projectionPort(fields["dest_port"])
		projection.Protocol = projectionText(fields["proto"])
		projection.Service = projectionText(fields["app_proto"])
		var flow map[string]json.RawMessage
		if json.Unmarshal(fields["flow"], &flow) == nil {
			projection.NetworkBytes, _ = projectionBytes(flow["bytes_toserver"], flow["bytes_toclient"])
		}
	case SourceMitmproxy:
		projection.SourceIP = projectionIP(fields["source_ip"])
		projection.DestinationIP = projectionIP(fields["destination_ip"])
		projection.SourcePort = projectionPort(fields["source_port"])
		projection.DestinationPort = projectionPort(fields["destination_port"])
		projection.Protocol = projectionText(fields["protocol"])
		projection.Service = projectionText(fields["service"])
	case SourceHost:
		// Only ShakerProxy's DNS forwarder lookups describe a device's
		// traffic; other HOST events (detections) keep no network fields.
		if envelope.Kind == HostDNSKind {
			projection.SourceIP = projectionIP(fields["source_ip"])
			projection.SourcePort = projectionPort(fields["source_port"])
			projection.DestinationPort = projectionPort(fields["destination_port"])
			projection.Protocol = projectionText(fields["protocol"])
			projection.Service = projectionText(fields["service"])
		}
	}
	return projection
}

// HostDNSKind is a lookup answered by ShakerProxy's lab DNS forwarder
// (shakerproxy-dnsd), recorded whether or not a capture runs.
const HostDNSKind = "shakerproxy.dns"

func isHostDNS(envelope Envelope) bool {
	return envelope.Source == SourceHost && envelope.Kind == HostDNSKind
}

func projectionIP(raw json.RawMessage) string {
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return ""
	}
	parsed := net.ParseIP(value)
	if parsed == nil {
		return ""
	}
	return parsed.String()
}

func validProjectionIP(value string) bool {
	if value == "" {
		return true
	}
	parsed := net.ParseIP(value)
	return parsed != nil && parsed.String() == value
}

func projectionPort(raw json.RawMessage) int {
	var value int
	if json.Unmarshal(raw, &value) != nil || value < 1 || value > 65535 {
		return 0
	}
	return value
}

func projectionText(raw json.RawMessage) string {
	var value string
	if json.Unmarshal(raw, &value) != nil || !projectionTextPattern.MatchString(value) {
		return ""
	}
	return strings.ToLower(value)
}

// projectionZeekService keeps the first confirmed analyzer from Zeek's
// comma-separated service list (for example "ssl,http" or "http,ssl") so a
// multi-protocol connection still has a queryable service.
func projectionZeekService(raw json.RawMessage) string {
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return ""
	}
	for _, candidate := range strings.Split(value, ",") {
		candidate = strings.TrimSpace(candidate)
		if projectionTextPattern.MatchString(candidate) && !strings.HasPrefix(candidate, "_") {
			return strings.ToLower(candidate)
		}
	}
	return ""
}

func projectionBytes(values ...json.RawMessage) (int64, bool) {
	var total int64
	present := false
	for _, raw := range values {
		if len(raw) == 0 {
			continue
		}
		var value int64
		if json.Unmarshal(raw, &value) != nil || value < 0 || value > math.MaxInt64-total {
			return 0, false
		}
		total += value
		present = true
	}
	if !present {
		return 0, false
	}
	return total, true
}
