package cloudconnector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"net"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
	"shakerproxy.dev/shakerproxy/internal/protocolclass"
)

// ProjectNormalizedEvents creates only bounded metadata projections. Raw event
// payloads, HTTP bodies, credentials, packet bytes, and TLS key material have
// no field in the resulting cloud schema.
func ProjectNormalizedEvents(envelope ingest.Envelope, now time.Time) []LocalMetadataEvent {
	if envelope.Validate() != nil || envelope.Source == ingest.SourceMitmproxy {
		return nil
	}
	now = now.UTC()
	if envelope.OccurredAt.Before(now.Add(-MaxMetadataQueueAge)) || envelope.OccurredAt.After(now.Add(2*time.Minute)) {
		return nil
	}
	fields := normalizedEventFields(envelope.Payload)
	network := ingest.ProjectNetworkFields(envelope)
	baseAttributes := map[string]any{
		"source":     strings.ToLower(string(envelope.Source)),
		"event_kind": boundedProjectionText(envelope.Kind, 256),
	}
	if envelope.FlowID != "" {
		baseAttributes["flow_id"] = envelope.FlowID
	}

	events := make([]LocalMetadataEvent, 0, 3)
	if net.ParseIP(network.DestinationIP) != nil {
		attributes := cloneProjectionAttributes(baseAttributes)
		addAlertProjection(attributes, fields)
		classification := addProtocolProjection(attributes, network)
		bytesSent, bytesReceived, durationMS := flowCounters(envelope.Source, fields)
		payload := map[string]any{
			"local_device_id":      envelope.DeviceID,
			"source_ip":            network.SourceIP,
			"destination_ip":       network.DestinationIP,
			"destination_port":     network.DestinationPort,
			"transport":            cloudTransport(network.Protocol),
			"application_protocol": classification.Protocol,
			"bytes_sent":           bytesSent,
			"bytes_received":       bytesReceived,
			"duration_ms":          durationMS,
			"capture_id":           envelope.CaptureSessionID,
			"attributes":           attributes,
		}
		if network.SourcePort > 0 {
			payload["source_port"] = network.SourcePort
		}
		if event, ok := projectedMetadataEvent(envelope, "flow", MetadataFlowSummary, payload); ok {
			events = append(events, event)
		}
	}

	dns := ingest.ProjectDNSFields(envelope)
	if dns.Query != "" {
		attributes := cloneProjectionAttributes(baseAttributes)
		if dns.AnswerCount != nil {
			attributes["answer_count"] = *dns.AnswerCount
		}
		queryName := dns.Query
		if queryName == "." {
			queryName = "root"
			attributes["root_query"] = true
		}
		payload := map[string]any{
			"local_device_id":      envelope.DeviceID,
			"client_ip":            network.SourceIP,
			"resolver_ip":          network.DestinationIP,
			"query_name":           queryName,
			"query_type":           dns.RecordType,
			"response_code":        dns.ResponseCode,
			"transport":            dnsTransport(network.Protocol),
			"encrypted":            false,
			"detection_confidence": float64(envelope.Confidence) / 100,
			"blocked":              false,
			"capture_id":           envelope.CaptureSessionID,
			"attributes":           attributes,
		}
		if event, ok := projectedMetadataEvent(envelope, "dns", MetadataDNSEvent, payload); ok {
			events = append(events, event)
		}
	}

	if isEncryptedHandshakeObservation(envelope.Kind, network.Service) {
		attributes := cloneProjectionAttributes(baseAttributes)
		serverName, alpn, version, encryptedTransport, transportVersion := encryptedHandshakeProjection(envelope.Source, envelope.Kind, network.Service, fields)
		attributes["encrypted_transport"] = encryptedTransport
		if transportVersion != "" {
			attributes["transport_version"] = transportVersion
		}
		if strings.HasPrefix(strings.ToLower(alpn), "h3") {
			attributes["application_protocol"] = "http3"
		}
		payload := map[string]any{
			"local_device_id":    envelope.DeviceID,
			"client_ip":          network.SourceIP,
			"destination_ip":     network.DestinationIP,
			"server_name":        serverName,
			"alpn":               alpn,
			"tls_version":        version,
			"interception_state": "encrypted-only",
			"pinning_suspected":  false,
			"capture_id":         envelope.CaptureSessionID,
			"attributes":         attributes,
		}
		if network.DestinationPort > 0 {
			payload["destination_port"] = network.DestinationPort
		}
		if event, ok := projectedMetadataEvent(envelope, "tls", MetadataTLSEvent, payload); ok {
			events = append(events, event)
		}
	}
	return events
}

func projectedMetadataEvent(envelope ingest.Envelope, suffix string, eventType MetadataEventType, payload map[string]any) (LocalMetadataEvent, bool) {
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) == 0 || len(encoded) > 64<<10 {
		return LocalMetadataEvent{}, false
	}
	return LocalMetadataEvent{
		EventID:    projectedMetadataID(envelope.EventID, suffix),
		Type:       eventType,
		ObservedAt: envelope.OccurredAt.UTC(),
		Payload:    encoded,
	}, true
}

func projectedMetadataID(eventID, suffix string) string {
	candidate := eventID + "." + suffix
	if metadataEventIDPattern.MatchString(candidate) {
		return candidate
	}
	digest := sha256.Sum256([]byte(eventID))
	return "event_" + hex.EncodeToString(digest[:]) + "." + suffix
}

func normalizedEventFields(payload json.RawMessage) map[string]json.RawMessage {
	var fields map[string]json.RawMessage
	if json.Unmarshal(payload, &fields) != nil {
		return map[string]json.RawMessage{}
	}
	return fields
}

func flowCounters(source ingest.Source, fields map[string]json.RawMessage) (uint64, uint64, uint64) {
	switch source {
	case ingest.SourceZeek:
		sent := unsignedProjectionNumber(firstProjectionField(fields, "orig_ip_bytes", "orig_bytes"))
		received := unsignedProjectionNumber(firstProjectionField(fields, "resp_ip_bytes", "resp_bytes"))
		return sent, received, secondsToMilliseconds(projectionFloat(fields["duration"]))
	case ingest.SourceSuricata:
		flow := projectionObject(fields["flow"])
		return unsignedProjectionNumber(flow["bytes_toserver"]), unsignedProjectionNumber(flow["bytes_toclient"]), secondsToMilliseconds(projectionFloat(flow["age"]))
	default:
		return 0, 0, 0
	}
}

func addAlertProjection(attributes map[string]any, fields map[string]json.RawMessage) {
	alert := projectionObject(fields["alert"])
	if len(alert) == 0 {
		return
	}
	attributes["alert"] = true
	if value := unsignedProjectionNumber(alert["signature_id"]); value != 0 {
		attributes["alert_signature_id"] = value
	}
	if value := boundedRawProjectionText(alert["signature"], 256); value != "" {
		attributes["alert_signature"] = value
	}
	if value := boundedRawProjectionText(alert["category"], 128); value != "" {
		attributes["alert_category"] = value
	}
	if value := unsignedProjectionNumber(alert["severity"]); value != 0 {
		attributes["alert_severity"] = value
	}
}

// addProtocolProjection classifies the flow with the shared protocol catalog
// and records the plain-language classification attributes. The raw analyzer
// service is kept (bounded) so cloud-side support can see what the analyzer
// reported when the catalog could only fall back to a port or an unknown bucket.
func addProtocolProjection(attributes map[string]any, network ingest.NetworkProjection) protocolclass.Classification {
	classification := protocolclass.Classify(protocolclass.Observation{
		Transport:  network.Protocol,
		Service:    network.Service,
		ServerPort: network.DestinationPort,
		ClientPort: network.SourcePort,
	})
	attributes["protocol_category"] = string(classification.Category)
	attributes["protocol_visibility"] = string(classification.Visibility)
	attributes["protocol_evidence"] = string(classification.Evidence)
	attributes["protocol_exotic"] = classification.Exotic
	if service := boundedProjectionText(strings.ToLower(network.Service), 64); service != "" && service != classification.Protocol {
		attributes["analyzer_service"] = service
	}
	return classification
}

func encryptedHandshakeProjection(source ingest.Source, kind, service string, fields map[string]json.RawMessage) (string, string, string, string, string) {
	if isQUICObservation(kind, service) {
		if source == ingest.SourceSuricata {
			quic := projectionObject(fields["quic"])
			return boundedRawProjectionText(firstProjectionField(quic, "sni", "server_name"), 253), boundedRawProjectionText(quic["alpn"], 64), "", "quic", boundedRawProjectionText(quic["version"], 32)
		}
		return boundedRawProjectionText(fields["server_name"], 253), boundedRawProjectionText(firstProjectionField(fields, "alpn", "next_protocol"), 64), "", "quic", boundedRawProjectionText(fields["version"], 32)
	}
	if source == ingest.SourceSuricata {
		tls := projectionObject(fields["tls"])
		return boundedRawProjectionText(tls["sni"], 253), boundedRawProjectionText(tls["alpn"], 64), boundedRawProjectionText(tls["version"], 32), "tls", ""
	}
	return boundedRawProjectionText(fields["server_name"], 253), boundedRawProjectionText(fields["next_protocol"], 64), boundedRawProjectionText(fields["version"], 32), "tls", ""
}

func isEncryptedHandshakeObservation(kind, service string) bool {
	kind = strings.ToLower(kind)
	return strings.Contains(kind, "tls") || strings.Contains(kind, "ssl") || isQUICObservation(kind, service)
}

func isQUICObservation(kind, service string) bool {
	return strings.Contains(strings.ToLower(kind), "quic") || strings.EqualFold(service, "quic")
}

func cloudTransport(value string) string {
	switch strings.ToLower(value) {
	case "tcp", "udp", "icmp", "icmpv6":
		return strings.ToLower(value)
	default:
		return "other"
	}
}

func dnsTransport(value string) string {
	if strings.EqualFold(value, "tcp") {
		return "dns-tcp"
	}
	if strings.EqualFold(value, "udp") {
		return "dns-udp"
	}
	return "unknown"
}

func projectionObject(raw json.RawMessage) map[string]json.RawMessage {
	var value map[string]json.RawMessage
	if json.Unmarshal(raw, &value) != nil {
		return map[string]json.RawMessage{}
	}
	return value
}

func firstProjectionField(fields map[string]json.RawMessage, names ...string) json.RawMessage {
	for _, name := range names {
		if len(fields[name]) != 0 {
			return fields[name]
		}
	}
	return nil
}

func projectionFloat(raw json.RawMessage) float64 {
	var value float64
	if json.Unmarshal(raw, &value) != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
		return 0
	}
	return value
}

func unsignedProjectionNumber(raw json.RawMessage) uint64 {
	value := projectionFloat(raw)
	if value <= 0 || value > math.MaxUint64 || math.Trunc(value) != value {
		return 0
	}
	return uint64(value)
}

func secondsToMilliseconds(seconds float64) uint64 {
	if seconds <= 0 || seconds > float64(math.MaxUint64)/1000 {
		return 0
	}
	return uint64(math.Round(seconds * 1000))
}

func boundedRawProjectionText(raw json.RawMessage, maximum int) string {
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return ""
	}
	return boundedProjectionText(value, maximum)
}

func boundedProjectionText(value string, maximum int) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maximum {
		return ""
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return ""
		}
	}
	return value
}

func cloneProjectionAttributes(source map[string]any) map[string]any {
	result := make(map[string]any, len(source)+4)
	for key, value := range source {
		result[key] = value
	}
	return result
}
