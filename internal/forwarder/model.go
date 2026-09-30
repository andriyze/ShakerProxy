// Package forwarder delivers a deliberately narrow, payload-free event
// projection to explicitly configured integrations. Raw event bodies, TLS key
// logs, CA material, credentials, and packet bytes have no field in its schema.
package forwarder

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"regexp"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/ingest"
)

const SchemaVersion = 1

type EventClass string

const (
	ClassAlert              EventClass = "ALERT"
	ClassDNS                EventClass = "DNS_ENFORCEMENT"
	ClassDevice             EventClass = "DEVICE_LIFECYCLE"
	ClassAudit              EventClass = "AUDIT"
	ClassHealth             EventClass = "SERVICE_HEALTH"
	ClassNetworkObservation EventClass = "NETWORK_OBSERVATION"
)

type SafeNetwork struct {
	SourceIP        string `json:"source_ip,omitempty"`
	DestinationIP   string `json:"destination_ip,omitempty"`
	SourcePort      int    `json:"source_port,omitempty"`
	DestinationPort int    `json:"destination_port,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
	Service         string `json:"service,omitempty"`
	NetworkBytes    int64  `json:"network_bytes,omitempty"`
}

type SafeEvent struct {
	Schema           int           `json:"schema"`
	ApplianceID      string        `json:"appliance_id"`
	Sequence         uint64        `json:"sequence"`
	Class            EventClass    `json:"class"`
	EventID          string        `json:"event_id"`
	Source           ingest.Source `json:"source"`
	Kind             string        `json:"kind"`
	OccurredAt       time.Time     `json:"occurred_at"`
	CaptureSessionID string        `json:"capture_session_id,omitempty"`
	FlowID           string        `json:"flow_id,omitempty"`
	DeviceID         string        `json:"device_id,omitempty"`
	Confidence       int           `json:"confidence,omitempty"`
	Network          *SafeNetwork  `json:"network,omitempty"`
}

var (
	safeOpaqueIDPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
	safeDeviceIDPattern    = regexp.MustCompile(`^device-[a-f0-9]{32}$`)
	safeNetworkTextPattern = regexp.MustCompile(`^[a-z0-9_.+-]{1,64}$`)
)

func Project(applianceID string, sequence uint64, envelope ingest.Envelope) (SafeEvent, error) {
	if err := envelope.Validate(); err != nil {
		return SafeEvent{}, err
	}
	if !validApplianceID(applianceID) || sequence == 0 {
		return SafeEvent{}, errors.New("safe event identity is invalid")
	}
	projection := ingest.ProjectNetworkFields(envelope)
	var network *SafeNetwork
	if projection.SourceIP != "" || projection.DestinationIP != "" || projection.SourcePort != 0 || projection.DestinationPort != 0 || projection.Protocol != "" || projection.Service != "" || projection.NetworkBytes != 0 {
		network = &SafeNetwork{SourceIP: projection.SourceIP, DestinationIP: projection.DestinationIP, SourcePort: projection.SourcePort, DestinationPort: projection.DestinationPort, Protocol: projection.Protocol, Service: projection.Service, NetworkBytes: projection.NetworkBytes}
	}
	event := SafeEvent{Schema: SchemaVersion, ApplianceID: applianceID, Sequence: sequence, Class: classify(envelope), EventID: envelope.EventID, Source: envelope.Source, Kind: envelope.Kind, OccurredAt: envelope.OccurredAt.UTC(), CaptureSessionID: envelope.CaptureSessionID, FlowID: envelope.FlowID, DeviceID: envelope.DeviceID, Confidence: envelope.Confidence, Network: network}
	if err := event.Validate(); err != nil {
		return SafeEvent{}, err
	}
	return event, nil
}

func (event SafeEvent) Validate() error {
	if event.Schema != SchemaVersion || !validApplianceID(event.ApplianceID) || event.Sequence == 0 || !safeOpaqueIDPattern.MatchString(event.EventID) || !safeText(event.Kind, 1, 256) || event.OccurredAt.IsZero() || event.OccurredAt.Year() < 2000 || event.OccurredAt.Year() > 3000 || event.Confidence < 0 || event.Confidence > 100 {
		return errors.New("safe event has invalid identity or bounds")
	}
	switch event.Class {
	case ClassAlert, ClassDNS, ClassDevice, ClassAudit, ClassHealth, ClassNetworkObservation:
	default:
		return errors.New("safe event class is invalid")
	}
	switch event.Source {
	case ingest.SourceHost, ingest.SourceZeek, ingest.SourceSuricata, ingest.SourceMitmproxy:
	default:
		return errors.New("safe event source is invalid")
	}
	if event.CaptureSessionID != "" && !capture.ValidSessionID(event.CaptureSessionID) || event.FlowID != "" && !safeOpaqueIDPattern.MatchString(event.FlowID) || event.DeviceID != "" && !safeDeviceIDPattern.MatchString(event.DeviceID) {
		return errors.New("safe event resource identity is invalid")
	}
	if event.Network != nil {
		network := event.Network
		for _, address := range []string{network.SourceIP, network.DestinationIP} {
			if address != "" && net.ParseIP(address) == nil {
				return errors.New("safe event network address is invalid")
			}
		}
		if network.SourcePort < 0 || network.SourcePort > 65535 || network.DestinationPort < 0 || network.DestinationPort > 65535 || network.NetworkBytes < 0 {
			return errors.New("safe event network counters are invalid")
		}
		for _, value := range []string{network.Protocol, network.Service} {
			if value != "" && !safeNetworkTextPattern.MatchString(value) {
				return errors.New("safe event network classification is invalid")
			}
		}
	}
	return nil
}

func safeText(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum || value != strings.TrimSpace(value) {
		return false
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func classify(envelope ingest.Envelope) EventClass {
	kind := strings.ToLower(envelope.Kind)
	switch {
	case strings.Contains(kind, "alert"):
		return ClassAlert
	case strings.HasPrefix(kind, "dns.") || strings.Contains(kind, "dns_enforcement"):
		return ClassDNS
	case strings.HasPrefix(kind, "device.") || strings.Contains(kind, "device_lifecycle"):
		return ClassDevice
	case strings.HasPrefix(kind, "audit.") || strings.Contains(kind, "config_audit"):
		return ClassAudit
	case strings.Contains(kind, "health") || strings.Contains(kind, "pressure") || strings.Contains(kind, "degraded"):
		return ClassHealth
	default:
		return ClassNetworkObservation
	}
}

func EventDigest(event SafeEvent) string {
	encoded, _ := json.Marshal(event)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
