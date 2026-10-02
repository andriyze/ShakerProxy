package ingest

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"time"

	"shakerproxy.dev/shakerproxy/internal/inventory"
)

// DeviceAttributor maps an event address to a device at the event time.
// IPv4 addresses resolve through DHCPv4 lease windows and IPv6 addresses
// through NDP neighbor windows.
type DeviceAttributor interface {
	ResolveAddress(netip.Addr, time.Time) (inventory.AddressAttribution, error)
}

const AttributionEvidenceSchema = 1

type AttributionEndpoint string

const (
	AttributionEndpointSource      AttributionEndpoint = "SOURCE"
	AttributionEndpointDestination AttributionEndpoint = "DESTINATION"
)

var attributionInterfacePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$`)
var attributionSHA256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type AttributionEvidence struct {
	Schema          int                      `json:"schema"`
	DeviceID        string                   `json:"device_id"`
	Address         string                   `json:"address"`
	Endpoint        AttributionEndpoint      `json:"endpoint"`
	Source          inventory.EvidenceSource `json:"source"`
	Confidence      int                      `json:"confidence"`
	ValidFrom       time.Time                `json:"valid_from"`
	ValidUntil      time.Time                `json:"valid_until"`
	Interface       string                   `json:"interface,omitempty"`
	VLANID          *int                     `json:"vlan_id,omitempty"`
	ScopePlanSHA256 string                   `json:"scope_plan_sha256,omitempty"`
}

func (e AttributionEvidence) Validate(event RecentEvent) error {
	address, err := netip.ParseAddr(e.Address)
	if err != nil || !attributionSourceMatchesFamily(address, e.Source) || address.String() != e.Address || e.Schema != AttributionEvidenceSchema || e.Endpoint != AttributionEndpointSource && e.Endpoint != AttributionEndpointDestination || e.Confidence < 1 || e.Confidence > 100 || e.ValidFrom.IsZero() || !e.ValidUntil.After(e.ValidFrom) {
		return errors.New("event attribution evidence is invalid")
	}
	if e.Interface == "" {
		if e.VLANID != nil || e.ScopePlanSHA256 != "" {
			return errors.New("event attribution scope is partial")
		}
	} else if !attributionInterfacePattern.MatchString(e.Interface) || e.VLANID != nil && (*e.VLANID < 1 || *e.VLANID > 4094) || !attributionSHA256Pattern.MatchString(e.ScopePlanSHA256) {
		return errors.New("event attribution scope is invalid")
	}
	attributable := event.Source == SourceZeek || event.Source == SourceSuricata || isHostClientKind(event.Source, event.Kind) && e.Endpoint == AttributionEndpointSource
	if event.DeviceID == "" || e.DeviceID != event.DeviceID || !deviceIDPattern.MatchString(e.DeviceID) || !attributable || event.Confidence > e.Confidence || event.OccurredAt.Before(e.ValidFrom) || !event.OccurredAt.Before(e.ValidUntil) {
		return errors.New("event attribution evidence does not cover the event")
	}
	if e.Endpoint == AttributionEndpointSource && event.SourceIP != e.Address || e.Endpoint == AttributionEndpointDestination && event.DestinationIP != e.Address {
		return errors.New("event attribution endpoint does not match the network projection")
	}
	return nil
}

// AttributeAnalyzerEvent attributes Zeek and Suricata events by either
// endpoint, and DNS forwarder lookups and gateway connection openings by the
// client that made them.
func AttributeAnalyzerEvent(envelope Envelope, attributor DeviceAttributor) (Envelope, *AttributionEvidence, error) {
	if attributor != nil && envelope.DeviceID == "" && isHostWiFi(envelope.Source, envelope.Kind) {
		// Wi-Fi frames carry hardware addresses, not IP addresses.
		attributed, err := attributeWiFiEvent(envelope, attributor)
		return attributed, nil, err
	}
	if attributor == nil || envelope.DeviceID != "" || envelope.Source != SourceZeek && envelope.Source != SourceSuricata && !isHostClientKind(envelope.Source, envelope.Kind) {
		return envelope, nil, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(envelope.Payload, &fields); err != nil || fields == nil {
		return envelope, nil, nil
	}
	endpoints := []string{"id.orig_h", "id.resp_h"}
	switch {
	case envelope.Source == SourceSuricata:
		endpoints = []string{"src_ip", "dest_ip"}
	case isHostClientKind(envelope.Source, envelope.Kind):
		// The client opened it: a lookup's other end is ShakerProxy itself,
		// and a connection's or blocked attempt's is somewhere on the internet.
		endpoints = []string{"source_ip"}
	}
	for endpointIndex, field := range endpoints {
		address, ok := analyzerAddress(fields[field])
		if !ok {
			continue
		}
		attribution, err := attributor.ResolveAddress(address, envelope.OccurredAt)
		if err != nil {
			return Envelope{}, nil, fmt.Errorf("attribute analyzer event: %w", err)
		}
		if attribution.Ambiguous {
			if endpointIndex == 0 {
				return envelope, nil, nil
			}
			continue
		}
		if attribution.Matched {
			envelope.DeviceID = attribution.DeviceID
			envelope.Confidence = min(envelope.Confidence, attribution.Confidence)
			if err := envelope.Validate(); err != nil {
				return Envelope{}, nil, fmt.Errorf("validate attributed analyzer event: %w", err)
			}
			endpoint := AttributionEndpointSource
			if endpointIndex == 1 {
				endpoint = AttributionEndpointDestination
			}
			evidence := &AttributionEvidence{
				Schema: AttributionEvidenceSchema, DeviceID: attribution.DeviceID, Address: attribution.Address, Endpoint: endpoint,
				Source: attribution.Source, Confidence: attribution.Confidence, ValidFrom: attribution.ValidFrom,
				ValidUntil: attribution.ValidUntil, Interface: attribution.Interface,
				VLANID: cloneAttributionVLAN(attribution.VLANID), ScopePlanSHA256: attribution.ScopePlanSHA256,
			}
			projection := ProjectNetworkFields(envelope)
			projected := RecentEvent{Source: envelope.Source, Kind: envelope.Kind, OccurredAt: envelope.OccurredAt, DeviceID: envelope.DeviceID, Confidence: envelope.Confidence, SourceIP: projection.SourceIP, DestinationIP: projection.DestinationIP}
			if err := evidence.Validate(projected); err != nil {
				return Envelope{}, nil, fmt.Errorf("validate analyzer attribution evidence: %w", err)
			}
			return envelope, evidence, nil
		}
	}
	return envelope, nil, nil
}

func cloneAttributionVLAN(value *int) *int {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

// analyzerAddress accepts the unicast IPv4 and IPv6 endpoint addresses that
// Zeek and Suricata log. IPv4-mapped IPv6 is treated as IPv4, matching the
// network projection; zoned (scope-qualified) addresses are never attributed.
func analyzerAddress(raw json.RawMessage) (netip.Addr, bool) {
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return netip.Addr{}, false
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, false
	}
	address = address.Unmap()
	if address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() {
		return netip.Addr{}, false
	}
	return address, true
}

func attributionSourceMatchesFamily(address netip.Addr, source inventory.EvidenceSource) bool {
	switch source {
	case inventory.SourceDHCP4Lease:
		return address.Is4()
	case inventory.SourceNDP:
		return address.Is6() && !address.Is4In6() && address.Zone() == ""
	case inventory.SourceARP, inventory.SourceObservedDHCP:
		return address.Is4()
	case inventory.SourcePinnedAddress:
		return address.Zone() == "" && !address.Is4In6()
	}
	return false
}
