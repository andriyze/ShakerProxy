package ingest

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"shakerproxy.dev/shakerproxy/internal/inventory"
	"shakerproxy.dev/shakerproxy/internal/protocolclass"
	"shakerproxy.dev/shakerproxy/internal/wifi"
)

// Wi-Fi events are HOST events from shakerproxy-wifi-worker: 802.11
// management frames a passive monitor interface recorded (wifi.probe,
// wifi.auth, wifi.assoc, wifi.deauth, wifi.disassoc, wifi.beacon_summary).

// HostWiFiKindPattern matches every Wi-Fi event kind in the query language.
const HostWiFiKindPattern = "wifi.*"

// WiFiAppProtocol is the protocol catalog ID of Wi-Fi management events.
const WiFiAppProtocol = "wifi"

func isHostWiFi(source Source, kind string) bool {
	return source == SourceHost && wifi.KnownKind(kind)
}

// MACAttributor maps a hardware address to a device. inventory.Attributor
// implements it; ingest attributes Wi-Fi events with it.
type MACAttributor interface {
	ResolveMAC(string) (inventory.MACAttribution, error)
}

// attributeWiFiEvent attributes a Wi-Fi event by the client's hardware
// address, or, for a randomized address the worker matched to a lab device
// by fingerprint and sequence numbers, to that device with low confidence.
func attributeWiFiEvent(envelope Envelope, attributor DeviceAttributor) (Envelope, error) {
	macs, ok := attributor.(MACAttributor)
	if !ok {
		return envelope, nil
	}
	var payload struct {
		ClientMAC   string `json:"client_mac"`
		PossibleMAC string `json:"possible_mac"`
	}
	if json.Unmarshal(envelope.Payload, &payload) != nil {
		return envelope, nil
	}
	for index, value := range []string{payload.ClientMAC, payload.PossibleMAC} {
		if value == "" {
			continue
		}
		attribution, err := macs.ResolveMAC(value)
		if err != nil {
			return Envelope{}, fmt.Errorf("attribute Wi-Fi event: %w", err)
		}
		if !attribution.Matched {
			continue
		}
		confidence := attribution.Confidence
		if index == 1 {
			confidence = wifi.PossibleMatchConfidence
		}
		envelope.DeviceID = attribution.DeviceID
		envelope.Confidence = min(envelope.Confidence, confidence)
		if err := envelope.Validate(); err != nil {
			return Envelope{}, fmt.Errorf("validate attributed Wi-Fi event: %w", err)
		}
		return envelope, nil
	}
	return envelope, nil
}

func wifiProtocolProjection() ProtocolProjection {
	protocol, ok := protocolclass.Lookup(WiFiAppProtocol)
	if !ok {
		return ProtocolProjection{}
	}
	return ProtocolProjection{AppProtocol: protocol.ID, Category: string(protocol.Category), Visibility: string(protocol.Visibility), Evidence: string(protocolclass.EvidenceAnalyzer), Exotic: protocol.Exotic}
}

// WiFiFields is what a Wi-Fi event says, read from its payload when the
// event is queried. Every string came off the air and is untrusted.
type WiFiFields struct {
	Scope         string `json:"scope"`
	ClientMAC     string `json:"client_mac,omitempty"`
	Randomized    bool   `json:"randomized_mac,omitempty"`
	BSSID         string `json:"bssid,omitempty"`
	SSID          string `json:"ssid,omitempty"`
	Wildcard      bool   `json:"wildcard,omitempty"`
	Hidden        bool   `json:"hidden,omitempty"`
	Channel       int    `json:"channel,omitempty"`
	FrequencyMHz  int    `json:"frequency_mhz,omitempty"`
	SignalDBM     *int   `json:"signal_dbm,omitempty"`
	SignalMinDBM  *int   `json:"signal_min_dbm,omitempty"`
	SignalMaxDBM  *int   `json:"signal_max_dbm,omitempty"`
	Count         int    `json:"count,omitempty"`
	Direction     string `json:"direction,omitempty"`
	ReasonCode    *int   `json:"reason_code,omitempty"`
	Reason        string `json:"reason,omitempty"`
	Protected     bool   `json:"protected,omitempty"`
	StatusCode    *int   `json:"status_code,omitempty"`
	Status        string `json:"status,omitempty"`
	Success       *bool  `json:"success,omitempty"`
	NoResponse    bool   `json:"no_response,omitempty"`
	Algorithm     string `json:"algorithm,omitempty"`
	Reassociation bool   `json:"reassociation,omitempty"`
	PreviousBSSID string `json:"previous_bssid,omitempty"`
	Security      string `json:"security,omitempty"`
	PossibleMAC   string `json:"possible_mac,omitempty"`
}

// parseWiFiFields reads and bounds a Wi-Fi event's payload; it returns nil
// for anything that does not look like one.
func parseWiFiFields(text string) *WiFiFields {
	if text == "" || len(text) > 16<<10 {
		return nil
	}
	var fields WiFiFields
	if json.Unmarshal([]byte(text), &fields) != nil || fields.Scope != wifi.ScopeLab && fields.Scope != wifi.ScopeNearby {
		return nil
	}
	clean := func(value string, limit int) string {
		value = strings.ToValidUTF8(value, "")
		if utf8.RuneCountInString(value) > limit {
			value = string([]rune(value)[:limit])
		}
		return strings.Map(func(char rune) rune {
			if char < 0x20 || char == 0x7f {
				return -1
			}
			return char
		}, value)
	}
	mac := func(value string) string {
		parsed, ok := wifi.ParseMAC(value)
		if !ok {
			return ""
		}
		return parsed.String()
	}
	fields.ClientMAC, fields.BSSID, fields.PreviousBSSID, fields.PossibleMAC = mac(fields.ClientMAC), mac(fields.BSSID), mac(fields.PreviousBSSID), mac(fields.PossibleMAC)
	fields.SSID = clean(fields.SSID, 4*wifi.MaxSSIDBytes)
	fields.Reason, fields.Status = clean(fields.Reason, 96), clean(fields.Status, 96)
	fields.Algorithm, fields.Security, fields.Direction = clean(fields.Algorithm, 32), clean(fields.Security, 32), clean(fields.Direction, 16)
	if wifi.ChannelForFrequency(fields.FrequencyMHz) == 0 {
		fields.FrequencyMHz = 0
	}
	if fields.Channel < 0 || fields.Channel > 233 {
		fields.Channel = 0
	}
	for _, signal := range []**int{&fields.SignalDBM, &fields.SignalMinDBM, &fields.SignalMaxDBM} {
		if *signal != nil && (**signal >= 0 || **signal < -120) {
			*signal = nil
		}
	}
	if fields.Count < 0 {
		fields.Count = 0
	}
	return &fields
}

// wifiProjectionSQL is the payload of a Wi-Fi event, read at query time.
const wifiProjectionSQL = `CASE WHEN source = 'HOST' AND starts_with(kind, 'wifi.') THEN payload::text ELSE '' END`

func signalText(value *int) string {
	if value == nil {
		return ""
	}
	return " · " + strconv.Itoa(*value) + " dBm"
}

func networkName(fields *WiFiFields) string {
	switch {
	case fields.SSID != "":
		return "“" + fields.SSID + "”"
	case fields.Hidden:
		return "a hidden network"
	case fields.BSSID != "":
		return fields.BSSID
	}
	return "a network"
}

// wifiSummary is the plain-language line of a Wi-Fi event.
func wifiSummary(event RecentEvent) string {
	fields := event.WiFi
	if fields == nil {
		return "Wi-Fi " + strings.TrimPrefix(event.Kind, "wifi.")
	}
	channel := ""
	if fields.Channel != 0 {
		channel = " · ch " + strconv.Itoa(fields.Channel)
	}
	switch event.Kind {
	case wifi.KindProbe:
		if fields.Wildcard {
			return "Wi-Fi scan for any network" + signalText(fields.SignalDBM) + channel
		}
		return "Wi-Fi search for " + networkName(fields) + signalText(fields.SignalDBM) + channel
	case wifi.KindAuth:
		if fields.Success != nil && !*fields.Success {
			return "Wi-Fi authentication with " + networkName(fields) + " failed: " + fields.Status
		}
		return "Wi-Fi authentication with " + networkName(fields) + " (" + fields.Algorithm + ")"
	case wifi.KindAssoc:
		verb := "joined"
		if fields.Reassociation && fields.PreviousBSSID != "" {
			verb = "roamed to"
		} else if fields.Reassociation {
			verb = "rejoined"
		}
		switch {
		case fields.NoResponse:
			return "Wi-Fi join " + networkName(fields) + " got no answer"
		case fields.Success != nil && !*fields.Success:
			return "Wi-Fi join " + networkName(fields) + " refused: " + fields.Status
		}
		return "Wi-Fi " + verb + " " + networkName(fields) + signalText(fields.SignalDBM) + channel
	case wifi.KindDeauth, wifi.KindDisassoc:
		who := "device left"
		if fields.Direction == wifi.DirectionFromAP {
			who = "access point dropped the device from"
		}
		reason := fields.Reason
		if fields.Protected {
			reason = "protected frame, reason hidden"
		}
		if reason == "" {
			return "Wi-Fi " + who + " " + networkName(fields)
		}
		return "Wi-Fi " + who + " " + networkName(fields) + " (" + reason + ")"
	case wifi.KindBeaconSummary:
		line := "Wi-Fi network " + networkName(fields)
		if fields.Security != "" {
			line += " · " + fields.Security
		}
		return line + signalText(fields.SignalDBM) + channel
	}
	return "Wi-Fi " + strings.TrimPrefix(event.Kind, "wifi.")
}
