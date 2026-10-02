package ingest

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/inventory"
	"shakerproxy.dev/shakerproxy/internal/wifi"
)

const wifiTestDevice = "device-0123456789abcdef0123456789abcdef"

type fakeMACAttributor struct{ macs map[string]string }

func (fakeMACAttributor) ResolveAddress(netip.Addr, time.Time) (inventory.AddressAttribution, error) {
	return inventory.AddressAttribution{}, nil
}

func (f fakeMACAttributor) ResolveMAC(value string) (inventory.MACAttribution, error) {
	if device, ok := f.macs[value]; ok {
		return inventory.MACAttribution{DeviceID: device, Confidence: 90, Matched: true}, nil
	}
	return inventory.MACAttribution{}, nil
}

func wifiEnvelope(t *testing.T, kind string, payload wifi.Payload) Envelope {
	t.Helper()
	encoded, err := wifi.Event{Kind: kind, At: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC), Payload: payload}.Encode("evt_00000000000000000001_00000001_0123456789ab")
	if err != nil {
		t.Fatal(err)
	}
	var envelope Envelope
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatal(err)
	}
	if err := envelope.Validate(); err != nil {
		t.Fatal(err)
	}
	return envelope
}

func TestWiFiEventsProjectAsWiFiManagement(t *testing.T) {
	envelope := wifiEnvelope(t, wifi.KindProbe, wifi.Payload{Scope: wifi.ScopeLab, ClientMAC: "3c:22:fb:00:00:10", SSID: "HomeWiFi"})
	network := ProjectNetworkFields(envelope)
	if network.Protocol != "802.11" || network.Service != "wifi" || network.SourceIP != "" {
		t.Fatalf("network = %+v", network)
	}
	protocol := ProjectProtocolFields(envelope, network, TLSProjection{})
	if protocol.AppProtocol != "wifi" || protocol.Category != "network-management" || protocol.Visibility != "CLEARTEXT" || protocol.Exotic {
		t.Fatalf("protocol = %+v", protocol)
	}
	if StreamType(RecentEvent{Source: SourceHost, Kind: wifi.KindDeauth}) != StreamWiFi {
		t.Fatal("Wi-Fi events are not their own stream type")
	}
	// Only the Wi-Fi worker's kinds count: another HOST kind under wifi.
	// is not trusted as one.
	if isHostWiFi(SourceHost, "wifi.other") || isHostWiFi(SourceZeek, wifi.KindProbe) {
		t.Fatal("unknown Wi-Fi kind or source accepted")
	}
}

func TestWiFiEventsAttributeByHardwareAddress(t *testing.T) {
	attributor := fakeMACAttributor{macs: map[string]string{"3c:22:fb:00:00:10": wifiTestDevice}}
	envelope := wifiEnvelope(t, wifi.KindAssoc, wifi.Payload{Scope: wifi.ScopeLab, ClientMAC: "3c:22:fb:00:00:10", SSID: "Lab"})
	attributed, evidence, err := AttributeAnalyzerEvent(envelope, attributor)
	if err != nil || evidence != nil || attributed.DeviceID != wifiTestDevice || attributed.Confidence != 90 {
		t.Fatalf("attributed = %+v evidence %v err %v", attributed, evidence, err)
	}
	possible := wifiEnvelope(t, wifi.KindProbe, wifi.Payload{Scope: wifi.ScopeLab, ClientMAC: "da:a1:19:00:00:01", PossibleMAC: "3c:22:fb:00:00:10", SSID: "Work"})
	attributed, _, err = AttributeAnalyzerEvent(possible, attributor)
	if err != nil || attributed.DeviceID != wifiTestDevice || attributed.Confidence != wifi.PossibleMatchConfidence {
		t.Fatalf("possible match = %+v %v", attributed, err)
	}
	stranger := wifiEnvelope(t, wifi.KindProbe, wifi.Payload{Scope: wifi.ScopeNearby, ClientMAC: "f2:00:00:00:00:99", SSID: "Cafe"})
	attributed, _, err = AttributeAnalyzerEvent(stranger, attributor)
	if err != nil || attributed.DeviceID != "" {
		t.Fatalf("a nearby device was attributed: %+v %v", attributed, err)
	}
}

func TestParseWiFiFieldsBoundsWhatCameOffTheAir(t *testing.T) {
	fields := parseWiFiFields(`{"scope":"lab","client_mac":"3C:22:FB:00:00:10","bssid":"nope","ssid":"evil\u0000\u001bname","signal_dbm":12,"signal_min_dbm":-60,"frequency_mhz":1234,"channel":999,"reason":"x\ny","count":-4}`)
	if fields == nil {
		t.Fatal("payload rejected")
	}
	if fields.ClientMAC != "3c:22:fb:00:00:10" || fields.BSSID != "" || fields.SSID != "evilname" || fields.SignalDBM != nil || fields.SignalMinDBM == nil || fields.FrequencyMHz != 0 || fields.Channel != 0 || fields.Reason != "xy" || fields.Count != 0 {
		t.Fatalf("fields = %+v", fields)
	}
	for _, bad := range []string{"", "not json", `{"scope":"elsewhere"}`, `{"ssid":"x"}`} {
		if parseWiFiFields(bad) != nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestWiFiEventSummaries(t *testing.T) {
	signal, success, failure := -52, true, false
	reason := 15
	cases := []struct {
		kind   string
		fields WiFiFields
		want   string
	}{
		{wifi.KindProbe, WiFiFields{Scope: "lab", SSID: "HomeWiFi", SignalDBM: &signal, Channel: 6}, "Wi-Fi search for “HomeWiFi” · -52 dBm · ch 6"},
		{wifi.KindProbe, WiFiFields{Scope: "lab", Wildcard: true}, "Wi-Fi scan for any network"},
		{wifi.KindAssoc, WiFiFields{Scope: "lab", SSID: "Lab", Success: &success}, "Wi-Fi joined “Lab”"},
		{wifi.KindAssoc, WiFiFields{Scope: "lab", SSID: "Lab", Success: &success, Reassociation: true, PreviousBSSID: "aa:bb:cc:00:00:01"}, "Wi-Fi roamed to “Lab”"},
		{wifi.KindAssoc, WiFiFields{Scope: "lab", SSID: "Lab", Success: &failure, Status: "access point is full"}, "Wi-Fi join “Lab” refused: access point is full"},
		{wifi.KindAssoc, WiFiFields{Scope: "lab", SSID: "Lab", NoResponse: true}, "Wi-Fi join “Lab” got no answer"},
		{wifi.KindAuth, WiFiFields{Scope: "lab", SSID: "Lab", Success: &failure, Status: "challenge failure"}, "Wi-Fi authentication with “Lab” failed: challenge failure"},
		{wifi.KindDeauth, WiFiFields{Scope: "lab", SSID: "Lab", Direction: wifi.DirectionFromAP, ReasonCode: &reason, Reason: "4-way handshake timeout (often a wrong password)"}, "Wi-Fi access point dropped the device from “Lab” (4-way handshake timeout (often a wrong password))"},
		{wifi.KindDisassoc, WiFiFields{Scope: "lab", SSID: "Lab", Direction: wifi.DirectionFromClient, Protected: true}, "Wi-Fi device left “Lab” (protected frame, reason hidden)"},
		{wifi.KindBeaconSummary, WiFiFields{Scope: "nearby", Hidden: true, Security: "wpa2-personal"}, "Wi-Fi network a hidden network · wpa2-personal"},
	}
	for _, item := range cases {
		fields := item.fields
		got := EventSummary(RecentEvent{Source: SourceHost, Kind: item.kind, WiFi: &fields})
		if got != item.want {
			t.Errorf("%s: %q, want %q", item.kind, got, item.want)
		}
	}
	if got := EventSummary(RecentEvent{Source: SourceHost, Kind: wifi.KindProbe}); !strings.HasPrefix(got, "Wi-Fi") {
		t.Errorf("summary without fields = %q", got)
	}
}
