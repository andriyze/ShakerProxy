package mcpserver

import (
	"context"
	"strings"
	"testing"

	"shakerproxy.dev/shakerproxy/internal/agentapi"
	"shakerproxy.dev/shakerproxy/internal/ingest"
	"shakerproxy.dev/shakerproxy/internal/querylang"
)

func TestWiFiActivitySummarizesSearchesJoinsAndAddresses(t *testing.T) {
	backend := newFakeBackend()
	success := true
	reason := 3
	wifiEvent := func(id byte, kind string, fields ingest.WiFiFields) agentapi.Event {
		return agentapi.Event{RecentEvent: ingest.RecentEvent{RecordID: strings.Repeat(string(id), 64), Source: ingest.SourceHost, Kind: kind, OccurredAt: fakeNow, DeviceID: tvID, DeviceFriendlyName: "Living room TV", WiFi: &fields}}
	}
	backend.page.Events = []agentapi.Event{
		wifiEvent('a', "wifi.probe", ingest.WiFiFields{Scope: "lab", ClientMAC: "3c:22:fb:00:00:10", SSID: "HomeWiFi"}),
		wifiEvent('b', "wifi.probe", ingest.WiFiFields{Scope: "lab", ClientMAC: "da:a1:19:00:00:01", Randomized: true, PossibleMAC: "3c:22:fb:00:00:10", SSID: "HomeWiFi"}),
		wifiEvent('c', "wifi.probe", ingest.WiFiFields{Scope: "lab", ClientMAC: "3c:22:fb:00:00:10", SSID: "Hotel Guest"}),
		wifiEvent('d', "wifi.assoc", ingest.WiFiFields{Scope: "lab", ClientMAC: "3c:22:fb:00:00:10", SSID: "ShakerProxy-Lab", Success: &success}),
		wifiEvent('e', "wifi.deauth", ingest.WiFiFields{Scope: "lab", ClientMAC: "3c:22:fb:00:00:10", SSID: "ShakerProxy-Lab", ReasonCode: &reason, Reason: "station is leaving (or has left)"}),
	}
	service := &Service{backend: backend}
	result, _, err := service.wifiActivity(context.Background(), nil, WiFiActivityArgs{Device: "tv", Window: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	query := backend.lastSearch().Query
	if parsed, err := querylang.Parse(query); err != nil || parsed.Root == nil {
		t.Fatalf("query does not parse: %q %v", query, err)
	}
	for _, fragment := range []string{"kind:wifi.*", "NOT kind:wifi.beacon_summary", "device.id:" + tvID, "time:last_1h"} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("query %q lacks %q", query, fragment)
		}
	}
	var data struct {
		Summary     string `json:"summary"`
		Monitoring  string `json:"monitoring"`
		SearchedFor []struct {
			SSID     string `json:"ssid"`
			Searches int    `json:"searches"`
		} `json:"searched_for"`
		Connections []struct{ SSID string } `json:"connections"`
		Disconnects []struct{ SSID string } `json:"disconnects"`
		Addresses   []struct {
			MAC        string `json:"mac"`
			Randomized bool   `json:"randomized"`
			Possible   bool   `json:"possible_match"`
		} `json:"addresses"`
	}
	decodeToolResult(t, result, &data)
	if len(data.SearchedFor) != 2 || data.SearchedFor[0].SSID != "HomeWiFi" || data.SearchedFor[0].Searches != 2 {
		t.Fatalf("searched for = %+v", data.SearchedFor)
	}
	if len(data.Connections) != 1 || len(data.Disconnects) != 1 || len(data.Addresses) != 2 {
		t.Fatalf("result = %+v", data)
	}
	if !strings.Contains(data.Monitoring, "listening with wlan1 (channel 6)") || !strings.Contains(data.Summary, "2 named networks") {
		t.Fatalf("summary %q monitoring %q", data.Summary, data.Monitoring)
	}
}
