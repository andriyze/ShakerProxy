package main

import (
	"strings"
	"testing"
)

const wifiOff = `{"schema":1,"settings":{"enabled":false,"channel_mode":"auto","nearby":false},"available":true,"active":false,
 "shared_with_access_point":false,"capturing":false,"worker_running":false,"lab_devices":3,
 "adapters":[{"interface":"wlan0","monitor_supported":false,"monitor_alongside_ap":false,"access_point":false,"in_use":true,"bands":["2.4GHz"],"channels":[1]},
 {"interface":"wlan1","monitor_supported":true,"monitor_alongside_ap":true,"access_point":false,"in_use":false,"bands":["2.4GHz","5GHz"],"channels":[1,6,11,36]}],
 "nearby_retention_hours":24,"checked_at":"2026-10-02T12:00:00Z","notes":["Listening is passive: ShakerProxy never transmits, injects or disconnects anything."]}`

const wifiOn = `{"schema":1,"settings":{"enabled":true,"channel_mode":"fixed","channel":6,"nearby":false},"available":true,"active":true,
 "interface":"spmon0","adapter":"wlan1","shared_with_access_point":false,"channel_mode":"fixed","channel":6,"frequency_mhz":2437,
 "capturing":true,"worker_running":true,"lab_devices":3,"adapters":[],"nearby_retention_hours":24,"checked_at":"2026-10-02T12:00:00Z","notes":[]}`

func TestWiFiShowsAndChangesWiFiVisibility(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /api/v1/wifi-visibility", 200, wifiOff)
	api.json("PUT /api/v1/wifi-visibility", 200, wifiOn)
	c, _, _ := testCLI()
	code, stdout, stderr := runCLI(t, c, "wifi")
	if code != exitOK || !strings.Contains(stdout, "Wi-Fi visibility  off") || !strings.Contains(stdout, "wlan1: monitor mode, 2.4GHz/5GHz") || !strings.Contains(stdout, "carries this host's connection") || !strings.Contains(stdout, "only lab devices") {
		t.Fatalf("wifi status: %d\n%s\n%s", code, stdout, stderr)
	}
	code, stdout, stderr = runCLI(t, c, "wifi", "channel", "6")
	if code != exitOK || !strings.Contains(stdout, "listening with wlan1 (channel 6)") {
		t.Fatalf("wifi channel 6: %d\n%s\n%s", code, stdout, stderr)
	}
	puts := api.find("PUT", "/api/v1/wifi-visibility")
	if len(puts) != 1 || string(puts[0].Body) != `{"channel":6,"channel_mode":"fixed"}` {
		t.Fatalf("PUT body = %v", puts)
	}
	if code, _, _ = runCLI(t, c, "wifi", "on", "--adapter", "wlan1"); code != exitOK {
		t.Fatalf("wifi on: %d", code)
	}
	puts = api.find("PUT", "/api/v1/wifi-visibility")
	if len(puts) != 2 || string(puts[1].Body) != `{"adapter":"wlan1","enabled":true}` {
		t.Fatalf("PUT bodies = %v", puts)
	}
	code, _, stderr = runCLI(t, c, "wifi", "nearby", "on")
	if code == exitOK || !strings.Contains(stderr, "--confirm") {
		t.Fatalf("nearby without --confirm: %d %s", code, stderr)
	}
	code, _, stderr = runCLI(t, c, "wifi", "channel", "loud")
	if code == exitOK || !strings.Contains(stderr, "not a channel") {
		t.Fatalf("bad channel: %d %s", code, stderr)
	}
	if code, _, _ = runCLI(t, c, "wifi", "nearby", "on", "--confirm"); code != exitOK {
		t.Fatalf("nearby --confirm: %d", code)
	}
	puts = api.find("PUT", "/api/v1/wifi-visibility")
	if len(puts) != 3 || string(puts[2].Body) != `{"acknowledge_nearby":true,"nearby":true}` {
		t.Fatalf("PUT bodies = %v", puts)
	}
}
