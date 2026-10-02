package ingest

import (
	"encoding/json"
	"fmt"
	"net/url"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/wifi"
)

// Wi-Fi events go through the real write path: attributed by hardware
// address, projected, classified, read back with their fields and summary,
// and nearby ones pruned after their retention.
func TestPostgresWiFiEventsRoundTripAndNearbyRetention(t *testing.T) {
	database, sink, ctx := openTrafficSummaryDatabase(t)
	sink.Attributor = fakeMACAttributor{macs: map[string]string{"3c:22:fb:00:00:10": wifiTestDevice}}
	now := time.Now().UTC().Truncate(time.Second)
	spool := &Spool{Root: t.TempDir(), MaxBytes: 16 << 20, ReserveBytes: 1, Now: func() time.Time { return now }}
	signal := -48
	seeds := []struct {
		kind    string
		at      time.Time
		payload wifi.Payload
	}{
		{wifi.KindProbe, now.Add(-time.Minute), wifi.Payload{Scope: wifi.ScopeLab, ClientMAC: "3c:22:fb:00:00:10", SSID: "HomeWiFi", Channel: 6, FrequencyMHz: 2437, SignalDBM: &signal, Direction: wifi.DirectionFromClient}},
		{wifi.KindBeaconSummary, now.Add(-time.Minute), wifi.Payload{Scope: wifi.ScopeNearby, BSSID: "10:22:33:00:00:09", SSID: "Neighbors", Security: "wpa2-personal"}},
		{wifi.KindProbe, now.Add(-25 * time.Hour), wifi.Payload{Scope: wifi.ScopeNearby, ClientMAC: "f2:00:00:00:00:99", SSID: "Cafe"}},
		{wifi.KindProbe, now.Add(-25 * time.Hour), wifi.Payload{Scope: wifi.ScopeLab, ClientMAC: "3c:22:fb:00:00:10", SSID: "Old"}},
	}
	for index, seed := range seeds {
		ensureSummaryPartition(t, ctx, database, seed.at)
		encoded, err := wifi.Event{Kind: seed.kind, At: seed.at, Payload: seed.payload}.Encode(fmt.Sprintf("evt_%020d_%08x_0123456789ab", seed.at.UnixNano(), index))
		if err != nil {
			t.Fatal(err)
		}
		if result, err := spool.Accept(encoded); err != nil || !result.Accepted {
			t.Fatalf("seed %d: %#v %v", index, result, err)
		}
	}
	batch, err := spool.PendingBatch(100)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.WriteBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	query, err := ParseRecentEventQuery(url.Values{"q": {"kind:" + HostWiFiKindPattern + " AND time:last_2h"}, "limit": {"10"}})
	if err != nil {
		t.Fatal(err)
	}
	page, err := sink.QueryRecent(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 2 {
		raw, _ := json.Marshal(page.Events)
		t.Fatalf("events = %s", raw)
	}
	var probe RecentEvent
	for _, event := range page.Events {
		if event.Kind == wifi.KindProbe {
			probe = event
		}
	}
	if probe.DeviceID != wifiTestDevice || probe.AppProtocol != "wifi" || probe.Protocol != "802.11" || probe.WiFi == nil || probe.WiFi.SSID != "HomeWiFi" || probe.WiFi.SignalDBM == nil || *probe.WiFi.SignalDBM != -48 {
		raw, _ := json.Marshal(probe)
		t.Fatalf("probe = %s", raw)
	}
	if probe.Summary != "Wi-Fi search for “HomeWiFi” · -48 dBm · ch 6" {
		t.Fatalf("summary = %q", probe.Summary)
	}
	var streamType string
	if err := database.QueryRowContext(ctx, `SELECT `+streamTypeSQL+` FROM normalized_events WHERE kind = 'wifi.beacon_summary'`).Scan(&streamType); err != nil || streamType != StreamWiFi {
		t.Fatalf("SQL stream type = %q %v", streamType, err)
	}
	deleted, err := sink.PruneNearbyWiFi(ctx, now.Add(-NearbyWiFiRetention))
	if err != nil || deleted != 1 {
		t.Fatalf("pruned %d: %v", deleted, err)
	}
	var remaining int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM normalized_events WHERE kind LIKE 'wifi.%'`).Scan(&remaining); err != nil || remaining != 3 {
		t.Fatalf("remaining = %d %v", remaining, err)
	}
}
