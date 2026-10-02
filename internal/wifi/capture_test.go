package wifi

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/pcapng/pcapngtest"
	"shakerproxy.dev/shakerproxy/internal/wifi/wifitest"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/golden_events.json")

// scenario is a lab session as a monitor interface on channel 6 captures
// it: the lab access point beaconing, the phone searching for networks,
// joining the lab, a neighbor's network and a stranger's probe (dropped),
// roaming, and a disconnect.
func scenario() []pcapngtest.RawPacket {
	ch6 := wifitest.Radio{FrequencyMHz: 2437, SignalDBM: -45, FCS: true}
	weak := wifitest.Radio{FrequencyMHz: 2437, SignalDBM: -78, FCS: true}
	at := func(milliseconds int) time.Time { return testAt.Add(time.Duration(milliseconds) * time.Millisecond) }
	return []pcapngtest.RawPacket{
		{At: at(0), Data: wifitest.Beacon(ch6, labAP, "ShakerProxy-Lab", 6, 0x0411, wifitest.RSN(0x0080, 2, 8))},
		{At: at(50), Data: wifitest.Beacon(weak, neighborAP, "Neighbors", 6, 0x0411, wifitest.RSN(0, 2))},
		{At: at(100), Data: wifitest.ProbeRequest(ch6, phone, "", 200)},
		{At: at(110), Data: wifitest.ProbeRequest(ch6, phone, "HomeWiFi", 201)},
		{At: at(120), Data: wifitest.ProbeRequest(ch6, phone, "Hotel Guest", 202)},
		{At: at(130), Data: wifitest.ProbeRequest(weak, stranger, "CoffeeShop", 9)},
		{At: at(140), Data: wifitest.ProbeRequest(ch6, phoneRand, "Airport_Free", 204)},
		{At: at(400), Data: wifitest.Authentication(ch6, phone, labAP, false, 3, 1, 0)},
		{At: at(410), Data: wifitest.Authentication(ch6, phone, labAP, true, 3, 1, 0)},
		{At: at(420), Data: wifitest.Authentication(ch6, phone, labAP, false, 3, 2, 0)},
		{At: at(430), Data: wifitest.Authentication(ch6, phone, labAP, true, 3, 2, 0)},
		{At: at(440), Data: wifitest.AssociationRequest(ch6, phone, labAP, "ShakerProxy-Lab", "", 205)},
		{At: at(450), Data: wifitest.AssociationResponse(ch6, phone, labAP, false, 0)},
		{At: at(60000), Data: wifitest.AssociationRequest(ch6, phone, otherAP, "ShakerProxy-Lab", labAP, 300)},
		{At: at(60010), Data: wifitest.AssociationResponse(ch6, phone, otherAP, true, 0)},
		{At: at(120000), Data: wifitest.Deauthentication(ch6, phone, otherAP, false, false, false, 3)},
		{At: at(120100), Data: wifitest.Deauthentication(weak, stranger, neighborAP, true, false, false, 7)},
	}
}

func TestObserveFileMatchesGoldenEvents(t *testing.T) {
	file := pcapngtest.File(LinkTypeRadiotap, scenario())
	observer := NewObserver(labScope(false))
	progress, err := ObserveFile(context.Background(), bytes.NewReader(file), observer, 0)
	if err != nil || !progress.Complete || progress.Packets != len(scenario()) || progress.Frames != len(scenario()) {
		t.Fatalf("progress = %+v, %v", progress, err)
	}
	observer.Flush(testAt.Add(10 * time.Minute))
	type golden struct {
		Kind    string    `json:"kind"`
		At      time.Time `json:"at"`
		Payload Payload   `json:"payload"`
	}
	events := []golden{}
	for _, event := range observer.Drain() {
		events = append(events, golden{Kind: event.Kind, At: event.At, Payload: event.Payload})
	}
	got, err := json.MarshalIndent(events, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", "golden_events.json")
	if *updateGolden {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/wifi -run Golden -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("events differ from %s; run with -update and review the diff.\n%s", path, got)
	}
	for _, event := range events {
		if event.Payload.ClientMAC == stranger || event.Payload.BSSID == neighborAP || event.Payload.SSID == "CoffeeShop" {
			t.Fatalf("a bystander's frame was recorded: %+v", event)
		}
	}
}

func TestObserveFileResumesAPartialSegment(t *testing.T) {
	packets := scenario()
	file := pcapngtest.File(LinkTypeRadiotap, packets)
	// dumpcap is still writing: the file ends in the middle of a block.
	partial := file[:len(file)-20]
	observer := NewObserver(labScope(false))
	first, err := ObserveFile(context.Background(), bytes.NewReader(partial), observer, 0)
	if err != nil || first.Complete || first.Packets != len(packets)-1 {
		t.Fatalf("partial = %+v, %v", first, err)
	}
	second, err := ObserveFile(context.Background(), bytes.NewReader(file), observer, first.Packets)
	if err != nil || !second.Complete || second.Packets != len(packets) || second.Frames != 1 {
		t.Fatalf("resumed = %+v, %v", second, err)
	}
	empty, err := ObserveFile(context.Background(), bytes.NewReader(nil), observer, 0)
	if err == nil {
		t.Fatalf("an empty file read as complete: %+v", empty)
	}
}

func TestObserveFileIgnoresOtherLinkTypes(t *testing.T) {
	file := pcapngtest.File(1, []pcapngtest.RawPacket{{At: testAt, Data: wifitest.ProbeRequest(radio, phone, "HomeWiFi", 1)}})
	observer := NewObserver(labScope(false))
	progress, err := ObserveFile(context.Background(), bytes.NewReader(file), observer, 0)
	if err != nil || progress.Frames != 0 || len(observer.Drain()) != 0 {
		t.Fatalf("Ethernet capture was read as Wi-Fi: %+v %v", progress, err)
	}
}
