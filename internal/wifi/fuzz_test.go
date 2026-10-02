package wifi

import (
	"encoding/json"
	"testing"
	"time"
	"unicode/utf8"

	"shakerproxy.dev/shakerproxy/internal/wifi/wifitest"
)

func fuzzSeeds() [][]byte {
	seeds := [][]byte{}
	for _, packet := range scenario() {
		seeds = append(seeds, packet.Data)
	}
	return append(seeds,
		wifitest.ProbeRequest(wifitest.Radio{FrequencyMHz: 5180, SignalDBM: -60, TSFT: true}, phoneRand, "\xff\x00x", 1),
		wifitest.Beacon(wifitest.Radio{FrequencyMHz: 2412}, labAP, "", 1, 0x0411, wifitest.RSN(0x00c0, 2, 8, 18)),
		wifitest.Deauthentication(wifitest.Radio{FrequencyMHz: 2412}, "ff:ff:ff:ff:ff:ff", labAP, true, false, true, 7),
		[]byte{0, 0, 8, 0, 0, 0, 0, 0},
	)
}

// FuzzDecode feeds arbitrary captures to the radiotap and 802.11 parsers:
// they must never panic, and what they return must be safe to record.
func FuzzDecode(f *testing.F) {
	for _, seed := range fuzzSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		frame, ok := Decode(testAt, data)
		if !ok {
			return
		}
		ssid := frame.Frame.SSID()
		if !utf8.ValidString(ssid.Name) || len(ssid.Name) > 4*MaxSSIDBytes {
			t.Fatalf("unsafe SSID %q", ssid.Name)
		}
		for _, char := range ssid.Name {
			if char < 0x20 || char == 0x7f {
				t.Fatalf("SSID %q carries a control character", ssid.Name)
			}
		}
		_ = frame.Frame.NetworkSecurity()
		_ = frame.Frame.Fingerprint()
		_ = frame.Frame.Channel()
		if len(frame.Frame.Elements) > maxElements {
			t.Fatalf("%d elements", len(frame.Frame.Elements))
		}
	})
}

// FuzzObserver feeds a stream of arbitrary frames through the observer and
// checks every event it produces encodes within bounds.
func FuzzObserver(f *testing.F) {
	seeds := fuzzSeeds()
	for index := range seeds {
		f.Add(seeds[index], seeds[(index+1)%len(seeds)], true)
	}
	f.Fuzz(func(t *testing.T, first, second []byte, nearby bool) {
		observer := NewObserver(labScope(nearby))
		for index, data := range [][]byte{first, second, first} {
			if frame, ok := Decode(testAt.Add(time.Duration(index)*time.Second), data); ok {
				observer.Observe(frame)
			}
		}
		observer.Flush(testAt.Add(time.Hour))
		for _, event := range observer.Drain() {
			encoded, err := event.Encode("0123456789abcdef0123456789abcdef")
			if err != nil {
				t.Fatalf("event %+v does not encode: %v", event, err)
			}
			if !json.Valid(encoded) {
				t.Fatal("invalid JSON")
			}
			if !nearby && event.Payload.Scope != ScopeLab {
				t.Fatalf("recorded outside the lab without opt-in: %+v", event)
			}
		}
	})
}
