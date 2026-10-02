package wifi

import (
	"encoding/binary"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/wifi/wifitest"
)

var testAt = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func decodeOrFail(t *testing.T, data []byte) Frame {
	t.Helper()
	frame, ok := Decode(testAt, data)
	if !ok {
		t.Fatalf("frame did not decode: % x", data)
	}
	return frame
}

func TestParseRadiotapReadsChannelSignalAndFCS(t *testing.T) {
	for _, tsft := range []bool{false, true} {
		header := wifitest.Radiotap(wifitest.Radio{FrequencyMHz: 2437, SignalDBM: -52, FCS: true, TSFT: tsft})
		radio, err := ParseRadiotap(header)
		if err != nil {
			t.Fatalf("tsft=%v: %v", tsft, err)
		}
		if radio.Length != len(header) || radio.FrequencyMHz != 2437 || !radio.HasSignal || radio.SignalDBM != -52 || !radio.FCS || radio.BadFCS {
			t.Fatalf("tsft=%v: radiotap = %+v", tsft, radio)
		}
	}
}

func TestParseRadiotapRejectsMalformedHeaders(t *testing.T) {
	valid := wifitest.Radiotap(wifitest.Radio{FrequencyMHz: 5180, SignalDBM: -60})
	cases := map[string][]byte{
		"short":   valid[:6],
		"version": append([]byte{1}, valid[1:]...),
		"length too long": func() []byte {
			value := append([]byte(nil), valid...)
			binary.LittleEndian.PutUint16(value[2:4], 200)
			return value
		}(),
		"length too short": func() []byte {
			value := append([]byte(nil), valid...)
			binary.LittleEndian.PutUint16(value[2:4], 9)
			return value
		}(),
		"extended present runs past header": func() []byte {
			value := append([]byte(nil), valid...)
			binary.LittleEndian.PutUint32(value[4:8], binary.LittleEndian.Uint32(value[4:8])|1<<31)
			binary.LittleEndian.PutUint16(value[2:4], 8)
			return value[:8]
		}(),
	}
	for name, data := range cases {
		if _, err := ParseRadiotap(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseRadiotapSkipsExtendedPresentWords(t *testing.T) {
	// present word 0 says "flags, channel, signal, and another present
	// word follows"; the second word is empty.
	header := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(header[4:8], 1<<1|1<<3|1<<5|1<<31)
	header = append(header, 0x10)                   // flags at 12
	header = append(header, 0)                      // pad to 14 for channel
	header = append(header, 0x85, 0x09, 0xa0, 0x00) // 2437 MHz
	header = append(header, byte(0xc8))             // -56 dBm
	binary.LittleEndian.PutUint16(header[2:4], uint16(len(header)))
	radio, err := ParseRadiotap(header)
	if err != nil || radio.FrequencyMHz != 2437 || radio.SignalDBM != -56 || !radio.FCS {
		t.Fatalf("radiotap = %+v, %v", radio, err)
	}
}

func TestChannelFrequencyConversions(t *testing.T) {
	for frequency, channel := range map[int]int{2412: 1, 2437: 6, 2462: 11, 2484: 14, 5180: 36, 5745: 149, 5955: 1, 6115: 33, 2400: 0, 5000: 0} {
		if got := ChannelForFrequency(frequency); got != channel {
			t.Errorf("ChannelForFrequency(%d) = %d, want %d", frequency, got, channel)
		}
	}
	for channel, frequency := range map[int]int{1: 2412, 6: 2437, 14: 2484, 36: 5180, 165: 5825, 0: 0, 15: 0} {
		if got := FrequencyForChannel(channel); got != frequency {
			t.Errorf("FrequencyForChannel(%d) = %d, want %d", channel, got, frequency)
		}
	}
	if Band(2437) != "2.4GHz" || Band(5180) != "5GHz" || Band(6115) != "6GHz" || Band(900) != "" {
		t.Fatal("bands are wrong")
	}
}

func TestParseProbeRequest(t *testing.T) {
	frame := decodeOrFail(t, wifitest.ProbeRequest(wifitest.Radio{FrequencyMHz: 2437, SignalDBM: -48, FCS: true}, "da:a1:19:00:00:01", "HomeWiFi", 77))
	if frame.Frame.Subtype != SubtypeProbeRequest || frame.Frame.Sequence != 77 || frame.Frame.Addr2.String() != "da:a1:19:00:00:01" || !frame.Frame.Addr2.Randomized() {
		t.Fatalf("frame = %+v", frame.Frame)
	}
	if ssid := frame.Frame.SSID(); ssid.Name != "HomeWiFi" || ssid.Wildcard || ssid.Hidden {
		t.Fatalf("ssid = %+v", ssid)
	}
	if frame.Frame.Fingerprint() == "" {
		t.Fatal("probe has no fingerprint")
	}
	wildcard := decodeOrFail(t, wifitest.ProbeRequest(wifitest.Radio{FrequencyMHz: 2437}, "da:a1:19:00:00:01", "", 78))
	if ssid := wildcard.Frame.SSID(); !ssid.Wildcard || ssid.Name != "" {
		t.Fatalf("wildcard ssid = %+v", ssid)
	}
	if frame.Frame.Fingerprint() != wildcard.Frame.Fingerprint() {
		t.Fatal("the fingerprint depends on the SSID asked for")
	}
}

func TestBeaconSecurity(t *testing.T) {
	cases := []struct {
		name       string
		capability uint16
		security   []byte
		want       string
	}{
		{"open", 0x0401, nil, SecurityOpen},
		{"wep", 0x0411, nil, SecurityWEP},
		{"wpa", 0x0411, wifitest.Element(221, []byte{0x00, 0x50, 0xf2, 0x01, 0x01, 0x00}), SecurityWPA},
		{"wpa2", 0x0411, wifitest.RSN(0, 2), SecurityWPA2Personal},
		{"wpa3", 0x0411, wifitest.RSN(0x00c0, 8), SecurityWPA3Personal},
		{"transition", 0x0411, wifitest.RSN(0x0080, 2, 8), SecurityWPA2WPA3Personal},
		{"enterprise", 0x0411, wifitest.RSN(0, 1), SecurityWPA2Enterprise},
		{"enterprise wpa3", 0x0411, wifitest.RSN(0x00c0, 5), SecurityWPA3Enterprise},
		{"owe", 0x0411, wifitest.RSN(0x00c0, 18), SecurityEnhancedOpen},
	}
	for _, item := range cases {
		frame := decodeOrFail(t, wifitest.Beacon(wifitest.Radio{FrequencyMHz: 2412, SignalDBM: -70}, "aa:bb:cc:00:00:01", "Office", 1, item.capability, item.security))
		if got := frame.Frame.NetworkSecurity(); got != item.want {
			t.Errorf("%s: security = %q, want %q", item.name, got, item.want)
		}
		if frame.Frame.Channel() != 1 || !frame.Frame.TransmitterIsBSSID() {
			t.Errorf("%s: channel or BSSID wrong", item.name)
		}
	}
}

func TestParseAuthAssocAndDeauth(t *testing.T) {
	radio := wifitest.Radio{FrequencyMHz: 5180, SignalDBM: -40}
	auth := decodeOrFail(t, wifitest.Authentication(radio, "02:00:00:00:00:10", "aa:bb:cc:00:00:01", true, 3, 2, 0))
	if auth.Frame.AuthAlgorithm != 3 || auth.Frame.AuthSequence != 2 || !auth.Frame.HasStatus || auth.Frame.StatusCode != 0 {
		t.Fatalf("auth = %+v", auth.Frame)
	}
	request := decodeOrFail(t, wifitest.AssociationRequest(radio, "02:00:00:00:00:10", "aa:bb:cc:00:00:02", "Office", "aa:bb:cc:00:00:01", 9))
	if request.Frame.Subtype != SubtypeReassocRequest || !request.Frame.HasCurrentAP || request.Frame.CurrentAP.String() != "aa:bb:cc:00:00:01" || request.Frame.SSID().Name != "Office" {
		t.Fatalf("reassociation request = %+v", request.Frame)
	}
	response := decodeOrFail(t, wifitest.AssociationResponse(radio, "02:00:00:00:00:10", "aa:bb:cc:00:00:02", true, 17))
	if response.Frame.Subtype != SubtypeReassocResponse || response.Frame.StatusCode != 17 {
		t.Fatalf("response = %+v", response.Frame)
	}
	deauth := decodeOrFail(t, wifitest.Deauthentication(radio, "02:00:00:00:00:10", "aa:bb:cc:00:00:02", true, false, false, 15))
	if !deauth.Frame.HasReason || deauth.Frame.ReasonCode != 15 || ReasonText(15) == "" {
		t.Fatalf("deauthentication = %+v", deauth.Frame)
	}
	protected := decodeOrFail(t, wifitest.Deauthentication(radio, "02:00:00:00:00:10", "aa:bb:cc:00:00:02", true, false, true, 15))
	if !protected.Frame.Protected || protected.Frame.HasReason {
		t.Fatalf("protected deauthentication = %+v", protected.Frame)
	}
}

func TestDecodeRejectsNonManagementAndDamagedFrames(t *testing.T) {
	radio := wifitest.Radiotap(wifitest.Radio{FrequencyMHz: 2437, SignalDBM: -50})
	ack := append(append([]byte(nil), radio...), 0xd4, 0x00, 0x00, 0x00, 1, 2, 3, 4, 5, 6)
	if _, ok := Decode(testAt, ack); ok {
		t.Fatal("control frame decoded as management")
	}
	data := append(append([]byte(nil), radio...), make([]byte, 24)...)
	data[len(radio)] = 0x08 // data frame
	if _, ok := Decode(testAt, data); ok {
		t.Fatal("data frame decoded as management")
	}
	bad := wifitest.ProbeRequest(wifitest.Radio{FrequencyMHz: 2437, BadFCS: true}, "02:00:00:00:00:10", "x", 1)
	if _, ok := Decode(testAt, bad); ok {
		t.Fatal("frame with a bad FCS decoded")
	}
	beacon := wifitest.Beacon(wifitest.Radio{FrequencyMHz: 2412}, "aa:bb:cc:00:00:01", "Office", 1, 0, nil)
	if _, ok := Decode(testAt, beacon[:len(radio)+30]); ok {
		t.Fatal("truncated beacon decoded")
	}
}

func TestDisplaySSIDEscapesUnprintableBytes(t *testing.T) {
	cases := map[string]string{
		"Café":        "Café",
		"a\x00b":      `a\x00b`,
		"\xff\xfe":    `\xff\xfe`,
		`back\slash`:  `back\\slash`,
		"line\nbreak": `line\x0abreak`,
		"‮evil":       `\xe2\x80\xaeevil`,
	}
	for raw, want := range cases {
		if got := DisplaySSID([]byte(raw)); got != want {
			t.Errorf("DisplaySSID(%q) = %q, want %q", raw, got, want)
		}
	}
	hidden := decodeOrFail(t, wifitest.Beacon(wifitest.Radio{FrequencyMHz: 2412}, "aa:bb:cc:00:00:01", "\x00\x00\x00", 1, 0, nil))
	if ssid := hidden.Frame.SSID(); !ssid.Hidden || ssid.Name != "" {
		t.Fatalf("zeroed SSID = %+v", ssid)
	}
}

func TestParseMAC(t *testing.T) {
	mac, ok := ParseMAC("AA-bb-cc-dd-ee-0F")
	if !ok || mac.String() != "aa:bb:cc:dd:ee:0f" {
		t.Fatalf("ParseMAC = %v %v", mac, ok)
	}
	for _, bad := range []string{"", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:gg", "aabbccddeeff00000"} {
		if _, ok := ParseMAC(bad); ok {
			t.Errorf("ParseMAC(%q) accepted", bad)
		}
	}
}
