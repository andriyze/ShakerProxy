package syslogcollector

import (
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

func TestParseRecognizesUniFiLines(t *testing.T) {
	now := time.Date(2026, 10, 2, 23, 48, 30, 0, time.UTC)
	cases := []struct {
		name     string
		line     string
		kind     string
		expected map[string]any
	}{
		{
			name: "dnsmasq DHCPACK with hostname",
			line: "<30>Oct  2 23:48:30 UDMPRO dnsmasq-dhcp[2001]: DHCPACK(br0) 192.168.10.130 62:bc:f1:bc:1d:8d iPhone",
			kind: ingest.NetworkGearDHCPKind,
			expected: map[string]any{
				"mac": "62:bc:f1:bc:1d:8d", "assigned_addr": "192.168.10.130", "host_name": "iPhone", "interface": "br0",
			},
		},
		{
			name:     "dnsmasq DHCPACK without hostname",
			line:     "<30>Oct  2 23:48:31 UDMPRO dnsmasq-dhcp[2001]: DHCPACK(br0) 192.168.10.64 a6:e2:08:f3:d2:61",
			kind:     ingest.NetworkGearDHCPKind,
			expected: map[string]any{"mac": "a6:e2:08:f3:d2:61", "assigned_addr": "192.168.10.64"},
		},
		{
			name:     "hostapd association",
			line:     "<30>Oct  2 23:49:00 U6 hostapd: ath0: STA 62:bc:f1:bc:1d:8d IEEE 802.11: associated",
			kind:     ingest.NetworkGearWiFiKind,
			expected: map[string]any{"mac": "62:bc:f1:bc:1d:8d", "event": "assoc", "access_point": "ath0"},
		},
		{
			name:     "hostapd disconnect",
			line:     "<30>Oct  2 23:49:10 U6 hostapd: ath0: AP-STA-DISCONNECTED 62:bc:f1:bc:1d:8d",
			kind:     ingest.NetworkGearWiFiKind,
			expected: map[string]any{"mac": "62:bc:f1:bc:1d:8d", "event": "leave", "access_point": "ath0"},
		},
		{
			name:     "firewall drop",
			line:     "<4>Oct  2 23:50:00 UDMPRO kernel: [WAN_LOCAL-default-D]IN=eth0 OUT= MAC=aa SRC=203.0.113.9 DST=192.168.10.177 PROTO=TCP SPT=40000 DPT=23 ",
			kind:     ingest.NetworkGearFirewallKind,
			expected: map[string]any{"source_ip": "203.0.113.9", "destination_ip": "192.168.10.177", "source_port": 40000, "destination_port": 23, "protocol": "tcp", "action": "drop", "chain": "WAN_LOCAL-default-D"},
		},
		{
			name:     "IDS alert",
			line:     "<4>Oct  2 23:50:30 UDMPRO suricata: [1:2010935:3] ET SCAN Suspicious [**] [Classification: x] {TCP} 192.168.10.130:1234 -> 203.0.113.9:23",
			kind:     ingest.NetworkGearIDSKind,
			expected: map[string]any{"signature": "ET SCAN Suspicious", "protocol": "tcp", "source_ip": "192.168.10.130", "destination_ip": "203.0.113.9", "source_port": 1234, "destination_port": 23},
		},
		{
			name:     "WAN up system line",
			line:     "<30>Oct  2 23:51:00 UDMPRO ubnt-util: WAN link up on eth0",
			kind:     ingest.NetworkGearSystemKind,
			expected: map[string]any{"event": "link_up"},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			record, ok := Parse(ParseSyslog([]byte(test.line), now))
			if !ok {
				t.Fatalf("line was not recognized: %q", test.line)
			}
			if record.Kind != test.kind {
				t.Fatalf("kind = %q, want %q", record.Kind, test.kind)
			}
			for key, want := range test.expected {
				got, present := record.Payload[key]
				if !present {
					t.Fatalf("payload missing %q; got %#v", key, record.Payload)
				}
				if toComparable(got) != toComparable(want) {
					t.Fatalf("payload[%q] = %#v, want %#v", key, got, want)
				}
			}
			// Every recognized record must normalize into a valid envelope.
			envelope, err := Normalize(record, "192.168.10.1", now)
			if err != nil {
				t.Fatalf("normalize: %v", err)
			}
			if envelope.Source != ingest.SourceNetworkGear || envelope.Kind != test.kind {
				t.Fatalf("envelope = %s/%s", envelope.Source, envelope.Kind)
			}
		})
	}
}

func TestParseIgnoresNoiseAndNeverPanics(t *testing.T) {
	now := time.Now()
	noise := []string{
		"",
		"<30>Oct  2 23:48:30 UDMPRO dropbear: login from 1.2.3.4",
		"not a syslog line at all",
		"<30>Oct  2 23:48:30 UDMPRO dnsmasq-dhcp[1]: DHCPDISCOVER(br0) 62:bc:f1:bc:1d:8d",
		"<30>1 2026-10-02T23:48:30Z UDMPRO dnsmasq - - - DHCPACK(br0) notanip 62:bc:f1:bc:1d:8d host",
		"<4>Oct  2 23:50:00 UDMPRO kernel: random kernel message with no fields",
		"\x00\x01\x02 binary garbage \xff\xfe",
	}
	for _, line := range noise {
		if _, ok := Parse(ParseSyslog([]byte(line), now)); ok {
			t.Errorf("noise was recognized as an event: %q", line)
		}
	}
}

// The IDS and firewall lines are treated purely as data: a signature that
// looks like a command or markup is stored verbatim and bounded, never acted
// on, and control characters are stripped.
func TestParseKeepsContentAsBoundedData(t *testing.T) {
	now := time.Now()
	line := "<4>Oct  2 23:50:30 UDMPRO suricata: [1:1:1] $(rm -rf /) [**] [Classification: x] {TCP} 10.0.0.1:1 -> 10.0.0.2:2"
	record, ok := Parse(ParseSyslog([]byte(line), now))
	if !ok {
		t.Fatal("expected the IDS line to be recognized")
	}
	if record.Payload["signature"] != "$(rm -rf /)" {
		t.Fatalf("signature not stored verbatim: %#v", record.Payload["signature"])
	}
}

func toComparable(value any) string {
	switch v := value.(type) {
	case int:
		return "i:" + time.Duration(v).String()
	default:
		return "s:" + fromAny(v)
	}
}

func fromAny(value any) string {
	if s, ok := value.(string); ok {
		return s
	}
	return ""
}

func FuzzParse(f *testing.F) {
	f.Add("<30>Oct  2 23:48:30 UDMPRO dnsmasq-dhcp[1]: DHCPACK(br0) 192.168.10.130 62:bc:f1:bc:1d:8d iPhone")
	f.Add("<4>Oct  2 23:50:00 UDMPRO kernel: [WAN_LOCAL-D]IN=eth0 SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP SPT=1 DPT=2")
	f.Add("1 2026-10-02T23:48:30.5Z host app - - [x@1 a=\"b\"] DHCPACK(br0) 10.0.0.1 aa:bb:cc:dd:ee:ff n")
	now := time.Now()
	f.Fuzz(func(t *testing.T, line string) {
		if len(line) > 2*MaxMessageBytes {
			t.Skip()
		}
		record, ok := Parse(ParseSyslog([]byte(line), now))
		if !ok {
			return
		}
		// A recognized record must always normalize to a valid envelope.
		if _, err := Normalize(record, "192.168.10.1", now); err != nil {
			t.Fatalf("recognized record failed to normalize: %v (line %q)", err, line)
		}
	})
}

// UniFi's BSD-syslog timestamps are the site's local time with no zone; the
// receive time places them, and a December line read in January keeps its
// year.
func TestRFC3164TimestampsAreAlignedToTheReceiveTime(t *testing.T) {
	cases := []struct{ line, now, want string }{
		// Eastern Daylight Time (UTC-4), received five seconds later.
		{"<30>Oct  2 19:48:30 UDMPRO dnsmasq: x", "2026-10-02T23:48:35Z", "2026-10-02T23:48:30Z"},
		// Already UTC.
		{"<30>Oct  2 23:48:30 UDMPRO dnsmasq: x", "2026-10-02T23:48:31Z", "2026-10-02T23:48:30Z"},
		// India (UTC+5:30).
		{"<30>Oct  3 05:18:30 UDMPRO dnsmasq: x", "2026-10-02T23:48:40Z", "2026-10-02T23:48:30Z"},
		// New Year in UTC-5: still last year's evening on the sender.
		{"<30>Dec 31 19:30:00 UDMPRO dnsmasq: x", "2027-01-01T00:30:02Z", "2027-01-01T00:30:00Z"},
		// A clock off by days is left alone.
		{"<30>Sep 20 10:00:00 UDMPRO dnsmasq: x", "2026-10-02T23:48:35Z", "2026-09-20T10:00:00Z"},
	}
	for _, test := range cases {
		now, _ := time.Parse(time.RFC3339, test.now)
		want, _ := time.Parse(time.RFC3339, test.want)
		if got := ParseSyslog([]byte(test.line), now).Timestamp; !got.Equal(want) {
			t.Errorf("%q at %s = %s, want %s", test.line, test.now, got, want)
		}
	}
	// RFC 5424 carries its zone and is not adjusted.
	at, _ := time.Parse(time.RFC3339, "2026-10-02T23:48:35Z")
	if got := ParseSyslog([]byte("<30>1 2026-10-02T19:48:30-04:00 UDMPRO dnsmasq - - - x"), at.Add(5*time.Hour)).Timestamp; !got.Equal(at.Add(-5 * time.Second)) {
		t.Errorf("RFC 5424 = %s", got)
	}
}
