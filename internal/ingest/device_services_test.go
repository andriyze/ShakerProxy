package ingest

import (
	"testing"
	"time"
)

func TestServiceTypeNormalizesMDNSNames(t *testing.T) {
	cases := map[string]string{
		"_rdlink._tcp.local":               "_rdlink._tcp",
		"_rdlink._tcp.local.":              "_rdlink._tcp",
		"Den Apple TV._airplay._tcp.local": "_airplay._tcp",
		"_RAOP._TCP.local":                 "_raop._tcp",
		"_matterc._udp.local":              "_matterc._udp",
		"_services._dns-sd._udp.local":     "",
		"_device-info._tcp.local":          "",
		"example.com":                      "",
		"_airplay._sctp.local":             "",
		"":                                 "",
	}
	for name, want := range cases {
		if got := ServiceType(name); got != want {
			t.Errorf("ServiceType(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestResolveDeviceServiceHintsDerivesTypeAndServices(t *testing.T) {
	const phone = "device-0123456789abcdef0123456789abcdef"
	const caster = "device-fedcba9876543210fedcba9876543210"
	at := func(minute int) time.Time { return time.Date(2026, 10, 3, 1, minute, 0, 0, time.UTC) }
	observations := []deviceServiceObservation{
		// The iPhone case: only _rdlink seen, repeatedly.
		{phone, "_rdlink._tcp.local", at(1)},
		{phone, "_rdlink._tcp.local", at(5)},
		// A Chromecast that also browses Spotify Connect: _googlecast is the
		// more specific type.
		{caster, "_spotify-connect._tcp.local", at(2)},
		{caster, "_googlecast._tcp.local", at(3)},
		// Unknown and meta names are ignored for the type, meta dropped.
		{caster, "_services._dns-sd._udp.local", at(4)},
		{caster, "_unknownservice._tcp.local", at(4)},
		// A bad device ID is dropped entirely.
		{"not-a-device", "_airplay._tcp.local", at(1)},
	}
	hints := resolveDeviceServiceHints(observations)
	byID := map[string]DeviceServiceHint{}
	for _, hint := range hints {
		byID[hint.DeviceID] = hint
	}
	if len(hints) != 2 {
		t.Fatalf("got %d hints, want 2: %#v", len(hints), hints)
	}
	if got := byID[phone]; got.Type != "Apple device" || len(got.Services) != 1 || got.Services[0].Service != "_rdlink._tcp" || got.Services[0].Label != "Apple Continuity" {
		t.Fatalf("phone hint = %#v", got)
	}
	if got := byID[phone].LastSeen; !got.Equal(at(5)) {
		t.Fatalf("phone last seen = %s, want %s", got, at(5))
	}
	cast := byID[caster]
	if cast.Type != "Chromecast / Google Cast device" {
		t.Fatalf("caster type = %q, want the Chromecast type", cast.Type)
	}
	// The unknown and meta services are not listed; the two known ones are,
	// newest first.
	if len(cast.Services) != 2 || cast.Services[0].Service != "_googlecast._tcp" || cast.Services[1].Service != "_spotify-connect._tcp" {
		t.Fatalf("caster services = %#v", cast.Services)
	}
	if err := (DeviceServiceHints{Schema: DeviceServiceHintsSchema, GeneratedAt: at(10), Hints: hints}).Validate(); err != nil {
		t.Fatalf("valid hints rejected: %v", err)
	}
}

func TestResolveDeviceServiceHintsBoundsServicesPerDevice(t *testing.T) {
	const id = "device-0123456789abcdef0123456789abcdef"
	services := []string{
		"_rdlink._tcp", "_airplay._tcp", "_raop._tcp", "_googlecast._tcp", "_spotify-connect._tcp",
		"_sonos._tcp", "_ipp._tcp", "_printer._tcp", "_hap._tcp", "_hue._tcp",
		"_dosvc._tcp", "_smb._tcp", "_daap._tcp", "_dacp._tcp",
	}
	var observations []deviceServiceObservation
	for index, service := range services {
		observations = append(observations, deviceServiceObservation{id, service + ".local", time.Date(2026, 10, 3, 1, index, 0, 0, time.UTC)})
	}
	hints := resolveDeviceServiceHints(observations)
	if len(hints) != 1 || len(hints[0].Services) != MaxServicesPerDevice {
		t.Fatalf("expected %d services, got %#v", MaxServicesPerDevice, hints)
	}
	// Newest first: the last-added service leads.
	if hints[0].Services[0].Service != "_dacp._tcp" {
		t.Fatalf("services not newest-first: %#v", hints[0].Services)
	}
}

func TestDeviceServiceHintsValidateRejectsBadRows(t *testing.T) {
	const id = "device-0123456789abcdef0123456789abcdef"
	service := DeviceService{Service: "_airplay._tcp", LastSeen: time.Now().UTC()}
	bad := []DeviceServiceHints{
		{Schema: 999, GeneratedAt: time.Now().UTC(), Hints: []DeviceServiceHint{{DeviceID: id, Services: []DeviceService{service}, LastSeen: time.Now().UTC()}}},
		{Schema: DeviceServiceHintsSchema, GeneratedAt: time.Now().UTC(), Hints: []DeviceServiceHint{{DeviceID: "bad", Services: []DeviceService{service}, LastSeen: time.Now().UTC()}}},
		{Schema: DeviceServiceHintsSchema, GeneratedAt: time.Now().UTC(), Hints: []DeviceServiceHint{{DeviceID: id, Services: nil, LastSeen: time.Now().UTC()}}},
		{Schema: DeviceServiceHintsSchema, GeneratedAt: time.Now().UTC(), Hints: []DeviceServiceHint{{DeviceID: id, Services: []DeviceService{{Service: ""}}, LastSeen: time.Now().UTC()}}},
	}
	for index, hints := range bad {
		if err := hints.Validate(); err == nil {
			t.Errorf("case %d: expected invalid", index)
		}
	}
}
