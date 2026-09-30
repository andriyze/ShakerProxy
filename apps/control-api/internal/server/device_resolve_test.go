package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/apitoken"
	"shakerproxy.dev/shakerproxy/internal/inventory"
)

type intelFixture struct {
	server   *Server
	session  string
	tokens   *apitoken.Store
	tv       string
	camera   string
	camera2  string
	phone    string
	now      time.Time
	activity *deviceActivityStub
}

// newIntelFixture seeds a TV, two cameras, and a phone without a friendly
// name, plus an event reader stub that serves device activity.
func newIntelFixture(t *testing.T) *intelFixture {
	t.Helper()
	fixture := &intelFixture{now: time.Now().UTC().Truncate(time.Second), activity: &deviceActivityStub{}}
	fixture.tokens = &apitoken.Store{Path: filepath.Join(t.TempDir(), "tokens.json")}
	fixture.server, fixture.session = configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) {
		config.EventReader = fixture.activity
		config.APITokens = fixture.tokens
	})
	now := fixture.now
	fixture.server.inventory = &inventory.Store{Path: filepath.Join(t.TempDir(), "inventory.json"), Now: func() time.Time { return now }}
	snapshot, err := fixture.server.inventory.ReconcileDHCP4([]inventory.DHCP4Lease{
		{Address: netip.MustParseAddr("10.77.0.23"), HardwareAddr: "52:54:00:aa:bb:23", ClientID: "01:23", Hostname: "living-room-tv", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)},
		{Address: netip.MustParseAddr("10.77.0.30"), HardwareAddr: "52:54:00:aa:bb:30", ClientID: "01:30", Hostname: "cam-a", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)},
		{Address: netip.MustParseAddr("10.77.0.31"), HardwareAddr: "52:54:00:aa:bb:31", ClientID: "01:31", Hostname: "cam-b", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)},
		{Address: netip.MustParseAddr("10.77.0.40"), HardwareAddr: "52:54:00:aa:bb:40", ClientID: "01:40", Hostname: "pixel-8", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)},
	})
	if err != nil || len(snapshot.Devices) != 4 {
		t.Fatalf("seed inventory: %#v err=%v", snapshot, err)
	}
	byMAC := map[string]string{}
	for _, device := range snapshot.Devices {
		for _, identity := range device.Identities {
			if identity.Kind == inventory.IdentityMAC {
				byMAC[identity.Value] = device.ID
			}
		}
	}
	fixture.tv, fixture.camera, fixture.camera2, fixture.phone = byMAC["52:54:00:aa:bb:23"], byMAC["52:54:00:aa:bb:30"], byMAC["52:54:00:aa:bb:31"], byMAC["52:54:00:aa:bb:40"]
	for index, item := range []struct{ id, name string }{{fixture.tv, "Living room TV"}, {fixture.camera, "Bench camera"}, {fixture.camera2, "Bench camera 2"}} {
		operation := "intel-fixture-name-" + string(rune('a'+index)) + "000000000"
		if _, err := fixture.server.inventory.UpdateMetadata(item.id, "admin", operation, inventory.DeviceMetadata{FriendlyName: item.name, Category: "smart-tv"}); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

func (f *intelFixture) token(t *testing.T, scopes ...apitoken.Scope) string {
	t.Helper()
	created, err := f.tokens.Create(apitoken.CreateRequest{Name: "intel test", Creator: "admin", Scopes: scopes, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return created.Secret
}

func (f *intelFixture) do(t *testing.T, method, target, body, credential string) *httptest.ResponseRecorder {
	t.Helper()
	request := authenticatedJSONRequest(method, target, body, credential, "")
	recorder := httptest.NewRecorder()
	f.server.Handler().ServeHTTP(recorder, request)
	return recorder
}

type errorBody struct {
	Error struct {
		Code       string        `json:"code"`
		Message    string        `json:"message"`
		Candidates []deviceMatch `json:"candidates"`
	} `json:"error"`
}

func TestResolveDeviceByIDMACIPAndName(t *testing.T) {
	fixture := newIntelFixture(t)
	cases := []struct {
		query string
		want  string
		match string
	}{
		{fixture.tv, fixture.tv, deviceMatchID},
		{"52:54:00:AA:BB:23", fixture.tv, deviceMatchMAC},
		{"52-54-00-aa-bb-23", fixture.tv, deviceMatchMAC},
		{"5254.00aa.bb23", fixture.tv, deviceMatchMAC},
		{"525400aabb23", fixture.tv, deviceMatchMAC},
		{"10.77.0.23", fixture.tv, deviceMatchIP},
		{"living room tv", fixture.tv, deviceMatchName},
		{"LIVING-ROOM-TV", fixture.tv, deviceMatchName},
		{"pixel-8", fixture.phone, deviceMatchName},
		{"Living", fixture.tv, deviceMatchNamePrefix},
		{"room", fixture.tv, deviceMatchNameContains},
		{"Bench camera", fixture.camera, deviceMatchName},
	}
	for _, item := range cases {
		recorder := fixture.do(t, http.MethodGet, "/api/v1/devices/resolve?q="+url.QueryEscape(item.query), "", fixture.session)
		var result deviceResolution
		if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &result) != nil {
			t.Fatalf("resolve %q returned %d: %s", item.query, recorder.Code, recorder.Body.String())
		}
		if !result.Unique || len(result.Matches) != 1 || result.Matches[0].DeviceID != item.want || result.Matches[0].Match != item.match || result.Query != item.query {
			t.Fatalf("resolve %q: %#v", item.query, result)
		}
	}
	tv := func() deviceMatch {
		recorder := fixture.do(t, http.MethodGet, "/api/v1/devices/resolve?q=10.77.0.23", "", fixture.session)
		var result deviceResolution
		_ = json.Unmarshal(recorder.Body.Bytes(), &result)
		return result.Matches[0]
	}()
	if tv.FriendlyName != "Living room TV" || len(tv.Addresses) != 1 || tv.Addresses[0] != "10.77.0.23" || len(tv.HardwareAddresses) != 1 || tv.HardwareAddresses[0] != "52:54:00:aa:bb:23" || !tv.Online {
		t.Fatalf("match object: %#v", tv)
	}
}

func TestResolveDeviceReportsAmbiguityAndMisses(t *testing.T) {
	fixture := newIntelFixture(t)
	recorder := fixture.do(t, http.MethodGet, "/api/v1/devices/resolve?q=bench", "", fixture.session)
	var result deviceResolution
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &result) != nil || result.Unique || len(result.Matches) != 2 || result.Matches[0].Match != deviceMatchNamePrefix {
		t.Fatalf("ambiguous prefix: %d %s", recorder.Code, recorder.Body.String())
	}
	recorder = fixture.do(t, http.MethodGet, "/api/v1/devices/resolve?q=toaster", "", fixture.session)
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &result) != nil || result.Unique || result.Matches == nil || len(result.Matches) != 0 {
		t.Fatalf("no match: %d %s", recorder.Code, recorder.Body.String())
	}
	for _, target := range []string{"/api/v1/devices/resolve", "/api/v1/devices/resolve?q=", "/api/v1/devices/resolve?q=a&q=b", "/api/v1/devices/resolve?q=x&limit=3"} {
		if recorder := fixture.do(t, http.MethodGet, target, "", fixture.session); recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s returned %d", target, recorder.Code)
		}
	}

	// The shared helper returns 409 with candidates, and 404 with guidance.
	recorder = fixture.do(t, http.MethodGet, "/api/v1/devices/bench/report", "", fixture.session)
	var failure errorBody
	if recorder.Code != http.StatusConflict || json.Unmarshal(recorder.Body.Bytes(), &failure) != nil || failure.Error.Code != "device_ambiguous" || len(failure.Error.Candidates) != 2 {
		t.Fatalf("ambiguous report reference: %d %s", recorder.Code, recorder.Body.String())
	}
	recorder = fixture.do(t, http.MethodGet, "/api/v1/devices/toaster/report", "", fixture.session)
	var missing errorBody
	if recorder.Code != http.StatusNotFound || json.Unmarshal(recorder.Body.Bytes(), &missing) != nil || missing.Error.Code != "device_not_found" || missing.Error.Candidates != nil || !strings.Contains(missing.Error.Message, "shakerproxy devices") {
		t.Fatalf("unknown report reference: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestResolveDeviceRequiresDevicesRead(t *testing.T) {
	fixture := newIntelFixture(t)
	if recorder := fixture.do(t, http.MethodGet, "/api/v1/devices/resolve?q=tv", "", "invalid-session"); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated resolve returned %d", recorder.Code)
	}
	traffic := fixture.token(t, apitoken.ScopeTrafficRead)
	if recorder := fixture.do(t, http.MethodGet, "/api/v1/devices/resolve?q=tv", "", traffic); recorder.Code != http.StatusForbidden {
		t.Fatalf("traffic-only token returned %d", recorder.Code)
	}
	devices := fixture.token(t, apitoken.ScopeDevicesRead)
	if recorder := fixture.do(t, http.MethodGet, "/api/v1/devices/resolve?q=tv", "", devices); recorder.Code != http.StatusOK {
		t.Fatalf("devices:read token returned %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestMatchDevicesPrefersCurrentThenMostRecentAddressHolder(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	device := func(id string, observed time.Time, active bool) inventory.Device {
		return inventory.Device{ID: id, Addresses: []inventory.AddressObservation{{Address: "10.77.0.50", Active: active, ObservedAt: observed}}}
	}
	older := device("device-00000000000000000000000000000001", now.Add(-2*time.Hour), false)
	newer := device("device-00000000000000000000000000000002", now.Add(-time.Hour), false)
	matches := matchDevices([]inventory.Device{older, newer}, "10.77.0.50")
	if len(matches) != 1 || matches[0].DeviceID != newer.ID || matches[0].Match != deviceMatchIP {
		t.Fatalf("recent holder: %#v", matches)
	}
	current := device("device-00000000000000000000000000000003", now.Add(-3*time.Hour), true)
	matches = matchDevices([]inventory.Device{older, newer, current}, "10.77.0.50")
	if len(matches) != 1 || matches[0].DeviceID != current.ID {
		t.Fatalf("current holder: %#v", matches)
	}
	if matches := matchDevices([]inventory.Device{older}, "10.77.0.99"); len(matches) != 0 {
		t.Fatalf("unrelated IP matched: %#v", matches)
	}
	if matches := matchDevices([]inventory.Device{older}, "device-ffffffffffffffffffffffffffffffff"); len(matches) != 0 {
		t.Fatalf("unknown ID matched: %#v", matches)
	}
}

func TestMatchDevicesBoundsCandidates(t *testing.T) {
	devices := make([]inventory.Device, 0, 30)
	for index := 0; index < 30; index++ {
		devices = append(devices, inventory.Device{ID: "device-" + fmtHex32(index), FriendlyName: "Sensor " + fmtHex32(index)[28:]})
	}
	matches := matchDevices(devices, "sensor")
	if len(matches) != maxDeviceMatches {
		t.Fatalf("matches were not bounded: %d", len(matches))
	}
}

func TestNormalizeMACReference(t *testing.T) {
	for input, want := range map[string]string{
		"AA:BB:CC:DD:EE:FF": "aa:bb:cc:dd:ee:ff", "aa-bb-cc-dd-ee-ff": "aa:bb:cc:dd:ee:ff",
		"aabb.ccdd.eeff": "aa:bb:cc:dd:ee:ff", "AABBCCDDEEFF": "aa:bb:cc:dd:ee:ff",
	} {
		if got, ok := normalizeMACReference(input); !ok || got != want {
			t.Errorf("normalizeMACReference(%q) = %q, %v", input, got, ok)
		}
	}
	for _, input := range []string{"aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:00", "gg:bb:cc:dd:ee:ff", "tv", ""} {
		if _, ok := normalizeMACReference(input); ok {
			t.Errorf("normalizeMACReference(%q) accepted", input)
		}
	}
}

func fmtHex32(value int) string {
	const digits = "0123456789abcdef"
	out := []byte("00000000000000000000000000000000")
	for index := len(out) - 1; value > 0 && index >= 0; index-- {
		out[index] = digits[value%16]
		value /= 16
	}
	return string(out)
}
