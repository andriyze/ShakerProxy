package ingest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	platformPhone  = "device-0123456789abcdef0123456789abcdef"
	platformLaptop = "device-fedcba9876543210fedcba9876543210"
)

func TestResolveDevicePlatformHintsPrefersTheMostSpecificCheck(t *testing.T) {
	at := time.Date(2026, 10, 1, 21, 0, 0, 0, time.UTC)
	hints := resolveDevicePlatformHints([]devicePlatformObservation{
		// The GrapheneOS phone also made Google's check, and more recently.
		{platformPhone, "connectivitycheck.gstatic.com", at.Add(time.Hour)},
		{platformPhone, "connectivitycheck.grapheneos.network", at},
		{platformLaptop, "www.msftconnecttest.com", at},
		{platformLaptop, "www.apple.com", at.Add(time.Hour)},
		{"not-a-device", "captive.apple.com", at},
	})
	if len(hints) != 2 {
		t.Fatalf("hints = %+v", hints)
	}
	if hints[0].DeviceID != platformPhone || hints[0].Platform != "GrapheneOS phone" || hints[0].Domain != "connectivitycheck.grapheneos.network" {
		t.Fatalf("phone hint = %+v", hints[0])
	}
	if hints[1].DeviceID != platformLaptop || hints[1].Platform != "Windows PC" {
		t.Fatalf("a website visit outweighed the connectivity check: %+v", hints[1])
	}
	if err := (DevicePlatformHints{Schema: DevicePlatformHintsSchema, GeneratedAt: at, Hints: hints}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestDevicePlatformHintsRejectMismatchedOrDuplicateHints(t *testing.T) {
	at := time.Date(2026, 10, 1, 21, 0, 0, 0, time.UTC)
	good := DevicePlatformHint{DeviceID: platformPhone, Platform: "GrapheneOS phone", Domain: "supl.grapheneos.org", LastSeen: at}
	for name, hints := range map[string][]DevicePlatformHint{
		"platform does not match the domain": {{DeviceID: platformPhone, Platform: "Windows PC", Domain: "supl.grapheneos.org", LastSeen: at}},
		"domain is not a platform check":     {{DeviceID: platformPhone, Platform: "GrapheneOS phone", Domain: "grapheneos.org", LastSeen: at}},
		"duplicate device":                   {good, good},
		"invalid device ID":                  {{DeviceID: "device-1", Platform: good.Platform, Domain: good.Domain, LastSeen: at}},
	} {
		if err := (DevicePlatformHints{Schema: DevicePlatformHintsSchema, GeneratedAt: at, Hints: hints}).Validate(); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestQueryClientDecodesDevicePlatformHintsStrictly(t *testing.T) {
	at := time.Date(2026, 10, 1, 21, 0, 0, 0, time.UTC)
	body := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/device-platform-hints" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("q", 43) {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	endpoint, _ := url.Parse(server.URL)
	client := &QueryClient{endpoint: endpoint, token: []byte(strings.Repeat("q", 43)), client: server.Client()}
	valid, _ := json.Marshal(DevicePlatformHints{Schema: DevicePlatformHintsSchema, GeneratedAt: at, Hints: []DevicePlatformHint{{DeviceID: platformPhone, Platform: "GrapheneOS phone", Domain: "connectivitycheck.grapheneos.network", LastSeen: at}}})
	body = string(valid)
	hints, err := client.QueryDevicePlatformHints(context.Background())
	if err != nil || len(hints.Hints) != 1 || hints.Hints[0].Platform != "GrapheneOS phone" {
		t.Fatalf("hints = %+v err=%v", hints, err)
	}
	body = strings.Replace(string(valid), `"hints"`, `"extra":1,"hints"`, 1)
	if _, err := client.QueryDevicePlatformHints(context.Background()); err == nil {
		t.Fatal("an unknown field was accepted")
	}
	body = strings.Replace(string(valid), "GrapheneOS phone", "Windows PC", 1)
	if _, err := client.QueryDevicePlatformHints(context.Background()); err == nil {
		t.Fatal("a hint that does not match its domain was accepted")
	}
}
