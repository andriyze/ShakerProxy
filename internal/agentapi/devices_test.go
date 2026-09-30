package agentapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDevicesListCarriesBoundedFiltersAndValidatesProjection(t *testing.T) {
	deviceID := "device-0123456789abcdef0123456789abcdef"
	now := time.Date(2026, 9, 3, 18, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/devices" || r.Header.Get("Authorization") != "Bearer "+testToken || r.URL.Query().Get("q") != "Living Room" || r.URL.Query().Get("limit") != "25" || r.URL.Query().Get("online") != "true" {
			t.Fatalf("unexpected device request %s auth=%q", r.URL.String(), r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"schema":1,"generated_at":%q,"query":"Living Room","matched":1,"returned":1,"truncated":false,"devices":[{"schema":1,"id":%q,"display_name":"Living Room TV","friendly_name":"Living Room TV","category":"smart-tv","addresses":[{"address":"10.77.0.10","family":"IPv4","confidence":95,"valid_from":%q,"valid_until":%q,"active":true}],"hostnames":[{"hostname":"living-room-tv","confidence":75,"first_seen":%q,"last_seen":%q}],"first_seen":%q,"last_seen":%q,"online":true,"attribution_confidence":95}]}`,
			now.Format(time.RFC3339Nano), deviceID, now.Add(-time.Hour).Format(time.RFC3339Nano), now.Add(time.Hour).Format(time.RFC3339Nano), now.Add(-time.Hour).Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), now.Add(-time.Hour).Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, testToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.DevicesList(context.Background(), DeviceListRequest{Query: " Living Room ", Limit: 25, OnlineOnly: true})
	if err != nil || len(page.Devices) != 1 || page.Devices[0].ID != deviceID || page.Devices[0].DisplayName != "Living Room TV" {
		t.Fatalf("unexpected device page: %#v err=%v", page, err)
	}
	if _, err := client.DevicesList(context.Background(), DeviceListRequest{Limit: maxAgentDeviceLimit + 1}); err == nil {
		t.Fatal("unbounded device list was accepted")
	}
}

func TestDeviceGetUsesExactIdentityAndRejectsMismatch(t *testing.T) {
	requested := "device-0123456789abcdef0123456789abcdef"
	returned := requested
	now := time.Date(2026, 9, 3, 18, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/devices/"+requested {
			t.Fatalf("unexpected device detail path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"schema":1,"id":%q,"display_name":"Phone","addresses":[],"hostnames":[],"first_seen":%q,"last_seen":%q,"online":false,"attribution_confidence":80}`,
			returned, now.Add(-time.Hour).Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, testToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	device, err := client.DeviceGet(context.Background(), requested)
	if err != nil || device.ID != requested {
		t.Fatalf("unexpected device detail: %#v err=%v", device, err)
	}
	returned = "device-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := client.DeviceGet(context.Background(), requested); err == nil {
		t.Fatal("mismatched device identity was accepted")
	}
	if _, err := client.DeviceGet(context.Background(), strings.Repeat("a", 39)); err == nil {
		t.Fatal("invalid device identity was accepted")
	}
}

func TestDevicesListRejectsInconsistentTruncation(t *testing.T) {
	now := time.Date(2026, 9, 3, 18, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"schema":1,"generated_at":%q,"matched":2,"returned":0,"truncated":false,"devices":[]}`, now.Format(time.RFC3339Nano))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, testToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.DevicesList(context.Background(), DeviceListRequest{Limit: 10}); err == nil {
		t.Fatal("inconsistent device truncation was accepted")
	}
}
