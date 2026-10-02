package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/apitoken"
	"shakerproxy.dev/shakerproxy/internal/ingest"
	"shakerproxy.dev/shakerproxy/internal/inventory"
)

type devicePlatformReaderStub struct {
	hints ingest.DevicePlatformHints
	err   error
	calls int
}

func (stub *devicePlatformReaderStub) QueryRecent(context.Context, ingest.RecentEventQuery) (ingest.RecentEventPage, error) {
	return ingest.RecentEventPage{}, nil
}

func (stub *devicePlatformReaderStub) QueryDevicePlatformHints(context.Context) (ingest.DevicePlatformHints, error) {
	stub.calls++
	return stub.hints, stub.err
}

func TestDeviceListSaysWhatEachDeviceIs(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	directory := t.TempDir()
	server.inventory = &inventory.Store{Path: filepath.Join(directory, "inventory.json")}
	server.keaLeasePath = filepath.Join(directory, "kea-leases4.csv")
	contents := fmt.Sprintf("address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n10.77.0.111,72:58:49:e8:e4:00,,600,%d,1,0,0,,0,,0\n", time.Now().Add(10*time.Minute).Unix())
	if err := os.WriteFile(server.keaLeasePath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := server.refreshInventory()
	if err != nil || len(snapshot.Devices) != 1 {
		t.Fatalf("inventory = %+v err=%v", snapshot, err)
	}
	phone := snapshot.Devices[0].ID
	at := time.Now().UTC().Truncate(time.Second)
	stub := &devicePlatformReaderStub{hints: ingest.DevicePlatformHints{Schema: ingest.DevicePlatformHintsSchema, GeneratedAt: at, Hints: []ingest.DevicePlatformHint{
		{DeviceID: phone, Platform: "GrapheneOS phone", Domain: "connectivitycheck.grapheneos.network", LastSeen: at},
	}}}
	server.eventReader = stub
	list := func() map[string]devicePlatformHint {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
		request.Host = "shakerproxy.test"
		request.Header.Set("Authorization", "Bearer "+session)
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("devices returned %d: %s", recorder.Code, recorder.Body.String())
		}
		var response struct {
			Devices       []inventory.Device            `json:"devices"`
			PlatformHints map[string]devicePlatformHint `json:"platform_hints"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || len(response.Devices) != 1 {
			t.Fatalf("devices response = %s err=%v", recorder.Body.String(), err)
		}
		return response.PlatformHints
	}
	if hints := list(); hints[phone].Platform != "GrapheneOS phone" || hints[phone].Domain != "connectivitycheck.grapheneos.network" {
		t.Fatalf("platform hints = %+v", hints)
	}
	// Within the cache interval the hints are not fetched again.
	list()
	if stub.calls != 1 {
		t.Fatalf("hints were fetched %d times", stub.calls)
	}
	// Devices still load when ingestd fails, with the hints last seen.
	server.devicePlatforms.fetchedAt = time.Time{}
	stub.err = errors.New("ingestd is down")
	if hints := list(); hints[phone].Platform != "GrapheneOS phone" {
		t.Fatalf("a failed refresh dropped the known hints: %+v", hints)
	}
}

func TestPlatformHintsForIncludeMergedRecords(t *testing.T) {
	at := time.Date(2026, 10, 1, 21, 0, 0, 0, time.UTC)
	current, former := "device-728223ab536ec3ac309086fdffecb7ff", "device-093b101f10afe8a8128992b54726d5fd"
	devices := []inventory.Device{{ID: current, FormerIDs: []string{former}}}
	hints := []ingest.DevicePlatformHint{
		{DeviceID: current, Platform: "Android device", Domain: "connectivitycheck.gstatic.com", LastSeen: at},
		// Recorded before the records were merged.
		{DeviceID: former, Platform: "GrapheneOS phone", Domain: "connectivitycheck.grapheneos.network", LastSeen: at.Add(-time.Hour)},
	}
	if got := platformHintsFor(devices, hints)[current]; got.Platform != "GrapheneOS phone" {
		t.Fatalf("hint = %+v, want the merged record's more specific hint", got)
	}
}

func TestPlatformHintsNeedTrafficReadForAPITokens(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	if !mayReadTraffic(request) {
		t.Fatal("a signed-in administrator cannot see platform hints")
	}
	devicesOnly := request.WithContext(context.WithValue(request.Context(), apiPrincipalContextKey{}, apitoken.Principal{Scopes: []apitoken.Scope{apitoken.ScopeDevicesRead}}))
	if mayReadTraffic(devicesOnly) {
		t.Fatal("a devices:read token sees facts derived from traffic")
	}
	both := request.WithContext(context.WithValue(request.Context(), apiPrincipalContextKey{}, apitoken.Principal{Scopes: []apitoken.Scope{apitoken.ScopeDevicesRead, apitoken.ScopeTrafficRead}}))
	if !mayReadTraffic(both) {
		t.Fatal("a token with traffic:read cannot see platform hints")
	}
}
