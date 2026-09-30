package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/inventory"
)

func TestEventQueryCompletionsAreAuthenticatedBoundedAndInventoryBacked(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	clock := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	store := &inventory.Store{Path: filepath.Join(t.TempDir(), "inventory.json"), Now: func() time.Time { return clock }}
	snapshot, err := store.ReconcileDHCP4([]inventory.DHCP4Lease{{Address: netip.MustParseAddr("10.77.0.120"), HardwareAddr: "52:54:00:ab:cd:20", ValidLifetime: time.Hour, ExpiresAt: clock.Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	deviceID := snapshot.Devices[0].ID
	clock = clock.Add(time.Minute)
	if _, err := store.UpdateAlias(deviceID, "admin", "completion-alias-op-0001", inventory.AliasUpdate{FriendlyName: "Bench Camera", Reason: "Initial name", ExpectedRevision: 0}); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(time.Minute)
	if _, err := store.UpdateMetadata(deviceID, "admin", "completion-meta-op-0001", inventory.DeviceMetadata{FriendlyName: "North Camera", Tags: []string{"Camera", "Lab Gear"}}); err != nil {
		t.Fatal(err)
	}
	server.inventory = store
	server.nameResolver = &inventory.NameResolver{Store: store}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/events/query-completions?field=device.name&prefix=Bench&limit=12", nil)
	request.Host = "shakerproxy.test"
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated completion returned %d", recorder.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/events/query-completions?field=device.name&prefix=Bench&limit=12", nil)
	request.Host = "shakerproxy.test"
	request.Header.Set("Authorization", "Bearer "+session)
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	var page eventQueryCompletionPage
	if err := json.Unmarshal(recorder.Body.Bytes(), &page); err != nil || recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || page.Schema != 1 || page.Field != "device.name" || len(page.Values) != 1 || page.Values[0].Value != "Bench Camera" || !page.Values[0].IncludesHistorical || page.Values[0].DeviceCount != 1 {
		t.Fatalf("unexpected alias completion %d: %s (%v)", recorder.Code, recorder.Body.String(), err)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/events/query-completions?field=device.tag&prefix=cam", nil)
	request.Host = "shakerproxy.test"
	request.Header.Set("Authorization", "Bearer "+session)
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"value":"camera"`) || strings.Contains(recorder.Body.String(), "device-") {
		t.Fatalf("unexpected tag completion %d: %s", recorder.Code, recorder.Body.String())
	}

	for _, target := range []string{
		"/api/v1/events/query-completions?field=policy",
		"/api/v1/events/query-completions?field=device.tag&limit=21",
		"/api/v1/events/query-completions?field=device.tag&field=device.name",
		"/api/v1/events/query-completions?field=device.tag&unknown=true",
		"/api/v1/events/query-completions?field=device.name&prefix=" + strings.Repeat("a", 129),
	} {
		request = httptest.NewRequest(http.MethodGet, target, nil)
		request.Host = "shakerproxy.test"
		request.Header.Set("Authorization", "Bearer "+session)
		recorder = httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("invalid completion %q returned %d: %s", target, recorder.Code, recorder.Body.String())
		}
	}
}
