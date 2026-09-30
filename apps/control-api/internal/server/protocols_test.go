package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/apitoken"
	"shakerproxy.dev/shakerproxy/internal/ingest"
	"shakerproxy.dev/shakerproxy/internal/inventory"
	"shakerproxy.dev/shakerproxy/internal/protocolclass"
)

type protocolSummaryReaderStub struct {
	queries []ingest.ProtocolSummaryQuery
	summary func(ingest.ProtocolSummaryQuery) ingest.ProtocolSummary
}

func (stub *protocolSummaryReaderStub) QueryRecent(context.Context, ingest.RecentEventQuery) (ingest.RecentEventPage, error) {
	return ingest.RecentEventPage{}, nil
}

func (stub *protocolSummaryReaderStub) QueryProtocolSummary(_ context.Context, query ingest.ProtocolSummaryQuery) (ingest.ProtocolSummary, error) {
	stub.queries = append(stub.queries, query)
	return stub.summary(query), nil
}

func protocolSummaryFixture(query ingest.ProtocolSummaryQuery, deviceID string) ingest.ProtocolSummary {
	end := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	mqtt, _ := protocolclass.Lookup("mqtt")
	windowLabel := map[int]string{3600: "1h", 86400: "24h", 604800: "7d", 2592000: "30d"}[query.WindowSeconds]
	return ingest.ProtocolSummary{
		Schema: 1, GeneratedAt: end, Window: windowLabel, WindowStart: end.Add(-time.Duration(query.WindowSeconds) * time.Second), WindowEnd: end,
		DeviceID: query.DeviceID,
		Protocols: []ingest.ProtocolUsage{{
			Protocol: "mqtt", Label: mqtt.Label, Category: string(mqtt.Category), Visibility: "CLEARTEXT", Evidence: "ANALYZER",
			Exotic: true, Novel: true, Description: mqtt.Description, Flows: 12, Bytes: 3456, Events: 20, DeviceCount: 1,
			Devices:   []ingest.ProtocolDeviceUsage{{DeviceID: deviceID, Flows: 12, Bytes: 3456, LastSeen: end.Add(-time.Minute)}},
			FirstSeen: end.Add(-time.Hour / 2), LastSeen: end.Add(-time.Minute),
			Ports: []ingest.ProtocolPortUsage{{Transport: "tcp", Port: 1883, Flows: 12}},
		}},
		Coverage: ingest.ProtocolCoverage{TotalBytes: 3456, CleartextBytes: 3456},
		Sources:  []ingest.Source{ingest.SourceZeek},
	}
}

func TestProtocolRoutesRequireTrafficReadAndProjectDeviceNames(t *testing.T) {
	clock := time.Date(2026, 9, 29, 11, 0, 0, 0, time.UTC)
	tokenStore := &apitoken.Store{Path: filepath.Join(t.TempDir(), "tokens.json")}
	stub := &protocolSummaryReaderStub{}
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) {
		config.EventReader = stub
		config.APITokens = tokenStore
	})
	server.inventory = &inventory.Store{Path: filepath.Join(t.TempDir(), "inventory.json"), Now: func() time.Time { return clock }}
	snapshot, err := server.inventory.ReconcileDHCP4([]inventory.DHCP4Lease{{Address: netip.MustParseAddr("10.77.0.40"), HardwareAddr: "52:54:00:ab:cd:40", ValidLifetime: time.Hour, ExpiresAt: clock.Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	deviceID := snapshot.Devices[0].ID
	if _, err := server.inventory.UpdateAlias(deviceID, "admin", "device-alias-proto-0001", inventory.AliasUpdate{FriendlyName: "Bench camera", Reason: "Label", ExpectedRevision: 0}); err != nil {
		t.Fatal(err)
	}
	server.nameResolver = &inventory.NameResolver{Store: server.inventory}
	stub.summary = func(query ingest.ProtocolSummaryQuery) ingest.ProtocolSummary {
		return protocolSummaryFixture(query, deviceID)
	}
	trafficToken, err := tokenStore.Create(apitoken.CreateRequest{Name: "mcp", Creator: "admin", Scopes: []apitoken.Scope{apitoken.ScopeTrafficRead}, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	devicesToken, err := tokenStore.Create(apitoken.CreateRequest{Name: "devices", Creator: "admin", Scopes: []apitoken.Scope{apitoken.ScopeDevicesRead}, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	handler := server.Handler()

	unauthenticated := httptest.NewRequest(http.MethodGet, "/api/v1/protocols", nil)
	unauthenticated.Host = "shakerproxy.test"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, unauthenticated)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated protocols returned %d", recorder.Code)
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, tokenRequest(http.MethodGet, "/api/v1/protocols", devicesToken.Secret))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("devices:read token read protocols: %d %s", recorder.Code, recorder.Body.String())
	}

	for _, credential := range []string{session, trafficToken.Secret} {
		recorder = httptest.NewRecorder()
		handler.ServeHTTP(recorder, tokenRequest(http.MethodGet, "/api/v1/protocols?window=7d&exotic=true&category=iot-messaging", credential))
		if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("protocols returned %d: %s", recorder.Code, recorder.Body.String())
		}
		var summary ingest.ProtocolSummary
		if err := json.Unmarshal(recorder.Body.Bytes(), &summary); err != nil {
			t.Fatal(err)
		}
		if summary.Window != "7d" || len(summary.Protocols) != 1 || summary.Protocols[0].Devices[0].DeviceName != "Bench camera" || !summary.Protocols[0].Novel {
			t.Fatalf("unexpected protocol summary: %s", recorder.Body.String())
		}
		for _, field := range []string{`"opaque_percent"`, `"unattributed_flows"`, `"device_count"`, `"ports":[{"transport":"tcp","port":1883,"flows":12}]`} {
			if !strings.Contains(recorder.Body.String(), field) {
				t.Fatalf("protocol summary missing %s: %s", field, recorder.Body.String())
			}
		}
	}
	last := stub.queries[len(stub.queries)-1]
	if last.WindowSeconds != 7*86400 || last.Category != "iot-messaging" || last.Exotic == nil || !*last.Exotic || last.DeviceID != "" {
		t.Fatalf("unexpected storage query: %#v", last)
	}

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, tokenRequest(http.MethodGet, "/api/v1/devices/"+deviceID+"/protocols?window=1h", session))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"device_id":"`+deviceID+`"`) {
		t.Fatalf("device protocols returned %d: %s", recorder.Code, recorder.Body.String())
	}
	if last := stub.queries[len(stub.queries)-1]; last.DeviceID != deviceID || last.WindowSeconds != 3600 {
		t.Fatalf("device route did not scope the query: %#v", last)
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, tokenRequest(http.MethodGet, "/api/v1/protocols?device="+deviceID, session))
	if recorder.Code != http.StatusOK || stub.queries[len(stub.queries)-1].DeviceID != deviceID {
		t.Fatalf("device query parameter was not applied: %d %s", recorder.Code, recorder.Body.String())
	}

	// Friendly names, IPs, and MAC addresses resolve like everywhere else.
	for _, target := range []string{"/api/v1/devices/bench%20camera/protocols", "/api/v1/devices/10.77.0.40/protocols", "/api/v1/protocols?device=52-54-00-AB-CD-40"} {
		recorder = httptest.NewRecorder()
		handler.ServeHTTP(recorder, tokenRequest(http.MethodGet, target, session))
		if recorder.Code != http.StatusOK || stub.queries[len(stub.queries)-1].DeviceID != deviceID {
			t.Fatalf("%s did not resolve the device reference: %d %s", target, recorder.Code, recorder.Body.String())
		}
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, tokenRequest(http.MethodGet, "/api/v1/devices/toaster/protocols", session))
	if recorder.Code != http.StatusNotFound || !strings.Contains(recorder.Body.String(), `"device_not_found"`) {
		t.Fatalf("unknown device reference returned %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestProtocolRoutesExplainInvalidInput(t *testing.T) {
	stub := &protocolSummaryReaderStub{summary: func(query ingest.ProtocolSummaryQuery) ingest.ProtocolSummary {
		return protocolSummaryFixture(query, "device-0123456789abcdef0123456789abcdef")
	}}
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) { config.EventReader = stub })
	server.inventory = &inventory.Store{Path: filepath.Join(t.TempDir(), "inventory.json")}
	handler := server.Handler()
	cases := map[string]struct {
		status int
		code   string
	}{
		"/api/v1/protocols?window=forever":                                           {http.StatusBadRequest, "invalid_window"},
		"/api/v1/protocols?category=gaming":                                          {http.StatusBadRequest, "invalid_category"},
		"/api/v1/protocols?exotic=maybe":                                             {http.StatusBadRequest, "invalid_exotic"},
		"/api/v1/protocols?window=1h&window=24h":                                     {http.StatusBadRequest, "invalid_query"},
		"/api/v1/protocols?limit=5":                                                  {http.StatusBadRequest, "invalid_query"},
		"/api/v1/protocols?device=Living%20room%20TV":                                {http.StatusNotFound, "device_not_found"},
		"/api/v1/devices/device-0123456789abcdef0123456789abcdef/protocols":          {http.StatusNotFound, "device_not_found"},
		"/api/v1/devices/device-0123456789abcdef0123456789abcdef/protocols?device=x": {http.StatusBadRequest, "invalid_query"},
		"/api/v1/protocols/catalog?x=1":                                              {http.StatusBadRequest, "invalid_query"},
	}
	for target, want := range cases {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, tokenRequest(http.MethodGet, target, session))
		if recorder.Code != want.status || !strings.Contains(recorder.Body.String(), `"code":"`+want.code+`"`) || !strings.Contains(recorder.Body.String(), `"message":"`) {
			t.Fatalf("%s returned %d: %s", target, recorder.Code, recorder.Body.String())
		}
	}
	if len(stub.queries) != 0 {
		t.Fatalf("storage was queried for invalid input: %#v", stub.queries)
	}
}

func TestProtocolCatalogListsCategoriesAndProtocols(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, tokenRequest(http.MethodGet, "/api/v1/protocols/catalog", session))
	if recorder.Code != http.StatusOK {
		t.Fatalf("catalog returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var catalog ingest.ProtocolCatalog
	if err := json.Unmarshal(recorder.Body.Bytes(), &catalog); err != nil {
		t.Fatal(err)
	}
	if catalog.Schema != 1 || len(catalog.Categories) != len(protocolclass.Categories()) || catalog.Categories[0] != "web" || len(catalog.Protocols) != len(protocolclass.Catalog()) {
		t.Fatalf("unexpected catalog: %s", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"id":"mqtt"`) || !strings.Contains(recorder.Body.String(), `"exotic":true`) {
		t.Fatalf("catalog is missing protocol fields: %s", recorder.Body.String())
	}
}
