package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
	"shakerproxy.dev/shakerproxy/internal/inventory"
)

type controlEventReaderFunc func(context.Context, ingest.RecentEventQuery) (ingest.RecentEventPage, error)

func (f controlEventReaderFunc) QueryRecent(ctx context.Context, query ingest.RecentEventQuery) (ingest.RecentEventPage, error) {
	return f(ctx, query)
}

type controlStatusReaderFunc func(context.Context) (ingest.Stats, error)

func (f controlStatusReaderFunc) IngestStatus(ctx context.Context) (ingest.Stats, error) {
	return f(ctx)
}

func TestRecentEventAPIAuthenticatesAndPassesOnlyValidatedQuery(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	server.eventReader = controlEventReaderFunc(func(_ context.Context, query ingest.RecentEventQuery) (ingest.RecentEventPage, error) {
		if query.Limit != 5 || query.Source != ingest.SourceSuricata || query.Filter.Canonical != "protocol:tcp" {
			t.Fatalf("unexpected normalized query: %#v", query)
		}
		return ingest.RecentEventPage{Schema: 1, GeneratedAt: time.Now().UTC(), CanonicalQuery: query.Filter.Canonical, Events: []ingest.RecentEvent{{RecordID: strings.Repeat("b", 64), Source: ingest.SourceSuricata, Kind: "suricata.alert", OccurredAt: time.Now().UTC(), ReceivedAt: time.Now().UTC(), Confidence: 70}}}, nil
	})
	request := httptest.NewRequest(http.MethodGet, "/api/v1/events?limit=5&source=SURICATA&q=protocol%3Atcp", nil)
	request.Host = "shakerproxy.test"
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated event API returned %d", recorder.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/api/v1/events?limit=5&source=SURICATA&q=protocol%3Atcp", nil)
	request.Host = "shakerproxy.test"
	request.Header.Set("Authorization", "Bearer "+session)
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || !strings.Contains(recorder.Body.String(), `"kind":"suricata.alert"`) || !strings.Contains(recorder.Body.String(), `"canonical_query":"protocol:tcp"`) || strings.Contains(recorder.Body.String(), `"payload"`) {
		t.Fatalf("unexpected event API response %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestRecentEventAPIProjectsCurrentAndCaptureTimeDeviceNames(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	clock := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	server.inventory = &inventory.Store{Path: filepath.Join(t.TempDir(), "inventory.json"), Now: func() time.Time { return clock }}
	snapshot, err := server.inventory.ReconcileDHCP4([]inventory.DHCP4Lease{{Address: netip.MustParseAddr("10.77.0.111"), HardwareAddr: "52:54:00:ab:cd:01", ValidLifetime: time.Hour, ExpiresAt: clock.Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	deviceID := snapshot.Devices[0].ID
	clock = clock.Add(time.Minute)
	if _, err := server.inventory.UpdateAlias(deviceID, "admin", "device-alias-event-0001", inventory.AliasUpdate{FriendlyName: "Bench Camera", Reason: "Initial label", ExpectedRevision: 0}); err != nil {
		t.Fatal(err)
	}
	capturedAt := clock.Add(30 * time.Second)
	clock = clock.Add(time.Minute)
	if _, err := server.inventory.UpdateAlias(deviceID, "admin", "device-alias-event-0002", inventory.AliasUpdate{FriendlyName: "North Camera", Reason: "Moved north", ExpectedRevision: 1}); err != nil {
		t.Fatal(err)
	}
	server.nameResolver = &inventory.NameResolver{Store: server.inventory}
	server.eventReader = controlEventReaderFunc(func(_ context.Context, query ingest.RecentEventQuery) (ingest.RecentEventPage, error) {
		if query.Filter.Canonical != `device.name:"Bench Camera"` || len(query.DeviceNameResolutions["Bench Camera"]) != 1 || query.DeviceNameResolutions["Bench Camera"][0] != deviceID {
			t.Fatalf("historical alias was not resolved to the immutable device ID: %#v", query)
		}
		return ingest.RecentEventPage{Schema: 1, GeneratedAt: clock, CanonicalQuery: query.Filter.Canonical, Events: []ingest.RecentEvent{{RecordID: strings.Repeat("c", 64), Source: ingest.SourceZeek, Kind: "zeek.conn", OccurredAt: capturedAt, ReceivedAt: capturedAt, SourceVersion: "8.2.1", ParserVersion: "shakerproxy-zeek-v1", DeviceID: deviceID, Confidence: 95, SourceIP: "10.77.0.111", AttributionEvidence: &ingest.AttributionEvidence{Schema: ingest.AttributionEvidenceSchema, DeviceID: deviceID, Address: "10.77.0.111", Endpoint: ingest.AttributionEndpointSource, Source: inventory.SourceDHCP4Lease, Confidence: 95, ValidFrom: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC), ValidUntil: time.Date(2026, 9, 1, 13, 0, 0, 0, time.UTC)}}}}, nil
	})
	request := httptest.NewRequest(http.MethodGet, "/api/v1/events?q=name%3A%22Bench%20Camera%22", nil)
	request.Host = "shakerproxy.test"
	request.Header.Set("Authorization", "Bearer "+session)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"canonical_query":"device.name:\"Bench Camera\""`) || !strings.Contains(recorder.Body.String(), `"device_labels_available":true`) || !strings.Contains(recorder.Body.String(), `"device_friendly_name":"North Camera"`) || !strings.Contains(recorder.Body.String(), `"device_friendly_name_at_capture":"Bench Camera"`) || !strings.Contains(recorder.Body.String(), `"device_friendly_name_at_capture_known":true`) || !strings.Contains(recorder.Body.String(), `"device_alias_revision":2`) || !strings.Contains(recorder.Body.String(), `"attribution_evidence":{"schema":1,"device_id":"`+deviceID+`","address":"10.77.0.111","endpoint":"SOURCE","source":"DHCP4_LEASE"`) {
		t.Fatalf("event name projection returned %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestRecentEventAPIResolvesAliasAndTagFromOneInventoryView(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	clock := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	server.inventory = &inventory.Store{Path: filepath.Join(t.TempDir(), "inventory.json"), Now: func() time.Time { return clock }}
	snapshot, err := server.inventory.ReconcileDHCP4([]inventory.DHCP4Lease{{Address: netip.MustParseAddr("10.77.0.112"), HardwareAddr: "52:54:00:ab:cd:02", ValidLifetime: time.Hour, ExpiresAt: clock.Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	deviceID := snapshot.Devices[0].ID
	if _, err := server.inventory.UpdateMetadata(deviceID, "admin", "event-selector-meta-0001", inventory.DeviceMetadata{FriendlyName: "North Camera", Tags: []string{"Camera"}}); err != nil {
		t.Fatal(err)
	}
	server.nameResolver = &inventory.NameResolver{Store: server.inventory}
	server.eventReader = controlEventReaderFunc(func(_ context.Context, query ingest.RecentEventQuery) (ingest.RecentEventPage, error) {
		if query.Filter.Canonical != `device.name:"North Camera" AND device.tag:camera` || len(query.DeviceNameResolutions["North Camera"]) != 1 || query.DeviceNameResolutions["North Camera"][0] != deviceID || len(query.DeviceTagResolutions["camera"]) != 1 || query.DeviceTagResolutions["camera"][0] != deviceID {
			t.Fatalf("device selectors were not resolved from one inventory view: %#v", query)
		}
		return ingest.RecentEventPage{Schema: 1, GeneratedAt: clock, CanonicalQuery: query.Filter.Canonical, Events: []ingest.RecentEvent{}}, nil
	})
	request := httptest.NewRequest(http.MethodGet, "/api/v1/events?q=name%3A%22North%20Camera%22%20AND%20tag%3Acamera", nil)
	request.Host = "shakerproxy.test"
	request.Header.Set("Authorization", "Bearer "+session)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"canonical_query":"device.name:\"North Camera\" AND device.tag:camera"`) {
		t.Fatalf("combined selector query returned %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestIngestStatusAPIAuthenticatesAndHidesReadCredential(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	server.ingestStatus = controlStatusReaderFunc(func(context.Context) (ingest.Stats, error) {
		return ingest.Stats{Schema: 1, GeneratedAt: time.Now().UTC(), PendingRecords: 2, PendingBytes: 2048, DatabaseConfigured: true, DatabaseConnected: true}, nil
	})
	request := httptest.NewRequest(http.MethodGet, "/api/v1/ingest/status", nil)
	request.Host = "shakerproxy.test"
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated ingestion status returned %d", recorder.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/api/v1/ingest/status", nil)
	request.Host = "shakerproxy.test"
	request.Header.Set("Authorization", "Bearer "+session)
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || !strings.Contains(recorder.Body.String(), `"pending_records":2`) || strings.Contains(recorder.Body.String(), "token") {
		t.Fatalf("unexpected ingestion status API response %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestRecentEventAPIRejectsInvalidQueriesAndHidesBackendFailures(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	request := httptest.NewRequest(http.MethodGet, "/api/v1/events?limit=101", nil)
	request.Host = "shakerproxy.test"
	request.Header.Set("Authorization", "Bearer "+session)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid query returned %d: %s", recorder.Code, recorder.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/api/v1/events?q=payload%3Asecret", nil)
	request.Host = "shakerproxy.test"
	request.Header.Set("Authorization", "Bearer "+session)
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unsupported typed query returned %d: %s", recorder.Code, recorder.Body.String())
	}
	server.eventReader = controlEventReaderFunc(func(context.Context, ingest.RecentEventQuery) (ingest.RecentEventPage, error) {
		return ingest.RecentEventPage{}, errors.New("postgres password=secret internal detail")
	})
	request = httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	request.Host = "shakerproxy.test"
	request.Header.Set("Authorization", "Bearer "+session)
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable || strings.Contains(recorder.Body.String(), "password") || strings.Contains(recorder.Body.String(), "postgres") {
		t.Fatalf("backend failure leaked details: %d %s", recorder.Code, recorder.Body.String())
	}
}
