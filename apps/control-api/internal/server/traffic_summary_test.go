package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/apitoken"
	"shakerproxy.dev/shakerproxy/internal/ingest"
	"shakerproxy.dev/shakerproxy/internal/inventory"
)

type trafficSummaryReaderStub struct {
	queries  []ingest.TrafficSummaryQuery
	deviceID string
	err      error
}

func (stub *trafficSummaryReaderStub) QueryRecent(context.Context, ingest.RecentEventQuery) (ingest.RecentEventPage, error) {
	return ingest.RecentEventPage{}, nil
}

func (stub *trafficSummaryReaderStub) QueryTrafficSummary(_ context.Context, query ingest.TrafficSummaryQuery) (ingest.TrafficSummary, error) {
	stub.queries = append(stub.queries, query)
	if stub.err != nil {
		return ingest.TrafficSummary{}, stub.err
	}
	from := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	summary := ingest.TrafficSummary{Schema: ingest.TrafficSummarySchemaVersion, GeneratedAt: from.Add(15 * time.Minute), From: from, To: from.Add(15 * time.Minute), BucketSeconds: 900 / float64(query.Buckets), Buckets: make([]ingest.TrafficSummaryBucket, query.Buckets), CanonicalQuery: query.Events.Filter.Canonical}
	for index := range summary.Buckets {
		summary.Buckets[index].Start = from.Add(time.Duration(index) * 15 * time.Minute / time.Duration(query.Buckets))
	}
	summary.Buckets[0].Counts.DNS = 2
	summary.Totals = ingest.TrafficSummaryTotals{Events: 2, Types: ingest.StreamTypeCounts{DNS: 2}}
	for _, field := range ingest.TrafficSummaryFacetFields {
		facet := ingest.TrafficSummaryFacet{Field: field, Values: []ingest.TrafficSummaryFacetValue{}, Exact: true}
		switch field {
		case ingest.SummaryFacetDevice:
			facet.Values = []ingest.TrafficSummaryFacetValue{{Value: stub.deviceID, Count: 1}, {Value: "ip:10.77.0.9", Label: "10.77.0.9", Count: 1}}
		case ingest.SummaryFacetType:
			facet.Values = []ingest.TrafficSummaryFacetValue{{Value: ingest.StreamDNS, Count: 2}}
		}
		summary.Facets = append(summary.Facets, facet)
	}
	return summary, nil
}

type recentOnlyReader struct{}

func (recentOnlyReader) QueryRecent(context.Context, ingest.RecentEventQuery) (ingest.RecentEventPage, error) {
	return ingest.RecentEventPage{}, nil
}

func TestTrafficSummaryRouteRequiresTrafficReadAndLabelsDevices(t *testing.T) {
	clock := time.Date(2026, 10, 2, 11, 0, 0, 0, time.UTC)
	tokenStore := &apitoken.Store{Path: filepath.Join(t.TempDir(), "tokens.json")}
	stub := &trafficSummaryReaderStub{}
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) {
		config.EventReader = stub
		config.APITokens = tokenStore
	})
	server.inventory = &inventory.Store{Path: filepath.Join(t.TempDir(), "inventory.json"), Now: func() time.Time { return clock }}
	snapshot, err := server.inventory.ReconcileDHCP4([]inventory.DHCP4Lease{{Address: netip.MustParseAddr("10.77.0.41"), HardwareAddr: "52:54:00:ab:cd:41", ValidLifetime: time.Hour, ExpiresAt: clock.Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	stub.deviceID = snapshot.Devices[0].ID
	if _, err := server.inventory.UpdateAlias(stub.deviceID, "admin", "device-alias-summary-01", inventory.AliasUpdate{FriendlyName: "Pixel", Reason: "Label", ExpectedRevision: 0}); err != nil {
		t.Fatal(err)
	}
	server.nameResolver = &inventory.NameResolver{Store: server.inventory}
	trafficToken, err := tokenStore.Create(apitoken.CreateRequest{Name: "soc", Creator: "admin", Scopes: []apitoken.Scope{apitoken.ScopeTrafficRead}, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	devicesToken, err := tokenStore.Create(apitoken.CreateRequest{Name: "devices", Creator: "admin", Scopes: []apitoken.Scope{apitoken.ScopeDevicesRead}, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	handler := server.Handler()

	unauthenticated := httptest.NewRequest(http.MethodGet, "/api/v1/events/summary", nil)
	unauthenticated.Host = "shakerproxy.test"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, unauthenticated)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated summary returned %d", recorder.Code)
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, tokenRequest(http.MethodGet, "/api/v1/events/summary", devicesToken.Secret))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("devices:read token read the summary: %d %s", recorder.Code, recorder.Body.String())
	}
	for _, credential := range []string{session, trafficToken.Secret} {
		recorder = httptest.NewRecorder()
		handler.ServeHTTP(recorder, tokenRequest(http.MethodGet, "/api/v1/events/summary?buckets=30&from=2026-10-02T12:00:00Z&to=2026-10-02T12:15:00Z&q=device.name%3APixel+AND+protocol%3Audp", credential))
		if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("summary returned %d: %s", recorder.Code, recorder.Body.String())
		}
		var summary ingest.TrafficSummary
		if err := json.Unmarshal(recorder.Body.Bytes(), &summary); err != nil {
			t.Fatal(err)
		}
		devices := summary.Facets[0]
		if devices.Field != ingest.SummaryFacetDevice || devices.Values[0].Label != "Pixel" || devices.Values[1].Label != "10.77.0.9" || len(summary.Buckets) != 30 || summary.Totals.Types.DNS != 2 {
			t.Fatalf("unexpected summary: %s", recorder.Body.String())
		}
		for _, field := range []string{`"bucket_seconds":30`, `"counts":{"dns":2,"tls":0,"quic":0,"http":0,"discovery":0,"alert":0,"other":0,"blocked":0}`, `"bytes_sent":0`, `"other_count":0`, `"exact":true`} {
			if !strings.Contains(recorder.Body.String(), field) {
				t.Fatalf("summary lacks %s: %s", field, recorder.Body.String())
			}
		}
	}
	last := stub.queries[len(stub.queries)-1]
	if last.Buckets != 30 || !last.From.Equal(time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)) || last.Events.Filter.Canonical != "device.name:Pixel AND protocol:udp" || !slices.Contains(last.Events.DeviceNameResolutions["Pixel"], stub.deviceID) {
		t.Fatalf("storage query did not carry the window and resolved device: %#v", last)
	}

	for _, target := range []string{"/api/v1/events/summary?buckets=0", "/api/v1/events/summary?limit=10", "/api/v1/events/summary?from=2026-10-02T12:00:00Z&to=2026-10-02T11:00:00Z", "/api/v1/events/summary?q=nope%3A%28"} {
		recorder = httptest.NewRecorder()
		handler.ServeHTTP(recorder, tokenRequest(http.MethodGet, target, session))
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), `"invalid_query"`) {
			t.Fatalf("%s returned %d: %s", target, recorder.Code, recorder.Body.String())
		}
	}
	stub.err = errors.New("statement timeout")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, tokenRequest(http.MethodGet, "/api/v1/events/summary", session))
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), `"event_summary_unavailable"`) || strings.Contains(recorder.Body.String(), "statement timeout") {
		t.Fatalf("storage failure returned %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestTrafficSummaryRouteNeedsASummaryReader(t *testing.T) {
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) {
		config.EventReader = recentOnlyReader{}
	})
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, tokenRequest(http.MethodGet, "/api/v1/events/summary", session))
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), `"event_summary_unavailable"`) {
		t.Fatalf("summary without a reader returned %d: %s", recorder.Code, recorder.Body.String())
	}
}
