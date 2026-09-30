package server

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
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

type controlLiveEventReaderFunc func(context.Context, ingest.LiveEventQuery) (ingest.LiveEventBatch, error)

func (f controlLiveEventReaderFunc) QueryAfter(ctx context.Context, query ingest.LiveEventQuery) (ingest.LiveEventBatch, error) {
	return f(ctx, query)
}

func TestLiveEventStreamAuthenticatesResumesAndOmitsPayload(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	after := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	afterID := strings.Repeat("0", 64)
	queryAnchor := after.Add(-30 * time.Second)
	eventTime := after.Add(time.Second)
	eventID := strings.Repeat("e", 64)
	clock := after.Add(-2 * time.Minute)
	server.inventory = &inventory.Store{Path: filepath.Join(t.TempDir(), "inventory.json"), Now: func() time.Time { return clock }}
	snapshot, err := server.inventory.ReconcileDHCP4([]inventory.DHCP4Lease{{Address: netip.MustParseAddr("10.77.0.111"), HardwareAddr: "52:54:00:ab:cd:01", ValidLifetime: time.Hour, ExpiresAt: after.Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	deviceID := snapshot.Devices[0].ID
	clock = after.Add(-time.Minute)
	if _, err := server.inventory.UpdateAlias(deviceID, "admin", "device-live-alias-0001", inventory.AliasUpdate{FriendlyName: "Bench Camera", Reason: "Live stream fixture", ExpectedRevision: 0}); err != nil {
		t.Fatal(err)
	}
	server.nameResolver = &inventory.NameResolver{Store: server.inventory}
	server.liveEventReader = controlLiveEventReaderFunc(func(_ context.Context, query ingest.LiveEventQuery) (ingest.LiveEventBatch, error) {
		if query.Limit != 2 || query.Source != ingest.SourceSuricata || query.Filter.Canonical != `device.name:"Bench Camera" AND protocol:tcp AND time:last_15m` || len(query.DeviceNameResolutions["Bench Camera"]) != 1 || query.DeviceNameResolutions["Bench Camera"][0] != deviceID || !query.AfterReceivedAt.Equal(after) || query.AfterRecordID != afterID || !query.TimeAnchor.Equal(queryAnchor) {
			t.Fatalf("unexpected live stream query: %#v", query)
		}
		return ingest.LiveEventBatch{Schema: 1, GeneratedAt: eventTime, Events: []ingest.RecentEvent{{RecordID: eventID, Source: ingest.SourceSuricata, Kind: "suricata.flow", OccurredAt: eventTime, ReceivedAt: eventTime, SourceVersion: "8.0.6", ParserVersion: "shakerproxy-suricata-v1", DeviceID: deviceID, Confidence: 80}}, NextCursor: controlAnchoredLiveCursor(eventTime, eventID, queryAnchor), CanonicalQuery: query.Filter.Canonical, QueryAnchor: queryAnchor}, nil
	})

	unauthenticated := httptest.NewRequest(http.MethodGet, "/api/v1/events/live", nil)
	unauthenticated.Host = "shakerproxy.test"
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, unauthenticated)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated live stream returned %d", recorder.Code)
	}

	endpoint := httptest.NewServer(server.Handler())
	defer endpoint.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.URL+"/api/v1/events/live?limit=2&source=SURICATA&q=device.name%3A%22Bench%20Camera%22%20AND%20protocol%3Atcp%20AND%20time%3Alast_15m&cursor="+controlAnchoredLiveCursor(after, afterID, queryAnchor), nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "shakerproxy.test"
	request.Header.Set("Authorization", "Bearer "+session)
	response, err := endpoint.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/event-stream" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Accel-Buffering") != "no" {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("unexpected live stream headers: %d %#v %s", response.StatusCode, response.Header, body)
	}
	reader := bufio.NewReader(response.Body)
	var frame strings.Builder
	for !strings.Contains(frame.String(), `"record_id":"`+eventID+`"`) {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatal(readErr)
		}
		frame.WriteString(line)
	}
	cancel()
	body := frame.String()
	if !strings.Contains(body, "id: "+controlAnchoredLiveCursor(eventTime, eventID, queryAnchor)) || !strings.Contains(body, `"record_id":"`+eventID+`"`) || !strings.Contains(body, `"query_anchor":"`+queryAnchor.Format(time.RFC3339Nano)+`"`) || !strings.Contains(body, `"device_labels_available":true`) || !strings.Contains(body, `"device_friendly_name":"Bench Camera"`) || !strings.Contains(body, `"device_friendly_name_at_capture":"Bench Camera"`) || strings.Contains(body, `"payload"`) {
		t.Fatalf("unexpected live event frame: %s", body)
	}
}

func TestLiveEventStreamEnforcesConnectionCap(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	for range cap(server.liveSlots) {
		server.liveSlots <- struct{}{}
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/events/live", nil)
	request.Host = "shakerproxy.test"
	request.Header.Set("Authorization", "Bearer "+session)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		// The reader availability check deliberately precedes slot allocation.
		t.Fatalf("unconfigured live stream returned %d", recorder.Code)
	}
	server.liveEventReader = controlLiveEventReaderFunc(func(context.Context, ingest.LiveEventQuery) (ingest.LiveEventBatch, error) {
		return ingest.LiveEventBatch{}, nil
	})
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("connection-capped live stream returned %d", recorder.Code)
	}
}

func controlLiveCursor(at time.Time, recordID string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(at.UTC().Format(time.RFC3339Nano) + "\n" + recordID))
}

func controlAnchoredLiveCursor(at time.Time, recordID string, anchor time.Time) string {
	return base64.RawURLEncoding.EncodeToString([]byte("v2\n" + anchor.UTC().Format(time.RFC3339Nano) + "\n" + at.UTC().Format(time.RFC3339Nano) + "\n" + recordID))
}
