package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/cloudconnector"
	"shakerproxy.dev/shakerproxy/internal/detection"
	"shakerproxy.dev/shakerproxy/internal/forwarder"
	"shakerproxy.dev/shakerproxy/internal/ingest"
)

const testToken = "ingest-test-token-0000000000000001"
const testQueryToken = "query-test-token-00000000000000001"

type retryingCloudMetadataQueue struct {
	fail    bool
	failErr error
	calls   int
	events  []cloudconnector.LocalMetadataEvent
}

func (queue *retryingCloudMetadataQueue) Enqueue(_ context.Context, events []cloudconnector.LocalMetadataEvent) error {
	queue.calls++
	if queue.failErr != nil {
		return queue.failErr
	}
	if queue.fail {
		return errors.New("connector restarting")
	}
	queue.events = append(queue.events, events...)
	return nil
}

func testServer(t *testing.T) *Server {
	t.Helper()
	server, err := New(Config{Spool: &ingest.Spool{Root: filepath.Join(t.TempDir(), "spool"), MaxBytes: 8 << 20, ReserveBytes: 1}, Token: []byte(testToken), QueryToken: []byte(testQueryToken), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func TestEventEndpointAuthenticatesAcceptsAndDeduplicates(t *testing.T) {
	server := testServer(t)
	request := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(validHTTPEvent))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+testToken)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("unexpected response %d: %s", recorder.Code, recorder.Body.String())
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(validHTTPEvent))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+testToken)
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"duplicate":true`) {
		t.Fatalf("duplicate response %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestAcceptedEventIsQueuedOnceForSafeForwarding(t *testing.T) {
	manager := &forwarder.Manager{Root: t.TempDir()}
	created, err := manager.Create(forwarder.CreateRequest{Name: "local alerts", Kind: forwarder.KindJSONL, Classes: []forwarder.EventClass{forwarder.ClassAlert}, Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.SetEnabled(created.Integration.ID, 1, true, "admin", "authorized test forwarding"); err != nil {
		t.Fatal(err)
	}
	server := testServer(t)
	server.forwarders = manager
	for index := 0; index < 2; index++ {
		request := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(validHTTPEvent))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+testToken)
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusAccepted && recorder.Code != http.StatusOK {
			t.Fatalf("event %d returned %d: %s", index, recorder.Code, recorder.Body.String())
		}
	}
	status, err := manager.Status()
	if err != nil || len(status) != 1 || status[0].Queued != 1 {
		t.Fatalf("deduplicated forwarding queue is wrong: %#v %v", status, err)
	}
}

func TestAcceptedObservationEmitsOneDurableNativeDetectionTransition(t *testing.T) {
	server := testServer(t)
	manager, err := detection.New(filepath.Join(t.TempDir(), "detections.json"), detection.Config{})
	if err != nil {
		t.Fatal(err)
	}
	server.detections = manager
	at := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	payload, _ := json.Marshal(detection.Observation{Schema: 1, Kind: detection.ObserveClock, OccurredAt: at.Add(-time.Hour), ClockSynchronized: false})
	envelope := ingest.Envelope{Schema: 1, EventID: "observation-1234567890abcdef", Source: ingest.SourceHost, Kind: "shakerproxy.observation", OccurredAt: at, SourceVersion: "gatewayd-v1", ParserVersion: "observation-v1", Payload: payload}
	encoded, _ := json.Marshal(envelope)
	for index := 0; index < 2; index++ {
		request := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(string(encoded)))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+testToken)
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusAccepted && recorder.Code != http.StatusOK {
			t.Fatalf("observation %d returned %d: %s", index, recorder.Code, recorder.Body.String())
		}
	}
	stats, err := server.spool.Stats()
	if err != nil || stats.PendingRecords != 2 {
		t.Fatalf("expected original and one derived detection, got %#v err=%v", stats, err)
	}
}

func TestEventEndpointRejectsMissingTokenAndQuarantinesMalformed(t *testing.T) {
	server := testServer(t)
	request := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(validHTTPEvent))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated response %d: %s", recorder.Code, recorder.Body.String())
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(`{"schema":1}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+testToken)
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity || !strings.Contains(recorder.Body.String(), `"quarantined":true`) {
		t.Fatalf("malformed response %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestEventEndpointRejectsTombstonedCaptureAsGone(t *testing.T) {
	server := testServer(t)
	captureID := "capture-0123456789abcdef0123456789abcdef"
	if _, err := server.spool.PutCaptureTombstone(ingest.CaptureTombstone{Schema: ingest.CaptureTombstoneSchemaVersion, CaptureSessionID: captureID, OperationID: "capture-delete-operation-0001", Actor: "admin", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	event := strings.Replace(validHTTPEvent, `"flow_id"`, `"capture_session_id":"`+captureID+`","flow_id"`, 1)
	request := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(event))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+testToken)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusGone || !strings.Contains(recorder.Body.String(), `"code":"capture_deleted"`) || strings.Contains(recorder.Body.String(), captureID) {
		t.Fatalf("unexpected tombstoned-capture response %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestEventEndpointRejectsTombstonedDeviceTimeSelectionAsGone(t *testing.T) {
	server := testServer(t)
	start := time.Date(2026, 9, 1, 11, 0, 0, 0, time.UTC)
	selection, err := ingest.CanonicalEventSelection("device-0123456789abcdef0123456789abcdef", start, start.Add(2*time.Hour), nil)
	if err != nil {
		t.Fatal(err)
	}
	selectionSHA, _ := selection.SHA256()
	tombstone := ingest.EventSelectionTombstone{
		Schema: ingest.EventSelectionSchemaVersion, OperationID: "device-event-delete-route-0001", Actor: "admin", Selection: selection, SelectionSHA256: selectionSHA,
		QuerySnapshotID: "qsnap-0123456789abcdef0123456789abcdef", QuerySnapshotSHA256: strings.Repeat("a", 64), CreatedAt: start.Add(time.Hour),
	}
	if _, err := server.spool.PutEventSelectionTombstoneForPreview(tombstone, ingest.EventSelectionSpoolFootprint{}); err != nil {
		t.Fatal(err)
	}
	event := strings.Replace(validHTTPEvent, `"flow_id"`, `"device_id":"`+selection.DeviceID+`","flow_id"`, 1)
	request := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(event))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+testToken)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusGone || !strings.Contains(recorder.Body.String(), `"code":"event_selection_deleted"`) || strings.Contains(recorder.Body.String(), tombstone.OperationID) {
		t.Fatalf("unexpected selection-tombstone response %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestStatsRequireToken(t *testing.T) {
	server := testServer(t)
	request := httptest.NewRequest(http.MethodGet, "/v1/stats", nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected response %d", recorder.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/stats", nil)
	request.Header.Set("Authorization", testToken)
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("token without Bearer scheme returned %d", recorder.Code)
	}
}

type recentEventReaderFunc func(context.Context, ingest.RecentEventQuery) (ingest.RecentEventPage, error)

func (f recentEventReaderFunc) QueryRecent(ctx context.Context, query ingest.RecentEventQuery) (ingest.RecentEventPage, error) {
	return f(ctx, query)
}

type liveEventReaderFunc func(context.Context, ingest.LiveEventQuery) (ingest.LiveEventBatch, error)

func (f liveEventReaderFunc) QueryAfter(ctx context.Context, query ingest.LiveEventQuery) (ingest.LiveEventBatch, error) {
	return f(ctx, query)
}

func TestRecentEventsRequireDistinctQueryTokenAndBoundParameters(t *testing.T) {
	server := testServer(t)
	server.recentEvents = recentEventReaderFunc(func(_ context.Context, query ingest.RecentEventQuery) (ingest.RecentEventPage, error) {
		if query.Limit != 2 || query.Source != ingest.SourceZeek || query.Filter.Canonical != "service:http" {
			t.Fatalf("unexpected event query: %#v", query)
		}
		return ingest.RecentEventPage{Schema: 1, GeneratedAt: time.Now().UTC(), CanonicalQuery: query.Filter.Canonical, Events: []ingest.RecentEvent{{RecordID: strings.Repeat("a", 64), Source: ingest.SourceZeek, Kind: "zeek.conn", OccurredAt: time.Now().UTC(), ReceivedAt: time.Now().UTC(), Confidence: 80}}}, nil
	})
	for name, token := range map[string]string{"missing": "", "write credential": testToken} {
		request := httptest.NewRequest(http.MethodGet, "/v1/events?limit=2&source=ZEEK&q=service%3Ahttp", nil)
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("%s query returned %d", name, recorder.Code)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/events?limit=2&source=ZEEK&q=service%3Ahttp", nil)
	request.Header.Set("Authorization", "Bearer "+testQueryToken)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || !strings.Contains(recorder.Body.String(), `"kind":"zeek.conn"`) || strings.Contains(recorder.Body.String(), `"payload"`) {
		t.Fatalf("unexpected bounded query response %d: %s", recorder.Code, recorder.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/events?limit=101", nil)
	request.Header.Set("Authorization", "Bearer "+testQueryToken)
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unbounded query returned %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestLiveEventsRequireQueryTokenAndReturnBoundedBatch(t *testing.T) {
	server := testServer(t)
	after := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	afterID := strings.Repeat("0", 64)
	eventTime := after.Add(time.Second)
	eventID := strings.Repeat("d", 64)
	server.liveEvents = liveEventReaderFunc(func(_ context.Context, query ingest.LiveEventQuery) (ingest.LiveEventBatch, error) {
		if query.Limit != 2 || query.Source != ingest.SourceZeek || !query.AfterReceivedAt.Equal(after) || query.AfterRecordID != afterID {
			t.Fatalf("unexpected live event query: %#v", query)
		}
		return ingest.LiveEventBatch{Schema: 1, GeneratedAt: eventTime, Events: []ingest.RecentEvent{{RecordID: eventID, Source: ingest.SourceZeek, Kind: "zeek.conn", OccurredAt: eventTime, ReceivedAt: eventTime, SourceVersion: "8.2.1", ParserVersion: "shakerproxy-zeek-v1", Confidence: 80}}, NextCursor: liveCursorForTest(eventTime, eventID)}, nil
	})
	cursor := liveCursorForTest(after, afterID)
	request := httptest.NewRequest(http.MethodGet, "/v1/events/live-batch?limit=2&source=ZEEK&cursor="+cursor, nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated live query returned %d", recorder.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/events/live-batch?limit=2&source=ZEEK&cursor="+cursor, nil)
	request.Header.Set("Authorization", "Bearer "+testQueryToken)
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || !strings.Contains(recorder.Body.String(), `"record_id":"`+eventID+`"`) || strings.Contains(recorder.Body.String(), `"payload"`) {
		t.Fatalf("unexpected live batch response %d: %s", recorder.Code, recorder.Body.String())
	}
}

func liveCursorForTest(at time.Time, recordID string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(at.UTC().Format(time.RFC3339Nano) + "\n" + recordID))
}

func TestServerRejectsSharedWriteAndQueryCredential(t *testing.T) {
	_, err := New(Config{Spool: &ingest.Spool{Root: filepath.Join(t.TempDir(), "spool"), MaxBytes: 8 << 20, ReserveBytes: 1}, Token: []byte(testToken), QueryToken: []byte(testToken)})
	if err == nil {
		t.Fatal("shared write and query token was accepted")
	}
}

func TestQueryCredentialReadsBoundedIngestStatusButWriteCredentialCannot(t *testing.T) {
	server := testServer(t)
	request := httptest.NewRequest(http.MethodGet, "/v1/query-stats", nil)
	request.Header.Set("Authorization", "Bearer "+testToken)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("write credential read query status with %d", recorder.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/query-stats", nil)
	request.Header.Set("Authorization", "Bearer "+testQueryToken)
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || !strings.Contains(recorder.Body.String(), `"pending_records":0`) {
		t.Fatalf("unexpected query status response %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestHealthAndStatsExposeDatabaseDegradationWithoutRejectingIngest(t *testing.T) {
	server, err := New(Config{
		Spool: &ingest.Spool{Root: filepath.Join(t.TempDir(), "spool"), MaxBytes: 8 << 20, ReserveBytes: 1},
		Token: []byte(testToken), QueryToken: []byte(testQueryToken), Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		DatabaseProbe: func(context.Context) error { return errors.New("database unavailable") },
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"status":"degraded"`) || !strings.Contains(recorder.Body.String(), `"database_connected":false`) {
		t.Fatalf("database degradation was not surfaced: %d %s", recorder.Code, recorder.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/stats", nil)
	request.Header.Set("Authorization", "Bearer "+testToken)
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"database_configured":true`) || !strings.Contains(recorder.Body.String(), `"database_connected":false`) {
		t.Fatalf("database status was not exposed in ingest stats: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestNativeAnalyzerAdaptersNormalizeAndShareSpool(t *testing.T) {
	server := testServer(t)
	zeek := `{"ts":1788278400.123456,"uid":"Cabc123","_path":"conn","id.orig_h":"10.77.0.111","id.resp_h":"1.1.1.1"}`
	request := httptest.NewRequest(http.MethodPost, "/v1/adapters/zeek", strings.NewReader(zeek))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+testToken)
	request.Header.Set("X-ShakerProxy-Source-Version", "7.2.2")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("Zeek response %d: %s", recorder.Code, recorder.Body.String())
	}
	suricata := `{"timestamp":"2026-09-01T12:00:00.123456+0000","flow_id":123456789,"event_type":"alert","src_ip":"10.77.0.111","alert":{"severity":1}}`
	request = httptest.NewRequest(http.MethodPost, "/v1/adapters/suricata", strings.NewReader(suricata))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+testToken)
	request.Header.Set("X-ShakerProxy-Source-Version", "7.0.10")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("Suricata response %d: %s", recorder.Code, recorder.Body.String())
	}
	stats, err := server.spool.Stats()
	if err != nil || stats.PendingRecords != 2 {
		t.Fatalf("adapters did not share the spool: %#v err=%v", stats, err)
	}
}

func TestAnalyzerCloudQueueFailureRetainsLocalEventForRetry(t *testing.T) {
	queue := &retryingCloudMetadataQueue{fail: true}
	server, err := New(Config{
		Spool:         &ingest.Spool{Root: filepath.Join(t.TempDir(), "spool"), MaxBytes: 8 << 20, ReserveBytes: 1},
		Token:         []byte(testToken),
		QueryToken:    []byte(testQueryToken),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		CloudMetadata: queue,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	raw := fmt.Sprintf(`{"timestamp":%q,"flow_id":123456789,"event_type":"alert","src_ip":"10.77.0.111","src_port":51000,"dest_ip":"198.51.100.9","dest_port":443,"proto":"TCP","alert":{"signature_id":9900001,"signature":"Test alert","severity":1},"password":"NEVER_UPLOAD"}`, now.Format(time.RFC3339Nano))
	request := httptest.NewRequest(http.MethodPost, "/v1/adapters/suricata", strings.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+testToken)
	request.Header.Set("X-ShakerProxy-Source-Version", "8.0.6")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "cloud_queue_unavailable") {
		t.Fatalf("cloud outage was not retryable: %d %s", recorder.Code, recorder.Body.String())
	}
	stats, err := server.spool.Stats()
	if err != nil || stats.PendingRecords != 1 {
		t.Fatalf("cloud outage lost the local event: %#v err=%v", stats, err)
	}

	queue.fail = false
	request = httptest.NewRequest(http.MethodPost, "/v1/adapters/suricata", strings.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+testToken)
	request.Header.Set("X-ShakerProxy-Source-Version", "8.0.6")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"duplicate":true`) {
		t.Fatalf("retry did not acknowledge the durable duplicate: %d %s", recorder.Code, recorder.Body.String())
	}
	if queue.calls != 2 || len(queue.events) != 1 || queue.events[0].Type != cloudconnector.MetadataFlowSummary {
		t.Fatalf("unexpected cloud retry projection: calls=%d events=%#v", queue.calls, queue.events)
	}
	if payload := string(queue.events[0].Payload); !strings.Contains(payload, `"alert":true`) || strings.Contains(payload, "NEVER_UPLOAD") || strings.Contains(payload, "password") {
		t.Fatalf("cloud alert projection violated its metadata boundary: %s", payload)
	}
}

func TestMalformedAnalyzerEventIsQuarantined(t *testing.T) {
	server := testServer(t)
	request := httptest.NewRequest(http.MethodPost, "/v1/adapters/zeek", strings.NewReader(`{"_path":"conn"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+testToken)
	request.Header.Set("X-ShakerProxy-Source-Version", "7.2.2")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity || !strings.Contains(recorder.Body.String(), `"quarantined":true`) {
		t.Fatalf("malformed adapter response %d: %s", recorder.Code, recorder.Body.String())
	}
}

const validHTTPEvent = `{"schema":1,"event_id":"suricata-event-0001","source":"SURICATA","kind":"alert","occurred_at":"2026-09-01T12:00:00Z","source_version":"7.0.10","parser_version":"shakerproxy-suricata-v1","flow_id":"flow-00000000001","confidence":95,"payload":{"severity":1}}`

func TestCloudConnectorNotRunningDoesNotBlockLocalIngestion(t *testing.T) {
	for name, cause := range map[string]error{"socket missing": syscall.ENOENT, "stale socket": syscall.ECONNREFUSED} {
		t.Run(name, func(t *testing.T) {
			dialErr := &url.Error{Op: "Post", URL: "http://unix/v1/metadata/enqueue", Err: &net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", cause)}}
			queue := &retryingCloudMetadataQueue{failErr: fmt.Errorf("queue local cloud metadata: %w", dialErr)}
			server, err := New(Config{
				Spool:         &ingest.Spool{Root: filepath.Join(t.TempDir(), "spool"), MaxBytes: 8 << 20, ReserveBytes: 1},
				Token:         []byte(testToken),
				QueryToken:    []byte(testQueryToken),
				Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
				CloudMetadata: queue,
			})
			if err != nil {
				t.Fatal(err)
			}
			raw := fmt.Sprintf(`{"timestamp":%q,"flow_id":123456789,"event_type":"flow","src_ip":"10.77.0.111","src_port":51000,"dest_ip":"198.51.100.9","dest_port":443,"proto":"TCP"}`, time.Now().UTC().Format(time.RFC3339Nano))
			request := httptest.NewRequest(http.MethodPost, "/v1/adapters/suricata", strings.NewReader(raw))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer "+testToken)
			request.Header.Set("X-ShakerProxy-Source-Version", "8.0.6")
			recorder := httptest.NewRecorder()
			server.Handler().ServeHTTP(recorder, request)
			if recorder.Code != http.StatusAccepted || queue.calls != 1 {
				t.Fatalf("absent connector blocked local ingestion: %d %s (calls=%d)", recorder.Code, recorder.Body.String(), queue.calls)
			}
		})
	}
}

// A segment's events arrive in one request and share one round of disk syncs;
// each line still gets its own result, in order.
func TestAnalyzerBatchStoresEachEventAndReportsQuarantines(t *testing.T) {
	server := testServer(t)
	lines := []string{}
	for index := 0; index < 30; index++ {
		lines = append(lines, fmt.Sprintf(`{"ts":1788278400.%06d,"uid":"Cbatch%03d","_path":"conn","id.orig_h":"10.77.0.111","id.resp_h":"1.1.1.1"}`, index, index))
	}
	lines = append(lines, lines[0], `{"_path":"conn"}`)
	post := func(contentType, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/v1/adapters/zeek/batch", strings.NewReader(body))
		request.Header.Set("Content-Type", contentType)
		request.Header.Set("Authorization", "Bearer "+testToken)
		request.Header.Set("X-ShakerProxy-Source-Version", "8.2.1")
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		return recorder
	}
	recorder := post("application/x-ndjson", strings.Join(lines, "\n")+"\n")
	if recorder.Code != http.StatusOK {
		t.Fatalf("batch response %d: %s", recorder.Code, recorder.Body.String())
	}
	var response adapterBatchResult
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || len(response.Results) != 32 {
		t.Fatalf("batch results: %v %s", err, recorder.Body.String())
	}
	for index := 0; index < 30; index++ {
		if !response.Results[index].Accepted || response.Results[index].Duplicate {
			t.Fatalf("line %d: %#v", index, response.Results[index])
		}
	}
	if !response.Results[30].Duplicate || !response.Results[31].Quarantined {
		t.Fatalf("duplicate and malformed lines: %#v %#v", response.Results[30], response.Results[31])
	}
	stats, err := server.spool.Stats()
	if err != nil || stats.PendingRecords != 30 || stats.QuarantinedRecords != 1 {
		t.Fatalf("spool after batch: %#v err=%v", stats, err)
	}
	if recorder := post("application/json", lines[0]); recorder.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("a JSON body on the batch route returned %d", recorder.Code)
	}
	if recorder := post("application/x-ndjson", "\n\n"); recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("an empty batch returned %d", recorder.Code)
	}
	unauthenticated := httptest.NewRequest(http.MethodPost, "/v1/adapters/suricata/batch", strings.NewReader(lines[0]))
	unauthenticated.Header.Set("Content-Type", "application/x-ndjson")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, unauthenticated)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("an unauthenticated batch returned %d", recorder.Code)
	}
}

// Each event used to be queued for the cloud connector separately, a local
// request and a durable write apiece, so a busy Suricata batch outlasted the
// analyzer's 15 s timeout and analysis fell behind. A batch now queues once.
func TestAnalyzerBatchQueuesCloudMetadataOnce(t *testing.T) {
	server := testServer(t)
	queue := &retryingCloudMetadataQueue{}
	server.cloudMetadata = queue
	lines := []string{}
	for index := 0; index < 40; index++ {
		lines = append(lines, fmt.Sprintf(`{"ts":%d.%06d,"uid":"Ccloud%03d","_path":"conn","id.orig_h":"10.77.0.111","id.resp_h":"1.1.1.1"}`, time.Now().Unix(), index, index))
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/adapters/zeek/batch", strings.NewReader(strings.Join(lines, "\n")+"\n"))
	request.Header.Set("Content-Type", "application/x-ndjson")
	request.Header.Set("Authorization", "Bearer "+testToken)
	request.Header.Set("X-ShakerProxy-Source-Version", "8.2.1")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("batch response %d: %s", recorder.Code, recorder.Body.String())
	}
	if queue.calls != 1 || len(queue.events) < 40 {
		t.Fatalf("cloud queue calls=%d events=%d, want one call carrying the whole batch", queue.calls, len(queue.events))
	}
}
