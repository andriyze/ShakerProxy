package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

type deviceActivityReaderStub struct {
	query    ingest.DeviceActivityQuery
	activity ingest.DeviceActivity
	err      error
}

func (stub *deviceActivityReaderStub) QueryRecent(context.Context, ingest.RecentEventQuery) (ingest.RecentEventPage, error) {
	return ingest.RecentEventPage{}, nil
}

func (stub *deviceActivityReaderStub) QueryDeviceActivity(_ context.Context, query ingest.DeviceActivityQuery) (ingest.DeviceActivity, error) {
	stub.query = query
	if stub.err != nil {
		return ingest.DeviceActivity{}, stub.err
	}
	activity := stub.activity
	activity.DeviceID, activity.Start, activity.End = query.DeviceID, query.Start, query.End
	return activity, nil
}

func deviceActivityStubResult(generatedAt time.Time) ingest.DeviceActivity {
	return ingest.DeviceActivity{
		Schema: ingest.SchemaVersion, GeneratedAt: generatedAt,
		Domains: []ingest.DeviceDomainObservation{}, FlowGroups: []ingest.DeviceFlowGroup{}, TLSHosts: []ingest.DeviceTLSHost{},
		TLSVersions: []ingest.DeviceTLSVersion{}, CleartextHTTP: []ingest.DeviceHTTPHost{}, HTTPStatus: []ingest.DeviceHTTPStatusCount{},
		Alerts: []ingest.DeviceAlertGroup{}, EncryptedDNS: []ingest.DeviceResolver{},
	}
}

func TestDeviceActivityEndpointRequiresQueryTokenAndReturnsAggregation(t *testing.T) {
	server := testServer(t)
	end := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	stub := &deviceActivityReaderStub{activity: deviceActivityStubResult(end)}
	server.recentEvents = stub
	target := "/v1/device-activity?device_id=device-0123456789abcdef0123456789abcdef&start=2026-09-28T12:00:00Z&end=2026-09-29T12:00:00Z"

	for name, token := range map[string]string{"missing": "", "ingest token": testToken} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		recorder := httptest.NewRecorder()
		server.DeviceActivityHandler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("%s credential reached device activity: %d %s", name, recorder.Code, recorder.Body.String())
		}
	}

	request := httptest.NewRequest(http.MethodGet, target, nil)
	request.Header.Set("Authorization", "Bearer "+testQueryToken)
	recorder := httptest.NewRecorder()
	server.DeviceActivityHandler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || !strings.Contains(recorder.Body.String(), `"device_id":"device-0123456789abcdef0123456789abcdef"`) {
		t.Fatalf("device activity response %d headers=%v body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	if stub.query.DeviceID != "device-0123456789abcdef0123456789abcdef" || !stub.query.End.Equal(end) || !stub.query.Start.Equal(end.Add(-24*time.Hour)) {
		t.Fatalf("unexpected device activity query: %#v", stub.query)
	}
}

func TestDeviceActivityEndpointRejectsInvalidQueriesAndHidesStorageErrors(t *testing.T) {
	server := testServer(t)
	stub := &deviceActivityReaderStub{}
	server.recentEvents = stub
	for _, target := range []string{
		"/v1/device-activity?device_id=bad&start=2026-09-28T12:00:00Z&end=2026-09-29T12:00:00Z",
		"/v1/device-activity?device_id=device-0123456789abcdef0123456789abcdef&start=2026-08-01T00:00:00Z&end=2026-09-29T12:00:00Z",
	} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		request.Header.Set("Authorization", "Bearer "+testQueryToken)
		recorder := httptest.NewRecorder()
		server.DeviceActivityHandler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("invalid device activity query %s returned %d", target, recorder.Code)
		}
	}
	if !reflect.DeepEqual(stub.query, ingest.DeviceActivityQuery{}) {
		t.Fatalf("storage was called for an invalid query: %#v", stub.query)
	}
	stub.err = errors.New("pq: secret internal detail")
	request := httptest.NewRequest(http.MethodGet, "/v1/device-activity?device_id=device-0123456789abcdef0123456789abcdef&start=2026-09-28T12:00:00Z&end=2026-09-29T12:00:00Z", nil)
	request.Header.Set("Authorization", "Bearer "+testQueryToken)
	recorder := httptest.NewRecorder()
	server.DeviceActivityHandler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable || strings.Contains(recorder.Body.String(), "secret") {
		t.Fatalf("storage failure returned %d %s", recorder.Code, recorder.Body.String())
	}
}
