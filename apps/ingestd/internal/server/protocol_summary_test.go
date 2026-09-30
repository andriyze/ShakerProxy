package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

type protocolSummaryReaderStub struct {
	query  ingest.ProtocolSummaryQuery
	calls  int
	result ingest.ProtocolSummary
	err    error
}

func (stub *protocolSummaryReaderStub) QueryRecent(context.Context, ingest.RecentEventQuery) (ingest.RecentEventPage, error) {
	return ingest.RecentEventPage{}, nil
}

func (stub *protocolSummaryReaderStub) QueryProtocolSummary(_ context.Context, query ingest.ProtocolSummaryQuery) (ingest.ProtocolSummary, error) {
	stub.calls++
	stub.query = query
	return stub.result, stub.err
}

func TestProtocolSummaryEndpointRequiresQueryToken(t *testing.T) {
	server := testServer(t)
	end := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	stub := &protocolSummaryReaderStub{result: ingest.ProtocolSummary{Schema: 1, GeneratedAt: end, Window: "1h", WindowStart: end.Add(-time.Hour), WindowEnd: end, Protocols: []ingest.ProtocolUsage{}, Sources: []ingest.Source{}}}
	server.recentEvents = stub
	target := "/v1/protocol-summary?window_seconds=3600&exotic=true"
	for _, token := range []string{"", testToken} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("protocol summary without the query token returned %d", recorder.Code)
		}
	}
	request := httptest.NewRequest(http.MethodGet, target, nil)
	request.Header.Set("Authorization", "Bearer "+testQueryToken)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || !strings.Contains(recorder.Body.String(), `"window":"1h"`) {
		t.Fatalf("protocol summary returned %d: %s", recorder.Code, recorder.Body.String())
	}
	if stub.query.WindowSeconds != 3600 || stub.query.Exotic == nil || !*stub.query.Exotic {
		t.Fatalf("unexpected storage query: %#v", stub.query)
	}
}

func TestProtocolSummaryEndpointRejectsInvalidQueriesAndHidesStorageErrors(t *testing.T) {
	server := testServer(t)
	stub := &protocolSummaryReaderStub{err: errors.New("pq: relation secret_table does not exist")}
	server.recentEvents = stub
	for _, target := range []string{"/v1/protocol-summary?window_seconds=5", "/v1/protocol-summary?device_id=tv", "/v1/protocol-summary?q=x"} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		request.Header.Set("Authorization", "Bearer "+testQueryToken)
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s returned %d", target, recorder.Code)
		}
	}
	if stub.calls != 0 {
		t.Fatal("storage was called for invalid queries")
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/protocol-summary", nil)
	request.Header.Set("Authorization", "Bearer "+testQueryToken)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable || strings.Contains(recorder.Body.String(), "secret_table") {
		t.Fatalf("storage failure was not hidden: %d %s", recorder.Code, recorder.Body.String())
	}
}
