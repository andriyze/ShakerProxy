package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

type httpActivityReaderStub struct {
	query ingest.HTTPActivityQuery
	page  ingest.HTTPActivityPage
}

func (stub *httpActivityReaderStub) QueryRecent(context.Context, ingest.RecentEventQuery) (ingest.RecentEventPage, error) {
	return ingest.RecentEventPage{}, nil
}

func (stub *httpActivityReaderStub) QueryHTTPActivity(_ context.Context, query ingest.HTTPActivityQuery) (ingest.HTTPActivityPage, error) {
	stub.query = query
	return stub.page, nil
}

func TestHTTPActivityEndpointRequiresQueryTokenAndReturnsNoStoreMetadata(t *testing.T) {
	server := testServer(t)
	anchor := time.Date(2026, 9, 3, 20, 0, 0, 0, time.UTC)
	stub := &httpActivityReaderStub{page: ingest.HTTPActivityPage{Schema: ingest.SchemaVersion, GeneratedAt: anchor.Add(time.Second), QueryAnchor: anchor, Events: []ingest.HTTPActivityEvent{}}}
	server.recentEvents = stub
	target := "/v1/http-activity?limit=25&window_seconds=900&host=API.Example.Test.&method=post"

	unauthenticated := httptest.NewRequest(http.MethodGet, target, nil)
	unauthenticatedRecorder := httptest.NewRecorder()
	server.HTTPActivityHandler().ServeHTTP(unauthenticatedRecorder, unauthenticated)
	if unauthenticatedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated HTTP activity returned %d: %s", unauthenticatedRecorder.Code, unauthenticatedRecorder.Body.String())
	}

	wrongCredential := httptest.NewRequest(http.MethodGet, target, nil)
	wrongCredential.Header.Set("Authorization", "Bearer "+testToken)
	wrongRecorder := httptest.NewRecorder()
	server.HTTPActivityHandler().ServeHTTP(wrongRecorder, wrongCredential)
	if wrongRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("ingest credential accessed HTTP activity: %d %s", wrongRecorder.Code, wrongRecorder.Body.String())
	}

	request := httptest.NewRequest(http.MethodGet, target, nil)
	request.Header.Set("Authorization", "Bearer "+testQueryToken)
	recorder := httptest.NewRecorder()
	server.HTTPActivityHandler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || !strings.Contains(recorder.Body.String(), `"events":[]`) {
		t.Fatalf("HTTP activity response %d headers=%v body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	if stub.query.Limit != 25 || stub.query.WindowSeconds != 900 || stub.query.Host != "api.example.test" || stub.query.Method != "POST" {
		t.Fatalf("unexpected HTTP activity query: %#v", stub.query)
	}
}

func TestHTTPActivityEndpointRejectsInvalidQueryBeforeStorage(t *testing.T) {
	server := testServer(t)
	stub := &httpActivityReaderStub{}
	server.recentEvents = stub
	request := httptest.NewRequest(http.MethodGet, "/v1/http-activity?limit=1&limit=2", nil)
	request.Header.Set("Authorization", "Bearer "+testQueryToken)
	recorder := httptest.NewRecorder()
	server.HTTPActivityHandler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid HTTP activity query returned %d: %s", recorder.Code, recorder.Body.String())
	}
	if stub.query != (ingest.HTTPActivityQuery{}) {
		t.Fatalf("storage was called for invalid query: %#v", stub.query)
	}
}
