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

type trafficSummaryReaderStub struct {
	query  ingest.TrafficSummaryQuery
	calls  int
	result func(ingest.TrafficSummaryQuery) ingest.TrafficSummary
	err    error
}

func (stub *trafficSummaryReaderStub) QueryRecent(context.Context, ingest.RecentEventQuery) (ingest.RecentEventPage, error) {
	return ingest.RecentEventPage{}, nil
}

func (stub *trafficSummaryReaderStub) QueryTrafficSummary(_ context.Context, query ingest.TrafficSummaryQuery) (ingest.TrafficSummary, error) {
	stub.calls++
	stub.query = query
	if stub.err != nil {
		return ingest.TrafficSummary{}, stub.err
	}
	return stub.result(query), nil
}

func emptyTrafficSummary(query ingest.TrafficSummaryQuery) ingest.TrafficSummary {
	from := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	width := 15 * time.Minute / time.Duration(query.Buckets)
	summary := ingest.TrafficSummary{Schema: 1, GeneratedAt: from.Add(15 * time.Minute), From: from, To: from.Add(15 * time.Minute), BucketSeconds: width.Seconds(), Buckets: make([]ingest.TrafficSummaryBucket, query.Buckets)}
	for index := range summary.Buckets {
		summary.Buckets[index].Start = from.Add(time.Duration(index) * width)
	}
	for _, field := range ingest.TrafficSummaryFacetFields {
		summary.Facets = append(summary.Facets, ingest.TrafficSummaryFacet{Field: field, Values: []ingest.TrafficSummaryFacetValue{}, Exact: true})
	}
	return summary
}

func TestTrafficSummaryEndpointRequiresQueryToken(t *testing.T) {
	server := testServer(t)
	stub := &trafficSummaryReaderStub{result: emptyTrafficSummary}
	server.recentEvents = stub
	target := "/v1/events/summary?buckets=12&q=protocol%3Audp"
	for _, token := range []string{"", testToken} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("summary without the query token returned %d", recorder.Code)
		}
	}
	request := httptest.NewRequest(http.MethodGet, target, nil)
	request.Header.Set("Authorization", "Bearer "+testQueryToken)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || !strings.Contains(recorder.Body.String(), `"bucket_seconds":75`) {
		t.Fatalf("summary returned %d: %s", recorder.Code, recorder.Body.String())
	}
	if stub.query.Buckets != 12 || stub.query.Events.Filter.Canonical != "protocol:udp" {
		t.Fatalf("unexpected storage query: %#v", stub.query)
	}
}

func TestTrafficSummaryEndpointRejectsBadInputAndHidesFailures(t *testing.T) {
	server := testServer(t)
	stub := &trafficSummaryReaderStub{result: emptyTrafficSummary}
	server.recentEvents = stub
	for _, target := range []string{"/v1/events/summary?buckets=0", "/v1/events/summary?limit=5", "/v1/events/summary?q=device.name%3Atv", "/v1/events/summary?from=soon"} {
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
	// A reader that returns an inconsistent summary is not served.
	stub.result = func(query ingest.TrafficSummaryQuery) ingest.TrafficSummary {
		summary := emptyTrafficSummary(query)
		summary.Totals.Events = 3
		return summary
	}
	for _, failure := range []error{nil, errors.New("pq: relation secret_table does not exist")} {
		stub.err = failure
		request := httptest.NewRequest(http.MethodGet, "/v1/events/summary", nil)
		request.Header.Set("Authorization", "Bearer "+testQueryToken)
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusServiceUnavailable || strings.Contains(recorder.Body.String(), "secret_table") {
			t.Fatalf("storage failure was not hidden: %d %s", recorder.Code, recorder.Body.String())
		}
	}
}
