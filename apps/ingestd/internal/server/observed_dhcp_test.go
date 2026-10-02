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

type observedDHCPReaderStub struct {
	result ingest.ObservedDHCP
	err    error
}

func (stub *observedDHCPReaderStub) QueryRecent(context.Context, ingest.RecentEventQuery) (ingest.RecentEventPage, error) {
	return ingest.RecentEventPage{}, nil
}

func (stub *observedDHCPReaderStub) QueryObservedDHCP(context.Context) (ingest.ObservedDHCP, error) {
	return stub.result, stub.err
}

func TestObservedDHCPEndpointRequiresTheQueryToken(t *testing.T) {
	server := testServer(t)
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	stub := &observedDHCPReaderStub{result: ingest.ObservedDHCP{Schema: ingest.ObservedDHCPSchema, GeneratedAt: at, Clients: []ingest.ObservedDHCPClient{
		{HardwareAddr: "0e:47:eb:9f:1b:6a", HostName: "iPad", RequestedAddr: "192.168.100.196", FirstSeen: at, LastSeen: at},
	}}}
	server.recentEvents = stub
	for _, token := range []string{"", testToken} {
		request := httptest.NewRequest(http.MethodGet, "/v1/observed-dhcp", nil)
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("observed DHCP without the query token returned %d", recorder.Code)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/observed-dhcp", nil)
	request.Header.Set("Authorization", "Bearer "+testQueryToken)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || !strings.Contains(recorder.Body.String(), `"host_name":"iPad"`) {
		t.Fatalf("observed DHCP returned %d: %s", recorder.Code, recorder.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/observed-dhcp?limit=1", nil)
	request.Header.Set("Authorization", "Bearer "+testQueryToken)
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("a parameter was accepted: %d", recorder.Code)
	}
	stub.err = errors.New("database is down")
	request = httptest.NewRequest(http.MethodGet, "/v1/observed-dhcp", nil)
	request.Header.Set("Authorization", "Bearer "+testQueryToken)
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable || strings.Contains(recorder.Body.String(), "database is down") {
		t.Fatalf("a storage failure returned %d: %s", recorder.Code, recorder.Body.String())
	}
}
