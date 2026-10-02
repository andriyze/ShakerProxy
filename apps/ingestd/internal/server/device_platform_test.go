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

type devicePlatformReaderStub struct {
	result ingest.DevicePlatformHints
	err    error
}

func (stub *devicePlatformReaderStub) QueryRecent(context.Context, ingest.RecentEventQuery) (ingest.RecentEventPage, error) {
	return ingest.RecentEventPage{}, nil
}

func (stub *devicePlatformReaderStub) QueryDevicePlatformHints(context.Context) (ingest.DevicePlatformHints, error) {
	return stub.result, stub.err
}

func TestDevicePlatformHintsEndpointRequiresTheQueryToken(t *testing.T) {
	server := testServer(t)
	at := time.Date(2026, 10, 1, 21, 0, 0, 0, time.UTC)
	stub := &devicePlatformReaderStub{result: ingest.DevicePlatformHints{Schema: ingest.DevicePlatformHintsSchema, GeneratedAt: at, Hints: []ingest.DevicePlatformHint{
		{DeviceID: "device-0123456789abcdef0123456789abcdef", Platform: "GrapheneOS phone", Domain: "connectivitycheck.grapheneos.network", LastSeen: at},
	}}}
	server.recentEvents = stub
	for _, token := range []string{"", testToken} {
		request := httptest.NewRequest(http.MethodGet, "/v1/device-platform-hints", nil)
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("device platform hints without the query token returned %d", recorder.Code)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/device-platform-hints", nil)
	request.Header.Set("Authorization", "Bearer "+testQueryToken)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || !strings.Contains(recorder.Body.String(), `"platform":"GrapheneOS phone"`) {
		t.Fatalf("device platform hints returned %d: %s", recorder.Code, recorder.Body.String())
	}
	stub.err = errors.New("database is down")
	request = httptest.NewRequest(http.MethodGet, "/v1/device-platform-hints", nil)
	request.Header.Set("Authorization", "Bearer "+testQueryToken)
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable || strings.Contains(recorder.Body.String(), "database is down") {
		t.Fatalf("a storage failure returned %d: %s", recorder.Code, recorder.Body.String())
	}
}
