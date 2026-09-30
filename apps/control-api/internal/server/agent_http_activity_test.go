package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/apitoken"
	"shakerproxy.dev/shakerproxy/internal/ingest"
)

type agentHTTPActivityReaderStub struct {
	query ingest.HTTPActivityQuery
	page  ingest.HTTPActivityPage
	calls int
}

func (stub *agentHTTPActivityReaderStub) QueryRecent(context.Context, ingest.RecentEventQuery) (ingest.RecentEventPage, error) {
	return ingest.RecentEventPage{}, nil
}

func (stub *agentHTTPActivityReaderStub) QueryHTTPActivity(_ context.Context, query ingest.HTTPActivityQuery) (ingest.HTTPActivityPage, error) {
	stub.calls++
	stub.query = query
	return stub.page, nil
}

func TestAgentHTTPActivityRequiresTrafficReadAndReturnsBoundedMetadata(t *testing.T) {
	anchor := time.Date(2026, 9, 3, 20, 0, 0, 0, time.UTC)
	decrypted := true
	requestBytes, responseBytes := int64(12), int64(34)
	deviceID := "device-0123456789abcdef0123456789abcdef"
	stub := &agentHTTPActivityReaderStub{page: ingest.HTTPActivityPage{
		Schema: ingest.SchemaVersion, GeneratedAt: anchor.Add(time.Second), QueryAnchor: anchor,
		Events: []ingest.HTTPActivityEvent{{
			RecordID: strings.Repeat("a", 64), Source: ingest.SourceMitmproxy, Kind: "http_response",
			OccurredAt: anchor.Add(-time.Minute), ReceivedAt: anchor.Add(-30 * time.Second),
			FlowID: "flow-0123456789abcdef", DeviceID: deviceID,
			Method: "POST", Scheme: "https", Host: "api.example.test", Port: 443,
			Path: "/v1/orders", Status: 201, HTTPVersion: "HTTP/2.0",
			RequestBytes: &requestBytes, ResponseBytes: &responseBytes, Decrypted: &decrypted,
		}},
	}}
	tokenStore := &apitoken.Store{Path: filepath.Join(t.TempDir(), "tokens.json")}
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) {
		config.EventReader = stub
		config.APITokens = tokenStore
	})
	trafficToken, err := tokenStore.Create(apitoken.CreateRequest{Name: "local MCP", Creator: "admin", Scopes: []apitoken.Scope{apitoken.ScopeTrafficRead}, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	wrongToken, err := tokenStore.Create(apitoken.CreateRequest{Name: "device reader", Creator: "admin", Scopes: []apitoken.Scope{apitoken.ScopeDevicesRead}, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	target := "/api/v1/agent/http-activity?window=1h&limit=1&device_id=" + deviceID + "&host=API.Example.Test.&method=post"
	handler := server.AgentHTTPActivityHandler()

	unauthenticated := httptest.NewRequest(http.MethodGet, target, nil)
	unauthenticated.Host = "shakerproxy.test"
	unauthenticatedRecorder := httptest.NewRecorder()
	handler.ServeHTTP(unauthenticatedRecorder, unauthenticated)
	if unauthenticatedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated HTTP activity returned %d: %s", unauthenticatedRecorder.Code, unauthenticatedRecorder.Body.String())
	}

	wrongScope := tokenRequest(http.MethodGet, target, wrongToken.Secret)
	wrongRecorder := httptest.NewRecorder()
	handler.ServeHTTP(wrongRecorder, wrongScope)
	if wrongRecorder.Code != http.StatusForbidden || !strings.Contains(wrongRecorder.Body.String(), "insufficient_scope") {
		t.Fatalf("wrong-scope token returned %d: %s", wrongRecorder.Code, wrongRecorder.Body.String())
	}

	for _, credential := range []string{session, trafficToken.Secret} {
		request := tokenRequest(http.MethodGet, target, credential)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || !strings.Contains(recorder.Body.String(), `"path":"/v1/orders"`) || !strings.Contains(recorder.Body.String(), `"status":201`) {
			t.Fatalf("authorized HTTP activity returned %d headers=%v body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
		}
		for _, forbidden := range []string{"request_headers", "response_headers", "request_body", "response_body", "authorization", "cookie", "Bearer "} {
			if strings.Contains(strings.ToLower(recorder.Body.String()), strings.ToLower(forbidden)) {
				t.Fatalf("HTTP activity leaked %q: %s", forbidden, recorder.Body.String())
			}
		}
	}
	if stub.calls != 2 || stub.query.Limit != 1 || stub.query.WindowSeconds != 3600 || stub.query.DeviceID != deviceID || stub.query.Host != "api.example.test" || stub.query.Method != "POST" {
		t.Fatalf("unexpected reader calls=%d query=%#v", stub.calls, stub.query)
	}
}

func TestAgentHTTPActivityRejectsInvalidQueryBeforeReader(t *testing.T) {
	stub := &agentHTTPActivityReaderStub{}
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) { config.EventReader = stub })
	for _, target := range []string{
		"/api/v1/agent/http-activity?window=forever",
		"/api/v1/agent/http-activity?limit=101",
		"/api/v1/agent/http-activity?host=example.test:443",
		"/api/v1/agent/http-activity?method=GET%0AX",
		"/api/v1/agent/http-activity?limit=1&limit=2",
		"/api/v1/agent/http-activity?unknown=true",
	} {
		request := tokenRequest(http.MethodGet, target, session)
		recorder := httptest.NewRecorder()
		server.AgentHTTPActivityHandler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("invalid query %q returned %d: %s", target, recorder.Code, recorder.Body.String())
		}
	}
	if stub.calls != 0 {
		t.Fatalf("reader was called for invalid queries: %d", stub.calls)
	}
}
