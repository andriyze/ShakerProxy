package agentapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

func TestAgentHTTPActivityClientCanonicalizesFiltersAndReadsMetadata(t *testing.T) {
	anchor := time.Date(2026, 9, 3, 20, 0, 0, 0, time.UTC)
	decrypted := true
	requestBytes, responseBytes := int64(7), int64(11)
	deviceID := "device-0123456789abcdef0123456789abcdef"
	page := ingest.HTTPActivityPage{
		Schema: ingest.SchemaVersion, GeneratedAt: anchor.Add(time.Second), QueryAnchor: anchor,
		Events: []ingest.HTTPActivityEvent{{
			RecordID: strings.Repeat("a", 64), Source: ingest.SourceMitmproxy, Kind: "http_response",
			OccurredAt: anchor.Add(-time.Minute), ReceivedAt: anchor.Add(-30 * time.Second),
			FlowID: "flow-0123456789abcdef", DeviceID: deviceID,
			Method: "POST", Scheme: "https", Host: "api.example.test", Port: 443,
			Path: "/v1/orders", Status: 201, HTTPVersion: "HTTP/2.0",
			RequestBytes: &requestBytes, ResponseBytes: &responseBytes, Decrypted: &decrypted,
		}},
	}
	token := "lgt_" + strings.Repeat("a", 40)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/http-activity" || r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("Accept") != "application/json" {
			t.Fatalf("unexpected agent HTTP activity request: path=%s headers=%v", r.URL.Path, r.Header)
		}
		values := r.URL.Query()
		if values.Get("window") != "1h" || values.Get("limit") != "1" || values.Get("device_id") != deviceID || values.Get("host") != "api.example.test" || values.Get("method") != "POST" {
			t.Fatalf("unexpected canonical agent query: %v", values)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(page)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.HTTPActivity(context.Background(), HTTPActivityRequest{
		Window: "1H", DeviceID: deviceID, Host: "API.Example.Test.", Method: "post", Limit: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 1 || result.Events[0].Host != "api.example.test" || result.Events[0].Path != "/v1/orders" || result.Events[0].ResponseBytes == nil || *result.Events[0].ResponseBytes != 11 {
		t.Fatalf("unexpected agent HTTP activity page: %#v", result)
	}
}

func TestAgentHTTPActivityClientRejectsPlaintextOrInvalidArguments(t *testing.T) {
	token := "lgt_" + strings.Repeat("a", 40)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"schema":1,"generated_at":"2026-09-03T20:00:01Z","query_anchor":"2026-09-03T20:00:00Z","events":[],"response_body":{"preview":"secret"}}`))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []HTTPActivityRequest{
		{Window: "forever"},
		{Limit: 101},
		{DeviceID: "192.0.2.1"},
		{Host: "example.test:443"},
		{Method: "GET\nX"},
		{Cursor: strings.Repeat("x", 257)},
	} {
		if _, err := client.HTTPActivity(context.Background(), request); err == nil {
			t.Fatalf("invalid HTTP activity request was accepted: %#v", request)
		}
	}
	if calls != 0 {
		t.Fatalf("invalid arguments reached the server %d times", calls)
	}
	if _, err := client.HTTPActivity(context.Background(), HTTPActivityRequest{Limit: 1}); err == nil {
		t.Fatal("plaintext-bearing HTTP activity response was accepted")
	}
	if calls != 1 {
		t.Fatalf("expected one response validation call, got %d", calls)
	}
}
