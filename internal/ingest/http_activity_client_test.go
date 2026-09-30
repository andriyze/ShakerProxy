package ingest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPActivityClientSendsScopedCanonicalQueryAndValidatesPage(t *testing.T) {
	anchor := time.Date(2026, 9, 3, 20, 0, 0, 0, time.UTC)
	decrypted := true
	requestBytes, responseBytes := int64(11), int64(22)
	query := HTTPActivityQuery{
		Limit: 2, WindowSeconds: 900,
		DeviceID: "device-0123456789abcdef0123456789abcdef",
		Host:     "api.example.test", Method: "POST",
	}
	page := HTTPActivityPage{
		Schema: SchemaVersion, GeneratedAt: anchor.Add(time.Second), QueryAnchor: anchor,
		Events: []HTTPActivityEvent{{
			RecordID: strings.Repeat("a", 64), Source: SourceMitmproxy, Kind: "http_response",
			OccurredAt: anchor.Add(-time.Minute), ReceivedAt: anchor.Add(-30 * time.Second),
			FlowID: "flow-0123456789abcdef", DeviceID: query.DeviceID,
			Method: "POST", Scheme: "https", Host: query.Host, Port: 443, Path: "/v1/orders",
			Status: 201, HTTPVersion: "HTTP/2.0", RequestBytes: &requestBytes,
			ResponseBytes: &responseBytes, Decrypted: &decrypted,
		}},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/http-activity" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("t", 32) || r.Header.Get("Accept") != "application/json" {
			t.Fatalf("unexpected HTTP activity request: method=%s path=%s headers=%v", r.Method, r.URL.Path, r.Header)
		}
		values := r.URL.Query()
		if values.Get("limit") != "2" || values.Get("window_seconds") != "900" || values.Get("device_id") != query.DeviceID || values.Get("host") != query.Host || values.Get("method") != query.Method || values.Get("cursor") != "" {
			t.Fatalf("unexpected HTTP activity query: %v", values)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(page)
	}))
	defer server.Close()
	client, err := NewQueryClient(server.URL, []byte(strings.Repeat("t", 32)), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.QueryHTTPActivity(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 1 || result.Events[0].Path != "/v1/orders" || result.Events[0].Status != 201 || result.Events[0].ResponseBytes == nil || *result.Events[0].ResponseBytes != 22 {
		t.Fatalf("unexpected HTTP activity response: %#v", result)
	}
}

func TestHTTPActivityClientRejectsUnknownOrPlaintextFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"schema":1,"generated_at":"2026-09-03T20:00:01Z","query_anchor":"2026-09-03T20:00:00Z","events":[],"request_body":{"preview":"secret"}}`))
	}))
	defer server.Close()
	client, err := NewQueryClient(server.URL, []byte(strings.Repeat("t", 32)), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.QueryHTTPActivity(context.Background(), HTTPActivityQuery{Limit: 1, WindowSeconds: 900})
	if err == nil {
		t.Fatal("HTTP activity client accepted an unknown plaintext-bearing response field")
	}
}
