package agentapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testToken = "lgt_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestNewClientRejectsRemoteCleartextAndUnsafeToken(t *testing.T) {
	if _, err := NewClient("http://example.com", testToken, nil); err == nil {
		t.Fatal("remote cleartext agent API was accepted")
	}
	if _, err := NewClient("https://example.com", "secret", nil); err == nil {
		t.Fatal("invalid agent API token was accepted")
	}
	if _, err := NewClient("https://user@example.com", testToken, nil); err == nil {
		t.Fatal("userinfo-bearing agent API URL was accepted")
	}
}

func TestTrafficSearchIsBoundedAndCarriesBearerToken(t *testing.T) {
	recordID := strings.Repeat("a", 64)
	now := time.Now().UTC()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/events" || r.Header.Get("Authorization") != "Bearer "+testToken {
			t.Errorf("unexpected request %s auth=%q", r.URL.String(), r.Header.Get("Authorization"))
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("limit") != "25" || r.URL.Query().Get("q") != "time:last_15m AND service:tls" {
			t.Errorf("unexpected query %s", r.URL.RawQuery)
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"schema":       1,
			"generated_at": now,
			"events": []map[string]any{{
				"record_id":      recordID,
				"source":         "MITMPROXY",
				"kind":           "tls_intercepted",
				"occurred_at":    now,
				"received_at":    now,
				"source_version": "test",
				"parser_version": "test",
				"confidence":     100,
			}},
		})
	}))
	defer server.Close()

	client, err := NewClient(server.URL, testToken, nil)
	if err != nil {
		t.Fatalf("create agent API client: %v", err)
	}
	page, err := client.TrafficSearch(context.Background(), TrafficSearchRequest{Query: "time:last_15m AND service:tls", Limit: 25})
	if err != nil || len(page.Events) != 1 || page.Events[0].RecordID != recordID {
		t.Fatalf("unexpected traffic search result: %#v err=%v", page, err)
	}
	if _, err := client.TrafficSearch(context.Background(), TrafficSearchRequest{Limit: maxAgentTrafficLimit + 1}); err == nil {
		t.Fatal("unbounded agent traffic search was accepted")
	}
}

func TestEventMetadataFailsClosedUnlessServerMarksProjection(t *testing.T) {
	recordID := strings.Repeat("b", 64)
	var marked atomic.Bool
	payload := map[string]any{"http_method": "GET", "http_path": "/safe"}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if marked.Load() {
			w.Header().Set("X-ShakerProxy-Event-Detail", "metadata-only")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"schema":        1,
			"event":         map[string]any{"record_id": recordID},
			"payload":       payload,
			"payload_bytes": len(payloadBytes),
		})
	}))
	defer server.Close()

	client, err := NewClient(server.URL, testToken, nil)
	if err != nil {
		t.Fatalf("create agent API client: %v", err)
	}
	if _, err := client.EventMetadata(context.Background(), recordID); err == nil {
		t.Fatal("unmarked event detail was accepted by agent API")
	}
	marked.Store(true)
	detail, err := client.EventMetadata(context.Background(), recordID)
	if err != nil || detail.Event.RecordID != recordID {
		t.Fatalf("metadata-only event detail was rejected: %#v err=%v", detail, err)
	}
}

func TestAgentClientDoesNotFollowRedirects(t *testing.T) {
	var redirected atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Store(true)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{})
	}))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, testToken, nil)
	if err != nil {
		t.Fatalf("create agent API client: %v", err)
	}
	_, err = client.TrafficSearch(context.Background(), TrafficSearchRequest{Limit: 1})
	if err == nil {
		t.Fatal("redirecting agent API response was accepted")
	}
	if redirected.Load() {
		t.Fatal("agent API followed a redirect and risked bearer-token disclosure")
	}
}
