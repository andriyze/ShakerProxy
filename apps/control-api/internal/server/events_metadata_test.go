package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestEventQueryMetadataIsAuthenticatedBoundedAndNoStore(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	request := httptest.NewRequest(http.MethodGet, "/api/v1/events/query-metadata", nil)
	request.Host = "shakerproxy.test"
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated query metadata returned %d", recorder.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/api/v1/events/query-metadata", nil)
	request.Host = "shakerproxy.test"
	request.Header.Set("Authorization", "Bearer "+session)
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || len(body) > 32<<10 || !strings.Contains(body, `"name":"time"`) || !strings.Contains(body, `"time:last_15m"`) || strings.Contains(body, "payload") {
		t.Fatalf("unexpected query metadata response %d: %s", recorder.Code, body)
	}
	request = httptest.NewRequest(http.MethodGet, "/api/v1/events/query-metadata?unknown=true", nil)
	request.Host = "shakerproxy.test"
	request.Header.Set("Authorization", "Bearer "+session)
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("parameterized query metadata returned %d", recorder.Code)
	}
}
