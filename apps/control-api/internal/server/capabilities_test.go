package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"shakerproxy.dev/shakerproxy/internal/capabilityregistry"
	"shakerproxy.dev/shakerproxy/internal/recoveryobjectives"
)

func TestCapabilityRegistryIsAuthenticatedBoundedAndNoStore(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate capability API test")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(current), "..", "..", "..", ".."))
	bundle, err := capabilityregistry.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) {
		config.Capabilities = bundle
	})
	request := httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil)
	request.Host = "shakerproxy.test"
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated capability registry returned %d", recorder.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil)
	request.Host = "shakerproxy.test"
	request.Header.Set("Authorization", "Bearer "+session)
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || len(body) > 128<<10 || !strings.Contains(body, `"id":"tls_interception"`) || !strings.Contains(body, `"status":"experimental"`) || !strings.Contains(body, `"support_matrix"`) {
		t.Fatalf("unexpected capability registry response %d: %s", recorder.Code, body)
	}
}

func TestRecoveryObjectivesAreAuthenticatedHonestAndNoStore(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate recovery objective API test")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(current), "..", "..", "..", ".."))
	registry, err := recoveryobjectives.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) {
		config.RecoveryObjectives = registry
	})
	request := httptest.NewRequest(http.MethodGet, "/api/v1/recovery-objectives", nil)
	request.Host = "shakerproxy.test"
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated recovery registry returned %d", recorder.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/api/v1/recovery-objectives", nil)
	request.Host = "shakerproxy.test"
	request.Header.Set("Authorization", "Bearer "+session)
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || len(body) > 64<<10 || !strings.Contains(body, `"status":"verified"`) || !strings.Contains(body, `"status":"not-offered"`) || !strings.Contains(body, `"rto_seconds":150`) {
		t.Fatalf("unexpected recovery objective response %d: %s", recorder.Code, body)
	}
}
