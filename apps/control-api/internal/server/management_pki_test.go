package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"shakerproxy.dev/shakerproxy/internal/managementpki"
)

func TestManagementPKIEndpointsAreAuthenticatedPurposeBoundAndNoStore(t *testing.T) {
	root := t.TempDir()
	status, err := managementpki.Ensure(managementpki.Options{EtcRoot: filepath.Join(root, "etc"), DataRoot: filepath.Join(root, "data"), EdgeGID: -1, Testing: true})
	if err != nil {
		t.Fatal(err)
	}
	server, session := configuredAPIServerWithConfig(t, filepath.Join(root, "absent.sock"), func(config *Config) {
		config.ManagementCACertPath = filepath.Join(root, "data", "public", "management-ca.crt")
		config.ManagementPKIStatusPath = filepath.Join(root, "data", "public", "management-pki.json")
	})
	for _, path := range []string{"/api/v1/system/management-pki", "/api/v1/system/management-ca.pem"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Host = "shakerproxy.test"
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("%s unauthenticated response %d", path, recorder.Code)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/system/management-pki", nil)
	request.Host = "shakerproxy.test"
	request.Header.Set("Authorization", "Bearer "+session)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || !strings.Contains(recorder.Body.String(), status.SHA256Fingerprint) || !strings.Contains(recorder.Body.String(), `"authority":"management-only"`) {
		t.Fatalf("unexpected status response %d %s", recorder.Code, recorder.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/api/v1/system/management-ca.pem", nil)
	request.Host = "shakerproxy.test"
	request.Header.Set("Authorization", "Bearer "+session)
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "application/x-pem-file" || recorder.Header().Get("X-ShakerProxy-Certificate-Purpose") != managementpki.Purpose || !strings.Contains(recorder.Header().Get("Content-Disposition"), "shakerproxy-management-ca.pem") || !strings.Contains(recorder.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatalf("unexpected download response %d %#v", recorder.Code, recorder.Header())
	}
}
