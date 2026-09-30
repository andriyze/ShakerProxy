package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"shakerproxy.dev/shakerproxy/internal/interceptionpki"
)

func TestInterceptionCAPublicAPIIsAuthenticatedAndNeverExportsKey(t *testing.T) {
	publicRoot := filepath.Join(t.TempDir(), "public")
	if _, err := interceptionpki.Ensure(interceptionpki.Options{
		PrivateRoot: filepath.Join(t.TempDir(), "private"),
		PublicRoot:  publicRoot,
		KeyBits:     2048,
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SHAKERPROXY_PUBLIC_ROOT", publicRoot)
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "unused.sock"))

	unauthenticated := httptest.NewRecorder()
	unauthenticatedRequest := httptest.NewRequest(http.MethodGet, "/api/v1/interception-ca", nil)
	unauthenticatedRequest.Host = "shakerproxy.test"
	server.Handler().ServeHTTP(unauthenticated, unauthenticatedRequest)
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status returned %d", unauthenticated.Code)
	}

	statusRequest := authenticatedJSONRequest(http.MethodGet, "/api/v1/interception-ca", "", session, "")
	status := httptest.NewRecorder()
	server.Handler().ServeHTTP(status, statusRequest)
	if status.Code != http.StatusOK || bytes.Contains(status.Body.Bytes(), []byte("PRIVATE KEY")) || !bytes.Contains(status.Body.Bytes(), []byte(`"private_key_downloadable":false`)) {
		t.Fatalf("unexpected interception CA status %d: %s", status.Code, status.Body.String())
	}

	downloadRequest := authenticatedJSONRequest(http.MethodGet, "/api/v1/interception-ca/download?format=pem", "", session, "")
	download := httptest.NewRecorder()
	server.Handler().ServeHTTP(download, downloadRequest)
	if download.Code != http.StatusOK || download.Header().Get("Cache-Control") != "private, no-store" || !bytes.Contains(download.Body.Bytes(), []byte("BEGIN CERTIFICATE")) || bytes.Contains(download.Body.Bytes(), []byte("PRIVATE KEY")) {
		t.Fatalf("unexpected interception CA download %d: %s", download.Code, download.Body.String())
	}
}
