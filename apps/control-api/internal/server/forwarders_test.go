package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"shakerproxy.dev/shakerproxy/internal/forwarder"
)

func TestForwarderAPIRequiresReauthenticationAndKeepsSecretsDisplayOnce(t *testing.T) {
	manager := &forwarder.Manager{Root: t.TempDir()}
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) { config.Forwarders = manager })
	bad := authenticatedJSONRequest(http.MethodPost, "/api/v1/integrations/forwarders", `{"name":"SOC","kind":"WEBHOOK","destination":"https://hooks.example.com/events","password":"wrong"}`, session, "")
	bad.Host = "shakerproxy.test"
	badRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(badRecorder, bad)
	if badRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("create without fresh password returned %d", badRecorder.Code)
	}
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/integrations/forwarders", `{"name":"SOC","kind":"WEBHOOK","destination":"https://hooks.example.com/events","classes":["ALERT"],"password":"`+activationTestPassword+`"}`, session, "")
	request.Host = "shakerproxy.test"
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated || recorder.Header().Get("X-ShakerProxy-Secret-Handling") != "display-once" {
		t.Fatalf("create returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var created forwarder.Created
	if err := json.Unmarshal(recorder.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Integration.Enabled || len(created.HMACSecret) < 40 {
		t.Fatalf("unexpected creation result: %#v", created)
	}
	list := tokenRequest(http.MethodGet, "/api/v1/integrations/forwarders", session)
	listRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(listRecorder, list)
	if listRecorder.Code != http.StatusOK || strings.Contains(listRecorder.Body.String(), created.HMACSecret) || strings.Contains(listRecorder.Body.String(), "hmac_secret") || !strings.Contains(listRecorder.Body.String(), "NO_EVENT_BODIES") {
		t.Fatalf("unsafe status returned %d: %s", listRecorder.Code, listRecorder.Body.String())
	}
	enable := authenticatedJSONRequest(http.MethodPut, "/api/v1/integrations/forwarders/"+created.Integration.ID+"/enabled", `{"expected_revision":1,"enabled":true,"reason":"send alerts to authorized SOC","password":"`+activationTestPassword+`"}`, session, "")
	enable.Host = "shakerproxy.test"
	enableRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(enableRecorder, enable)
	if enableRecorder.Code != http.StatusOK || !strings.Contains(enableRecorder.Body.String(), `"enabled":true`) {
		t.Fatalf("enable returned %d: %s", enableRecorder.Code, enableRecorder.Body.String())
	}
	stale := authenticatedJSONRequest(http.MethodPut, "/api/v1/integrations/forwarders/"+created.Integration.ID+"/enabled", `{"expected_revision":1,"enabled":false,"reason":"stale browser action","password":"`+activationTestPassword+`"}`, session, "")
	stale.Host = "shakerproxy.test"
	staleRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(staleRecorder, stale)
	if staleRecorder.Code != http.StatusConflict {
		t.Fatalf("stale activation returned %d: %s", staleRecorder.Code, staleRecorder.Body.String())
	}
}
