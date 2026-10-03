package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"shakerproxy.dev/shakerproxy/internal/syslogcollector"
)

func TestSyslogCollectorRequiresReauthAndEnforcesAllowlist(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "syslog-collector.json")
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) {
		config.SyslogCollectorConfigPath = configPath
		config.SyslogCollectorStatusPath = filepath.Join(t.TempDir(), "status.json")
	})
	serve := func(request *http.Request) *httptest.ResponseRecorder {
		request.Host = "shakerproxy.test"
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		return recorder
	}

	// Starts off, revision 0.
	get := serve(tokenRequest(http.MethodGet, "/api/v1/integrations/syslog-collector", session))
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), `"enabled":false`) || !strings.Contains(get.Body.String(), `"revision":0`) {
		t.Fatalf("initial GET returned %d: %s", get.Code, get.Body.String())
	}

	// Wrong password is rejected.
	bad := serve(authenticatedJSONRequest(http.MethodPut, "/api/v1/integrations/syslog-collector", `{"enabled":true,"tcp":true,"allowed_sources":["192.168.10.1"],"password":"wrong"}`, session, ""))
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password returned %d", bad.Code)
	}

	// Enabling with no allowed source is rejected by validation.
	empty := serve(authenticatedJSONRequest(http.MethodPut, "/api/v1/integrations/syslog-collector", `{"enabled":true,"tcp":true,"allowed_sources":[],"password":"`+activationTestPassword+`"}`, session, ""))
	if empty.Code != http.StatusBadRequest {
		t.Fatalf("enable with no source returned %d: %s", empty.Code, empty.Body.String())
	}

	// A valid enable with the router's address.
	ok := serve(authenticatedJSONRequest(http.MethodPut, "/api/v1/integrations/syslog-collector", `{"enabled":true,"tcp":true,"udp":false,"bind_address":":1514","allowed_sources":["192.168.10.1","192.168.10.1"],"expected_revision":0,"password":"`+activationTestPassword+`"}`, session, ""))
	if ok.Code != http.StatusOK || !strings.Contains(ok.Body.String(), `"enabled":true`) || !strings.Contains(ok.Body.String(), `"revision":1`) {
		t.Fatalf("valid enable returned %d: %s", ok.Code, ok.Body.String())
	}
	// It persisted and deduplicated the allowlist.
	stored, err := syslogcollector.LoadConfig(configPath)
	if err != nil || !stored.Enabled || len(stored.AllowedSources) != 1 || stored.AllowedSources[0] != "192.168.10.1" {
		t.Fatalf("stored = %+v err=%v", stored, err)
	}

	// A stale revision conflicts.
	stale := serve(authenticatedJSONRequest(http.MethodPut, "/api/v1/integrations/syslog-collector", `{"enabled":false,"tcp":true,"allowed_sources":["192.168.10.1"],"expected_revision":0,"password":"`+activationTestPassword+`"}`, session, ""))
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale revision returned %d: %s", stale.Code, stale.Body.String())
	}
}

func TestSyslogCollectorUnavailableWhenUnconfigured(t *testing.T) {
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) {
		config.SyslogCollectorConfigPath = ""
	})
	request := tokenRequest(http.MethodGet, "/api/v1/integrations/syslog-collector", session)
	request.Host = "shakerproxy.test"
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured collector returned %d", recorder.Code)
	}
}
