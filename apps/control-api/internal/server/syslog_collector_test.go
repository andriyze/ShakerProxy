package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// The dashboard, CLI and MCP read the receiver counts directly under
// "status"; the collector's own file nests them under "stats", which made
// the dashboard tile throw and the CLI and MCP report zero. A status the
// service stopped refreshing is not shown as listening.
func TestSyslogCollectorStatusIsFlatAndGoesStale(t *testing.T) {
	dir := t.TempDir()
	configPath, statusPath := filepath.Join(dir, "config.json"), filepath.Join(dir, "status.json")
	enabled := syslogcollector.DefaultFileConfig()
	enabled.Enabled, enabled.AllowedSources = true, []string{"192.168.10.1"}
	if err := syslogcollector.SaveConfig(configPath, enabled); err != nil {
		t.Fatal(err)
	}
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) {
		config.SyslogCollectorConfigPath, config.SyslogCollectorStatusPath = configPath, statusPath
	})
	read := func() map[string]any {
		request := tokenRequest(http.MethodGet, "/api/v1/integrations/syslog-collector", session)
		request.Host = "shakerproxy.test"
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		var view map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &view); err != nil {
			t.Fatalf("%d: %s", recorder.Code, recorder.Body.String())
		}
		status, _ := view["status"].(map[string]any)
		return status
	}
	if err := syslogcollector.WriteStatusFile(statusPath, syslogcollector.Status{Enabled: true, Listening: true, Stats: syslogcollector.Stats{Received: 10, Parsed: 8, Delivered: 8}}); err != nil {
		t.Fatal(err)
	}
	if status := read(); status["received"] != float64(10) || status["delivered"] != float64(8) || status["listening"] != true {
		t.Fatalf("status = %v", status)
	}
	if err := syslogcollector.WriteStatusFile(statusPath, syslogcollector.Status{GeneratedAt: time.Now().Add(-10 * time.Minute), Enabled: true, Listening: true}); err != nil {
		t.Fatal(err)
	}
	if status := read(); status["listening"] != false || !strings.Contains(status["error"].(string), "has not reported") {
		t.Fatalf("stale status = %v", status)
	}
}
