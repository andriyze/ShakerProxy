package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"

	"shakerproxy.dev/shakerproxy/internal/apitoken"
)

func TestAgentInvestigatorConnectionMintsOnlyFixedReadScopes(t *testing.T) {
	tokenStore := &apitoken.Store{Path: filepath.Join(t.TempDir(), "tokens.json")}
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) {
		config.APITokens = tokenStore
	})
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/agent-connections/investigator", `{"name":"Codex investigator","password":"`+activationTestPassword+`"}`, session, "")
	request.Host = "shakerproxy.test"
	recorder := httptest.NewRecorder()
	server.AgentConnectionHandler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated || recorder.Header().Get("X-ShakerProxy-Secret-Handling") != "display-once" || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("investigator connection returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Profile     string                `json:"profile"`
		Token       apitoken.PublicRecord `json:"token"`
		Secret      string                `json:"secret"`
		FixedScopes []apitoken.Scope      `json:"fixed_scopes"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	want := []apitoken.Scope{apitoken.ScopeSystemRead, apitoken.ScopeDevicesRead, apitoken.ScopeTrafficRead, apitoken.ScopeCapturesRead, apitoken.ScopeCasesRead}
	for _, scope := range want {
		if slices.Contains(apitoken.SensitiveScopes(), scope) {
			t.Fatalf("the investigator profile carries the sensitive scope %s", scope)
		}
	}
	// The token store canonicalizes scope order, so compare the minted token's scopes as a set.
	if response.Profile != "INVESTIGATOR" || !slices.Equal(slices.Sorted(slices.Values(response.Token.Scopes)), slices.Sorted(slices.Values(want))) || !slices.Equal(response.FixedScopes, want) {
		t.Fatalf("unexpected investigator profile: %#v", response)
	}
	if response.Secret == "" {
		t.Fatal("display-once investigator secret is missing")
	}
	read := tokenRequest(http.MethodGet, "/api/v1/system/status", response.Secret)
	readRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(readRecorder, read)
	if readRecorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("system read did not reach handler: %d %s", readRecorder.Code, readRecorder.Body.String())
	}
	write := tokenRequest(http.MethodPost, "/api/v1/captures", response.Secret)
	writeRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(writeRecorder, write)
	if writeRecorder.Code != http.StatusForbidden {
		t.Fatalf("investigator token unexpectedly reached capture mutation: %d %s", writeRecorder.Code, writeRecorder.Body.String())
	}
}

func TestAgentInvestigatorConnectionRequiresFreshAdminPassword(t *testing.T) {
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) {
		config.APITokens = &apitoken.Store{Path: filepath.Join(t.TempDir(), "tokens.json")}
	})
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/agent-connections/investigator", `{"password":"wrong"}`, session, "")
	request.Host = "shakerproxy.test"
	recorder := httptest.NewRecorder()
	server.AgentConnectionHandler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password returned %d: %s", recorder.Code, recorder.Body.String())
	}
}
