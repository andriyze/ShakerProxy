package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/apitoken"
)

func TestAPITokensAreDisplayOnceScopedRestrictedAndRevocable(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "api-tokens.json")
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) {
		config.APITokens = &apitoken.Store{Path: tokenPath}
	})
	createBody := `{"name":"case robot","scopes":["cases:read"],"restrictions":{"case_ids":["case-0123456789abcdef0123456789abcdef"]},"expires_in_seconds":3600,"password":"` + activationTestPassword + `"}`
	created := authenticatedJSONRequest(http.MethodPost, "/api/v1/auth/tokens", createBody, session, "")
	created.Host = "shakerproxy.test"
	createdRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(createdRecorder, created)
	if createdRecorder.Code != http.StatusCreated || createdRecorder.Header().Get("Cache-Control") != "no-store" || createdRecorder.Header().Get("X-ShakerProxy-Secret-Handling") != "display-once" {
		t.Fatalf("create returned %d: %s", createdRecorder.Code, createdRecorder.Body.String())
	}
	var result apitoken.Created
	if err := json.Unmarshal(createdRecorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(result.Secret, "lgt_") {
		t.Fatalf("missing display-once secret: %#v", result)
	}
	persisted, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(persisted), result.Secret) {
		t.Fatal("clear-text API credential was persisted")
	}

	allowed := tokenRequest(http.MethodGet, "/api/v1/cases/case-0123456789abcdef0123456789abcdef", result.Secret)
	allowedRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(allowedRecorder, allowed)
	if allowedRecorder.Code != http.StatusServiceUnavailable || !strings.Contains(allowedRecorder.Body.String(), "cases_unavailable") {
		t.Fatalf("authorized restricted request did not reach handler: %d %s", allowedRecorder.Code, allowedRecorder.Body.String())
	}
	denied := tokenRequest(http.MethodGet, "/api/v1/cases/case-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", result.Secret)
	deniedRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(deniedRecorder, denied)
	if deniedRecorder.Code != http.StatusForbidden || !strings.Contains(deniedRecorder.Body.String(), "resource_restricted") {
		t.Fatalf("resource escape returned %d: %s", deniedRecorder.Code, deniedRecorder.Body.String())
	}
	wrongScope := tokenRequest(http.MethodGet, "/api/v1/system/status", result.Secret)
	wrongScopeRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(wrongScopeRecorder, wrongScope)
	if wrongScopeRecorder.Code != http.StatusForbidden || !strings.Contains(wrongScopeRecorder.Body.String(), "insufficient_scope") {
		t.Fatalf("scope escape returned %d: %s", wrongScopeRecorder.Code, wrongScopeRecorder.Body.String())
	}

	list := tokenRequest(http.MethodGet, "/api/v1/auth/tokens", session)
	listRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(listRecorder, list)
	if listRecorder.Code != http.StatusOK || strings.Contains(listRecorder.Body.String(), result.Secret) || strings.Contains(listRecorder.Body.String(), "token_sha256") {
		t.Fatalf("unsafe token listing returned %d: %s", listRecorder.Code, listRecorder.Body.String())
	}
	revoke := authenticatedJSONRequest(http.MethodDelete, "/api/v1/auth/tokens/"+result.Token.ID, `{"password":"`+activationTestPassword+`","reason":"credential rotation"}`, session, "")
	revoke.Host = "shakerproxy.test"
	revokeRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(revokeRecorder, revoke)
	if revokeRecorder.Code != http.StatusOK {
		t.Fatalf("revoke returned %d: %s", revokeRecorder.Code, revokeRecorder.Body.String())
	}
	revoked := tokenRequest(http.MethodGet, "/api/v1/cases/case-0123456789abcdef0123456789abcdef", result.Secret)
	revokedRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(revokedRecorder, revoked)
	if revokedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token returned %d: %s", revokedRecorder.Code, revokedRecorder.Body.String())
	}
}

func TestOpenMetricsRequiresMetricsTokenNotBrowserSession(t *testing.T) {
	tokenStore := &apitoken.Store{Path: filepath.Join(t.TempDir(), "tokens.json")}
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) { config.APITokens = tokenStore })
	created, err := tokenStore.Create(apitoken.CreateRequest{Name: "prometheus", Creator: "admin", Scopes: []apitoken.Scope{apitoken.ScopeMetricsRead}, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	browser := tokenRequest(http.MethodGet, "/api/v1/metrics", session)
	browserRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(browserRecorder, browser)
	if browserRecorder.Code != http.StatusForbidden || !strings.Contains(browserRecorder.Body.String(), "api_token_required") {
		t.Fatalf("browser session metrics returned %d: %s", browserRecorder.Code, browserRecorder.Body.String())
	}
	request := tokenRequest(http.MethodGet, "/api/v1/metrics", created.Secret)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.HasPrefix(recorder.Header().Get("Content-Type"), "application/openmetrics-text") || !strings.Contains(recorder.Body.String(), "shakerproxy_gateway_available 0") || !strings.HasSuffix(recorder.Body.String(), "# EOF\n") {
		t.Fatalf("metrics returned %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestAPITokenCreateRequiresFreshPasswordAndBoundedExpiry(t *testing.T) {
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) {
		config.APITokens = &apitoken.Store{Path: filepath.Join(t.TempDir(), "tokens.json")}
	})
	for _, body := range []string{
		`{"name":"automation","scopes":["system:read"],"expires_in_seconds":3600,"password":"wrong"}`,
		`{"name":"automation","scopes":["system:read"],"expires_in_seconds":9223372036854775807,"password":"` + activationTestPassword + `"}`,
	} {
		request := authenticatedJSONRequest(http.MethodPost, "/api/v1/auth/tokens", body, session, "")
		request.Host = "shakerproxy.test"
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code < 400 {
			t.Fatalf("unsafe token request returned %d: %s", recorder.Code, recorder.Body.String())
		}
	}
}

func tokenRequest(method, target, token string) *http.Request {
	request := httptest.NewRequest(method, target, nil)
	request.Host = "shakerproxy.test"
	request.Header.Set("Authorization", "Bearer "+token)
	return request
}
