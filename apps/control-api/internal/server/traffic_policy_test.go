package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

func TestTrafficPolicyAPIUsesAuthenticatedBoundedGatewayRPC(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	policy := trafficpolicy.DefaultPolicy()
	document := trafficpolicy.Document{Schema: 1, Policy: policy, Digest: "initial", AppliedAt: time.Now().UTC()}
	catalog := trafficpolicy.Catalog{Schema: 1, Revision: "test", Resolvers: []trafficpolicy.Resolver{}}
	policy.Revision = 2
	policy.Name = "Local DNS enforcement"
	policy.EncryptedDNS.Mode = trafficpolicy.EncryptedDNSEnforceLocal
	policy.EncryptedDNS.RedirectPlainDNS = true
	policy.EncryptedDNS.UpstreamServers = []string{"1.1.1.1:53"}
	preview := gatewayprotocol.TrafficPolicyPreview{Policy: policy, Digest: "preview", ChangedObjects: []string{"local DNS forwarder runtime policy"}}
	applied := trafficpolicy.Document{Schema: 1, Policy: policy, Digest: "applied", AppliedAt: time.Now().UTC(), Previous: &document.Policy}
	rolledBack := document
	rolledBack.Policy.Revision = 3
	rolledBack.Digest = "rolled-back"
	// The apply handler reads the current policy to keep device controls
	// that older clients omit.
	requests := startGatewaySequenceStub(t, socketPath, document, catalog, preview, document, applied, rolledBack)
	server, session := configuredAPIServer(t, socketPath)

	unauthenticated := httptest.NewRequest(http.MethodGet, "/api/v1/traffic-policy", nil)
	unauthenticated.Host = "shakerproxy.test"
	unauthenticatedRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthenticatedRecorder, unauthenticated)
	if unauthenticatedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated traffic policy returned %d", unauthenticatedRecorder.Code)
	}

	for _, request := range []*http.Request{
		authenticatedJSONRequest(http.MethodGet, "/api/v1/traffic-policy", "", session, ""),
		authenticatedJSONRequest(http.MethodGet, "/api/v1/traffic-policy/catalog", "", session, ""),
		authenticatedJSONRequest(http.MethodPost, "/api/v1/traffic-policy/preview", mustTrafficJSON(t, policy), session, ""),
		authenticatedJSONRequest(http.MethodPut, "/api/v1/traffic-policy", mustTrafficJSON(t, applyTrafficPolicyRequest{ExpectedRevision: 1, Policy: policy, Password: activationTestPassword}), session, ""),
		authenticatedJSONRequest(http.MethodPost, "/api/v1/traffic-policy/rollback", mustTrafficJSON(t, rollbackTrafficPolicyRequest{ExpectedRevision: 2, Password: activationTestPassword}), session, ""),
	} {
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("unexpected response for %s %s: %d %s", request.Method, request.URL.Path, recorder.Code, recorder.Body.String())
		}
	}

	wantMethods := []string{"GetTrafficPolicy", "GetTrafficResolverCatalog", "PreviewTrafficPolicy", "GetTrafficPolicy", "ApplyTrafficPolicy", "RollbackTrafficPolicy"}
	for _, want := range wantMethods {
		rpc := <-requests
		if rpc.Method != want {
			t.Fatalf("got RPC %q, want %q", rpc.Method, want)
		}
		if strings.Contains(string(rpc.Params), activationTestPassword) {
			t.Fatalf("administrator password leaked to privileged RPC: %s", rpc.Params)
		}
	}
}

func TestTrafficPolicyMutationRejectsFailedReauthenticationBeforeRPC(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	policy := trafficpolicy.DefaultPolicy()
	policy.Revision = 2
	request := authenticatedJSONRequest(http.MethodPut, "/api/v1/traffic-policy", mustTrafficJSON(t, applyTrafficPolicyRequest{ExpectedRevision: 1, Policy: policy, Password: "wrong"}), session, "")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected response %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestTrafficPolicyAPIRejectsUnknownFieldsAndQueries(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/traffic-policy/preview", `{"schema":1,"unexpected":true}`, session, "")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown field returned %d: %s", recorder.Code, recorder.Body.String())
	}

	request = authenticatedJSONRequest(http.MethodGet, "/api/v1/traffic-policy?revision=1", "", session, "")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("query returned %d: %s", recorder.Code, recorder.Body.String())
	}
}

func mustTrafficJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
