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

func TestDNSVisibilitySwitchesReadAndChangeThePolicy(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	current := trafficpolicy.Document{Schema: 1, Policy: trafficpolicy.DefaultPolicy(), Digest: "default", AppliedAt: time.Now().UTC()}
	changed := current.Policy
	changed.Revision = 2
	changed.EncryptedDNS = changed.EncryptedDNS.WithSwitches(true, false)
	applied := trafficpolicy.Document{Schema: 1, Policy: changed, Digest: "applied", AppliedAt: time.Now().UTC(), Previous: &current.Policy}
	requests := startGatewaySequenceStub(t, socketPath, current, current, applied)
	server, session := configuredAPIServer(t, socketPath)

	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, authenticatedJSONRequest(http.MethodGet, "/api/v1/dns-visibility", "", session, ""))
	var view dnsVisibilityView
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &view) != nil {
		t.Fatalf("GET returned %d: %s", recorder.Code, recorder.Body.String())
	}
	if !view.ForcePlainDNS || !view.BlockEncryptedDNS || view.Mode != "ENFORCE_LOCAL" || len(view.BlockedResolvers) < 10 || view.BlockedAddresses < 40 {
		t.Fatalf("default view = %+v", view)
	}
	names := " " + strings.Join(view.BlockedNames, " ") + " "
	for _, want := range []string{" dns.google ", " cloudflare-dns.com ", " use-application-dns.net ", " mask.icloud.com "} {
		if !strings.Contains(names, want) {
			t.Fatalf("blocked names lack %q", want)
		}
	}
	if !strings.Contains(strings.Join(view.Notes, " "), "Android Private DNS") {
		t.Fatalf("notes lack the Android Private DNS warning: %v", view.Notes)
	}

	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, authenticatedJSONRequest(http.MethodPut, "/api/v1/dns-visibility", `{"block_encrypted_dns":false}`, session, ""))
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &view) != nil || view.BlockEncryptedDNS || !view.ForcePlainDNS || view.PolicyRevision != 2 {
		t.Fatalf("PUT returned %d: %s", recorder.Code, recorder.Body.String())
	}
	for _, want := range []string{"GetTrafficPolicy", "GetTrafficPolicy", "ApplyTrafficPolicy"} {
		rpc := <-requests
		if rpc.Method != want {
			t.Fatalf("got RPC %q, want %q", rpc.Method, want)
		}
		if want == "ApplyTrafficPolicy" {
			var params gatewayprotocol.ApplyTrafficPolicyParams
			if err := json.Unmarshal(rpc.Params, &params); err != nil || params.ExpectedRevision != 1 || params.Policy.Revision != 2 || params.Policy.EncryptedDNS.BlockEncryptedDNS() || !params.Policy.EncryptedDNS.ForcePlainDNS() {
				t.Fatalf("applied %s err=%v", rpc.Params, err)
			}
		}
	}

	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, authenticatedJSONRequest(http.MethodPut, "/api/v1/dns-visibility", `{}`, session, ""))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("an empty change returned %d", recorder.Code)
	}
}
