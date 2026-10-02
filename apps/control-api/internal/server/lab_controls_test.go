package server

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/interceptionpki"
	deviceinventory "shakerproxy.dev/shakerproxy/internal/inventory"
	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

type labGatewayStub struct {
	mu       sync.Mutex
	requests []gatewayprotocol.Request
}

func (s *labGatewayStub) methods() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]string, 0, len(s.requests))
	for _, request := range s.requests {
		result = append(result, request.Method)
	}
	return result
}

func (s *labGatewayStub) last(method string) gatewayprotocol.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	for index := len(s.requests) - 1; index >= 0; index-- {
		if s.requests[index].Method == method {
			return s.requests[index]
		}
	}
	return gatewayprotocol.Request{}
}

// startLabGatewayStub answers every privileged RPC through handle.
func startLabGatewayStub(t *testing.T, socketPath string, handle func(gatewayprotocol.Request) (any, *gatewayprotocol.RPCError)) *labGatewayStub {
	t.Helper()
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	stub := &labGatewayStub{}
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				var request gatewayprotocol.Request
				if json.NewDecoder(connection).Decode(&request) != nil {
					return
				}
				stub.mu.Lock()
				stub.requests = append(stub.requests, request)
				stub.mu.Unlock()
				result, rpcErr := handle(request)
				_ = json.NewEncoder(connection).Encode(gatewayprotocol.Response{JSONRPC: gatewayprotocol.JSONRPCVersion, ID: request.ID, Result: result, Error: rpcErr})
			}()
		}
	}()
	return stub
}

// labGateway keeps a traffic policy document and applies changes like
// gatewayd would, so handler tests exercise the whole read-modify-apply path.
type labGateway struct {
	mu         sync.Mutex
	document   trafficpolicy.Document
	onboarding gatewayprotocol.LabOnboarding
	applyErr   *gatewayprotocol.RPCError
}

func newLabGateway() *labGateway {
	policy := trafficpolicy.LegacyDefaultPolicy()
	return &labGateway{
		document:   trafficpolicy.Document{Schema: 1, Policy: policy, Digest: strings.Repeat("a", 64), AppliedAt: time.Now().UTC()},
		onboarding: gatewayprotocol.LabOnboarding{Schema: 1, Routed: true, LabInterface: "lab0", GatewayIPv4: "10.77.0.1", Port: 8086},
	}
}

func (g *labGateway) update(change func(*labGateway)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	change(g)
}

func (g *labGateway) handle(request gatewayprotocol.Request) (any, *gatewayprotocol.RPCError) {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch request.Method {
	case "GetTrafficPolicy":
		return g.document, nil
	case "GetLabOnboarding":
		onboarding := g.onboarding
		onboarding.InterceptionConfigured = g.document.Policy.TLS.Enabled
		onboarding.Published = onboarding.InterceptionConfigured && onboarding.Routed
		return onboarding, nil
	case "ApplyTrafficPolicy":
		if g.applyErr != nil {
			return nil, g.applyErr
		}
		var params gatewayprotocol.ApplyTrafficPolicyParams
		if err := json.Unmarshal(request.Params, &params); err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		if params.ExpectedRevision != g.document.Policy.Revision {
			return nil, &gatewayprotocol.RPCError{Code: -32073, Message: "traffic policy revision conflict"}
		}
		normalized, err := trafficpolicy.Normalize(params.Policy)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32073, Message: err.Error()}
		}
		previous := g.document.Policy
		g.document = trafficpolicy.Document{Schema: 1, Policy: normalized, Digest: strings.Repeat("b", 64), AppliedAt: time.Now().UTC(), Previous: &previous}
		return g.document, nil
	}
	return nil, &gatewayprotocol.RPCError{Code: -32601, Message: "method not found"}
}

type labFixture struct {
	server  *Server
	session string
	gateway *labGateway
	stub    *labGatewayStub
	tvID    string
	phoneID string
}

func newLabFixture(t *testing.T, withCA bool) *labFixture {
	t.Helper()
	publicRoot := filepath.Join(t.TempDir(), "public")
	if withCA {
		if _, err := interceptionpki.Ensure(interceptionpki.Options{PrivateRoot: filepath.Join(t.TempDir(), "private"), PublicRoot: publicRoot, KeyBits: 2048}); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("SHAKERPROXY_PUBLIC_ROOT", publicRoot)
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	gateway := newLabGateway()
	stub := startLabGatewayStub(t, socketPath, gateway.handle)
	server, session := configuredAPIServer(t, socketPath)
	server.inventory = &deviceinventory.Store{Path: filepath.Join(t.TempDir(), "inventory.json")}
	now := time.Now().UTC()
	snapshot, err := server.inventory.ReconcileDHCP4([]deviceinventory.DHCP4Lease{
		{Address: netip.MustParseAddr("10.77.0.10"), HardwareAddr: "52:54:00:00:00:10", Hostname: "tv", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)},
		{Address: netip.MustParseAddr("10.77.0.20"), HardwareAddr: "52:54:00:00:00:20", Hostname: "phone", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)},
	})
	if err != nil || len(snapshot.Devices) != 2 {
		t.Fatalf("seed inventory: %v", err)
	}
	fixture := &labFixture{server: server, session: session, gateway: gateway, stub: stub}
	for _, device := range snapshot.Devices {
		name := "Lab Phone"
		if labDeviceMACs(device)[0] == "52:54:00:00:00:10" {
			fixture.tvID, name = device.ID, "Living Room TV"
		} else {
			fixture.phoneID = device.ID
		}
		if _, err := server.inventory.UpdateMetadata(device.ID, "admin", "lab-controls-name-"+device.ID[7:23], deviceinventory.DeviceMetadata{FriendlyName: name}); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

func (f *labFixture) do(t *testing.T, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	f.server.Handler().ServeHTTP(recorder, authenticatedJSONRequest(method, target, body, f.session, ""))
	return recorder
}

func (f *labFixture) lastApply(t *testing.T) gatewayprotocol.ApplyTrafficPolicyParams {
	t.Helper()
	var params gatewayprotocol.ApplyTrafficPolicyParams
	if err := json.Unmarshal(f.stub.last("ApplyTrafficPolicy").Params, &params); err != nil {
		t.Fatal(err)
	}
	return params
}

func decodeControls(t *testing.T, recorder *httptest.ResponseRecorder) deviceControlsView {
	t.Helper()
	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected response %d: %s", recorder.Code, recorder.Body.String())
	}
	var view deviceControlsView
	if err := json.Unmarshal(recorder.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	return view
}

func errorCode(t *testing.T, recorder *httptest.ResponseRecorder) (string, string) {
	t.Helper()
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || body.Error.Code == "" || body.Error.Message == "" {
		t.Fatalf("response is not the standard error shape: %d %s", recorder.Code, recorder.Body.String())
	}
	return body.Error.Code, body.Error.Message
}

func TestDeviceControlsApplyThroughPolicyAndExplainWhatHappens(t *testing.T) {
	fixture := newLabFixture(t, true)
	view := decodeControls(t, fixture.do(t, http.MethodPut, "/api/v1/devices/"+url.PathEscape("living room tv")+"/controls", `{"decrypt_https":true,"internet":"block","blocked_domains":["*.Ads.Example.","ads.example"]}`))
	if view.DeviceID != fixture.tvID || !view.DecryptHTTPS || view.Internet != "BLOCK" || strings.Join(view.BlockedDomains, ",") != "ads.example" || !view.Effective || view.Schema != 1 {
		t.Fatalf("unexpected controls: %#v", view)
	}
	notes := strings.Join(view.Notes, "\n")
	for _, expected := range []string{"Domain blocking needs ShakerProxy DNS enforcement; it was enabled for this device.", "QUIC (UDP 443) is blocked", "open http://10.77.0.1/ on the device", "Internet is blocked"} {
		if !strings.Contains(notes, expected) {
			t.Fatalf("notes lack %q:\n%s", expected, notes)
		}
	}
	params := fixture.lastApply(t)
	policy := params.Policy
	if params.ExpectedRevision != 1 || policy.Revision != 2 || !policy.TLS.Enabled || strings.Join(policy.TLS.SelectedDeviceIDs, ",") != fixture.tvID || len(policy.DeviceControls) != 1 {
		t.Fatalf("unexpected applied policy: %#v", params)
	}
	control := policy.DeviceControls[0]
	if control.DeviceID != fixture.tvID || strings.Join(control.HardwareAddresses, ",") != "52:54:00:00:00:10" || strings.Join(control.Addresses, ",") != "10.77.0.10" || !control.BlockInternet {
		t.Fatalf("control lacks identity evidence: %#v", control)
	}

	// The same device by MAC (any separator) and by current IP.
	for _, reference := range []string{"52-54-00-00-00-10", "10.77.0.10", fixture.tvID} {
		if got := decodeControls(t, fixture.do(t, http.MethodGet, "/api/v1/devices/"+reference+"/controls", "")); got.DeviceID != fixture.tvID || got.Internet != "BLOCK" {
			t.Fatalf("%s resolved to %#v", reference, got)
		}
	}

	// Partial update: only internet changes; decryption and domains stay.
	view = decodeControls(t, fixture.do(t, http.MethodPut, "/api/v1/devices/"+fixture.tvID+"/controls", `{"internet":"ALLOW"}`))
	if view.Internet != "ALLOW" || !view.DecryptHTTPS || len(view.BlockedDomains) != 1 {
		t.Fatalf("partial update changed other controls: %#v", view)
	}
	// Turning everything off removes the device from the policy.
	view = decodeControls(t, fixture.do(t, http.MethodPut, "/api/v1/devices/"+fixture.tvID+"/controls", `{"decrypt_https":false,"blocked_domains":[]}`))
	if view.DecryptHTTPS || len(view.BlockedDomains) != 0 {
		t.Fatalf("controls were not cleared: %#v", view)
	}
	params = fixture.lastApply(t)
	if params.Policy.TLS.Enabled || len(params.Policy.TLS.SelectedDeviceIDs) != 0 || len(params.Policy.DeviceControls) != 0 {
		t.Fatalf("clearing controls left policy state: %#v", params.Policy)
	}
	// A no-op change does not create a revision.
	applies := len(fixture.stub.methods())
	decodeControls(t, fixture.do(t, http.MethodPut, "/api/v1/devices/"+fixture.tvID+"/controls", `{"internet":"ALLOW"}`))
	for _, method := range fixture.stub.methods()[applies:] {
		if method == "ApplyTrafficPolicy" {
			t.Fatal("a no-op change applied a new policy revision")
		}
	}
}

func TestDeviceControlsErrorsSayWhatToDoNext(t *testing.T) {
	fixture := newLabFixture(t, false)
	for _, test := range []struct {
		method, target, body string
		status               int
		code, hint           string
	}{
		{http.MethodPut, "/api/v1/devices/" + fixture.tvID + "/controls", `{"decrypt_https":true}`, http.StatusConflict, "interception_ca_missing", "shakerproxy-interception-pki"},
		{http.MethodPut, "/api/v1/devices/" + fixture.tvID + "/controls", `{"internet":"OFF"}`, http.StatusBadRequest, "invalid_internet", "ALLOW"},
		{http.MethodPut, "/api/v1/devices/" + fixture.tvID + "/controls", `{"blocked_domains":["not a domain"]}`, http.StatusBadRequest, "invalid_domain", "example.com"},
		{http.MethodPut, "/api/v1/devices/" + fixture.tvID + "/controls", `{"unexpected":true}`, http.StatusBadRequest, "invalid_request", "decrypt_https"},
		{http.MethodGet, "/api/v1/devices/nothing-matches/controls", "", http.StatusNotFound, "device_not_found", "shakerproxy devices"},
		{http.MethodGet, "/api/v1/devices/l/controls", "", http.StatusConflict, "device_ambiguous", "matches 2 devices"},
	} {
		recorder := fixture.do(t, test.method, test.target, test.body)
		code, message := errorCode(t, recorder)
		if recorder.Code != test.status || code != test.code || !strings.Contains(message, test.hint) {
			t.Fatalf("%s %s: %d %s %q", test.method, test.target, recorder.Code, code, message)
		}
	}
	ambiguous := fixture.do(t, http.MethodGet, "/api/v1/devices/l/controls", "")
	if !strings.Contains(ambiguous.Body.String(), `"candidates":[`) || !strings.Contains(ambiguous.Body.String(), fixture.phoneID) {
		t.Fatalf("ambiguous error lacks candidates: %s", ambiguous.Body.String())
	}

	fixture.gateway.update(func(g *labGateway) {
		g.applyErr = &gatewayprotocol.RPCError{Code: -32073, Message: "active encrypted DNS, TLS or device controls require a confirmed routed network plan"}
	})
	recorder := fixture.do(t, http.MethodPut, "/api/v1/devices/"+fixture.tvID+"/controls", `{"internet":"BLOCK"}`)
	if code, message := errorCode(t, recorder); recorder.Code != http.StatusConflict || code != "network_not_ready" || !strings.Contains(message, "routed network plan") {
		t.Fatalf("routing error mapped to %d %s %q", recorder.Code, code, message)
	}
	fixture.gateway.update(func(g *labGateway) {
		g.applyErr = &gatewayprotocol.RPCError{Code: -32060, Message: "appliance configuration is locked by network operation x"}
	})
	recorder = fixture.do(t, http.MethodPut, "/api/v1/devices/"+fixture.tvID+"/controls", `{"internet":"BLOCK"}`)
	if code, _ := errorCode(t, recorder); recorder.Code != http.StatusConflict || code != "configuration_locked" {
		t.Fatalf("lock error mapped to %d %s", recorder.Code, code)
	}

	unauthenticated := httptest.NewRequest(http.MethodPut, "/api/v1/devices/"+fixture.tvID+"/controls", strings.NewReader(`{}`))
	unauthenticated.Host = "shakerproxy.test"
	response := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(response, unauthenticated)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated controls change returned %d", response.Code)
	}
}

func TestTLSBypassForOneDeviceOrEveryDevice(t *testing.T) {
	fixture := newLabFixture(t, true)
	recorder := fixture.do(t, http.MethodPost, "/api/v1/traffic-policy/bypass", `{"host":"API.Example.com","device":"Living Room TV"}`)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"scope":"device"`) || !strings.Contains(recorder.Body.String(), "Retry the action on the device") {
		t.Fatalf("device bypass returned %d: %s", recorder.Code, recorder.Body.String())
	}
	params := fixture.lastApply(t)
	if len(params.Policy.DeviceControls) != 1 || strings.Join(params.Policy.DeviceControls[0].BypassHosts, ",") != "api.example.com" {
		t.Fatalf("device bypass not stored: %#v", params.Policy.DeviceControls)
	}
	recorder = fixture.do(t, http.MethodPost, "/api/v1/traffic-policy/bypass", `{"host":"cdn.example.net"}`)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"scope":"all_devices"`) || !strings.Contains(recorder.Body.String(), `"device_id":null`) {
		t.Fatalf("global bypass returned %d: %s", recorder.Code, recorder.Body.String())
	}
	params = fixture.lastApply(t)
	if strings.Join(params.Policy.TLS.ExcludeHosts, ",") != "cdn.example.net" {
		t.Fatalf("global bypass not stored: %#v", params.Policy.TLS.ExcludeHosts)
	}
	recorder = fixture.do(t, http.MethodDelete, "/api/v1/traffic-policy/bypass?host=cdn.example.net", "")
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"removed":true`) {
		t.Fatalf("bypass removal returned %d: %s", recorder.Code, recorder.Body.String())
	}
	recorder = fixture.do(t, http.MethodDelete, "/api/v1/traffic-policy/bypass?host=cdn.example.net", "")
	if code, _ := errorCode(t, recorder); recorder.Code != http.StatusNotFound || code != "bypass_not_found" {
		t.Fatalf("missing bypass returned %d %s", recorder.Code, code)
	}
	recorder = fixture.do(t, http.MethodPost, "/api/v1/traffic-policy/bypass", `{"host":"not a host"}`)
	if code, _ := errorCode(t, recorder); recorder.Code != http.StatusBadRequest || code != "invalid_host" {
		t.Fatalf("invalid host returned %d %s", recorder.Code, code)
	}
}

func TestInterceptionCAOnboardingReportsWhereAndWhy(t *testing.T) {
	fixture := newLabFixture(t, true)
	get := func() interceptionOnboarding {
		t.Helper()
		recorder := fixture.do(t, http.MethodGet, "/api/v1/interception-ca/onboarding", "")
		if recorder.Code != http.StatusOK {
			t.Fatalf("onboarding returned %d: %s", recorder.Code, recorder.Body.String())
		}
		var response interceptionOnboarding
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		return response
	}
	response := get()
	if response.Available || !strings.Contains(response.Reason, "Decrypt HTTPS for a device first") || len(response.SHA256Fingerprint) != 95 || response.CommonName == "" || response.NotAfter == "" || len(response.URLs) != 0 {
		t.Fatalf("unexpected onboarding before decryption: %#v", response)
	}
	decodeControls(t, fixture.do(t, http.MethodPut, "/api/v1/devices/"+fixture.tvID+"/controls", `{"decrypt_https":true}`))
	response = get()
	if !response.Available || response.Reason != "" || len(response.URLs) != 1 || response.URLs[0].URL != "http://10.77.0.1/" {
		t.Fatalf("onboarding not available once decryption is on: %#v", response)
	}
	platforms := map[string]string{}
	for _, instruction := range response.Instructions {
		platforms[instruction.Platform] = strings.Join(instruction.Steps, " ")
	}
	if !strings.Contains(platforms["ios"], "Certificate Trust Settings") || !strings.Contains(platforms["ios"], "http://10.77.0.1/") || platforms["smart-tv"] == "" || platforms["android-tv"] == "" {
		t.Fatalf("instructions incomplete: %#v", platforms)
	}
	fixture.gateway.update(func(g *labGateway) { g.onboarding.Routed = false })
	if response = get(); response.Available || !strings.Contains(response.Reason, "routed network plan") {
		t.Fatalf("unrouted onboarding: %#v", response)
	}
}

func TestInterceptionCAErrorsUseStandardShape(t *testing.T) {
	fixture := newLabFixture(t, false)
	for _, test := range []struct {
		target string
		status int
		code   string
	}{
		{"/api/v1/interception-ca", http.StatusServiceUnavailable, "interception_ca_not_provisioned"},
		{"/api/v1/interception-ca/download?format=pem", http.StatusServiceUnavailable, "interception_ca_not_provisioned"},
		{"/api/v1/interception-ca/download?format=pfx", http.StatusBadRequest, "unsupported_certificate_format"},
	} {
		recorder := fixture.do(t, http.MethodGet, test.target, "")
		if code, message := errorCode(t, recorder); recorder.Code != test.status || code != test.code || message == "" {
			t.Fatalf("%s: %d %s", test.target, recorder.Code, code)
		}
	}
	onboarding := fixture.do(t, http.MethodGet, "/api/v1/interception-ca/onboarding", "")
	if onboarding.Code != http.StatusOK || !strings.Contains(onboarding.Body.String(), "has not created its interception certificate") {
		t.Fatalf("onboarding without CA returned %d: %s", onboarding.Code, onboarding.Body.String())
	}
}

func TestLegacyTrafficPolicyPutKeepsDeviceControls(t *testing.T) {
	fixture := newLabFixture(t, true)
	decodeControls(t, fixture.do(t, http.MethodPut, "/api/v1/devices/"+fixture.tvID+"/controls", `{"internet":"BLOCK"}`))
	policy := trafficpolicy.LegacyDefaultPolicy()
	policy.Revision = 3
	policy.Name = "Edited in the old policy editor"
	body, _ := json.Marshal(map[string]any{"expected_revision": 2, "policy": policy, "password": activationTestPassword})
	recorder := fixture.do(t, http.MethodPut, "/api/v1/traffic-policy", string(body))
	if recorder.Code != http.StatusOK {
		t.Fatalf("legacy policy apply returned %d: %s", recorder.Code, recorder.Body.String())
	}
	params := fixture.lastApply(t)
	if len(params.Policy.DeviceControls) != 1 || !params.Policy.DeviceControls[0].BlockInternet {
		t.Fatalf("a policy without device_controls cleared them: %#v", params.Policy.DeviceControls)
	}
}

func TestPolicyEditorDeviceSelectionCarriesDeviceIdentity(t *testing.T) {
	fixture := newLabFixture(t, true)
	policy := trafficpolicy.LegacyDefaultPolicy()
	policy.Revision = 2
	policy.TLS.Enabled = true
	policy.TLS.SelectedDeviceIDs = []string{fixture.tvID}
	body, _ := json.Marshal(map[string]any{"expected_revision": 1, "policy": policy, "password": activationTestPassword})
	recorder := fixture.do(t, http.MethodPut, "/api/v1/traffic-policy", string(body))
	if recorder.Code != http.StatusOK {
		t.Fatalf("policy apply returned %d: %s", recorder.Code, recorder.Body.String())
	}
	params := fixture.lastApply(t)
	control, ok := trafficpolicy.FindDeviceControl(params.Policy, fixture.tvID)
	if !ok || len(control.HardwareAddresses) == 0 {
		t.Fatalf("selected device was sent without its identity: %#v", params.Policy.DeviceControls)
	}

	policy.TLS.SelectedDeviceIDs = nil
	policy.TLS.Enabled = false
	policy.Revision = 3
	body, _ = json.Marshal(map[string]any{"expected_revision": 2, "policy": policy, "password": activationTestPassword})
	if recorder := fixture.do(t, http.MethodPut, "/api/v1/traffic-policy", string(body)); recorder.Code != http.StatusOK {
		t.Fatalf("policy apply returned %d: %s", recorder.Code, recorder.Body.String())
	}
	if _, ok := trafficpolicy.FindDeviceControl(fixture.lastApply(t).Policy, fixture.tvID); ok {
		t.Fatal("identity-only control outlived the device's selection")
	}
}
