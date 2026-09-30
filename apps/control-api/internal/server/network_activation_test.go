package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
)

const (
	activationTestApplyID  = "apply-0123456789abcdef0123456789abcdef"
	activationTestPlanHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	activationTestPassword = "LongEnough1!Password"
)

func configuredAPIServer(t *testing.T, socketPath string) (*Server, string) {
	return configuredAPIServerWithConfig(t, socketPath, nil)
}

func configuredAPIServerWithConfig(t *testing.T, socketPath string, configure func(*Config)) (*Server, string) {
	t.Helper()
	dataDirectory := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(dataDirectory, 0o750); err != nil {
		t.Fatal(err)
	}
	passwordHash, err := hashPassword(activationTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := json.Marshal(Admin{Username: "admin", PasswordHash: passwordHash, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDirectory, "admin.json"), admin, 0o600); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	config := Config{
		Store: NewStore(dataDirectory, filepath.Join(dataDirectory, "unused-token")), GatewaySocket: socketPath,
		AllowedHosts: []string{"shakerproxy.test"}, Logger: logger,
		ZeekCheckpointDeletions:     &captureDeletionAnalyzerStub{engine: "ZEEK"},
		SuricataCheckpointDeletions: &captureDeletionAnalyzerStub{engine: "SURICATA"},
	}
	if configure != nil {
		configure(&config)
	}
	server := New(config)
	session, err := server.newSession("admin")
	if err != nil {
		t.Fatal(err)
	}
	return server, session
}

func startGatewayStub(t *testing.T, socketPath string, result any) <-chan gatewayprotocol.Request {
	t.Helper()
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan gatewayprotocol.Request, 1)
	go func() {
		defer listener.Close()
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		var request gatewayprotocol.Request
		if json.NewDecoder(connection).Decode(&request) != nil {
			return
		}
		requests <- request
		_ = json.NewEncoder(connection).Encode(gatewayprotocol.Response{JSONRPC: gatewayprotocol.JSONRPCVersion, ID: request.ID, Result: result})
	}()
	return requests
}

func startGatewaySequenceStub(t *testing.T, socketPath string, results ...any) <-chan gatewayprotocol.Request {
	t.Helper()
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan gatewayprotocol.Request, len(results))
	go func() {
		defer listener.Close()
		defer close(requests)
		for _, result := range results {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			var request gatewayprotocol.Request
			if json.NewDecoder(connection).Decode(&request) == nil {
				requests <- request
				if responder, ok := result.(func(gatewayprotocol.Request) any); ok {
					result = responder(request)
				}
				_ = json.NewEncoder(connection).Encode(gatewayprotocol.Response{JSONRPC: gatewayprotocol.JSONRPCVersion, ID: request.ID, Result: result})
			}
			connection.Close()
		}
	}()
	return requests
}

func authenticatedJSONRequest(method, target, body, session, idempotencyKey string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Host = "shakerproxy.test"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+session)
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	return request
}

func TestCommitEndpointReauthenticatesWithoutForwardingPassword(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	result := gatewayprotocol.CommitNetworkPlanResult{ApplyID: activationTestApplyID, PlanHash: activationTestPlanHash, Status: "ACCEPTED", HealthToken: "opaque", HealthDeadline: time.Now().Add(2 * time.Minute)}
	requests := startGatewayStub(t, socketPath, result)
	server, session := configuredAPIServer(t, socketPath)
	body := `{"plan_hash":"` + activationTestPlanHash + `","password":"` + activationTestPassword + `","rollback_window_seconds":120}`
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/network/staged/"+activationTestApplyID+"/commit", body, session, "http-commit-request-0001")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("unexpected response %d: %s", recorder.Code, recorder.Body.String())
	}
	rpcRequest := <-requests
	if rpcRequest.Method != "CommitNetworkPlan" || strings.Contains(string(rpcRequest.Params), activationTestPassword) {
		t.Fatalf("unsafe privileged request: method=%q params=%s", rpcRequest.Method, rpcRequest.Params)
	}
	var params gatewayprotocol.CommitNetworkPlanParams
	if err := gatewayprotocol.DecodeParams(rpcRequest.Params, &params); err != nil {
		t.Fatal(err)
	}
	if params.ApplyID != activationTestApplyID || params.PlanHash != activationTestPlanHash || params.IdempotencyKey != "http-commit-request-0001" || params.RollbackWindowSeconds != 120 {
		t.Fatalf("unexpected commit params: %+v", params)
	}
}

func TestDiagnosticsEndpointAuthenticatesAndUsesBoundedRPC(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	report := gatewayprotocol.DiagnosticReport{Schema: 1, GeneratedAt: time.Now().UTC(), Overall: gatewayprotocol.DiagnosticWarning, Checks: []gatewayprotocol.DiagnosticCheck{{Name: "docker", Status: gatewayprotocol.DiagnosticUnknown, Summary: "Docker state unavailable", Observations: []string{}}}}
	requests := startGatewayStub(t, socketPath, report)
	server, session := configuredAPIServer(t, socketPath)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/system/diagnostics", nil)
	request.Host = "shakerproxy.test"
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated diagnostics returned %d", recorder.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/api/v1/system/diagnostics", nil)
	request.Host = "shakerproxy.test"
	request.Header.Set("Authorization", "Bearer "+session)
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"overall":"WARNING"`) || !strings.Contains(recorder.Body.String(), `"name":"docker"`) {
		t.Fatalf("unexpected diagnostics response %d: %s", recorder.Code, recorder.Body.String())
	}
	if rpc := <-requests; rpc.Method != "GetDiagnostics" || string(rpc.Params) != "{}" {
		t.Fatalf("unexpected diagnostics RPC: %#v", rpc)
	}
}

func TestCommitEndpointRejectsFailedReauthenticationBeforeRPC(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	body := `{"plan_hash":"` + activationTestPlanHash + `","password":"wrong","rollback_window_seconds":120}`
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/network/staged/"+activationTestApplyID+"/commit", body, session, "http-commit-request-0002")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected response %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestHeartbeatEndpointUsesASeparateAuthenticatedRequest(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	requests := startGatewayStub(t, socketPath, map[string]any{"apply_id": activationTestApplyID, "status": "MANAGEMENT_HEALTH_SIGNALLED"})
	server, session := configuredAPIServer(t, socketPath)
	body := `{"plan_hash":"` + activationTestPlanHash + `","token":"second-channel-token"}`
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/network/staged/"+activationTestApplyID+"/heartbeat", body, session, "")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected response %d: %s", recorder.Code, recorder.Body.String())
	}
	rpcRequest := <-requests
	if rpcRequest.Method != "SignalNetworkHealth" {
		t.Fatalf("unexpected RPC method: %s", rpcRequest.Method)
	}
	var params gatewayprotocol.SignalNetworkHealthParams
	if err := gatewayprotocol.DecodeParams(rpcRequest.Params, &params); err != nil || params.Token != "second-channel-token" {
		t.Fatalf("unexpected heartbeat params: %+v err=%v", params, err)
	}
}

func TestConfirmEndpointRequiresReauthenticationAndIdempotency(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	requests := startGatewayStub(t, socketPath, networkplan.StagedPlan{ApplyID: activationTestApplyID, PlanHash: activationTestPlanHash, Status: "CONFIRMED"})
	server, session := configuredAPIServer(t, socketPath)
	body := `{"plan_hash":"` + activationTestPlanHash + `","password":"` + activationTestPassword + `"}`
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/network/staged/"+activationTestApplyID+"/confirm", body, session, "http-confirm-request-0001")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected response %d: %s", recorder.Code, recorder.Body.String())
	}
	rpcRequest := <-requests
	if rpcRequest.Method != "ConfirmNetworkPlan" || strings.Contains(string(rpcRequest.Params), activationTestPassword) {
		t.Fatalf("unsafe confirmation RPC: method=%q params=%s", rpcRequest.Method, rpcRequest.Params)
	}
}

func TestNetworkActivationEndpointsStillRequireASession(t *testing.T) {
	server, _ := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/network/staged/"+activationTestApplyID+"/heartbeat", strings.NewReader(`{}`))
	request.Host = "shakerproxy.test"
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected response %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestRevertEndpointNeedsThePasswordAndNeverForwardsIt(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	requests := startGatewayStub(t, socketPath, map[string]any{"operating_mode": "SETUP_SAFE", "emergency_bypass": false})
	server, session := configuredAPIServer(t, socketPath)

	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, authenticatedJSONRequest(http.MethodPost, "/api/v1/network/active/revert", `{}`, session, ""))
	if recorder.Code != http.StatusUnauthorized || !strings.Contains(recorder.Body.String(), "password") {
		t.Fatalf("revert without the password: %d %s", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, authenticatedJSONRequest(http.MethodPost, "/api/v1/network/active/revert", `{"password":"`+activationTestPassword+`"}`, session, ""))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"operating_mode":"SETUP_SAFE"`) {
		t.Fatalf("revert: %d %s", recorder.Code, recorder.Body.String())
	}
	rpc := <-requests
	if rpc.Method != "RevertNetworkPlan" || strings.Contains(string(rpc.Params), activationTestPassword) {
		t.Fatalf("unsafe privileged request: method=%q params=%s", rpc.Method, rpc.Params)
	}
}

func TestRevertEndpointExplainsGatewayFailures(t *testing.T) {
	for _, test := range []struct {
		code   int
		status int
		error  string
	}{
		{-32030, http.StatusServiceUnavailable, "network_activation_unavailable"},
		{-32036, http.StatusConflict, "network_revert_failed"},
	} {
		socketPath := filepath.Join(t.TempDir(), "gateway.sock")
		startGatewayErrorStub(t, socketPath, test.code, "no confirmed network plan is running")
		server, session := configuredAPIServer(t, socketPath)
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, authenticatedJSONRequest(http.MethodPost, "/api/v1/network/active/revert", `{"password":"`+activationTestPassword+`"}`, session, ""))
		if recorder.Code != test.status || !strings.Contains(recorder.Body.String(), test.error) {
			t.Fatalf("gateway code %d: %d %s", test.code, recorder.Code, recorder.Body.String())
		}
	}
}
