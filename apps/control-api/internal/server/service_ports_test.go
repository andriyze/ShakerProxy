package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
)

func TestServicePortPlanIsAuthenticatedNoStoreAndBoundToFixedRPC(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	result := gatewayprotocol.ServicePortPlan{
		Schema:              1,
		GeneratedAt:         time.Now().UTC(),
		SystemdResolvedStub: true,
		ResolverHandling:    "PRESERVE_STUB_BIND_LAB_ADDRESS_ONLY",
		Reservations: []gatewayprotocol.PortReservation{{
			Transport: "udp", Port: 53, Purpose: "local plain DNS", IntendedBinding: "lab-interface-only", State: "COEXIST", Action: "PRESERVE_STUB_BIND_LAB_ADDRESS_ONLY", Listeners: []gatewayprotocol.PortListener{},
		}},
	}
	requests := startGatewayStub(t, socketPath, result)
	server, session := configuredAPIServer(t, socketPath)

	unauthenticated := httptest.NewRequest(http.MethodGet, "/api/v1/system/ports", nil)
	unauthenticated.Host = "shakerproxy.test"
	unauthenticatedRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthenticatedRecorder, unauthenticated)
	if unauthenticatedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated inventory returned %d", unauthenticatedRecorder.Code)
	}

	request := authenticatedJSONRequest(http.MethodGet, "/api/v1/system/ports", "", session, "")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || !strings.Contains(recorder.Body.String(), "PRESERVE_STUB_BIND_LAB_ADDRESS_ONLY") {
		t.Fatalf("unexpected port plan response %d: %s", recorder.Code, recorder.Body.String())
	}
	if rpc := <-requests; rpc.Method != "GetServicePortPlan" {
		t.Fatalf("unexpected RPC method %q", rpc.Method)
	}
}

func TestConnectivityProbeIsExplicitSessionOnlyStrictAndRateLimited(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	result := gatewayprotocol.ConnectivityReport{
		Schema: 1, GeneratedAt: time.Now().UTC(), DNSIndependentHTTPS: true, RestrictedPort53: true,
		Probes: []gatewayprotocol.ConnectivityProbe{},
	}
	requests := startGatewayStub(t, socketPath, result)
	server, session := configuredAPIServer(t, socketPath)

	bad := authenticatedJSONRequest(http.MethodPost, "/api/v1/system/connectivity-probe", `{"target":"caller-selected.example"}`, session, "")
	badRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(badRecorder, bad)
	if badRecorder.Code != http.StatusBadRequest {
		t.Fatalf("caller-selected probe target returned %d: %s", badRecorder.Code, badRecorder.Body.String())
	}

	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/system/connectivity-probe", `{}`, session, "")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || !strings.Contains(recorder.Body.String(), `"restricted_port_53":true`) {
		t.Fatalf("unexpected probe response %d: %s", recorder.Code, recorder.Body.String())
	}
	if rpc := <-requests; rpc.Method != "ProbeConnectivity" {
		t.Fatalf("unexpected RPC method %q", rpc.Method)
	}

	repeated := authenticatedJSONRequest(http.MethodPost, "/api/v1/system/connectivity-probe", `{}`, session, "")
	repeatedRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(repeatedRecorder, repeated)
	if repeatedRecorder.Code != http.StatusTooManyRequests || repeatedRecorder.Header().Get("Retry-After") != "15" {
		t.Fatalf("unlimited probe returned %d: %s", repeatedRecorder.Code, repeatedRecorder.Body.String())
	}
}
