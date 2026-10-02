package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
)

func TestLabRecordingSettingIsForwardedToTheGateway(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	requests := startGatewayStub(t, socketPath, gatewayprotocol.LabRecordingStatus{Enabled: false, Reason: "Automatic lab recording is turned off."})
	server, session := configuredAPIServer(t, socketPath)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, authenticatedJSONRequest(http.MethodPut, "/api/v1/captures/lab-recording", `{"enabled":false}`, session, ""))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "turned off") {
		t.Fatalf("unexpected response %d: %s", recorder.Code, recorder.Body.String())
	}
	rpcRequest := <-requests
	var params gatewayprotocol.SetLabRecordingParams
	if rpcRequest.Method != "SetLabRecording" || gatewayprotocol.DecodeParams(rpcRequest.Params, &params) != nil || params.Enabled {
		t.Fatalf("unexpected RPC: %s %s", rpcRequest.Method, rpcRequest.Params)
	}
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, authenticatedJSONRequest(http.MethodPut, "/api/v1/captures/lab-recording", `{}`, session, ""))
	if code, _ := decodeErrorBody(t, recorder); recorder.Code != http.StatusBadRequest || code != "enabled_required" {
		t.Fatalf("a request without enabled returned %d %s", recorder.Code, code)
	}
}

func TestCaptureStartCannotClaimToBeTheAutomaticRecording(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/captures", `{"name":"forged","mode":"FULL_PACKETS","automatic":true}`, session, "http-capture-request-0009")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("a client-marked automatic capture returned %d: %s", recorder.Code, recorder.Body.String())
	}
}
