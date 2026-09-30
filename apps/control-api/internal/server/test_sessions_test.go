package server

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/apitoken"
	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/testsession"
)

func TestTestSessionLifecycle(t *testing.T) {
	fixture := newIntelFixture(t)
	recorder := fixture.do(t, http.MethodPost, "/api/v1/test-sessions", `{"device":"Bench camera"}`, fixture.session)
	var created testSessionResponse
	if recorder.Code != http.StatusCreated || json.Unmarshal(recorder.Body.Bytes(), &created) != nil {
		t.Fatalf("start: %d %s", recorder.Code, recorder.Body.String())
	}
	if !testsession.ValidID(created.ID) || created.DeviceID != fixture.camera || created.DeviceName != "Bench camera" || created.State != testsession.StateRunning || created.CreatedBy != "admin" || len(created.Warnings) != 0 {
		t.Fatalf("created session: %#v", created)
	}
	if !strings.HasPrefix(created.Name, "Bench camera — ") || len(created.Name) != len("Bench camera — 2026-09-29 12:00") {
		t.Fatalf("default name: %q", created.Name)
	}
	for _, field := range []string{`"ended_at":null`, `"capture_session_id":null`, `"notes":""`} {
		if !strings.Contains(recorder.Body.String(), field) {
			t.Fatalf("session JSON lacks %s: %s", field, recorder.Body.String())
		}
	}

	recorder = fixture.do(t, http.MethodPatch, "/api/v1/test-sessions/"+created.ID, `{"name":"Firmware 2.1 first boot","notes":"Factory reset before test"}`, fixture.session)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"name":"Firmware 2.1 first boot"`) {
		t.Fatalf("patch: %d %s", recorder.Code, recorder.Body.String())
	}
	recorder = fixture.do(t, http.MethodGet, "/api/v1/test-sessions/"+created.ID, "", fixture.session)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "Factory reset before test") {
		t.Fatalf("get: %d %s", recorder.Code, recorder.Body.String())
	}

	recorder = fixture.do(t, http.MethodGet, "/api/v1/test-sessions?device=10.77.0.30&state=running", "", fixture.session)
	var list testSessionList
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &list) != nil || list.Total != 1 || len(list.Sessions) != 1 || list.Sessions[0].ID != created.ID || list.Truncated {
		t.Fatalf("list: %d %s", recorder.Code, recorder.Body.String())
	}

	recorder = fixture.do(t, http.MethodPost, "/api/v1/test-sessions/"+created.ID+"/stop", "", fixture.session)
	var stopped testSessionResponse
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &stopped) != nil || stopped.State != testsession.StateStopped || stopped.EndedAt == nil {
		t.Fatalf("stop: %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder := fixture.do(t, http.MethodPost, "/api/v1/test-sessions/"+created.ID+"/stop", "", fixture.session); recorder.Code != http.StatusOK {
		t.Fatalf("stopping twice: %d", recorder.Code)
	}
	recorder = fixture.do(t, http.MethodDelete, "/api/v1/test-sessions/"+created.ID, "", fixture.session)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"deleted":true`) {
		t.Fatalf("delete: %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder := fixture.do(t, http.MethodGet, "/api/v1/test-sessions/"+created.ID, "", fixture.session); recorder.Code != http.StatusNotFound {
		t.Fatalf("deleted session readable: %d", recorder.Code)
	}
}

func TestTestSessionOneRunningPerDeviceAndValidation(t *testing.T) {
	fixture := newIntelFixture(t)
	first := fixture.do(t, http.MethodPost, "/api/v1/test-sessions", `{"device":"`+fixture.tv+`","name":"Run 1"}`, fixture.session)
	second := fixture.do(t, http.MethodPost, "/api/v1/test-sessions", `{"device":"living room tv","name":"Run 2"}`, fixture.session)
	var run2 testSessionResponse
	if first.Code != http.StatusCreated || second.Code != http.StatusCreated || json.Unmarshal(second.Body.Bytes(), &run2) != nil || len(run2.Warnings) != 1 || !strings.Contains(run2.Warnings[0], `"Run 1"`) {
		t.Fatalf("second start: %d %s", second.Code, second.Body.String())
	}
	recorder := fixture.do(t, http.MethodGet, "/api/v1/test-sessions?device="+fixture.tv+"&state=RUNNING", "", fixture.session)
	var list testSessionList
	if json.Unmarshal(recorder.Body.Bytes(), &list) != nil || list.Total != 1 || list.Sessions[0].ID != run2.ID {
		t.Fatalf("running list: %s", recorder.Body.String())
	}
	for _, body := range []string{`{"device":"toaster"}`, `{"device":"bench"}`, `{"device":"` + fixture.tv + `","name":"line\nbreak"}`, `{"device":"` + fixture.tv + `","unknown":true}`, `{}`} {
		recorder := fixture.do(t, http.MethodPost, "/api/v1/test-sessions", body, fixture.session)
		if recorder.Code < 400 || recorder.Code >= 500 {
			t.Fatalf("%s returned %d: %s", body, recorder.Code, recorder.Body.String())
		}
	}
	for _, target := range []string{"/api/v1/test-sessions?state=PAUSED", "/api/v1/test-sessions?limit=0", "/api/v1/test-sessions?limit=501", "/api/v1/test-sessions?sort=name"} {
		if recorder := fixture.do(t, http.MethodGet, target, "", fixture.session); recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s returned %d", target, recorder.Code)
		}
	}
	if recorder := fixture.do(t, http.MethodPatch, "/api/v1/test-sessions/"+run2.ID, `{}`, fixture.session); recorder.Code != http.StatusBadRequest {
		t.Fatalf("empty patch: %d", recorder.Code)
	}
	if recorder := fixture.do(t, http.MethodGet, "/api/v1/test-sessions/not-a-session", "", fixture.session); recorder.Code != http.StatusNotFound {
		t.Fatalf("invalid ID: %d", recorder.Code)
	}
}

func TestTestSessionAuthorization(t *testing.T) {
	fixture := newIntelFixture(t)
	reader := fixture.token(t, apitoken.ScopeDevicesRead)
	if recorder := fixture.do(t, http.MethodPost, "/api/v1/test-sessions", `{"device":"`+fixture.tv+`"}`, reader); recorder.Code != http.StatusForbidden {
		t.Fatalf("read token started a session: %d", recorder.Code)
	}
	labWriter := fixture.token(t, apitoken.ScopeLabWrite)
	byToken := fixture.do(t, http.MethodPost, "/api/v1/test-sessions", `{"device":"`+fixture.camera+`","name":"CI run"}`, labWriter)
	var tokenSession testSessionResponse
	if byToken.Code != http.StatusCreated || json.Unmarshal(byToken.Body.Bytes(), &tokenSession) != nil || tokenSession.CreatedBy != "token:intel test" {
		t.Fatalf("lab:write token start: %d %s", byToken.Code, byToken.Body.String())
	}
	if recorder := fixture.do(t, http.MethodPost, "/api/v1/test-sessions/"+tokenSession.ID+"/stop", "", labWriter); recorder.Code != http.StatusOK {
		t.Fatalf("lab:write token stop: %d %s", recorder.Code, recorder.Body.String())
	}
	created := fixture.do(t, http.MethodPost, "/api/v1/test-sessions", `{"device":"`+fixture.tv+`"}`, fixture.session)
	var session testSessionResponse
	if json.Unmarshal(created.Body.Bytes(), &session) != nil {
		t.Fatal(created.Body.String())
	}
	if recorder := fixture.do(t, http.MethodGet, "/api/v1/test-sessions", "", reader); recorder.Code != http.StatusOK {
		t.Fatalf("devices:read list: %d", recorder.Code)
	}
	if recorder := fixture.do(t, http.MethodGet, "/api/v1/test-sessions/"+session.ID, "", reader); recorder.Code != http.StatusOK {
		t.Fatalf("devices:read get: %d", recorder.Code)
	}
	traffic := fixture.token(t, apitoken.ScopeTrafficRead)
	if recorder := fixture.do(t, http.MethodGet, "/api/v1/test-sessions", "", traffic); recorder.Code != http.StatusForbidden {
		t.Fatalf("traffic-only list: %d", recorder.Code)
	}
	for _, request := range []struct{ method, target, body string }{
		{http.MethodPatch, "/api/v1/test-sessions/" + session.ID, `{"name":"x"}`},
		{http.MethodPost, "/api/v1/test-sessions/" + session.ID + "/stop", ""},
		{http.MethodDelete, "/api/v1/test-sessions/" + session.ID, ""},
	} {
		if recorder := fixture.do(t, request.method, request.target, request.body, reader); recorder.Code != http.StatusForbidden {
			t.Fatalf("%s %s with a read token returned %d", request.method, request.target, recorder.Code)
		}
	}
}

func TestTestSessionCaptureIsOptionalAndLinked(t *testing.T) {
	fixture := newIntelFixture(t)
	// No gateway: the session still starts, with a plain warning.
	recorder := fixture.do(t, http.MethodPost, "/api/v1/test-sessions", `{"device":"`+fixture.tv+`","capture":true}`, fixture.session)
	var withoutGateway testSessionResponse
	if recorder.Code != http.StatusCreated || json.Unmarshal(recorder.Body.Bytes(), &withoutGateway) != nil || withoutGateway.CaptureSessionID != nil || len(withoutGateway.Warnings) != 1 || !strings.Contains(withoutGateway.Warnings[0], "without a capture") {
		t.Fatalf("capture without gateway: %d %s", recorder.Code, recorder.Body.String())
	}

	socket := filepath.Join(t.TempDir(), "gw.sock")
	captureID := "capture-0123456789abcdef0123456789abcdef"
	requests := startGatewaySequenceStub(t, socket, capture.View{Session: capture.Session{ID: captureID}, State: capture.StateRunning, Active: true}, capture.View{Session: capture.Session{ID: captureID}, State: capture.StateStopped})
	fixture.server.gateway.SocketPath = socket
	recorder = fixture.do(t, http.MethodPost, "/api/v1/test-sessions", `{"device":"`+fixture.camera+`","name":"With packets","capture":true}`, fixture.session)
	var withCapture testSessionResponse
	if recorder.Code != http.StatusCreated || json.Unmarshal(recorder.Body.Bytes(), &withCapture) != nil || withCapture.CaptureSessionID == nil || *withCapture.CaptureSessionID != captureID || len(withCapture.Warnings) != 0 {
		t.Fatalf("capture with gateway: %d %s", recorder.Code, recorder.Body.String())
	}
	select {
	case request := <-requests:
		var params struct {
			Request capture.StartRequest `json:"request"`
		}
		if request.Method != "StartCapture" || json.Unmarshal(request.Params, &params) != nil || params.Request.Mode != capture.ModeHeaders || params.Request.Name != "With packets" || params.Request.IdempotencyKey != "test-session-"+strings.TrimPrefix(withCapture.ID, "ts-") {
			t.Fatalf("capture request: %s %s", request.Method, request.Params)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("capture was not requested")
	}
	recorder = fixture.do(t, http.MethodPost, "/api/v1/test-sessions/"+withCapture.ID+"/stop", "", fixture.session)
	if recorder.Code != http.StatusOK {
		t.Fatalf("stop: %d %s", recorder.Code, recorder.Body.String())
	}
	select {
	case request := <-requests:
		if request.Method != "StopCapture" || !strings.Contains(string(request.Params), captureID) {
			t.Fatalf("stop request: %s %s", request.Method, request.Params)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("capture was not stopped")
	}
}

func TestDeletingRunningSessionStopsItsCapture(t *testing.T) {
	fixture := newIntelFixture(t)
	socket := filepath.Join(t.TempDir(), "gw.sock")
	captureID := "capture-fedcba9876543210fedcba9876543210"
	requests := startGatewaySequenceStub(t, socket, capture.View{Session: capture.Session{ID: captureID}, State: capture.StateRunning, Active: true}, capture.View{Session: capture.Session{ID: captureID}, State: capture.StateStopped})
	fixture.server.gateway.SocketPath = socket
	recorder := fixture.do(t, http.MethodPost, "/api/v1/test-sessions", `{"device":"`+fixture.tv+`","capture":true}`, fixture.session)
	var created testSessionResponse
	if recorder.Code != http.StatusCreated || json.Unmarshal(recorder.Body.Bytes(), &created) != nil || created.CaptureSessionID == nil {
		t.Fatalf("start: %d %s", recorder.Code, recorder.Body.String())
	}
	<-requests
	recorder = fixture.do(t, http.MethodDelete, "/api/v1/test-sessions/"+created.ID, "", fixture.session)
	if recorder.Code != http.StatusOK || strings.Contains(recorder.Body.String(), "warnings") {
		t.Fatalf("delete: %d %s", recorder.Code, recorder.Body.String())
	}
	select {
	case request := <-requests:
		if request.Method != "StopCapture" || !strings.Contains(string(request.Params), captureID) {
			t.Fatalf("stop request: %s %s", request.Method, request.Params)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("deleting a running session left its capture running")
	}
}

// Headers-only test runs lose TLS handshakes (server names, certificates),
// so a run can ask for whole packets; full_capture implies capture.
func TestTestSessionFullCaptureRecordsWholePackets(t *testing.T) {
	fixture := newIntelFixture(t)
	socket := filepath.Join(t.TempDir(), "gw.sock")
	captureID := "capture-00112233445566778899aabbccddeeff"
	requests := startGatewaySequenceStub(t, socket, capture.View{Session: capture.Session{ID: captureID}, State: capture.StateRunning, Active: true})
	fixture.server.gateway.SocketPath = socket
	recorder := fixture.do(t, http.MethodPost, "/api/v1/test-sessions", `{"device":"`+fixture.camera+`","name":"TLS details","full_capture":true}`, fixture.session)
	var started testSessionResponse
	if recorder.Code != http.StatusCreated || json.Unmarshal(recorder.Body.Bytes(), &started) != nil || started.CaptureSessionID == nil || *started.CaptureSessionID != captureID {
		t.Fatalf("full capture run: %d %s", recorder.Code, recorder.Body.String())
	}
	select {
	case request := <-requests:
		var params struct {
			Request capture.StartRequest `json:"request"`
		}
		if request.Method != "StartCapture" || json.Unmarshal(request.Params, &params) != nil || params.Request.Mode != capture.ModeFull {
			t.Fatalf("expected a full-packet capture: %s %s", request.Method, request.Params)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("capture was not requested")
	}
}
