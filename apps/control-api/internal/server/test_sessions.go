package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/testsession"
)

type startTestSessionRequest struct {
	Device  string `json:"device"`
	Name    string `json:"name,omitempty"`
	Notes   string `json:"notes,omitempty"`
	Capture bool   `json:"capture,omitempty"`
	// FullCapture records whole packets instead of headers, so TLS
	// handshakes (server names, certificates) can be analyzed. It implies
	// Capture.
	FullCapture bool `json:"full_capture,omitempty"`
}

type updateTestSessionRequest struct {
	Name  *string `json:"name,omitempty"`
	Notes *string `json:"notes,omitempty"`
}

type testSessionResponse struct {
	testsession.Session
	Warnings []string `json:"warnings,omitempty"`
}

type testSessionList struct {
	Schema    int                   `json:"schema"`
	Sessions  []testsession.Session `json:"sessions"`
	Total     int                   `json:"total"`
	Truncated bool                  `json:"truncated"`
}

type deletedTestSession struct {
	Schema   int      `json:"schema"`
	ID       string   `json:"id"`
	Deleted  bool     `json:"deleted"`
	Warnings []string `json:"warnings,omitempty"`
}

func (s *Server) startTestSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	store := s.testSessions()
	if store == nil {
		writeError(w, http.StatusServiceUnavailable, "test_sessions_unavailable", "Test sessions are unavailable because the control API has no data directory.")
		return
	}
	var request startTestSessionRequest
	if err := decodeJSONBounded(r, &request, 8<<10); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", `Send JSON like {"device":"Living room TV","name":"Firmware 2.1 first boot"} with Content-Type: application/json.`)
		return
	}
	device, err := s.resolveDeviceRef(r.Context(), request.Device)
	if err != nil {
		writeDeviceRefError(w, err)
		return
	}
	now := time.Now().UTC()
	deviceName := deviceDisplayName(device)
	name := strings.TrimSpace(request.Name)
	if name == "" {
		name = defaultTestSessionName(deviceName, now)
	}
	actor := sessionUsername(r.Context())
	if actor == "" {
		actor = "admin"
	}
	session, stopped, err := store.Start(testsession.StartInput{DeviceID: device.ID, DeviceName: deviceName, Name: name, Notes: request.Notes, Actor: actor})
	if err != nil {
		writeTestSessionError(w, err)
		return
	}
	response := testSessionResponse{Session: session}
	for _, previous := range stopped {
		response.Warnings = append(response.Warnings, fmt.Sprintf("Stopped the previous test session %q for this device.", previous.Name))
		if warning := s.stopLinkedCapture(r.Context(), previous); warning != "" {
			response.Warnings = append(response.Warnings, warning)
		}
	}
	if request.Capture || request.FullCapture {
		captureID, warning := s.startSessionCapture(r.Context(), session, actor, request.FullCapture)
		if warning != "" {
			response.Warnings = append(response.Warnings, warning)
		}
		if captureID != "" {
			if attached, attachErr := store.AttachCapture(session.ID, captureID); attachErr == nil {
				response.Session = attached
			} else {
				response.Warnings = append(response.Warnings, fmt.Sprintf("Capture %s started but could not be linked to the test session.", captureID))
			}
		}
	}
	s.logger.Info("test session started", "username", actor, "test_session_id", session.ID, "device_id", device.ID, "capture", request.Capture || request.FullCapture, "full_capture", request.FullCapture)
	writeJSON(w, http.StatusCreated, response)
}

func defaultTestSessionName(deviceName string, now time.Time) string {
	suffix := " — " + now.UTC().Format("2006-01-02 15:04")
	runes := []rune(deviceName)
	for len(string(runes))+len(suffix) > testsession.MaxNameBytes && len(runes) > 0 {
		runes = runes[:len(runes)-1]
	}
	return strings.TrimSpace(string(runes)) + suffix
}

// startSessionCapture starts a bounded capture (headers only unless full)
// through the same gateway path as POST /api/v1/captures. Failure never
// blocks the session.
func (s *Server) startSessionCapture(ctx context.Context, session testsession.Session, actor string, full bool) (string, string) {
	name := session.Name
	if len([]rune(name)) > 96 {
		name = string([]rune(name)[:96])
	}
	start := capture.StartRequest{
		Name:          strings.TrimSpace(name),
		Description:   fmt.Sprintf("Packet capture for test session %s (%s).", session.ID, session.DeviceName),
		Mode:          captureMode(full),
		StartReason:   "Test session " + session.ID,
		Administrator: actor,
		// The session ID makes retries of the same session idempotent.
		IdempotencyKey: "test-session-" + strings.TrimPrefix(session.ID, "ts-"),
	}.WithDefaults()
	if err := start.Validate(); err != nil {
		return "", "The packet capture could not be configured, so the test session is running without one."
	}
	var result capture.View
	if err := s.gateway.Call(ctx, "StartCapture", gatewayprotocol.StartCaptureParams{Request: start}, &result); err != nil {
		s.logger.Warn("test session capture did not start", "test_session_id", session.ID, "error", err)
		return "", "Packet capture could not start (for example, another capture is running or the gateway is unavailable). The test session is running without a capture; start one from Captures if you need packets."
	}
	if !capture.ValidSessionID(result.Session.ID) {
		return "", "Packet capture returned an invalid identity, so the test session is running without a capture."
	}
	return result.Session.ID, ""
}

// stopLinkedCapture stops the capture started with a session, if any.
func (s *Server) stopLinkedCapture(ctx context.Context, session testsession.Session) string {
	if session.CaptureSessionID == nil {
		return ""
	}
	var result capture.View
	if err := s.gateway.Call(ctx, "StopCapture", gatewayprotocol.StopCaptureParams{SessionID: *session.CaptureSessionID}, &result); err != nil {
		s.logger.Warn("test session capture did not stop", "test_session_id", session.ID, "capture_id", *session.CaptureSessionID, "error", err)
		return fmt.Sprintf("Capture %s could not be stopped automatically (it may already have ended). Check Captures.", *session.CaptureSessionID)
	}
	return ""
}

func (s *Server) listTestSessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	store := s.testSessions()
	if store == nil {
		writeError(w, http.StatusServiceUnavailable, "test_sessions_unavailable", "Test sessions are unavailable because the control API has no data directory.")
		return
	}
	values := r.URL.Query()
	if err := allowIntelParameters(values, "device", "state", "limit"); err != nil {
		writeIntelError(w, err)
		return
	}
	filter := testsession.Filter{Limit: testsession.DefaultLimit}
	if raw := values.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > testsession.MaxLimit {
			writeError(w, http.StatusBadRequest, "invalid_limit", "Limit must be between 1 and 500.")
			return
		}
		filter.Limit = limit
	}
	if raw := strings.ToUpper(strings.TrimSpace(values.Get("state"))); raw != "" {
		if raw != string(testsession.StateRunning) && raw != string(testsession.StateStopped) {
			writeError(w, http.StatusBadRequest, "invalid_state", "State must be RUNNING or STOPPED.")
			return
		}
		filter.State = testsession.State(raw)
	}
	if ref := values.Get("device"); ref != "" {
		device, err := s.resolveDeviceRef(r.Context(), ref)
		if err != nil {
			writeDeviceRefError(w, err)
			return
		}
		filter.DeviceID = device.ID
	}
	sessions, total, err := store.List(filter)
	if err != nil {
		writeTestSessionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, testSessionList{Schema: 1, Sessions: sessions, Total: total, Truncated: total > len(sessions)})
}

func (s *Server) getTestSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	session, err := s.lookupTestSession(r.PathValue("sessionID"))
	if err != nil {
		writeIntelError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, session)
}

func (s *Server) updateTestSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	store := s.testSessions()
	if store == nil {
		writeError(w, http.StatusServiceUnavailable, "test_sessions_unavailable", "Test sessions are unavailable because the control API has no data directory.")
		return
	}
	var request updateTestSessionRequest
	if err := decodeJSONBounded(r, &request, 8<<10); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", `Send JSON like {"name":"Firmware 2.1 first boot","notes":"…"} with Content-Type: application/json.`)
		return
	}
	session, err := store.Update(r.PathValue("sessionID"), testsession.Update{Name: request.Name, Notes: request.Notes})
	if err != nil {
		writeTestSessionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, session)
}

func (s *Server) stopTestSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	store := s.testSessions()
	if store == nil {
		writeError(w, http.StatusServiceUnavailable, "test_sessions_unavailable", "Test sessions are unavailable because the control API has no data directory.")
		return
	}
	before, err := store.Get(r.PathValue("sessionID"))
	if err != nil {
		writeTestSessionError(w, err)
		return
	}
	session, err := store.Stop(before.ID)
	if err != nil {
		writeTestSessionError(w, err)
		return
	}
	response := testSessionResponse{Session: session}
	if before.State == testsession.StateRunning {
		if warning := s.stopLinkedCapture(r.Context(), session); warning != "" {
			response.Warnings = append(response.Warnings, warning)
		}
		s.logger.Info("test session stopped", "username", sessionUsername(r.Context()), "test_session_id", session.ID)
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) deleteTestSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	store := s.testSessions()
	if store == nil {
		writeError(w, http.StatusServiceUnavailable, "test_sessions_unavailable", "Test sessions are unavailable because the control API has no data directory.")
		return
	}
	removed, err := store.Delete(r.PathValue("sessionID"))
	if err != nil {
		writeTestSessionError(w, err)
		return
	}
	response := deletedTestSession{Schema: 1, ID: removed.ID, Deleted: true}
	// A running session's capture would otherwise keep running unowned.
	if removed.State == testsession.StateRunning {
		if warning := s.stopLinkedCapture(r.Context(), removed); warning != "" {
			response.Warnings = append(response.Warnings, warning)
		}
	}
	s.logger.Info("test session deleted", "username", sessionUsername(r.Context()), "test_session_id", removed.ID)
	writeJSON(w, http.StatusOK, response)
}

func writeTestSessionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, testsession.ErrNotFound):
		writeError(w, http.StatusNotFound, "test_session_not_found", "No test session has that ID. Run `shakerproxy test list` or open Tests.")
	case errors.Is(err, testsession.ErrInvalid):
		writeError(w, http.StatusBadRequest, "invalid_test_session", "Names must be 1-120 characters on one line and notes at most 4096 characters.")
	case errors.Is(err, testsession.ErrStoreFull):
		writeError(w, http.StatusConflict, "test_sessions_full", "Too many test sessions are running. Stop some sessions, then try again.")
	default:
		writeError(w, http.StatusServiceUnavailable, "test_sessions_unavailable", "Test sessions are unavailable right now. Try again, or check System → Status.")
	}
}

func captureMode(full bool) capture.Mode {
	if full {
		return capture.ModeFull
	}
	return capture.ModeHeaders
}
