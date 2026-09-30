package server

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/testlab"
)

type testLabRunRequest struct {
	Profile  testlab.Profile `json:"profile"`
	Password string          `json:"password"`
}

type testLabCleanupRequest struct {
	Password string `json:"password"`
}

func (s *Server) TestLabHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/self-test/status", s.requireAuth(http.HandlerFunc(s.testLabStatus)))
	mux.Handle("POST /api/v1/self-test/run", s.requireAuth(http.HandlerFunc(s.runTestLab)))
	mux.Handle("POST /api/v1/self-test/cleanup", s.requireAuth(http.HandlerFunc(s.cleanupTestLab)))
	return s.wrapMux(mux)
}

func testLabClient(timeout time.Duration) testlab.Client {
	path := strings.TrimSpace(os.Getenv("SHAKERPROXY_TESTLAB_SOCKET"))
	if path == "" {
		path = testlab.DefaultSocketPath
	}
	return testlab.Client{SocketPath: path, Timeout: timeout}
}

func (s *Server) testLabStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	status, err := testLabClient(3 * time.Second).Status(ctx)
	if err != nil {
		testLabError(w, http.StatusServiceUnavailable, "test_lab_unavailable", "The virtual test lab is unavailable; check that shakerproxy-testlabd is running.")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) runTestLab(w http.ResponseWriter, r *http.Request) {
	var request testLabRunRequest
	if err := decodeJSONBounded(r, &request, 8<<10); err != nil {
		w.Header().Set("Cache-Control", "no-store")
		writeDecodeError(w, err, "virtual test-lab run")
		return
	}
	request.Password = strings.TrimSpace(request.Password)
	if !testlab.ValidProfile(request.Profile) {
		testLabError(w, http.StatusBadRequest, "invalid_test_lab_request", "Choose a supported virtual test-lab profile.")
		return
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordRecent) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), testlab.DefaultRunTimeout+10*time.Second)
	defer cancel()
	run, err := testLabClient(testlab.DefaultRunTimeout+10*time.Second).Run(ctx, request.Profile)
	if err != nil {
		testLabError(w, http.StatusServiceUnavailable, "test_lab_run_failed", "The virtual test lab could not complete; check shakerproxy-testlabd logs and try again.")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) cleanupTestLab(w http.ResponseWriter, r *http.Request) {
	var request testLabCleanupRequest
	if err := decodeOptionalJSON(r, &request, 4<<10); err != nil {
		w.Header().Set("Cache-Control", "no-store")
		writeDecodeError(w, err, "virtual test-lab cleanup")
		return
	}
	request.Password = strings.TrimSpace(request.Password)
	if !s.confirmAdministrator(w, r, request.Password, passwordRecent) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := testLabClient(10 * time.Second).Cleanup(ctx); err != nil {
		testLabError(w, http.StatusServiceUnavailable, "test_lab_cleanup_failed", "The virtual test lab cleanup failed; check shakerproxy-testlabd logs and try again.")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"clean": true})
}

func testLabError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Cache-Control", "no-store")
	writeError(w, status, code, message)
}
