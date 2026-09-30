package server

import (
	"errors"
	"net/http"
	"strings"

	"shakerproxy.dev/shakerproxy/internal/contentpolicy"
)

const defaultHTTPContentPolicyPath = "/var/lib/shakerproxy/content-policy/policy.json"

type httpContentPolicyView struct {
	Schema                     int                  `json:"schema"`
	Policy                     contentpolicy.Policy `json:"policy"`
	TLSInterceptionIndependent bool                 `json:"tls_interception_independent"`
	AppliesWithoutRestart      bool                 `json:"applies_without_restart"`
	StorageBoundary            string               `json:"storage_boundary"`
	MaximumBodyPreviewBytes    int                  `json:"maximum_body_preview_bytes"`
	SensitiveHeadersMasked     bool                 `json:"sensitive_headers_masked_by_default"`
}

type applyHTTPContentPolicyRequest struct {
	ExpectedRevision   uint64 `json:"expected_revision"`
	CaptureHTTPContent bool   `json:"capture_http_content"`
	Password           string `json:"password"`
}

// HTTPContentPolicyHandler exposes a narrow session-only control surface for
// decrypted HTTP retention. It is intentionally separate from traffic-policy
// TLS interception: disabling plaintext retention must not alter routing,
// certificate trust, or whether eligible TLS connections are intercepted.
func (s *Server) HTTPContentPolicyHandler(path string) http.Handler {
	path = strings.TrimSpace(path)
	if path == "" {
		path = defaultHTTPContentPolicyPath
	}
	store := &contentpolicy.Store{Path: path}
	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/http-content-policy", s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.getHTTPContentPolicy(store, w, r)
	})))
	mux.Handle("PUT /api/v1/http-content-policy", s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.applyHTTPContentPolicy(store, w, r)
	})))
	return s.wrapMux(mux)
}

func (s *Server) getHTTPContentPolicy(store *contentpolicy.Store, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "HTTP content policy does not accept query parameters")
		return
	}
	policy, err := store.Load()
	if err != nil {
		s.logger.Warn("HTTP content policy read failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "http_content_policy_unavailable", "decrypted-content retention policy is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, newHTTPContentPolicyView(policy))
}

func (s *Server) applyHTTPContentPolicy(store *contentpolicy.Store, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "HTTP content policy does not accept query parameters")
		return
	}
	var request applyHTTPContentPolicyRequest
	if err := decodeJSON(r, &request); err != nil || request.ExpectedRevision == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "request does not match the HTTP content policy schema")
		return
	}
	username := sessionUsername(r.Context())
	if !s.confirmAdministrator(w, r, request.Password, httpContentPasswordPolicy(request.CaptureHTTPContent)) {
		s.logger.Warn("HTTP content policy reauthentication failed", "username", username)
		return
	}
	policy, err := store.Apply(request.ExpectedRevision, request.CaptureHTTPContent, username)
	if errors.Is(err, contentpolicy.ErrRevisionConflict) {
		writeError(w, http.StatusConflict, "http_content_policy_revision_conflict", contentpolicy.ErrRevisionConflict.Error())
		return
	}
	if err != nil {
		s.logger.Error("HTTP content policy persistence failed", "username", username, "error", err)
		writeError(w, http.StatusServiceUnavailable, "http_content_policy_unavailable", "decrypted-content retention policy could not be persisted")
		return
	}
	s.logger.Info("HTTP content retention changed", "username", username, "capture_http_content", policy.CaptureHTTPContent, "revision", policy.Revision)
	writeJSON(w, http.StatusOK, newHTTPContentPolicyView(policy))
}

func newHTTPContentPolicyView(policy contentpolicy.Policy) httpContentPolicyView {
	return httpContentPolicyView{
		Schema:                     1,
		Policy:                     policy,
		TLSInterceptionIndependent: true,
		AppliesWithoutRestart:      true,
		StorageBoundary:            "local_sensor_only",
		MaximumBodyPreviewBytes:    64 * 1024,
		SensitiveHeadersMasked:     true,
	}
}
