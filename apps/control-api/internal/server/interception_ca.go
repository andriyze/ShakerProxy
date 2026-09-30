package server

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"shakerproxy.dev/shakerproxy/internal/interceptionpki"
)

const (
	interceptionCAMissingMessage     = "ShakerProxy has not created its interception certificate yet. Run `sudo systemctl restart shakerproxy-interception-pki`, then try again."
	interceptionCAUnreadableMessage  = "The interception certificate could not be read. Check `sudo systemctl status shakerproxy-interception-pki`."
	interceptionCAFormatErrorMessage = "Use format=pem or format=der."
)

func (s *Server) interceptionCAStatus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	status, err := interceptionpki.LoadPublicStatus(interceptionPublicRoot())
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusServiceUnavailable, "interception_ca_not_provisioned", interceptionCAMissingMessage)
		return
	}
	if err != nil {
		s.logger.Warn("interception CA status unavailable", "error", err)
		writeError(w, http.StatusServiceUnavailable, "interception_ca_unavailable", interceptionCAUnreadableMessage)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":                   status,
		"download_pem":             "/api/v1/interception-ca/download?format=pem",
		"download_der":             "/api/v1/interception-ca/download?format=der",
		"onboarding":               "/api/v1/interception-ca/onboarding",
		"private_key_downloadable": false,
	})
}

func (s *Server) downloadInterceptionCA(w http.ResponseWriter, r *http.Request) {
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	switch format {
	case "", "pem", "crt", "der", "cer":
	default:
		writeError(w, http.StatusBadRequest, "unsupported_certificate_format", interceptionCAFormatErrorMessage)
		return
	}
	data, contentType, filename, err := interceptionpki.PublicCertificate(interceptionPublicRoot(), format)
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusServiceUnavailable, "interception_ca_not_provisioned", interceptionCAMissingMessage)
		return
	}
	if err != nil {
		s.logger.Warn("interception CA download unavailable", "error", err)
		writeError(w, http.StatusServiceUnavailable, "interception_ca_unavailable", interceptionCAUnreadableMessage)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func interceptionPublicRoot() string {
	if value := strings.TrimSpace(os.Getenv("SHAKERPROXY_PUBLIC_ROOT")); value != "" {
		return filepath.Clean(value)
	}
	return "/var/lib/shakerproxy/public"
}
