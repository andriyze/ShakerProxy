package server

import (
	"context"
	"net/http"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

const devicePlatformTimeout = 3 * time.Second

// listDevicePlatformHints serves what each device most likely is, from the
// connectivity checks it made. It is protected by the event query token.
func (s *Server) listDevicePlatformHints(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if len(r.URL.Query()) != 0 {
		writeError(w, http.StatusBadRequest, "invalid_query", "device platform hints take no parameters")
		return
	}
	reader, ok := s.recentEvents.(ingest.DevicePlatformHintReader)
	if !ok || reader == nil {
		writeError(w, http.StatusServiceUnavailable, "device_platform_unavailable", "device platform hints are unavailable")
		return
	}
	queryContext, cancel := context.WithTimeout(r.Context(), devicePlatformTimeout)
	defer cancel()
	hints, err := reader.QueryDevicePlatformHints(queryContext)
	if err != nil {
		s.logger.Warn("device platform query failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "device_platform_unavailable", "device platform hints are temporarily unavailable")
		return
	}
	if err := hints.Validate(); err != nil {
		s.logger.Error("device platform reader returned invalid hints", "error", err)
		writeError(w, http.StatusServiceUnavailable, "device_platform_unavailable", "device platform hints are temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, hints)
}
