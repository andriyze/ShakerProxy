package server

import (
	"context"
	"net/http"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

// DeviceActivityHandler exposes one private, query-token-protected, read-only
// aggregation of a single device's normalized events for device reports.
func (s *Server) DeviceActivityHandler() http.Handler {
	return securityHeaders(s.requireQueryToken(http.HandlerFunc(s.getDeviceActivity)))
}

func (s *Server) getDeviceActivity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	query, err := ingest.ParseInternalDeviceActivityQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_query", err.Error())
		return
	}
	reader, ok := s.recentEvents.(ingest.DeviceActivityReader)
	if !ok || reader == nil {
		writeError(w, http.StatusServiceUnavailable, "device_activity_unavailable", "device activity storage is unavailable")
		return
	}
	queryContext, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	activity, err := reader.QueryDeviceActivity(queryContext, query)
	if err != nil {
		s.logger.Warn("device activity query failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "device_activity_unavailable", "device activity is temporarily unavailable")
		return
	}
	if err := activity.Validate(query); err != nil {
		s.logger.Error("device activity reader returned an invalid aggregation", "error", err)
		writeError(w, http.StatusServiceUnavailable, "device_activity_unavailable", "device activity is temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, activity)
}
