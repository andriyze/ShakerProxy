package server

import (
	"context"
	"net/http"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

// HTTPActivityHandler exposes one private query-token-protected metadata route.
// The storage reader selects only bounded HTTP scalars and never full payloads.
func (s *Server) HTTPActivityHandler() http.Handler {
	return securityHeaders(s.requireQueryToken(http.HandlerFunc(s.listHTTPActivity)))
}

func (s *Server) listHTTPActivity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	query, err := ingest.ParseInternalHTTPActivityQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_query", err.Error())
		return
	}
	reader, ok := s.recentEvents.(ingest.HTTPActivityReader)
	if !ok || reader == nil {
		writeError(w, http.StatusServiceUnavailable, "http_activity_unavailable", "HTTP activity metadata storage is unavailable")
		return
	}
	queryContext, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	page, err := reader.QueryHTTPActivity(queryContext, query)
	if err != nil {
		s.logger.Warn("HTTP activity metadata query failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "http_activity_unavailable", "HTTP activity metadata is temporarily unavailable")
		return
	}
	if err := page.Validate(query); err != nil {
		s.logger.Error("HTTP activity metadata reader returned an invalid page", "error", err)
		writeError(w, http.StatusServiceUnavailable, "http_activity_unavailable", "HTTP activity metadata is temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, page)
}
