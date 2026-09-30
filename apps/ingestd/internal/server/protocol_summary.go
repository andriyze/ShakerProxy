package server

import (
	"context"
	"net/http"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

// protocolSummaryTimeout stays below the HTTP server's 10 s write timeout.
const protocolSummaryTimeout = 8 * time.Second

// listProtocolSummary serves the private protocol discovery aggregate. It is
// protected by the event query token like the other read routes.
func (s *Server) listProtocolSummary(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	query, err := ingest.ParseInternalProtocolSummaryQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_query", err.Error())
		return
	}
	reader, ok := s.recentEvents.(ingest.ProtocolSummaryReader)
	if !ok || reader == nil {
		writeError(w, http.StatusServiceUnavailable, "protocol_summary_unavailable", "protocol summary storage is unavailable")
		return
	}
	queryContext, cancel := context.WithTimeout(r.Context(), protocolSummaryTimeout)
	defer cancel()
	summary, err := reader.QueryProtocolSummary(queryContext, query)
	if err != nil {
		s.logger.Warn("protocol summary query failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "protocol_summary_unavailable", "protocol summary is temporarily unavailable")
		return
	}
	if err := summary.Validate(query); err != nil {
		s.logger.Error("protocol summary reader returned an invalid summary", "error", err)
		writeError(w, http.StatusServiceUnavailable, "protocol_summary_unavailable", "protocol summary is temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, summary)
}
