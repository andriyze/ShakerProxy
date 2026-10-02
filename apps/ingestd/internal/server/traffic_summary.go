package server

import (
	"context"
	"net/http"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

// trafficSummaryTimeout bounds one summary below the query client's 4 s; each
// statement also has a database-side timeout.
const trafficSummaryTimeout = 3500 * time.Millisecond

// listTrafficSummary serves the private events summary (timeline, facets and
// totals) behind the event query token.
func (s *Server) listTrafficSummary(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	query, err := ingest.ParseInternalTrafficSummaryQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_query", err.Error())
		return
	}
	reader, ok := s.recentEvents.(ingest.TrafficSummaryReader)
	if !ok || reader == nil {
		writeError(w, http.StatusServiceUnavailable, "event_summary_unavailable", "events summary storage is unavailable")
		return
	}
	queryContext, cancel := context.WithTimeout(r.Context(), trafficSummaryTimeout)
	defer cancel()
	summary, err := reader.QueryTrafficSummary(queryContext, query)
	if err != nil {
		s.logger.Warn("events summary query failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "event_summary_unavailable", "the events summary is temporarily unavailable")
		return
	}
	if err := ingest.ValidateTrafficSummary(summary, query); err != nil {
		s.logger.Error("events summary reader returned an invalid summary", "error", err)
		writeError(w, http.StatusServiceUnavailable, "event_summary_unavailable", "the events summary is temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, summary)
}
