package server

import (
	"context"
	"net/http"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

const labPresenceTimeout = 3 * time.Second

// listLabPresence reports who was seen on the lab prefix recently and
// whether their traffic reached ShakerProxy.
func (s *Server) listLabPresence(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	query := r.URL.Query()
	if len(query) != 1 || len(query["prefix"]) != 1 {
		writeError(w, http.StatusBadRequest, "invalid_query", "lab presence takes exactly one prefix parameter")
		return
	}
	prefix, err := ingest.ParseLabPresencePrefix(query.Get("prefix"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_query", err.Error())
		return
	}
	reader, ok := s.recentEvents.(ingest.LabPresenceReader)
	if !ok || reader == nil {
		writeError(w, http.StatusServiceUnavailable, "lab_presence_unavailable", "lab presence is unavailable")
		return
	}
	queryContext, cancel := context.WithTimeout(r.Context(), labPresenceTimeout)
	defer cancel()
	presence, err := reader.QueryLabPresence(queryContext, prefix)
	if err != nil {
		s.logger.Warn("lab presence query failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "lab_presence_unavailable", "lab presence is temporarily unavailable")
		return
	}
	if err := presence.Validate(); err != nil || presence.Prefix != prefix.String() {
		s.logger.Error("lab presence reader returned an invalid answer", "error", err)
		writeError(w, http.StatusServiceUnavailable, "lab_presence_unavailable", "lab presence is temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, presence)
}
