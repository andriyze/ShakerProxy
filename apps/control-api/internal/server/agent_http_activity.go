package server

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"shakerproxy.dev/shakerproxy/internal/apitoken"
	"shakerproxy.dev/shakerproxy/internal/ingest"
)

var agentHTTPActivityWindows = map[string]int{
	"5m": 5 * 60, "15m": 15 * 60, "1h": 60 * 60, "6h": 6 * 60 * 60, "24h": 24 * 60 * 60,
}

// AgentHTTPActivityHandler is a read-only metadata route for local automation.
// It cannot return HTTP headers, bodies, cookies, credentials, or full URLs.
func (s *Server) AgentHTTPActivityHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/agent/http-activity", s.requireAuthOrScope(apitoken.ScopeTrafficRead, http.HandlerFunc(s.listAgentHTTPActivity)))
	return s.wrapMux(mux)
}

func (s *Server) listAgentHTTPActivity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	query, err := parseAgentHTTPActivityQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_query", err.Error())
		return
	}
	reader, ok := s.eventReader.(ingest.HTTPActivityReader)
	if !ok || reader == nil {
		writeError(w, http.StatusServiceUnavailable, "http_activity_unavailable", "HTTP activity metadata is unavailable")
		return
	}
	queryContext, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	page, err := reader.QueryHTTPActivity(queryContext, query)
	if err != nil {
		s.logger.Warn("agent HTTP activity query failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "http_activity_unavailable", "HTTP activity metadata is temporarily unavailable")
		return
	}
	if err := page.Validate(query); err != nil {
		s.logger.Error("agent HTTP activity reader returned an invalid page", "error", err)
		writeError(w, http.StatusServiceUnavailable, "http_activity_unavailable", "HTTP activity metadata is temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func parseAgentHTTPActivityQuery(values url.Values) (ingest.HTTPActivityQuery, error) {
	allowed := map[string]bool{"limit": true, "window": true, "device_id": true, "host": true, "method": true, "cursor": true}
	for key, entries := range values {
		if !allowed[key] || len(entries) != 1 {
			return ingest.HTTPActivityQuery{}, errors.New("agent HTTP activity query contains an unsupported or repeated parameter")
		}
	}
	limit := ingest.DefaultHTTPActivityLimit
	if raw := values.Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return ingest.HTTPActivityQuery{}, errors.New("agent HTTP activity limit is invalid")
		}
		limit = parsed
	}
	window := values.Get("window")
	if window == "" {
		window = "15m"
	}
	windowSeconds, ok := agentHTTPActivityWindows[window]
	if !ok {
		return ingest.HTTPActivityQuery{}, errors.New("agent HTTP activity window must be 5m, 15m, 1h, 6h, or 24h")
	}
	internal := make(url.Values)
	internal.Set("limit", strconv.Itoa(limit))
	internal.Set("window_seconds", strconv.Itoa(windowSeconds))
	for _, name := range []string{"device_id", "host", "method", "cursor"} {
		if value := values.Get(name); value != "" {
			internal.Set(name, value)
		}
	}
	return ingest.ParseInternalHTTPActivityQuery(internal)
}
