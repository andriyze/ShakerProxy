package server

import (
	"errors"
	"net/http"
	"strconv"
	"unicode/utf8"

	deviceinventory "shakerproxy.dev/shakerproxy/internal/inventory"
)

type eventQueryCompletionPage struct {
	Schema    int                                    `json:"schema"`
	Field     string                                 `json:"field"`
	Prefix    string                                 `json:"prefix"`
	Values    []deviceinventory.QueryValueCompletion `json:"values"`
	Truncated bool                                   `json:"truncated"`
}

func (s *Server) eventQueryCompletions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	values := r.URL.Query()
	for key, entries := range values {
		if key != "field" && key != "prefix" && key != "limit" || len(entries) != 1 {
			writeError(w, http.StatusBadRequest, "invalid_query", "query completion contains an unsupported or repeated parameter")
			return
		}
	}
	field := values.Get("field")
	if field != "device.name" && field != "device.tag" {
		writeError(w, http.StatusBadRequest, "invalid_query", "query completion field is unsupported")
		return
	}
	prefix := values.Get("prefix")
	if len(prefix) > 128 || !utf8.ValidString(prefix) {
		writeError(w, http.StatusBadRequest, "invalid_query", "query completion prefix is invalid")
		return
	}
	for _, character := range prefix {
		if character < 0x20 || character == 0x7f {
			writeError(w, http.StatusBadRequest, "invalid_query", "query completion prefix is invalid")
			return
		}
	}
	limit := 10
	if raw := values.Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > deviceinventory.MaxQueryValueCompletions {
			writeError(w, http.StatusBadRequest, "invalid_query", "query completion limit must be between 1 and 20")
			return
		}
		limit = parsed
	}
	if s.nameResolver == nil {
		writeError(w, http.StatusServiceUnavailable, "device_selectors_unavailable", "device selector completion is not configured")
		return
	}
	completed, truncated, err := s.nameResolver.CompleteQueryValues(field, prefix, limit)
	if err != nil {
		if errors.Is(err, deviceinventory.ErrAliasResolutionLimit) {
			writeError(w, http.StatusUnprocessableEntity, "query_too_broad", "device selector completion is too broad")
			return
		}
		s.logger.Warn("device selector completion failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "device_selectors_unavailable", "device selector completion is temporarily unavailable")
		return
	}
	if completed == nil {
		completed = []deviceinventory.QueryValueCompletion{}
	}
	writeJSON(w, http.StatusOK, eventQueryCompletionPage{Schema: 1, Field: field, Prefix: prefix, Values: completed, Truncated: truncated})
}
