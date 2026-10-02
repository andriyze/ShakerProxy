package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
	deviceinventory "shakerproxy.dev/shakerproxy/internal/inventory"
)

// listTrafficSummary serves the live Traffic view's timeline, facet sidebar
// and totals for the same filter GET /api/v1/events takes.
func (s *Server) listTrafficSummary(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	query, err := ingest.ParseTrafficSummaryQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_query", err.Error())
		return
	}
	reader, ok := s.eventReader.(ingest.TrafficSummaryReader)
	if !ok || reader == nil {
		writeError(w, http.StatusServiceUnavailable, "event_summary_unavailable", "The events summary needs the event store. Check `shakerproxy status` and make sure ingestd and PostgreSQL are running.")
		return
	}
	if err := s.resolveEventDeviceSelectors(&query.Events); err != nil {
		if errors.Is(err, deviceinventory.ErrAliasResolutionLimit) {
			writeError(w, http.StatusUnprocessableEntity, "query_too_broad", "device selector query matches too many devices; use device.id to narrow it")
			return
		}
		s.logger.Warn("device selector query resolution failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "device_selectors_unavailable", "device selector search is temporarily unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	summary, err := reader.QueryTrafficSummary(ctx, query)
	if err != nil {
		s.logger.Warn("events summary query failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "event_summary_unavailable", "The events summary is temporarily unavailable. Try again, or narrow the time window.")
		return
	}
	s.projectSummaryDeviceNames(&summary)
	writeJSON(w, http.StatusOK, summary)
}

// projectSummaryDeviceNames labels the device facet with friendly names.
func (s *Server) projectSummaryDeviceNames(summary *ingest.TrafficSummary) {
	if s.nameResolver == nil || s.nameResolver.Ready() != nil {
		return
	}
	now := time.Now().UTC()
	for facetIndex := range summary.Facets {
		if summary.Facets[facetIndex].Field != ingest.SummaryFacetDevice {
			continue
		}
		values := summary.Facets[facetIndex].Values
		for index := range values {
			if strings.HasPrefix(values[index].Value, "ip:") {
				continue
			}
			if projection, found, err := s.nameResolver.Resolve(values[index].Value, now); err == nil && found && projection.CurrentFriendlyName != "" {
				values[index].Label = projection.CurrentFriendlyName
			}
		}
	}
}
