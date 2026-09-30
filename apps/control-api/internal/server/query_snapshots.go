package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
	deviceinventory "shakerproxy.dev/shakerproxy/internal/inventory"
	"shakerproxy.dev/shakerproxy/internal/querylang"
)

func (s *Server) createEventQuerySnapshot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.eventSnapshots == nil {
		writeError(w, http.StatusServiceUnavailable, "query_snapshot_unavailable", "event query snapshots are not configured")
		return
	}
	var input ingest.EventQuerySnapshotInput
	if err := decodeJSON(r, &input); err != nil || ingest.ValidateEventQuerySort(input.Sort) != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "event query snapshot request does not match the schema")
		return
	}
	filter, err := querylang.Parse(input.Query)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_query", "event query snapshot filter is invalid")
		return
	}
	lifetime := ingest.DefaultQuerySnapshotTTL
	if input.ExpiresInSeconds != 0 {
		if input.ExpiresInSeconds < int(ingest.MinQuerySnapshotTTL/time.Second) || input.ExpiresInSeconds > int(ingest.MaxQuerySnapshotTTL/time.Second) {
			writeError(w, http.StatusBadRequest, "invalid_request", "event query snapshot expiry must be between 60 and 3600 seconds")
			return
		}
		lifetime = time.Duration(input.ExpiresInSeconds) * time.Second
	}
	query := ingest.RecentEventQuery{Limit: 1, Filter: filter}
	if err := s.resolveEventDeviceSelectors(&query); err != nil {
		if errors.Is(err, deviceinventory.ErrAliasResolutionLimit) {
			writeError(w, http.StatusUnprocessableEntity, "query_too_broad", "device selector query matches too many devices; use device.id to narrow it")
			return
		}
		s.logger.Warn("event query snapshot selector resolution failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "device_selectors_unavailable", "device selector search is temporarily unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 7*time.Second)
	defer cancel()
	snapshot, err := s.eventSnapshots.CreateEventQuerySnapshot(ctx, sessionUsername(r.Context()), filter.Canonical, query, lifetime)
	if err != nil {
		s.writeEventQuerySnapshotError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, snapshot)
}

func (s *Server) getEventQuerySnapshot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.eventSnapshots == nil {
		writeError(w, http.StatusServiceUnavailable, "query_snapshot_unavailable", "event query snapshots are not configured")
		return
	}
	id := r.PathValue("snapshotID")
	if !ingest.ValidQuerySnapshotID(id) {
		writeError(w, http.StatusBadRequest, "invalid_request", "event query snapshot ID is invalid")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	snapshot, err := s.eventSnapshots.GetEventQuerySnapshot(ctx, sessionUsername(r.Context()), id)
	if err != nil {
		s.writeEventQuerySnapshotError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) writeEventQuerySnapshotError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ingest.ErrQuerySnapshotNotFound):
		writeError(w, http.StatusNotFound, "query_snapshot_not_found", "event query snapshot was not found or has expired")
	case errors.Is(err, ingest.ErrQuerySnapshotLimit):
		writeError(w, http.StatusConflict, "query_snapshot_limit", "too many active event query snapshots; wait for one to expire")
	default:
		s.logger.Warn("event query snapshot request failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "query_snapshot_unavailable", "event query snapshots are temporarily unavailable")
	}
}
