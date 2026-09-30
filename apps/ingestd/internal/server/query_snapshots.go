package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

type internalQuerySnapshotRequest struct {
	Schema               int    `json:"schema"`
	PublicCanonicalQuery string `json:"public_canonical_query"`
	EncodedQuery         string `json:"encoded_query"`
	ExpiresInSeconds     int    `json:"expires_in_seconds"`
}

func (s *Server) createEventQuerySnapshot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := eventQuerySnapshotActor(w, r)
	if !ok {
		return
	}
	var request internalQuerySnapshotRequest
	if err := decodeQuerySnapshotJSON(r, &request); err != nil || request.Schema != ingest.QuerySnapshotSchemaVersion || len(request.EncodedQuery) > 40<<10 || request.ExpiresInSeconds < int(ingest.MinQuerySnapshotTTL/time.Second) || request.ExpiresInSeconds > int(ingest.MaxQuerySnapshotTTL/time.Second) {
		writeError(w, http.StatusBadRequest, "invalid_request", "event query snapshot request is invalid")
		return
	}
	values, err := url.ParseQuery(request.EncodedQuery)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_query", "event query snapshot filter is invalid")
		return
	}
	query, err := ingest.ParseInternalRecentEventQuery(values)
	if err != nil || !query.BeforeOccurredAt.IsZero() || query.BeforeRecordID != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "event query snapshot filter is invalid")
		return
	}
	lifetime := time.Duration(request.ExpiresInSeconds) * time.Second
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	snapshot, err := s.eventSnapshots.CreateEventQuerySnapshot(ctx, actor, request.PublicCanonicalQuery, query, lifetime)
	if err != nil {
		s.writeEventQuerySnapshotError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, snapshot)
}

func (s *Server) getEventQuerySnapshot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := eventQuerySnapshotActor(w, r)
	if !ok {
		return
	}
	id := r.PathValue("snapshotID")
	if !ingest.ValidQuerySnapshotID(id) {
		writeError(w, http.StatusBadRequest, "invalid_request", "event query snapshot ID is invalid")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	snapshot, err := s.eventSnapshots.GetEventQuerySnapshot(ctx, actor, id)
	if err != nil {
		s.writeEventQuerySnapshotError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func eventQuerySnapshotActor(w http.ResponseWriter, r *http.Request) (string, bool) {
	actor := r.Header.Get("X-ShakerProxy-Actor")
	if actor == "" || len(actor) > 96 {
		writeError(w, http.StatusBadRequest, "invalid_actor", "event query snapshot actor is invalid")
		return "", false
	}
	for _, char := range actor {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '.' || char == '_' || char == '@' || char == '-') {
			writeError(w, http.StatusBadRequest, "invalid_actor", "event query snapshot actor is invalid")
			return "", false
		}
	}
	return actor, true
}

func decodeQuerySnapshotJSON(r *http.Request, destination any) error {
	if r.Header.Get("Content-Type") != "application/json" {
		return errors.New("Content-Type must be application/json")
	}
	limited := &io.LimitedReader{R: r.Body, N: (48 << 10) + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil || decoder.Decode(&struct{}{}) != io.EOF || limited.N <= 0 {
		return errors.New("event query snapshot JSON is invalid or oversized")
	}
	return nil
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
