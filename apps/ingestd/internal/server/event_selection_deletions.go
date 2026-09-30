package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

const maxEventSelectionDeletionRequestBytes = 128 << 10

type EventSelectionDeletionLifecycle interface {
	Preview(context.Context, ingest.EventSelectionDeletionPreviewRequest) (ingest.EventSelectionDeletionBundle, error)
	Delete(context.Context, ingest.EventSelectionDeletionRequest) (ingest.EventSelectionDeletionOutcome, error)
}

func (s *Server) previewEventSelectionDeletion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var request ingest.EventSelectionDeletionPreviewRequest
	if err := decodeStrictDeletionJSON(r, &request, maxEventSelectionDeletionRequestBytes); err != nil || request.Validate() != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "event selection deletion preview request is invalid")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	preview, err := s.selectionDeletions.Preview(ctx, request)
	if err != nil {
		s.writeEventSelectionDeletionError(w, err)
		return
	}
	if preview.Validate() != nil || preview.Actor != request.Actor || preview.SelectionSHA256 == "" {
		s.logger.Error("event selection deletion preview returned invalid evidence")
		writeError(w, http.StatusServiceUnavailable, "event_selection_deletion_unavailable", "event selection deletion preview is temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

func (s *Server) executeEventSelectionDeletion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var request ingest.EventSelectionDeletionRequest
	if err := decodeStrictDeletionJSON(r, &request, maxEventSelectionDeletionRequestBytes); err != nil || request.Validate() != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "event selection deletion request is invalid")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	outcome, err := s.selectionDeletions.Delete(ctx, request)
	if err != nil {
		s.writeEventSelectionDeletionError(w, err)
		return
	}
	if outcome.Validate() != nil || outcome.OperationID != request.OperationID || outcome.PreviewSHA256 != request.Preview.PreviewSHA256 {
		s.logger.Error("event selection deletion returned invalid outcome")
		writeError(w, http.StatusServiceUnavailable, "event_selection_deletion_unavailable", "event selection deletion is temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, outcome)
}

func (s *Server) writeEventSelectionDeletionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ingest.ErrEventSelectionDeletionPreviewExpired):
		writeError(w, http.StatusGone, "deletion_preview_expired", "event selection deletion preview has expired")
	case errors.Is(err, ingest.ErrEventSelectionDeletionPreviewStale), errors.Is(err, ingest.ErrCaptureEventDeletionPreviewStale):
		writeError(w, http.StatusConflict, "deletion_preview_stale", "event selection data changed; create a new preview")
	case errors.Is(err, ingest.ErrEventSelectionDeletionConflict), errors.Is(err, ingest.ErrEventSelectionConflict):
		writeError(w, http.StatusConflict, "deletion_conflict", "event selection deletion already used different evidence")
	case errors.Is(err, ingest.ErrEventSelectionTombstoneMissing):
		writeError(w, http.StatusConflict, "deletion_barrier_missing", "event selection replay barrier is missing")
	default:
		s.logger.Warn("event selection deletion failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "event_selection_deletion_unavailable", "event selection deletion is temporarily unavailable")
	}
}
