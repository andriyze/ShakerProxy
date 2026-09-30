package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/ingest"
)

const maxCaptureEventDeletionRequestBytes = 32 << 10

type CaptureEventDeletionLifecycle interface {
	Preview(context.Context, string) (ingest.CaptureEventDeletionPreview, error)
	Delete(context.Context, ingest.CaptureEventDeletionRequest) (ingest.CaptureEventDeletionOutcome, error)
}

func (s *Server) previewCaptureEventDeletion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if body, err := io.ReadAll(io.LimitReader(r.Body, 1)); err != nil || len(body) != 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "capture event deletion preview does not accept a body")
		return
	}
	captureSessionID := r.PathValue("sessionID")
	if !capture.ValidSessionID(captureSessionID) {
		writeError(w, http.StatusBadRequest, "invalid_capture", "capture session ID is invalid")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	preview, err := s.captureDeletions.Preview(ctx, captureSessionID)
	if err != nil {
		s.logger.Warn("capture event deletion preview failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "capture_event_deletion_unavailable", "capture event deletion preview is temporarily unavailable")
		return
	}
	if err := preview.Validate(); err != nil || preview.CaptureSessionID != captureSessionID {
		s.logger.Error("capture event deletion preview returned invalid evidence")
		writeError(w, http.StatusServiceUnavailable, "capture_event_deletion_unavailable", "capture event deletion preview is temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

func (s *Server) executeCaptureEventDeletion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	captureSessionID := r.PathValue("sessionID")
	if !capture.ValidSessionID(captureSessionID) {
		writeError(w, http.StatusBadRequest, "invalid_capture", "capture session ID is invalid")
		return
	}
	var request ingest.CaptureEventDeletionRequest
	if err := decodeCaptureEventDeletionJSON(r, &request); err != nil || request.Validate() != nil || request.Preview.CaptureSessionID != captureSessionID {
		writeError(w, http.StatusBadRequest, "invalid_request", "capture event deletion request is invalid")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	outcome, err := s.captureDeletions.Delete(ctx, request)
	if err != nil {
		s.writeCaptureEventDeletionError(w, err)
		return
	}
	if err := outcome.Validate(); err != nil || outcome.CaptureSessionID != captureSessionID || outcome.PreviewSHA256 != request.Preview.PreviewSHA256 {
		s.logger.Error("capture event deletion returned invalid outcome")
		writeError(w, http.StatusServiceUnavailable, "capture_event_deletion_unavailable", "capture event deletion is temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, outcome)
}

func decodeCaptureEventDeletionJSON(r *http.Request, destination any) error {
	return decodeStrictDeletionJSON(r, destination, maxCaptureEventDeletionRequestBytes)
}

func decodeStrictDeletionJSON(r *http.Request, destination any, maxBytes int64) error {
	if r.Header.Get("Content-Type") != "application/json" {
		return errors.New("Content-Type must be application/json")
	}
	limited := &io.LimitedReader{R: r.Body, N: maxBytes + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil || decoder.Decode(&struct{}{}) != io.EOF || limited.N <= 0 {
		return errors.New("capture event deletion JSON is invalid or oversized")
	}
	return nil
}

func (s *Server) writeCaptureEventDeletionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ingest.ErrCaptureEventDeletionPreviewExpired):
		writeError(w, http.StatusGone, "deletion_preview_expired", "capture event deletion preview has expired")
	case errors.Is(err, ingest.ErrCaptureEventDeletionPreviewStale):
		writeError(w, http.StatusConflict, "deletion_preview_stale", "capture event data changed; create a new preview")
	case errors.Is(err, ingest.ErrCaptureEventDeletionConflict):
		writeError(w, http.StatusConflict, "deletion_conflict", "capture event deletion already completed with different evidence")
	default:
		s.logger.Warn("capture event deletion failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "capture_event_deletion_unavailable", "capture event deletion is temporarily unavailable")
	}
}
