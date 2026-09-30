package analyzer

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

const maxCheckpointDeletionRequestBytes = 32 << 10

func NewMaintenanceHandler(service *CheckpointDeletionService, token []byte) (http.Handler, error) {
	if err := service.validate(); err != nil || !validMaintenanceToken(token) {
		return nil, errors.New("analyzer maintenance service configuration is invalid")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		if body, err := io.ReadAll(io.LimitReader(r.Body, 1)); err != nil || len(body) != 0 {
			writeMaintenanceError(w, http.StatusBadRequest, "invalid_request", "analyzer status does not accept a body")
			return
		}
		snapshot, err := service.Store.Health(service.Now().UTC())
		if err != nil || snapshot.Validate() != nil {
			writeMaintenanceError(w, http.StatusServiceUnavailable, "status_unavailable", "analyzer status is temporarily unavailable")
			return
		}
		writeMaintenanceJSON(w, http.StatusOK, snapshot)
	})
	mux.HandleFunc("POST /v1/checkpoints/{sessionID}/deletion-preview", func(w http.ResponseWriter, r *http.Request) {
		if body, err := io.ReadAll(io.LimitReader(r.Body, 1)); err != nil || len(body) != 0 {
			writeMaintenanceError(w, http.StatusBadRequest, "invalid_request", "checkpoint deletion preview does not accept a body")
			return
		}
		preview, err := service.Preview(r.PathValue("sessionID"))
		if err != nil {
			writeMaintenanceError(w, http.StatusServiceUnavailable, "checkpoint_deletion_unavailable", "checkpoint deletion preview is temporarily unavailable")
			return
		}
		writeMaintenanceJSON(w, http.StatusOK, preview)
	})
	mux.HandleFunc("POST /v1/checkpoints/{sessionID}/deletion", func(w http.ResponseWriter, r *http.Request) {
		var request CheckpointDeletionRequest
		if err := decodeMaintenanceJSON(r, &request); err != nil || request.Validate() != nil || request.Preview.CaptureSessionID != r.PathValue("sessionID") {
			writeMaintenanceError(w, http.StatusBadRequest, "invalid_request", "checkpoint deletion request is invalid")
			return
		}
		outcome, err := service.Delete(request)
		if err != nil {
			switch {
			case errors.Is(err, ErrCheckpointDeletionPreviewExpired):
				writeMaintenanceError(w, http.StatusGone, "deletion_preview_expired", "checkpoint deletion preview has expired")
			case errors.Is(err, ErrCheckpointDeletionPreviewStale):
				writeMaintenanceError(w, http.StatusConflict, "deletion_preview_stale", "analyzer checkpoint changed; create a new preview")
			case errors.Is(err, ErrCheckpointDeletionConflict):
				writeMaintenanceError(w, http.StatusConflict, "deletion_conflict", "checkpoint deletion already started with different evidence")
			default:
				writeMaintenanceError(w, http.StatusServiceUnavailable, "checkpoint_deletion_unavailable", "checkpoint deletion is temporarily unavailable")
			}
			return
		}
		writeMaintenanceJSON(w, http.StatusOK, outcome)
	})
	mux.HandleFunc("POST /v1/checkpoints/{sessionID}/reindex", func(w http.ResponseWriter, r *http.Request) {
		var request CheckpointReindexRequest
		if err := decodeMaintenanceJSON(r, &request); err != nil || request.Validate() != nil || request.CaptureSessionID != r.PathValue("sessionID") {
			writeMaintenanceError(w, http.StatusBadRequest, "invalid_request", "checkpoint reindex request is invalid")
			return
		}
		outcome, err := service.AuthorizeReindex(request)
		if err != nil {
			switch {
			case errors.Is(err, ErrCheckpointReindexConflict):
				writeMaintenanceError(w, http.StatusConflict, "reindex_conflict", "checkpoint reindex already started with different evidence")
			case errors.Is(err, ErrCheckpointReindexBarrier):
				writeMaintenanceError(w, http.StatusConflict, "reindex_barrier_missing", "checkpoint deletion barrier does not match the reindex request")
			default:
				writeMaintenanceError(w, http.StatusServiceUnavailable, "checkpoint_reindex_unavailable", "checkpoint reindex authorization is temporarily unavailable")
			}
			return
		}
		writeMaintenanceJSON(w, http.StatusOK, outcome)
	})
	return maintenanceSecurity(requireMaintenanceToken(token, mux)), nil
}

func requireMaintenanceToken(token []byte, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		provided := strings.TrimPrefix(header, "Bearer ")
		if !strings.HasPrefix(header, "Bearer ") || len(provided) != len(token) || subtle.ConstantTimeCompare([]byte(provided), token) != 1 {
			writeMaintenanceError(w, http.StatusUnauthorized, "authentication_required", "valid analyzer maintenance authentication is required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func decodeMaintenanceJSON(r *http.Request, destination any) error {
	if r.Header.Get("Content-Type") != "application/json" {
		return errors.New("Content-Type must be application/json")
	}
	limited := &io.LimitedReader{R: r.Body, N: maxCheckpointDeletionRequestBytes + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil || decoder.Decode(&struct{}{}) != io.EOF || limited.N <= 0 {
		return errors.New("checkpoint deletion JSON is invalid or oversized")
	}
	return nil
}

func validMaintenanceToken(token []byte) bool {
	if len(token) < 32 || len(token) > 128 {
		return false
	}
	for _, char := range token {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

func maintenanceSecurity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func writeMaintenanceJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeMaintenanceError(w http.ResponseWriter, status int, code, message string) {
	writeMaintenanceJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}
