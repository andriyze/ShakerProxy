package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"shakerproxy.dev/shakerproxy/internal/savedview"
)

func (s *Server) listSavedViews(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := savedViewActor(w, r)
	if !ok {
		return
	}
	values := r.URL.Query()
	scope, page := savedview.Scope(values.Get("scope")), values.Get("page")
	if len(values) > 2 || len(values["scope"]) > 1 || len(values["page"]) > 1 || scope != "" && scope != savedview.ScopePersonal && scope != savedview.ScopeShared || page != "" && page != "live-traffic" {
		writeError(w, http.StatusBadRequest, "invalid_request", "saved view list parameters are invalid")
		return
	}
	ctx, cancel := contextWithSavedViewTimeout(r)
	defer cancel()
	result, err := s.savedViews.List(ctx, actor, savedview.ListFilter{Scope: scope, Page: page})
	if err != nil {
		savedViewError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) createSavedView(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := savedViewActor(w, r)
	if !ok {
		return
	}
	var configuration savedview.Configuration
	if err := decodeSavedViewJSON(r, &configuration); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "saved view does not match the schema")
		return
	}
	configuration, err := savedview.Normalize(configuration)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_saved_view", err.Error())
		return
	}
	ctx, cancel := contextWithSavedViewTimeout(r)
	defer cancel()
	view, err := s.savedViews.Create(ctx, actor, configuration)
	if err != nil {
		savedViewError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, view)
}

func (s *Server) getSavedView(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := savedViewActor(w, r)
	if !ok {
		return
	}
	if !savedview.ValidID(r.PathValue("viewID")) {
		writeError(w, http.StatusBadRequest, "invalid_request", "saved view ID is invalid")
		return
	}
	ctx, cancel := contextWithSavedViewTimeout(r)
	defer cancel()
	view, err := s.savedViews.Get(ctx, actor, r.PathValue("viewID"))
	if err != nil {
		savedViewError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) updateSavedView(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := savedViewActor(w, r)
	if !ok {
		return
	}
	if !savedview.ValidID(r.PathValue("viewID")) {
		writeError(w, http.StatusBadRequest, "invalid_request", "saved view ID is invalid")
		return
	}
	var update savedview.Update
	if err := decodeSavedViewJSON(r, &update); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "saved view update does not match the schema")
		return
	}
	configuration, err := savedview.Normalize(update.Configuration)
	if err != nil || update.ExpectedRevision < 1 {
		writeError(w, http.StatusBadRequest, "invalid_saved_view", "saved view update is invalid")
		return
	}
	update.Configuration = configuration
	ctx, cancel := contextWithSavedViewTimeout(r)
	defer cancel()
	view, err := s.savedViews.Update(ctx, actor, r.PathValue("viewID"), update)
	if err != nil {
		savedViewError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) deleteSavedView(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := savedViewActor(w, r)
	if !ok {
		return
	}
	if !savedview.ValidID(r.PathValue("viewID")) {
		writeError(w, http.StatusBadRequest, "invalid_request", "saved view ID is invalid")
		return
	}
	values := r.URL.Query()
	if len(values) != 1 || len(values["expected_revision"]) != 1 {
		writeError(w, http.StatusBadRequest, "invalid_request", "expected_revision is required")
		return
	}
	revision, err := strconv.ParseInt(values.Get("expected_revision"), 10, 64)
	if err != nil || revision < 1 {
		writeError(w, http.StatusBadRequest, "invalid_request", "expected_revision is invalid")
		return
	}
	ctx, cancel := contextWithSavedViewTimeout(r)
	defer cancel()
	if err := s.savedViews.Delete(ctx, actor, r.PathValue("viewID"), revision); err != nil {
		savedViewError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) savedViewHistory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := savedViewActor(w, r)
	if !ok {
		return
	}
	if !savedview.ValidID(r.PathValue("viewID")) {
		writeError(w, http.StatusBadRequest, "invalid_request", "saved view ID is invalid")
		return
	}
	ctx, cancel := contextWithSavedViewTimeout(r)
	defer cancel()
	history, err := s.savedViews.History(ctx, actor, r.PathValue("viewID"))
	if err != nil {
		savedViewError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, history)
}

func savedViewActor(w http.ResponseWriter, r *http.Request) (string, bool) {
	actor := r.Header.Get("X-ShakerProxy-Actor")
	if !savedview.ValidActor(actor) {
		writeError(w, http.StatusBadRequest, "invalid_actor", "saved view actor is invalid")
		return "", false
	}
	return actor, true
}

func contextWithSavedViewTimeout(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), 3*time.Second)
}

func decodeSavedViewJSON(r *http.Request, destination any) error {
	if r.Header.Get("Content-Type") != "application/json" {
		return errors.New("Content-Type must be application/json")
	}
	limited := &io.LimitedReader{R: r.Body, N: (32 << 10) + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil || decoder.Decode(&struct{}{}) != io.EOF || limited.N <= 0 {
		return errors.New("saved view JSON is invalid or oversized")
	}
	return nil
}

func savedViewError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, savedview.ErrNotFound):
		writeError(w, http.StatusNotFound, "saved_view_not_found", "saved view was not found")
	case errors.Is(err, savedview.ErrConflict):
		writeError(w, http.StatusConflict, "saved_view_conflict", "saved view revision changed; reload before editing")
	case errors.Is(err, savedview.ErrForbidden):
		writeError(w, http.StatusForbidden, "saved_view_forbidden", "only the saved view owner may change it")
	case errors.Is(err, savedview.ErrLimit):
		writeError(w, http.StatusConflict, "saved_view_limit", "archive or delete a saved view before creating another")
	default:
		writeError(w, http.StatusServiceUnavailable, "saved_view_store_unavailable", "saved view storage is temporarily unavailable")
	}
}
