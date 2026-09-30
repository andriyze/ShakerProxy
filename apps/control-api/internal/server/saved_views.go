package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"shakerproxy.dev/shakerproxy/internal/savedview"
)

func contextWithTimeout(r *http.Request, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), timeout)
}

func (s *Server) listSavedViews(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.savedViewsAvailable(w) {
		return
	}
	values := r.URL.Query()
	scope, page := savedview.Scope(values.Get("scope")), values.Get("page")
	if len(values) > 2 || len(values["scope"]) > 1 || len(values["page"]) > 1 || scope != "" && scope != savedview.ScopePersonal && scope != savedview.ScopeShared || page != "" && page != "live-traffic" {
		writeError(w, http.StatusBadRequest, "invalid_request", "saved view list parameters are invalid")
		return
	}
	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()
	result, err := s.savedViews.List(ctx, sessionUsername(r.Context()), savedview.ListFilter{Scope: scope, Page: page})
	if err != nil {
		s.writeSavedViewError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) createSavedView(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.savedViewsAvailable(w) {
		return
	}
	var configuration savedview.Configuration
	if err := decodeJSON(r, &configuration); err != nil {
		writeDecodeError(w, err, "saved view")
		return
	}
	s.createSavedViewConfiguration(w, r, configuration)
}

func (s *Server) getSavedView(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.savedViewsAvailable(w) {
		return
	}
	if !savedview.ValidID(r.PathValue("viewID")) {
		writeError(w, http.StatusBadRequest, "invalid_request", "saved view ID is invalid")
		return
	}
	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()
	view, err := s.savedViews.Get(ctx, sessionUsername(r.Context()), r.PathValue("viewID"))
	if err != nil {
		s.writeSavedViewError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) updateSavedView(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.savedViewsAvailable(w) {
		return
	}
	if !savedview.ValidID(r.PathValue("viewID")) {
		writeError(w, http.StatusBadRequest, "invalid_request", "saved view ID is invalid")
		return
	}
	var update savedview.Update
	if err := decodeJSON(r, &update); err != nil {
		writeDecodeError(w, err, "saved view update")
		return
	}
	normalized, err := savedview.Normalize(update.Configuration)
	if err != nil || update.ExpectedRevision < 1 {
		writeError(w, http.StatusBadRequest, "invalid_saved_view", "saved view update is invalid")
		return
	}
	update.Configuration = normalized
	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()
	view, err := s.savedViews.Update(ctx, sessionUsername(r.Context()), r.PathValue("viewID"), update)
	if err != nil {
		s.writeSavedViewError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) deleteSavedView(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.savedViewsAvailable(w) {
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
	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()
	if err := s.savedViews.Delete(ctx, sessionUsername(r.Context()), r.PathValue("viewID"), revision); err != nil {
		s.writeSavedViewError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type duplicateSavedViewRequest struct {
	Name  string          `json:"name"`
	Scope savedview.Scope `json:"scope"`
}

func (s *Server) duplicateSavedView(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.savedViewsAvailable(w) {
		return
	}
	if !savedview.ValidID(r.PathValue("viewID")) {
		writeError(w, http.StatusBadRequest, "invalid_request", "saved view ID is invalid")
		return
	}
	var request duplicateSavedViewRequest
	if err := decodeJSON(r, &request); err != nil {
		writeDecodeError(w, err, "saved view duplicate request")
		return
	}
	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()
	view, err := s.savedViews.Get(ctx, sessionUsername(r.Context()), r.PathValue("viewID"))
	if err != nil {
		s.writeSavedViewError(w, err)
		return
	}
	// A duplicate keeps the original's scope unless the request picks one, and
	// defaults its name to "<original> (copy)".
	if request.Scope != "" {
		view.Configuration.Scope = request.Scope
	}
	if strings.TrimSpace(request.Name) != "" {
		view.Configuration.Name = request.Name
	} else {
		view.Configuration.Name = duplicateSavedViewName(view.Configuration.Name)
	}
	view.Configuration, err = savedview.Normalize(view.Configuration)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_saved_view", err.Error())
		return
	}
	copy, err := s.savedViews.Create(ctx, sessionUsername(r.Context()), view.Configuration)
	if err != nil {
		s.writeSavedViewError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, copy)
}

func duplicateSavedViewName(name string) string {
	const suffix = " (copy)"
	name = strings.TrimSpace(name)
	for len(name)+len(suffix) > 96 {
		_, size := utf8.DecodeLastRuneInString(name)
		name = name[:len(name)-size]
	}
	return strings.TrimSpace(name) + suffix
}

func (s *Server) exportSavedView(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.savedViewsAvailable(w) {
		return
	}
	if !savedview.ValidID(r.PathValue("viewID")) {
		writeError(w, http.StatusBadRequest, "invalid_request", "saved view ID is invalid")
		return
	}
	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()
	view, err := s.savedViews.Get(ctx, sessionUsername(r.Context()), r.PathValue("viewID"))
	if err != nil {
		s.writeSavedViewError(w, err)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="shakerproxy-%s.json"`, view.ID))
	writeJSON(w, http.StatusOK, savedview.Export{Schema: savedview.SchemaVersion, ExportedAt: time.Now().UTC(), View: view.Configuration})
}

func (s *Server) importSavedView(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.savedViewsAvailable(w) {
		return
	}
	var document savedview.Export
	if err := decodeJSON(r, &document); err != nil || document.Schema != savedview.SchemaVersion || document.ExportedAt.IsZero() {
		writeError(w, http.StatusBadRequest, "invalid_request", "saved view import does not match the export schema")
		return
	}
	s.createSavedViewConfiguration(w, r, document.View)
}

func (s *Server) savedViewHistory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.savedViewsAvailable(w) {
		return
	}
	if !savedview.ValidID(r.PathValue("viewID")) {
		writeError(w, http.StatusBadRequest, "invalid_request", "saved view ID is invalid")
		return
	}
	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()
	history, err := s.savedViews.History(ctx, sessionUsername(r.Context()), r.PathValue("viewID"))
	if err != nil {
		s.writeSavedViewError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, history)
}

func (s *Server) createSavedViewConfiguration(w http.ResponseWriter, r *http.Request, configuration savedview.Configuration) {
	normalized, err := savedview.Normalize(configuration)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_saved_view", err.Error())
		return
	}
	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()
	view, err := s.savedViews.Create(ctx, sessionUsername(r.Context()), normalized)
	if err != nil {
		s.writeSavedViewError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, view)
}

func (s *Server) savedViewsAvailable(w http.ResponseWriter) bool {
	if s.savedViews == nil {
		writeError(w, http.StatusServiceUnavailable, "saved_view_store_unavailable", "saved view storage is not configured")
		return false
	}
	return true
}

func (s *Server) writeSavedViewError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, savedview.ErrNotFound):
		writeError(w, http.StatusNotFound, "saved_view_not_found", "saved view was not found")
	case errors.Is(err, savedview.ErrConflict):
		writeError(w, http.StatusConflict, "saved_view_conflict", "saved view revision changed; reload before editing")
	case errors.Is(err, savedview.ErrForbidden):
		writeError(w, http.StatusForbidden, "saved_view_forbidden", "only the saved view owner may change it")
	case errors.Is(err, savedview.ErrLimit):
		writeError(w, http.StatusConflict, "saved_view_limit", "archive or delete a saved view before creating another")
	case errors.Is(err, savedview.ErrInvalid):
		writeError(w, http.StatusBadRequest, "invalid_saved_view", "The saved view was rejected: "+err.Error()+".")
	default:
		s.logger.Warn("saved view request failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "saved_view_store_unavailable", "saved view storage is temporarily unavailable")
	}
}
