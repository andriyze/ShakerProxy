package server

import (
	"errors"
	"net/http"
	"os"
	"strings"

	"shakerproxy.dev/shakerproxy/internal/forwarder"
)

type createForwarderRequest struct {
	Name        string                 `json:"name"`
	Kind        forwarder.Kind         `json:"kind"`
	Destination string                 `json:"destination,omitempty"`
	Classes     []forwarder.EventClass `json:"classes,omitempty"`
	Password    string                 `json:"password"`
}

type setForwarderEnabledRequest struct {
	ExpectedRevision uint64 `json:"expected_revision"`
	Enabled          bool   `json:"enabled"`
	Reason           string `json:"reason"`
	Password         string `json:"password"`
}

func (s *Server) listForwarders(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "forwarder listing does not accept query parameters")
		return
	}
	if s.forwarders == nil {
		writeError(w, http.StatusServiceUnavailable, "forwarders_unavailable", "safe event forwarding is unavailable")
		return
	}
	status, err := s.forwarders.Status()
	if err != nil {
		s.logger.Error("forwarder status failed", "error", err)
		writeError(w, http.StatusInternalServerError, "forwarder_store_failed", "forwarder state could not be read")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"forwarders": status, "allowed_classes": forwarder.AllowedClasses(), "allowed_transports": []forwarder.Kind{forwarder.KindJSONL, forwarder.KindWebhook, forwarder.KindSyslogTLS}, "payload_policy": "METADATA_ONLY_NO_EVENT_BODIES_NO_KEYLOGS_NO_CA_MATERIAL_NO_CREDENTIALS", "queue_limit_per_forwarder": forwarder.MaxPending})
}

func (s *Server) createForwarder(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "forwarder creation does not accept query parameters")
		return
	}
	if s.forwarders == nil {
		writeError(w, http.StatusServiceUnavailable, "forwarders_unavailable", "safe event forwarding is unavailable")
		return
	}
	var request createForwarderRequest
	if err := decodeJSONBounded(r, &request, 16<<10); err != nil {
		writeDecodeError(w, err, "forwarder")
		return
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordRecent) {
		return
	}
	created, err := s.forwarders.Create(forwarder.CreateRequest{Name: request.Name, Kind: request.Kind, Destination: request.Destination, Classes: request.Classes, Actor: sessionUsername(r.Context())})
	if err != nil {
		writeError(w, http.StatusBadRequest, "forwarder_rejected", err.Error())
		return
	}
	if created.HMACSecret != "" {
		w.Header().Set("X-ShakerProxy-Secret-Handling", "display-once")
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) setForwarderEnabled(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "forwarder activation does not accept query parameters")
		return
	}
	if s.forwarders == nil {
		writeError(w, http.StatusServiceUnavailable, "forwarders_unavailable", "safe event forwarding is unavailable")
		return
	}
	var request setForwarderEnabledRequest
	if err := decodeJSONBounded(r, &request, 8<<10); err != nil {
		writeDecodeError(w, err, "forwarder activation")
		return
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordRecent) {
		return
	}
	if strings.TrimSpace(request.Reason) == "" {
		request.Reason = "Forwarder disabled"
		if request.Enabled {
			request.Reason = "Forwarder enabled"
		}
	}
	item, err := s.forwarders.SetEnabled(r.PathValue("forwarderID"), request.ExpectedRevision, request.Enabled, sessionUsername(r.Context()), request.Reason)
	if err != nil {
		s.writeForwarderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

type updateForwarderRequest struct {
	ExpectedRevision uint64                  `json:"expected_revision"`
	Name             *string                 `json:"name,omitempty"`
	Destination      *string                 `json:"destination,omitempty"`
	Classes          *[]forwarder.EventClass `json:"classes,omitempty"`
	Reason           string                  `json:"reason"`
	Password         string                  `json:"password"`
}

// updateForwarder edits a forwarder's name, destination or event classes.
func (s *Server) updateForwarder(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.forwarders == nil {
		writeError(w, http.StatusServiceUnavailable, "forwarders_unavailable", "safe event forwarding is unavailable")
		return
	}
	var request updateForwarderRequest
	if err := decodeJSONBounded(r, &request, 16<<10); err != nil {
		writeDecodeError(w, err, "forwarder update")
		return
	}
	if request.Name == nil && request.Destination == nil && request.Classes == nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Include name, destination or classes to change.")
		return
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordRecent) {
		return
	}
	item, err := s.forwarders.Update(r.PathValue("forwarderID"), request.ExpectedRevision, forwarder.UpdateRequest{Name: request.Name, Destination: request.Destination, Classes: request.Classes, Actor: sessionUsername(r.Context()), Reason: request.Reason})
	if err != nil {
		s.writeForwarderError(w, err)
		return
	}
	s.logger.Info("forwarder updated", "username", sessionUsername(r.Context()), "forwarder_id", item.ID, "revision", item.Revision)
	writeJSON(w, http.StatusOK, item)
}

type deleteForwarderRequest struct {
	ExpectedRevision uint64 `json:"expected_revision"`
	Reason           string `json:"reason"`
	Password         string `json:"password"`
}

// deleteForwarder removes a forwarder and its pending delivery queue.
func (s *Server) deleteForwarder(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.forwarders == nil {
		writeError(w, http.StatusServiceUnavailable, "forwarders_unavailable", "safe event forwarding is unavailable")
		return
	}
	var request deleteForwarderRequest
	if err := decodeOptionalJSON(r, &request, 4<<10); err != nil {
		writeDecodeError(w, err, "forwarder deletion")
		return
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordRecent) {
		return
	}
	item, err := s.forwarders.Delete(r.PathValue("forwarderID"), request.ExpectedRevision, sessionUsername(r.Context()), request.Reason)
	if err != nil && item.ID == "" {
		s.writeForwarderError(w, err)
		return
	}
	if err != nil {
		s.logger.Warn("forwarder deleted with a leftover delivery queue", "forwarder_id", item.ID, "error", err)
	}
	s.logger.Info("forwarder deleted", "username", sessionUsername(r.Context()), "forwarder_id", item.ID)
	writeJSON(w, http.StatusOK, map[string]any{"schema": 1, "deleted": true, "forwarder": item})
}

func (s *Server) writeForwarderError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, forwarder.ErrConflict):
		writeError(w, http.StatusConflict, "revision_conflict", "The forwarder changed since it was loaded; reload it and try again.")
	case errors.Is(err, os.ErrNotExist):
		writeError(w, http.StatusNotFound, "forwarder_not_found", "No forwarder has this ID; list forwarders with GET /api/v1/integrations/forwarders.")
	default:
		writeError(w, http.StatusBadRequest, "forwarder_rejected", err.Error())
	}
}
