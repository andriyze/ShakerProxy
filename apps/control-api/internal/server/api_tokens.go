package server

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/apitoken"
)

type createAPITokenRequest struct {
	Name                       string                `json:"name"`
	Scopes                     []apitoken.Scope      `json:"scopes"`
	Restrictions               apitoken.Restrictions `json:"restrictions,omitempty"`
	ExpiresInSeconds           int64                 `json:"expires_in_seconds"`
	Password                   string                `json:"password"`
	SensitiveScopeAcknowledged bool                  `json:"sensitive_scope_acknowledged,omitempty"`
}

type revokeAPITokenRequest struct {
	Password string `json:"password"`
	Reason   string `json:"reason"`
}

func (s *Server) listAPITokens(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "API token listing does not accept query parameters")
		return
	}
	if s.apiTokens == nil {
		writeError(w, http.StatusServiceUnavailable, "api_tokens_unavailable", "API token storage is unavailable")
		return
	}
	tokens, err := s.apiTokens.List()
	if err != nil {
		s.logger.Error("API token list failed", "error", err)
		writeError(w, http.StatusInternalServerError, "api_token_store_failed", "API token store could not be read")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": tokens, "allowed_scopes": apitoken.AllowedScopes(), "sensitive_scopes": apitoken.SensitiveScopes(), "maximum_lifetime_seconds": int64(apitoken.MaxLifetime / time.Second)})
}

func (s *Server) createAPIToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "API token creation does not accept query parameters")
		return
	}
	if s.apiTokens == nil {
		writeError(w, http.StatusServiceUnavailable, "api_tokens_unavailable", "API token storage is unavailable")
		return
	}
	var request createAPITokenRequest
	if err := decodeJSONBounded(r, &request, 16<<10); err != nil {
		writeDecodeError(w, err, "API token")
		return
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordAlways) {
		return
	}
	if request.ExpiresInSeconds < int64(apitoken.MinLifetime/time.Second) || request.ExpiresInSeconds > int64(apitoken.MaxLifetime/time.Second) {
		writeError(w, http.StatusBadRequest, "invalid_expiry", "API token expiry is outside the supported range")
		return
	}
	created, err := s.apiTokens.Create(apitoken.CreateRequest{Name: request.Name, Creator: sessionUsername(r.Context()), Scopes: request.Scopes, Restrictions: request.Restrictions, ExpiresAt: time.Now().UTC().Add(time.Duration(request.ExpiresInSeconds) * time.Second), SensitiveAcknowledged: request.SensitiveScopeAcknowledged})
	if err != nil {
		writeError(w, http.StatusBadRequest, "api_token_rejected", err.Error())
		return
	}
	w.Header().Set("X-ShakerProxy-Secret-Handling", "display-once")
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) revokeAPIToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "API token revocation does not accept query parameters")
		return
	}
	if s.apiTokens == nil {
		writeError(w, http.StatusServiceUnavailable, "api_tokens_unavailable", "API token storage is unavailable")
		return
	}
	var request revokeAPITokenRequest
	if err := decodeJSONBounded(r, &request, 4<<10); err != nil {
		writeDecodeError(w, err, "API token revocation")
		return
	}
	request.Reason = strings.TrimSpace(request.Reason)
	if len(request.Reason) < 3 || len(request.Reason) > 256 {
		writeError(w, http.StatusBadRequest, "invalid_reason", "a 3-256 character revocation reason is required")
		return
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordRecent) {
		return
	}
	token, err := s.apiTokens.Revoke(r.PathValue("tokenID"), sessionUsername(r.Context()), request.Reason)
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "api_token_not_found", "API token was not found")
		return
	}
	if err != nil {
		s.logger.Error("API token revocation failed", "error", err)
		writeError(w, http.StatusInternalServerError, "api_token_store_failed", "API token could not be revoked")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "reason": request.Reason})
}
