package server

import (
	"net/http"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/apitoken"
)

const agentInvestigatorLifetime = 24 * time.Hour

type createAgentInvestigatorRequest struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

func (s *Server) AgentConnectionHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /api/v1/agent-connections/investigator", s.requireAuth(http.HandlerFunc(s.createAgentInvestigator)))
	return s.wrapMux(mux)
}

func (s *Server) createAgentInvestigator(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "AI investigator token creation does not accept query parameters")
		return
	}
	if s.apiTokens == nil {
		writeError(w, http.StatusServiceUnavailable, "api_tokens_unavailable", "API token storage is unavailable")
		return
	}
	var request createAgentInvestigatorRequest
	if err := decodeJSONBounded(r, &request, 4<<10); err != nil {
		writeDecodeError(w, err, "AI investigator token")
		return
	}
	request.Name = strings.TrimSpace(request.Name)
	if request.Name == "" {
		request.Name = "AI investigator"
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordAlways) {
		return
	}
	created, err := s.apiTokens.Create(apitoken.CreateRequest{
		Name:      request.Name,
		Creator:   sessionUsername(r.Context()),
		Scopes:    []apitoken.Scope{apitoken.ScopeSystemRead, apitoken.ScopeDevicesRead, apitoken.ScopeTrafficRead},
		ExpiresAt: time.Now().UTC().Add(agentInvestigatorLifetime),
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "agent_connection_rejected", err.Error())
		return
	}
	w.Header().Set("X-ShakerProxy-Secret-Handling", "display-once")
	writeJSON(w, http.StatusCreated, map[string]any{
		"profile":            "INVESTIGATOR",
		"token":              created.Token,
		"secret":             created.Secret,
		"fixed_scopes":       []apitoken.Scope{apitoken.ScopeSystemRead, apitoken.ScopeDevicesRead, apitoken.ScopeTrafficRead},
		"expires_in_seconds": int64(agentInvestigatorLifetime / time.Second),
	})
}
