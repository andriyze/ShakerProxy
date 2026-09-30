package server

import (
	"net/http"

	"shakerproxy.dev/shakerproxy/internal/querylang"
)

func (s *Server) eventQueryMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if len(r.URL.Query()) != 0 {
		writeError(w, http.StatusBadRequest, "invalid_query", "query metadata does not accept parameters")
		return
	}
	writeJSON(w, http.StatusOK, querylang.AutocompleteMetadata())
}
