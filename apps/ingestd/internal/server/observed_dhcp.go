package server

import (
	"context"
	"net/http"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

const observedDHCPTimeout = 3 * time.Second

// listObservedDHCP serves the DHCP exchanges recorded on the lab, merged per
// client MAC, for the device inventory. It is protected by the event query
// token.
func (s *Server) listObservedDHCP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if len(r.URL.Query()) != 0 {
		writeError(w, http.StatusBadRequest, "invalid_query", "observed DHCP takes no parameters")
		return
	}
	reader, ok := s.recentEvents.(ingest.ObservedDHCPReader)
	if !ok || reader == nil {
		writeError(w, http.StatusServiceUnavailable, "observed_dhcp_unavailable", "observed DHCP is unavailable")
		return
	}
	queryContext, cancel := context.WithTimeout(r.Context(), observedDHCPTimeout)
	defer cancel()
	observed, err := reader.QueryObservedDHCP(queryContext)
	if err != nil {
		s.logger.Warn("observed DHCP query failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "observed_dhcp_unavailable", "observed DHCP is temporarily unavailable")
		return
	}
	if err := observed.Validate(); err != nil {
		s.logger.Error("observed DHCP reader returned invalid clients", "error", err)
		writeError(w, http.StatusServiceUnavailable, "observed_dhcp_unavailable", "observed DHCP is temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, observed)
}
