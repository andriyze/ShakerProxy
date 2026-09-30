package server

import (
	"net/http"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
)

func (s *Server) servicePortPlan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "service port plan does not accept query parameters")
		return
	}
	var plan gatewayprotocol.ServicePortPlan
	if err := s.gateway.Call(r.Context(), "GetServicePortPlan", gatewayprotocol.EmptyParams{}, &plan); err != nil {
		writeError(w, http.StatusServiceUnavailable, "service_ports_unavailable", "service port ownership is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

func (s *Server) connectivityProbe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "connectivity probe does not accept query parameters")
		return
	}
	var request struct{}
	if err := decodeOptionalJSON(r, &request, 1024); err != nil {
		writeDecodeError(w, err, "connectivity probe")
		return
	}
	s.connectivityProbeMu.Lock()
	if !s.lastConnectivityProbe.IsZero() && time.Since(s.lastConnectivityProbe) < 15*time.Second {
		s.connectivityProbeMu.Unlock()
		w.Header().Set("Retry-After", "15")
		writeError(w, http.StatusTooManyRequests, "connectivity_probe_rate_limited", "connectivity probe may run once every 15 seconds")
		return
	}
	s.lastConnectivityProbe = time.Now()
	s.connectivityProbeMu.Unlock()
	var report gatewayprotocol.ConnectivityReport
	if err := s.gateway.Call(r.Context(), "ProbeConnectivity", gatewayprotocol.EmptyParams{}, &report); err != nil {
		writeError(w, http.StatusServiceUnavailable, "connectivity_probe_unavailable", "connectivity probe did not complete")
		return
	}
	writeJSON(w, http.StatusOK, report)
}
