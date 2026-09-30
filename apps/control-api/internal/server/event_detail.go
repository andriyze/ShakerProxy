package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"

	"shakerproxy.dev/shakerproxy/internal/apitoken"
	"shakerproxy.dev/shakerproxy/internal/ingest"
)

var eventDetailRecordIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// API-token consumers, including the future MCP server, receive a deliberately
// narrow metadata projection. Browser administrator sessions may inspect the
// bounded local payload, but traffic:read must not silently become a plaintext
// exfiltration scope.
var eventDetailMetadataKeys = map[string]struct{}{
	"source_ip": {}, "source_port": {}, "destination_ip": {}, "destination_port": {},
	"protocol": {}, "service": {}, "hostname": {}, "device_id": {}, "platform": {},
	"sni": {}, "reason": {}, "classification": {}, "policy_revision": {},
	"client_has_recent_successful_interception": {}, "dynamic_bypass_added": {},
	"retry_required": {}, "failure_count": {}, "pinning_threshold": {},
	"failure_window_seconds": {}, "recent_success_window_seconds": {}, "evidence_note": {},
	"bypass_rule_id": {}, "bypass_source": {}, "decrypted": {},
	"tls_version": {}, "alpn": {}, "cipher": {}, "client_tls": {}, "upstream_tls": {},
	"upstream_certificate_sha256": {}, "upstream_certificate_subject": {},
	"upstream_certificate_issuer": {}, "upstream_certificate_serial": {},
	"dns_transport": {}, "query": {}, "query_name": {}, "query_type": {},
	"qtype_name": {}, "rcode": {}, "rcode_name": {}, "answer_count": {}, "answers": {},
	"ttls": {}, "TTLs": {}, "resolver_id": {}, "resolver_provider": {},
	"resolver_catalog_revision": {}, "resolver_ip": {}, "blocked": {}, "fallback_outcome": {},
	"http_method": {}, "http_scheme": {}, "http_host": {}, "http_port": {},
	"http_path": {}, "http_status": {}, "http_version": {},
	"request_bytes": {}, "response_bytes": {}, "http_url_truncated": {},
	"content_local_only": {},
}

// EventDetailHandler exposes only the event-detail read path so the top-level
// process can add the new route without widening or duplicating the main API
// router. It applies the same host/origin, security-header, session, and
// traffic:read API-token checks as the regular event list endpoint.
func (s *Server) EventDetailHandler() http.Handler {
	return s.securityHeaders(s.validateHost(s.requireAuthOrScope(apitoken.ScopeTrafficRead, http.HandlerFunc(s.getEventDetail))))
}

// EventDetailOrFallback prevents the wildcard event-detail route from
// shadowing existing static routes such as /events/query-metadata. Only a
// normalized 64-hex record identity is allowed to enter the detail handler.
func (s *Server) EventDetailOrFallback(fallback http.Handler) http.Handler {
	detail := s.EventDetailHandler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if eventDetailRecordIDPattern.MatchString(r.PathValue("recordID")) {
			detail.ServeHTTP(w, r)
			return
		}
		fallback.ServeHTTP(w, r)
	})
}

func (s *Server) getEventDetail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "event detail does not accept query parameters")
		return
	}
	reader, ok := s.eventReader.(ingest.EventDetailReader)
	if !ok || reader == nil {
		writeError(w, http.StatusServiceUnavailable, "event_detail_unavailable", "normalized event detail storage is unavailable")
		return
	}
	queryContext, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	detail, err := reader.GetEventDetail(queryContext, r.PathValue("recordID"))
	if errors.Is(err, ingest.ErrEventNotFound) {
		writeError(w, http.StatusNotFound, "event_not_found", "normalized event was not found")
		return
	}
	if err != nil {
		s.logger.Warn("normalized event detail proxy failed", "record_id", r.PathValue("recordID"), "error", err)
		writeError(w, http.StatusServiceUnavailable, "event_detail_unavailable", "normalized event detail is temporarily unavailable")
		return
	}
	// Device names remain control-plane projections. Storage never receives or
	// persists the mutable friendly-name mapping.
	projected := []ingest.RecentEvent{detail.Event}
	_ = s.projectDeviceNames(projected)
	detail.Event = projected[0]

	if _, tokenPrincipal := r.Context().Value(apiPrincipalContextKey{}).(apitoken.Principal); tokenPrincipal {
		redacted, redactErr := metadataOnlyEventPayload(detail.Payload)
		if redactErr != nil {
			s.logger.Warn("normalized event detail redaction failed", "record_id", detail.Event.RecordID, "error", redactErr)
			writeError(w, http.StatusServiceUnavailable, "event_detail_unavailable", "normalized event detail could not be safely projected")
			return
		}
		detail.Payload = redacted
		detail.PayloadBytes = len(redacted)
		w.Header().Set("X-ShakerProxy-Event-Detail", "metadata-only")
	}
	writeJSON(w, http.StatusOK, detail)
}

func metadataOnlyEventPayload(payload json.RawMessage) (json.RawMessage, error) {
	var source map[string]json.RawMessage
	if err := json.Unmarshal(payload, &source); err != nil {
		return nil, err
	}
	projected := make(map[string]json.RawMessage, len(source))
	for key, value := range source {
		if _, allowed := eventDetailMetadataKeys[key]; allowed {
			projected[key] = value
		}
	}
	encoded, err := json.Marshal(projected)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(encoded), nil
}
