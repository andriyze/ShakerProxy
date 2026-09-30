package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/apitoken"
	"shakerproxy.dev/shakerproxy/internal/ingest"
	deviceinventory "shakerproxy.dev/shakerproxy/internal/inventory"
	"shakerproxy.dev/shakerproxy/internal/protocolclass"
)

// registerProtocolRoutes adds protocol discovery. The device-scoped route
// uses the {deviceID} wildcard so device-restricted API tokens keep working.
func (s *Server) registerProtocolRoutes(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/protocols", s.requireAuthOrScope(apitoken.ScopeTrafficRead, http.HandlerFunc(s.listProtocols)))
	mux.Handle("GET /api/v1/protocols/catalog", s.requireAuthOrScope(apitoken.ScopeTrafficRead, http.HandlerFunc(s.protocolCatalog)))
	mux.Handle("GET /api/v1/devices/{deviceID}/protocols", s.requireAuthOrScope(apitoken.ScopeTrafficRead, http.HandlerFunc(s.listDeviceProtocols)))
}

// protocolRequestError is a client-facing error with a next step.
type protocolRequestError struct {
	status  int
	code    string
	message string
}

func (e *protocolRequestError) Error() string { return e.message }

func (s *Server) listProtocols(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	query, err := s.parseProtocolQuery(r.Context(), r.URL.Query(), "", true)
	if err != nil {
		writeProtocolError(w, err)
		return
	}
	s.serveProtocolSummary(w, r, query)
}

func (s *Server) listDeviceProtocols(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	query, err := s.parseProtocolQuery(r.Context(), r.URL.Query(), r.PathValue("deviceID"), false)
	if err != nil {
		writeProtocolError(w, err)
		return
	}
	s.serveProtocolSummary(w, r, query)
}

func (s *Server) protocolCatalog(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "The protocol catalog takes no parameters. Remove the query string and try again.")
		return
	}
	writeJSON(w, http.StatusOK, ingest.NewProtocolCatalog())
}

func (s *Server) serveProtocolSummary(w http.ResponseWriter, r *http.Request, query ingest.ProtocolSummaryQuery) {
	reader, ok := s.eventReader.(ingest.ProtocolSummaryReader)
	if !ok || reader == nil {
		writeError(w, http.StatusServiceUnavailable, "protocol_summary_unavailable", "Protocol discovery needs the event store. Check `shakerproxy status` and make sure ingestd and PostgreSQL are running.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	summary, err := reader.QueryProtocolSummary(ctx, query)
	if err != nil {
		s.logger.Warn("protocol summary query failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "protocol_summary_unavailable", "Protocol discovery is temporarily unavailable. Try again, or use a shorter window such as window=1h.")
		return
	}
	s.projectProtocolDeviceNames(&summary)
	writeJSON(w, http.StatusOK, summary)
}

// parseProtocolQuery validates the public query. pathDevice is the {device}
// path segment for the device route; allowDeviceParam enables ?device=.
func (s *Server) parseProtocolQuery(ctx context.Context, values url.Values, pathDevice string, allowDeviceParam bool) (ingest.ProtocolSummaryQuery, error) {
	allowed := map[string]bool{"window": true, "category": true, "exotic": true, "device": allowDeviceParam}
	for key, entries := range values {
		if !allowed[key] {
			return ingest.ProtocolSummaryQuery{}, &protocolRequestError{http.StatusBadRequest, "invalid_query", fmt.Sprintf("Unsupported parameter %q. Use window, category, exotic, or device.", key)}
		}
		if len(entries) != 1 {
			return ingest.ProtocolSummaryQuery{}, &protocolRequestError{http.StatusBadRequest, "invalid_query", fmt.Sprintf("Parameter %q was given more than once. Pass it once.", key)}
		}
	}
	window := values.Get("window")
	if window == "" {
		window = ingest.DefaultProtocolSummaryWindow
	}
	seconds, ok := ingest.ProtocolSummaryWindowSeconds(window)
	if !ok {
		return ingest.ProtocolSummaryQuery{}, &protocolRequestError{http.StatusBadRequest, "invalid_window", "Window must be 1h, 24h, 7d, or 30d."}
	}
	query := ingest.ProtocolSummaryQuery{WindowSeconds: seconds}
	if category := strings.ToLower(strings.TrimSpace(values.Get("category"))); category != "" {
		if !protocolclass.ValidCategory(category) {
			return ingest.ProtocolSummaryQuery{}, &protocolRequestError{http.StatusBadRequest, "invalid_category", fmt.Sprintf("Unknown category %q. List categories with GET /api/v1/protocols/catalog.", category)}
		}
		query.Category = category
	}
	if raw := values.Get("exotic"); raw != "" {
		exotic, err := strconv.ParseBool(raw)
		if err != nil {
			return ingest.ProtocolSummaryQuery{}, &protocolRequestError{http.StatusBadRequest, "invalid_exotic", "exotic must be true or false."}
		}
		query.Exotic = &exotic
	}
	reference := pathDevice
	if allowDeviceParam {
		reference = values.Get("device")
	}
	if reference != "" || !allowDeviceParam {
		deviceID, err := s.resolveProtocolDevice(ctx, reference)
		if err != nil {
			return ingest.ProtocolSummaryQuery{}, err
		}
		query.DeviceID = deviceID
	}
	if err := query.Validate(); err != nil {
		return ingest.ProtocolSummaryQuery{}, &protocolRequestError{http.StatusBadRequest, "invalid_query", err.Error()}
	}
	return query, nil
}

// resolveProtocolDevice turns any device reference (ID, friendly name, IP, or
// MAC address) into a device ID using the shared device resolver.
func (s *Server) resolveProtocolDevice(ctx context.Context, reference string) (string, error) {
	reference = strings.TrimSpace(reference)
	if s.inventory == nil && deviceinventory.ValidDeviceID(reference) {
		return reference, nil
	}
	device, err := s.resolveDeviceRef(ctx, reference)
	if err != nil {
		return "", err
	}
	if err := requireDeviceAccess(ctx, device.ID); err != nil {
		return "", err
	}
	return device.ID, nil
}

// projectProtocolDeviceNames adds current friendly names. Storage never sees
// or returns inventory names; a missing name is left empty.
func (s *Server) projectProtocolDeviceNames(summary *ingest.ProtocolSummary) {
	if s.nameResolver == nil || s.nameResolver.Ready() != nil {
		return
	}
	names := map[string]string{}
	now := time.Now().UTC()
	for protocolIndex := range summary.Protocols {
		devices := summary.Protocols[protocolIndex].Devices
		for deviceIndex := range devices {
			id := devices[deviceIndex].DeviceID
			name, cached := names[id]
			if !cached {
				if projection, found, err := s.nameResolver.Resolve(id, now); err == nil && found {
					name = projection.CurrentFriendlyName
				}
				names[id] = name
			}
			devices[deviceIndex].DeviceName = name
		}
	}
}

func writeProtocolError(w http.ResponseWriter, err error) {
	var requestErr *protocolRequestError
	if errors.As(err, &requestErr) {
		writeError(w, requestErr.status, requestErr.code, requestErr.message)
		return
	}
	var refErr *deviceRefError
	if errors.As(err, &refErr) {
		writeDeviceRefError(w, err)
		return
	}
	writeError(w, http.StatusBadRequest, "invalid_query", err.Error())
}
