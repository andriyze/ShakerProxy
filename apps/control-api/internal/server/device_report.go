package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"shakerproxy.dev/shakerproxy/internal/devicereport"
	"shakerproxy.dev/shakerproxy/internal/ingest"
	deviceinventory "shakerproxy.dev/shakerproxy/internal/inventory"
	"shakerproxy.dev/shakerproxy/internal/testsession"
)

const (
	defaultReportWindow = 24 * time.Hour
	reportQueryTimeout  = 12 * time.Second
)

var reportWindows = map[string]time.Duration{
	"15m": 15 * time.Minute, "1h": time.Hour, "6h": 6 * time.Hour, "24h": 24 * time.Hour,
	"7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour,
}

// reportRange is one resolved time range, optionally tied to a test session.
type reportRange struct {
	start     time.Time
	end       time.Time
	session   *testsession.Session
	truncated bool
}

// intelError is a handler error with a status, stable code, and a sentence
// that says what to do next.
type intelError struct {
	status  int
	code    string
	message string
}

func (e *intelError) Error() string { return e.message }

func writeIntelError(w http.ResponseWriter, err error) {
	var failure *intelError
	if errors.As(err, &failure) {
		writeError(w, failure.status, failure.code, failure.message)
		return
	}
	var refErr *deviceRefError
	if errors.As(err, &refErr) {
		writeDeviceRefError(w, err)
		return
	}
	writeError(w, http.StatusServiceUnavailable, "unavailable", "The request could not be completed right now. Try again, or check System → Status.")
}

func (s *Server) getDeviceReport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	values := r.URL.Query()
	if err := allowIntelParameters(values, "window", "session", "start", "end"); err != nil {
		writeIntelError(w, err)
		return
	}
	device, err := s.resolveReportDevice(r)
	if err != nil {
		writeIntelError(w, err)
		return
	}
	now := time.Now().UTC().Truncate(time.Second)
	selected, err := s.parseReportRange(values, "", device, now, true)
	if err != nil {
		writeIntelError(w, err)
		return
	}
	report, err := s.buildDeviceReport(r.Context(), device, selected, now)
	if err != nil {
		writeIntelError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) compareDeviceRuns(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	values := r.URL.Query()
	if err := allowIntelParameters(values, "base", "compare", "base_start", "base_end", "compare_start", "compare_end"); err != nil {
		writeIntelError(w, err)
		return
	}
	device, err := s.resolveReportDevice(r)
	if err != nil {
		writeIntelError(w, err)
		return
	}
	now := time.Now().UTC().Truncate(time.Second)
	sides := [2]reportRange{}
	for index, prefix := range []string{"base", "compare"} {
		side := url.Values{}
		if id := values.Get(prefix); id != "" {
			side.Set("session", id)
		}
		if start := values.Get(prefix + "_start"); start != "" {
			side.Set("start", start)
		}
		if end := values.Get(prefix + "_end"); end != "" {
			side.Set("end", end)
		}
		if len(side) == 0 {
			writeError(w, http.StatusBadRequest, "invalid_query", fmt.Sprintf("Choose the %s run with ?%s=<test session ID> or ?%s_start=…&%s_end=… (RFC 3339 times).", prefix, prefix, prefix, prefix))
			return
		}
		sides[index], err = s.parseReportRange(side, prefix, device, now, false)
		if err != nil {
			writeIntelError(w, err)
			return
		}
	}
	// Build both runs concurrently so a comparison takes about as long as
	// one report.
	reports := [2]devicereport.Report{}
	failures := [2]error{}
	var wait sync.WaitGroup
	for index := range sides {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			reports[index], failures[index] = s.buildDeviceReport(r.Context(), device, sides[index], now)
		}(index)
	}
	wait.Wait()
	for _, failure := range failures {
		if failure != nil {
			writeIntelError(w, failure)
			return
		}
	}
	comparison := devicereport.Compare(now, reports[0], reports[1], reportSide(sides[0]), reportSide(sides[1]))
	comparison.DeviceID = device.ID
	writeJSON(w, http.StatusOK, comparison)
}

func reportSide(selected reportRange) devicereport.Side {
	if selected.session == nil {
		return devicereport.Side{}
	}
	return devicereport.Side{SessionID: selected.session.ID, Name: selected.session.Name}
}

func (s *Server) resolveReportDevice(r *http.Request) (deviceinventory.Device, error) {
	device, err := s.resolveDeviceRef(r.Context(), r.PathValue("deviceID"))
	if err != nil {
		return deviceinventory.Device{}, err
	}
	if err := requireDeviceAccess(r.Context(), device.ID); err != nil {
		return deviceinventory.Device{}, err
	}
	return device, nil
}

// parseReportRange accepts ?session=, ?start=&end=, or ?window= (in that
// precedence; mixing them is rejected). With nothing given it uses the
// device's running test session when allowDefaultSession is set, and
// otherwise the last 24 hours.
func (s *Server) parseReportRange(values url.Values, label string, device deviceinventory.Device, now time.Time, allowDefaultSession bool) (reportRange, error) {
	sessionID := strings.TrimSpace(values.Get("session"))
	window := strings.TrimSpace(values.Get("window"))
	startText, endText := strings.TrimSpace(values.Get("start")), strings.TrimSpace(values.Get("end"))
	name := "report"
	if label != "" {
		name = label + " run"
	}
	given := 0
	for _, present := range []bool{sessionID != "", window != "", startText != "" || endText != ""} {
		if present {
			given++
		}
	}
	if given > 1 {
		return reportRange{}, &intelError{http.StatusBadRequest, "invalid_query", fmt.Sprintf("Choose the %s time range one way: a test session, a window such as 24h, or a start and end time.", name)}
	}
	switch {
	case sessionID != "":
		session, err := s.lookupTestSession(sessionID)
		if err != nil {
			return reportRange{}, err
		}
		if session.DeviceID != device.ID {
			return reportRange{}, &intelError{http.StatusBadRequest, "session_device_mismatch", fmt.Sprintf("Test session %s belongs to %q, not %q. Use that device or pick another session.", session.ID, session.DeviceName, deviceDisplayName(device))}
		}
		return sessionRange(session, now), nil
	case startText != "" || endText != "":
		start, startErr := time.Parse(time.RFC3339, startText)
		end, endErr := now, error(nil)
		if endText != "" {
			end, endErr = time.Parse(time.RFC3339, endText)
		}
		if startErr != nil || endErr != nil {
			return reportRange{}, &intelError{http.StatusBadRequest, "invalid_time_range", fmt.Sprintf("The %s start and end must be RFC 3339 times such as 2026-09-29T10:00:00Z.", name)}
		}
		start, end = start.UTC().Truncate(time.Second), end.UTC().Truncate(time.Second)
		if !end.After(start) || end.Sub(start) > ingest.MaxDeviceActivityWindow || start.Year() < 2000 {
			return reportRange{}, &intelError{http.StatusBadRequest, "invalid_time_range", fmt.Sprintf("The %s end must be after its start, and the range can cover at most 31 days.", name)}
		}
		return reportRange{start: start, end: end}, nil
	case window != "":
		duration, ok := reportWindows[strings.ToLower(window)]
		if !ok {
			return reportRange{}, &intelError{http.StatusBadRequest, "invalid_window", "Window must be one of 15m, 1h, 6h, 24h, 7d, or 30d."}
		}
		return reportRange{start: now.Add(-duration), end: now}, nil
	}
	if allowDefaultSession {
		if store := s.testSessions(); store != nil {
			if session, running, err := store.Running(device.ID); err == nil && running {
				return sessionRange(session, now), nil
			}
		}
	}
	return reportRange{start: now.Add(-defaultReportWindow), end: now}, nil
}

func sessionRange(session testsession.Session, now time.Time) reportRange {
	start := session.StartedAt.UTC().Truncate(time.Second)
	end := session.End(now).UTC().Truncate(time.Second)
	if !end.After(start) {
		end = start.Add(time.Second)
	}
	selected := reportRange{start: start, end: end, session: &session}
	if end.Sub(start) > ingest.MaxDeviceActivityWindow {
		selected.start, selected.truncated = end.Add(-ingest.MaxDeviceActivityWindow), true
	}
	return selected
}

func (s *Server) lookupTestSession(id string) (testsession.Session, error) {
	store := s.testSessions()
	if store == nil {
		return testsession.Session{}, &intelError{http.StatusServiceUnavailable, "test_sessions_unavailable", "Test sessions are unavailable because the control API has no data directory."}
	}
	session, err := store.Get(strings.TrimSpace(id))
	if errors.Is(err, testsession.ErrNotFound) {
		return testsession.Session{}, &intelError{http.StatusNotFound, "test_session_not_found", fmt.Sprintf("No test session has ID %q. Run `shakerproxy test list` or open Tests.", id)}
	}
	if err != nil {
		return testsession.Session{}, &intelError{http.StatusServiceUnavailable, "test_sessions_unavailable", "Test sessions are unavailable right now. Try again, or check System → Status."}
	}
	return session, nil
}

func (s *Server) buildDeviceReport(ctx context.Context, device deviceinventory.Device, selected reportRange, now time.Time) (devicereport.Report, error) {
	reader, ok := s.eventReader.(ingest.DeviceActivityReader)
	if !ok || reader == nil {
		return devicereport.Report{}, &intelError{http.StatusServiceUnavailable, "traffic_unavailable", "Traffic storage is not available, so the report cannot be built. Check System → Status."}
	}
	queryContext, cancel := context.WithTimeout(ctx, reportQueryTimeout)
	defer cancel()
	activity, err := reader.QueryDeviceActivity(queryContext, ingest.DeviceActivityQuery{DeviceID: device.ID, Start: selected.start, End: selected.end, Addresses: deviceAddressesDuring(device, selected.start, selected.end)})
	if err != nil {
		s.logger.Warn("device activity query failed", "device_id", device.ID, "error", err)
		return devicereport.Report{}, &intelError{http.StatusServiceUnavailable, "traffic_unavailable", "Traffic storage did not answer in time. Try a shorter window, or check System → Status."}
	}
	report := devicereport.Build(devicereport.Input{
		GeneratedAt: now,
		Device:      reportDevice(device),
		Session:     selected.session,
		CATrust:     devicereport.NormalizeCATrust(device.CATrust),
		Activity:    activity,
	})
	report.Truncated = report.Truncated || selected.truncated
	return report, nil
}

func reportDevice(device deviceinventory.Device) devicereport.Device {
	vendor := ""
	if device.Vendor != nil {
		vendor = device.Vendor.Name
	}
	return devicereport.Device{
		DeviceID:          device.ID,
		FriendlyName:      deviceDisplayName(device),
		Vendor:            vendor,
		Category:          device.Category,
		Addresses:         deviceCurrentAddresses(device),
		HardwareAddresses: deviceHardwareAddresses(device),
		Online:            device.Online,
	}
}

func allowIntelParameters(values url.Values, allowed ...string) error {
	permitted := make(map[string]bool, len(allowed))
	for _, name := range allowed {
		permitted[name] = true
	}
	for key, entries := range values {
		if !permitted[key] {
			return &intelError{http.StatusBadRequest, "invalid_query", fmt.Sprintf("Unknown parameter %q. Supported parameters: %s.", key, strings.Join(allowed, ", "))}
		}
		if len(entries) != 1 {
			return &intelError{http.StatusBadRequest, "invalid_query", fmt.Sprintf("Give %q only once.", key)}
		}
	}
	return nil
}

// deviceAddressesDuring returns the device's addresses whose validity overlaps
// [start, end), most recently valid first, bounded for the activity query.
// Connections other hosts opened to these addresses show up as services the
// device accepts.
func deviceAddressesDuring(device deviceinventory.Device, start, end time.Time) []string {
	validUntil := map[string]time.Time{}
	for _, observation := range device.Addresses {
		if observation.ValidUntil.Before(start) || !observation.ValidFrom.Before(end) {
			continue
		}
		address, err := netip.ParseAddr(observation.Address)
		if err != nil || address.Zone() != "" {
			continue
		}
		canonical := address.Unmap().String()
		if observation.ValidUntil.After(validUntil[canonical]) {
			validUntil[canonical] = observation.ValidUntil
		}
	}
	addresses := make([]string, 0, len(validUntil))
	for address := range validUntil {
		addresses = append(addresses, address)
	}
	sort.Slice(addresses, func(i, j int) bool {
		if !validUntil[addresses[i]].Equal(validUntil[addresses[j]]) {
			return validUntil[addresses[i]].After(validUntil[addresses[j]])
		}
		return addresses[i] < addresses[j]
	})
	if len(addresses) > ingest.MaxDeviceActivityAddresses {
		addresses = addresses[:ingest.MaxDeviceActivityAddresses]
	}
	return addresses
}
