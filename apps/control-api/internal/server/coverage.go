package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"shakerproxy.dev/shakerproxy/internal/apitoken"
	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/coverage"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/ingest"
	"shakerproxy.dev/shakerproxy/internal/labrouting"
	"shakerproxy.dev/shakerproxy/internal/testlab"
	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

// The visibility coverage check proves, per traffic type, what ShakerProxy
// actually records. control-api runs it end to end: the test lab builds the
// virtual clients, gatewayd records their bridge with a normal capture, the
// probes send one of each traffic type, the real analyzers and DNS forwarder
// store events, and this file reads them back through the same event query
// the Traffic page uses. Nothing here writes events.

type coverageLab interface {
	CoveragePrepare(context.Context, string) (testlab.CoveragePrepareResponse, error)
	CoverageProbe(context.Context, coverage.Plan) (testlab.CoverageProbeResponse, error)
	CoverageCleanup(context.Context, string) error
}

type coverageState struct {
	mu      sync.Mutex
	running bool
	last    *coverage.Report
	loaded  bool
	// Test hooks; production uses the test-lab socket and real time.
	lab          coverageLab
	pause        func(context.Context, time.Duration) error
	analysisWait time.Duration
	reportPath   string
}

const (
	coverageAnalysisWait = 150 * time.Second
	coveragePollInterval = 3 * time.Second
	coverageRunTimeout   = 5 * time.Minute
	maxCoverageEventPage = 10
)

func (s *Server) CoverageHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/coverage", s.requireAuthOrScope(apitoken.ScopeSystemRead, http.HandlerFunc(s.getCoverage)))
	mux.Handle("POST /api/v1/coverage/runs", s.requireAuth(http.HandlerFunc(s.startCoverageRun)))
	return s.wrapMux(mux)
}

func (s *Server) coverageReportPath() string {
	if s.coverage.reportPath != "" {
		return s.coverage.reportPath
	}
	if path := strings.TrimSpace(os.Getenv("SHAKERPROXY_COVERAGE_REPORT_PATH")); path != "" {
		return path
	}
	return "/var/lib/shakerproxy/control-api/coverage/last-run.json"
}

// lastCoverage returns a copy of the latest report, loading the persisted one
// after a restart.
func (s *Server) lastCoverage() *coverage.Report {
	s.coverage.mu.Lock()
	defer s.coverage.mu.Unlock()
	if !s.coverage.loaded {
		s.coverage.loaded = true
		if data, err := os.ReadFile(s.coverageReportPath()); err == nil && len(data) < 1<<20 {
			var report coverage.Report
			if json.Unmarshal(data, &report) == nil && report.Schema == coverage.SchemaVersion {
				if report.State == coverage.StateRunning {
					// The appliance restarted mid-run.
					report.State, report.Error = coverage.StateFailed, "The check was interrupted by a restart; run it again."
				}
				s.coverage.last = &report
			}
		}
	}
	if s.coverage.last == nil {
		return nil
	}
	copied := *s.coverage.last
	return &copied
}

func (s *Server) storeCoverage(report coverage.Report, persist bool) {
	s.coverage.mu.Lock()
	s.coverage.last = &report
	s.coverage.loaded = true
	s.coverage.mu.Unlock()
	if !persist {
		return
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return
	}
	path := s.coverageReportPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		s.logger.Warn("coverage report could not be saved", "error", err)
		return
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0o640); err == nil {
		_ = os.Rename(temporary, path)
	}
}

func (s *Server) getCoverage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "the coverage overview does not accept query parameters")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	routing := s.inspectCoverageRouting(ctx)
	writeJSON(w, http.StatusOK, coverage.Overview{
		Schema:    coverage.SchemaVersion,
		LastRun:   s.lastCoverage(),
		Routing:   routing,
		GapCount:  coverage.CountGaps(routing),
		CheckedAt: time.Now().UTC(),
	})
}

type coverageRunRequest struct {
	Password string `json:"password"`
}

func (s *Server) startCoverageRun(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var request coverageRunRequest
	if err := decodeOptionalJSON(r, &request, 4<<10); err != nil {
		writeDecodeError(w, err, "coverage run")
		return
	}
	if !s.confirmAdministrator(w, r, strings.TrimSpace(request.Password), passwordRecent) {
		return
	}
	s.coverage.mu.Lock()
	if s.coverage.running {
		s.coverage.mu.Unlock()
		writeError(w, http.StatusConflict, "coverage_running", "A visibility coverage check is already running.")
		return
	}
	s.coverage.running = true
	s.coverage.mu.Unlock()
	runID, err := newCoverageRunID()
	if err != nil {
		s.coverage.mu.Lock()
		s.coverage.running = false
		s.coverage.mu.Unlock()
		writeError(w, http.StatusInternalServerError, "coverage_unavailable", "The coverage check could not start.")
		return
	}
	report := coverage.Report{Schema: coverage.SchemaVersion, RunID: runID, State: coverage.StateRunning, Phase: "Building the virtual test lab",
		StartedAt: time.Now().UTC(), Results: []coverage.Result{}, Routing: []coverage.Finding{}, Limitations: coverage.Limitations()}
	s.storeCoverage(report, true)
	administrator := sessionUsername(r.Context())
	s.logger.Info("visibility coverage check started", "run_id", runID, "username", administrator)
	go s.runCoverage(report, administrator)
	writeJSON(w, http.StatusAccepted, report)
}

func newCoverageRunID() (string, error) {
	value := make([]byte, 12)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return "coverage-" + hex.EncodeToString(value), nil
}

func (s *Server) coverageLabClient() coverageLab {
	if s.coverage.lab != nil {
		return s.coverage.lab
	}
	return testLabClient(90 * time.Second)
}

func (s *Server) coveragePause(ctx context.Context, duration time.Duration) error {
	if s.coverage.pause != nil {
		return s.coverage.pause(ctx, duration)
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// runCoverage drives one run; every exit path cleans the test lab, stops the
// capture and stores a final report.
func (s *Server) runCoverage(report coverage.Report, administrator string) {
	ctx, cancel := context.WithTimeout(context.Background(), coverageRunTimeout)
	defer cancel()
	defer func() {
		s.coverage.mu.Lock()
		s.coverage.running = false
		s.coverage.mu.Unlock()
	}()
	plan := coverage.NewPlan(report.RunID, report.StartedAt)
	lab := s.coverageLabClient()
	phase := func(text string) {
		report.Phase = text
		s.storeCoverage(report, false)
	}
	finish := func(state coverage.State, message string) {
		finished := time.Now().UTC()
		report.State, report.Error, report.Phase, report.FinishedAt = state, message, "", &finished
		routingCtx, routingCancel := context.WithTimeout(context.Background(), 10*time.Second)
		report.Routing = s.inspectCoverageRouting(routingCtx)
		routingCancel()
		report.Count()
		s.storeCoverage(report, true)
		s.logger.Info("visibility coverage check finished", "run_id", report.RunID, "state", state, "pass", report.PassCount, "fail", report.FailCount, "gaps", report.GapCount)
	}
	labPrepared := false
	cleanupLab := func() {
		if !labPrepared {
			return
		}
		labPrepared = false
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if err := lab.CoverageCleanup(cleanupCtx, report.RunID); err != nil {
			s.logger.Warn("coverage lab cleanup failed; the test lab removes it when its lease ends", "run_id", report.RunID, "error", err)
		}
	}
	defer cleanupLab()
	if _, err := lab.CoveragePrepare(ctx, report.RunID); err != nil {
		finish(coverage.StateFailed, "The virtual test lab could not be built: "+boundedMessage(err))
		return
	}
	labPrepared = true
	phase("Recording the virtual clients")
	var started capture.View
	start := capture.StartRequest{
		Name: "Visibility coverage check", Description: "Probe traffic from the virtual test lab for the visibility coverage check.",
		Mode: capture.ModeFull, SegmentSizeMiB: 8, SegmentSeconds: 10, MaxFiles: 8, StopAfterSeconds: 180,
		IdempotencyKey: report.RunID, Administrator: administrator, StartReason: "visibility coverage check", CoverageLab: true,
	}
	if err := s.gateway.Call(ctx, "StartCapture", gatewayprotocol.StartCaptureParams{Request: start}, &started); err != nil {
		finish(coverage.StateFailed, "The coverage recording could not start: "+boundedMessage(err))
		return
	}
	report.CaptureSessionID = started.Session.ID
	stopCapture := func() {
		if report.CaptureSessionID == "" {
			return
		}
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer stopCancel()
		var stopped capture.View
		if err := s.gateway.Call(stopCtx, "StopCapture", gatewayprotocol.StopCaptureParams{SessionID: report.CaptureSessionID}, &stopped); err != nil {
			s.logger.Warn("coverage recording could not be stopped", "run_id", report.RunID, "capture_id", report.CaptureSessionID, "error", err)
		}
	}
	// dumpcap needs a moment before the first probe.
	if err := s.coveragePause(ctx, 2*time.Second); err != nil {
		stopCapture()
		finish(coverage.StateFailed, "The check was cancelled.")
		return
	}
	phase("Sending one of each traffic type")
	probed, err := lab.CoverageProbe(ctx, plan)
	_ = s.coveragePause(ctx, 2*time.Second)
	stopCapture()
	cleanupLab()
	if err != nil {
		finish(coverage.StateFailed, "The probes could not run: "+boundedMessage(err))
		return
	}
	phase("Waiting for ShakerProxy to analyze and store the traffic")
	wait := s.coverage.analysisWait
	if wait == 0 {
		wait = coverageAnalysisWait
	}
	deadline := time.Now().Add(wait)
	for {
		events, queryErr := s.coverageEvents(ctx, report.CaptureSessionID, report.StartedAt)
		if queryErr == nil {
			report.Results = coverage.Evaluate(plan, probed.Outcomes, events)
			report.Count()
			s.storeCoverage(report, false)
			if coverage.Settled(report.Results) {
				break
			}
		} else {
			s.logger.Warn("coverage events could not be read", "run_id", report.RunID, "error", queryErr)
		}
		if time.Now().After(deadline) {
			if queryErr != nil && len(report.Results) == 0 {
				finish(coverage.StateFailed, "Stored events could not be read: "+boundedMessage(queryErr))
				return
			}
			break
		}
		if s.coveragePause(ctx, coveragePollInterval) != nil {
			break
		}
	}
	report.Results = append(report.Results, s.coverageWiFiRadio(ctx))
	report.Count()
	finish(coverage.StateCompleted, "")
}

// coverageWiFiRadio reports whether ShakerProxy listens on the radio.
func (s *Server) coverageWiFiRadio(ctx context.Context) coverage.Result {
	var status gatewayprotocol.WiFiMonitorStatus
	if err := s.gateway.Call(ctx, "GetWiFiMonitor", gatewayprotocol.EmptyParams{}, &status); err != nil {
		return coverage.WiFiRadioResult(coverage.WiFiRadio{Unknown: true})
	}
	return coverage.WiFiRadioResult(coverage.WiFiRadio{
		Enabled: status.Settings.Enabled, Active: status.Active, Available: status.Available, Reason: status.Reason,
		Adapter: status.Adapter, ChannelMode: status.ChannelMode, Channel: status.Channel, WorkerRunning: status.WorkerRunning,
	})
}

func boundedMessage(err error) string {
	message := err.Error()
	if len(message) > 300 {
		message = message[:300] + "…"
	}
	return message
}

// coverageEvents reads the run's events back through the Traffic page's
// query: the coverage recording's analyzer events, plus the DNS forwarder's
// lookups from the virtual clients.
func (s *Server) coverageEvents(ctx context.Context, captureID string, since time.Time) ([]coverage.Event, error) {
	if s.eventReader == nil {
		return nil, errors.New("normalized event storage is not configured")
	}
	scope := "(source:HOST AND (src.ip:" + coverage.ClientCIDR + " OR src.ip:" + coverage.ClientIPv6CIDR + "))"
	if captureID != "" {
		scope = "(capture.id:" + captureID + " OR " + scope + ")"
	}
	text := scope + " AND time>=" + since.Add(-5*time.Second).UTC().Format(time.RFC3339)
	events := []coverage.Event{}
	cursor := ""
	for page := 0; page < maxCoverageEventPage; page++ {
		values := url.Values{"limit": {"100"}, "q": {text}}
		if cursor != "" {
			values.Set("cursor", cursor)
		}
		query, err := ingest.ParseRecentEventQuery(values)
		if err != nil {
			return nil, err
		}
		queryCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		result, err := s.eventReader.QueryRecent(queryCtx, query)
		cancel()
		if err != nil {
			return nil, err
		}
		for _, event := range result.Events {
			events = append(events, coverageEvent(event))
		}
		if result.NextCursor == "" {
			break
		}
		cursor = result.NextCursor
	}
	return events, nil
}

func coverageEvent(event ingest.RecentEvent) coverage.Event {
	return coverage.Event{
		RecordID: event.RecordID, Source: string(event.Source), Kind: event.Kind, OccurredAt: event.OccurredAt, ReceivedAt: event.ReceivedAt,
		DeviceID: event.DeviceID, SourceIP: event.SourceIP, DestinationIP: event.DestinationIP, DestinationPort: event.DestinationPort,
		Protocol: event.Protocol, Service: event.Service, AppProtocol: event.AppProtocol, DNSQuery: event.DNSQuery,
		TLSServerName: event.TLSServerName, HTTPHost: event.HTTPHost, HTTPPath: event.HTTPPath,
	}
}

// inspectCoverageRouting judges the live configuration: what gatewayd
// reports about the lab and DNS policy, and what recorded traffic shows
// about other routers and DHCP servers on the lab network.
func (s *Server) inspectCoverageRouting(ctx context.Context) []coverage.Finding {
	var status gatewayprotocol.Status
	if err := s.gateway.Call(ctx, "GetManagedState", gatewayprotocol.EmptyParams{}, &status); err != nil {
		return []coverage.Finding{{ID: coverage.FindingNotRouting, Title: "Gateway", Status: coverage.FindingUnknown,
			Detail: "ShakerProxy's gateway service did not answer, so the lab's routing could not be checked."}}
	}
	input := coverage.RoutingInput{
		Routing:             status.OperatingMode == gatewayprotocol.ModeRouted && !status.EmergencyBypass && status.LabInterface != "",
		Topology:            status.LabTopology,
		IPv6Strategy:        status.LabIPv6Strategy,
		LabInterface:        status.LabInterface,
		WirelessAccessPoint: status.LabWiFi,
		WirelessClients:     status.LabWiFiClientTraffic,
	}
	var onboarding gatewayprotocol.LabOnboarding
	if s.gateway.Call(ctx, "GetLabOnboarding", gatewayprotocol.EmptyParams{}, &onboarding) == nil {
		input.GatewayIPv4 = onboarding.GatewayIPv4
	}
	own := map[netip.Addr]bool{}
	for _, value := range []string{input.GatewayIPv4, status.LabIPv6Gateway} {
		if address, err := netip.ParseAddr(value); err == nil {
			own[address] = true
		}
	}
	var inspection gatewayprotocol.HostInspection
	if s.gateway.Call(ctx, "InspectHost", gatewayprotocol.EmptyParams{}, &inspection) == nil {
		input.LabIPv6 = labHasForeignIPv6(inspection, status.LabInterface, status.LabIPv6Prefix)
		for address := range hostAddresses(inspection) {
			own[address] = true
		}
	}
	var policy trafficpolicy.Document
	if s.gateway.Call(ctx, "GetTrafficPolicy", gatewayprotocol.EmptyParams{}, &policy) == nil {
		dns := policy.Policy.EncryptedDNS
		input.PolicyAvailable = true
		input.BlockDoT, input.BlockDoQ, input.BlockKnownDoH, input.RedirectPlainDNS = dns.BlockDoT, dns.BlockDoQ, dns.BlockKnownDoH, dns.RedirectPlainDNS
	}
	var vpnStatus gatewayprotocol.VPNStatus
	if s.gateway.Call(ctx, "GetVPN", gatewayprotocol.EmptyParams{}, &vpnStatus) == nil && vpnStatus.Enabled && vpnStatus.Up && !status.EmergencyBypass {
		input.VPN, input.VPNDevices, input.VPNPeerToPeer, input.VPNIPv6Routed = true, len(vpnStatus.Peers), vpnStatus.AllowPeerToPeer, vpnStatus.IPv6Routed
	}
	// Zeek records an ICMPv6 router advertisement (type 134) as an icmp
	// connection with the type as its source port.
	input.ForeignRouterAdverts, input.RouterAdvertsSearched = s.coverageForeignSources(ctx, "protocol:icmp AND src.port:134 AND time:last_24h", own)
	input.ForeignDHCPServers, _ = s.coverageForeignSources(ctx, "protocol:udp AND src.port:67 AND time:last_24h", own)
	if routing := s.currentLabRouting(ctx); routing.Available {
		input.LabPresenceChecked, input.ShakerProxyIPv4, input.RouterIPv4 = true, routing.ShakerProxyAddress, routing.RouterAddress
		for _, device := range routing.Devices {
			if device.Routing == labrouting.Bypassing {
				input.BypassingDevices = append(input.BypassingDevices, labDeviceTitle(device))
			}
		}
	}
	return coverage.InspectRouting(input)
}

// hostAddresses is every address on the appliance's interfaces, including
// the link-local ones its own router advertisements come from.
func hostAddresses(inspection gatewayprotocol.HostInspection) map[netip.Addr]bool {
	addresses := map[netip.Addr]bool{}
	for _, observed := range inspection.Interfaces {
		for _, value := range observed.Addresses {
			if prefix, err := netip.ParsePrefix(value); err == nil {
				addresses[prefix.Addr().WithZone("").Unmap()] = true
			} else if address, err := netip.ParseAddr(value); err == nil {
				addresses[address.WithZone("").Unmap()] = true
			}
		}
	}
	return addresses
}

// labHasForeignIPv6 reports IPv6 on the lab interface that ShakerProxy did
// not configure: a global or unique-local address outside the lab's own
// IPv6 prefix, or an IPv6 default route, which another router's
// advertisements provide.
func labHasForeignIPv6(inspection gatewayprotocol.HostInspection, labInterface, ownPrefix string) bool {
	own, ownErr := netip.ParsePrefix(ownPrefix)
	for _, observed := range inspection.Interfaces {
		if observed.Name != labInterface {
			continue
		}
		if observed.DefaultIPv6 {
			return true
		}
		for _, value := range observed.Addresses {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				continue
			}
			address := prefix.Addr()
			if !address.Is6() || address.Is4In6() || address.IsLinkLocalUnicast() || address.IsLoopback() {
				continue
			}
			if ownErr == nil && own.Contains(address) {
				continue
			}
			return true
		}
	}
	return false
}

// coverageForeignSources lists the senders of matching recorded traffic
// that are not ShakerProxy itself, and reports whether the recorded traffic
// could be searched at all.
func (s *Server) coverageForeignSources(ctx context.Context, text string, own map[netip.Addr]bool) ([]string, bool) {
	if s.eventReader == nil {
		return nil, false
	}
	query, err := ingest.ParseRecentEventQuery(url.Values{"limit": {"50"}, "q": {text}})
	if err != nil {
		s.logger.Warn("coverage routing query is invalid", "query", text, "error", err)
		return nil, false
	}
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	result, err := s.eventReader.QueryRecent(queryCtx, query)
	if err != nil {
		return nil, false
	}
	sources := []string{}
	for _, event := range result.Events {
		address, err := netip.ParseAddr(event.SourceIP)
		if err != nil {
			continue
		}
		address = address.WithZone("").Unmap()
		if own[address] || address.IsUnspecified() {
			continue
		}
		sources = append(sources, address.String())
	}
	return sources, true
}
