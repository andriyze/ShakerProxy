package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/coverage"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/ingest"
	"shakerproxy.dev/shakerproxy/internal/testlab"
	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

type fakeCoverageLab struct {
	mu       sync.Mutex
	plan     coverage.Plan
	prepared bool
	cleaned  bool
	failPrep bool
}

func (l *fakeCoverageLab) CoveragePrepare(_ context.Context, runID string) (testlab.CoveragePrepareResponse, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failPrep {
		return testlab.CoveragePrepareResponse{}, errors.New("prerequisite missing: nft")
	}
	l.prepared = true
	return testlab.CoveragePrepareResponse{Schema: 1, RunID: runID, Bridge: "lgtest-client"}, nil
}

func (l *fakeCoverageLab) CoverageProbe(_ context.Context, plan coverage.Plan) (testlab.CoverageProbeResponse, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.plan = plan
	outcomes := []coverage.ProbeOutcome{}
	for _, probe := range coverage.Probes {
		outcomes = append(outcomes, coverage.ProbeOutcome{ID: probe.ID, SentAt: time.Now().UTC(), Sent: probe.ID != coverage.ProbeIPv6, Skipped: probe.ID == coverage.ProbeIPv6})
	}
	return testlab.CoverageProbeResponse{Schema: 1, RunID: plan.RunID, Outcomes: outcomes}, nil
}

func (l *fakeCoverageLab) CoverageCleanup(context.Context, string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cleaned = true
	return nil
}

func (l *fakeCoverageLab) currentPlan() coverage.Plan {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.plan
}

// coverageEventStore answers the coverage query with what the analyzers and
// DNS forwarder would have stored for a few of the probes.
type coverageEventStore struct {
	lab     *fakeCoverageLab
	mu      sync.Mutex
	queries []string
}

func (s *coverageEventStore) QueryRecent(_ context.Context, query ingest.RecentEventQuery) (ingest.RecentEventPage, error) {
	s.mu.Lock()
	s.queries = append(s.queries, query.Filter.Canonical)
	s.mu.Unlock()
	plan := s.lab.currentPlan()
	if plan.RunID == "" || !strings.Contains(query.Filter.Canonical, "198.18.240.0/24") {
		return ingest.RecentEventPage{Events: []ingest.RecentEvent{}}, nil
	}
	now := time.Now().UTC()
	return ingest.RecentEventPage{Events: []ingest.RecentEvent{
		{RecordID: "dns", Source: "HOST", Kind: "shakerproxy.dns", OccurredAt: now, ReceivedAt: now, SourceIP: coverage.NormalClient, DNSQuery: plan.DNSGatewayName},
		{RecordID: "tls", Source: "ZEEK", Kind: "zeek.conn", OccurredAt: now, ReceivedAt: now, SourceIP: coverage.NormalClient, DestinationIP: coverage.TargetIPv4,
			DestinationPort: coverage.PortHTTPS, Protocol: "tcp", AppProtocol: "tls", TLSServerName: plan.TLSServerName},
	}}, nil
}

// startCoverageGateway answers every gateway call the check makes, for the
// whole test.
func startCoverageGateway(t *testing.T, socketPath string, calls chan<- gatewayprotocol.Request) {
	t.Helper()
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func(connection net.Conn) {
				defer connection.Close()
				var request gatewayprotocol.Request
				if json.NewDecoder(connection).Decode(&request) != nil {
					return
				}
				select {
				case calls <- request:
				default:
				}
				var result any = map[string]any{}
				switch request.Method {
				case "StartCapture":
					result = map[string]any{"session": map[string]any{"id": "capture-0123456789abcdef0123456789abcdef"}}
				case "GetManagedState":
					result = gatewayprotocol.Status{OperatingMode: gatewayprotocol.ModeRouted, LabInterface: "ens18", LabTopology: "SINGLE_ARM", LabIPv6Strategy: "DISABLED"}
				case "GetLabOnboarding":
					result = gatewayprotocol.LabOnboarding{Schema: 1, Routed: true, LabInterface: "ens18", GatewayIPv4: "192.168.10.177"}
				case "InspectHost":
					result = gatewayprotocol.HostInspection{Interfaces: []gatewayprotocol.Interface{{Name: "ens18", Addresses: []string{"192.168.10.177/24", "fe80::1/64"}}}}
				case "GetTrafficPolicy":
					result = trafficpolicy.Document{Schema: 1, Policy: trafficpolicy.Policy{EncryptedDNS: trafficpolicy.EncryptedDNSPolicy{Mode: trafficpolicy.EncryptedDNSObserve}}}
				}
				_ = json.NewEncoder(connection).Encode(gatewayprotocol.Response{JSONRPC: gatewayprotocol.JSONRPCVersion, ID: request.ID, Result: result})
			}(connection)
		}
	}()
}

func coverageTestServer(t *testing.T) (*Server, string, *fakeCoverageLab, chan gatewayprotocol.Request) {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "gatewayd.sock")
	server, session := configuredAPIServer(t, socket)
	calls := make(chan gatewayprotocol.Request, 64)
	startCoverageGateway(t, socket, calls)
	lab := &fakeCoverageLab{}
	server.coverage.lab = lab
	server.coverage.pause = func(context.Context, time.Duration) error { return nil }
	server.coverage.analysisWait = 20 * time.Millisecond
	server.coverage.reportPath = filepath.Join(t.TempDir(), "coverage", "last-run.json")
	server.eventReader = &coverageEventStore{lab: lab}
	return server, session, lab, calls
}

func waitForCoverage(t *testing.T, server *Server) coverage.Report {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if report := server.lastCoverage(); report != nil && report.State != coverage.StateRunning {
			return *report
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the coverage check did not finish")
	return coverage.Report{}
}

func TestCoverageRunProbesThroughTheRealPathAndReportsGaps(t *testing.T) {
	server, session, lab, calls := coverageTestServer(t)
	handler := server.CoverageHandler()

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, authenticatedJSONRequest(http.MethodPost, "/api/v1/coverage/runs", `{"password":"wrong"}`, session, ""))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("a run without the administrator password returned %d", recorder.Code)
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, authenticatedJSONRequest(http.MethodPost, "/api/v1/coverage/runs", `{"password":"`+activationTestPassword+`"}`, session, ""))
	if recorder.Code != http.StatusAccepted || !strings.Contains(recorder.Body.String(), `"state":"RUNNING"`) || strings.Contains(recorder.Body.String(), activationTestPassword) {
		t.Fatalf("start returned %d: %s", recorder.Code, recorder.Body.String())
	}
	report := waitForCoverage(t, server)
	if report.State != coverage.StateCompleted || report.CaptureSessionID == "" || !lab.prepared || !lab.cleaned {
		t.Fatalf("report = %+v prepared=%v cleaned=%v", report, lab.prepared, lab.cleaned)
	}
	results := map[string]coverage.Result{}
	for _, result := range report.Results {
		results[result.ID] = result
	}
	if results[coverage.ProbeDNSGateway].Status != coverage.StatusPass || results[coverage.ProbeHTTPS].Status != coverage.StatusPass {
		t.Fatalf("seen probes did not pass: %+v", report.Results)
	}
	if results[coverage.ProbeSSH].Status != coverage.StatusFail || results[coverage.ProbeIPv6].Status != coverage.StatusSkip {
		t.Fatalf("unseen probes must fail and IPv6 skip: %+v", report.Results)
	}
	if report.GapCount == 0 || report.PassCount != 2 {
		t.Fatalf("counts: pass %d gaps %d", report.PassCount, report.GapCount)
	}
	started, stopped := false, false
	for len(calls) > 0 {
		call := <-calls
		switch call.Method {
		case "StartCapture":
			var params gatewayprotocol.StartCaptureParams
			if err := json.Unmarshal(call.Params, &params); err != nil || !params.Request.CoverageLab || params.Request.Mode != "FULL_PACKETS" || params.Request.Administrator != "admin" {
				t.Fatalf("coverage capture request = %+v err=%v", params.Request, err)
			}
			started = true
		case "StopCapture":
			stopped = true
		}
	}
	if !started || !stopped {
		t.Fatalf("capture started=%v stopped=%v", started, stopped)
	}

	// The overview carries the last run and a fresh routing inspection.
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, authenticatedJSONRequest(http.MethodGet, "/api/v1/coverage", "", session, ""))
	var overview coverage.Overview
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &overview) != nil || overview.LastRun == nil || overview.LastRun.RunID != report.RunID {
		t.Fatalf("overview returned %d: %s", recorder.Code, recorder.Body.String())
	}
	gaps := map[string]coverage.FindingStatus{}
	for _, finding := range overview.Routing {
		gaps[finding.ID] = finding.Status
	}
	if gaps[coverage.FindingPeerToPeer] != coverage.FindingGap || gaps[coverage.FindingEncryptedDNS] != coverage.FindingGap || gaps[coverage.FindingIPv6] != coverage.FindingOK {
		t.Fatalf("routing findings = %+v", overview.Routing)
	}

	// The report survives a restart, read from disk.
	restarted, _, _, _ := coverageTestServer(t)
	restarted.coverage.reportPath = server.coverage.reportPath
	if last := restarted.lastCoverage(); last == nil || last.RunID != report.RunID || last.State != coverage.StateCompleted {
		t.Fatalf("persisted report = %+v", last)
	}
}

func TestCoverageRunFailsPlainlyWhenTheLabCannotBeBuilt(t *testing.T) {
	server, session, lab, _ := coverageTestServer(t)
	lab.failPrep = true
	recorder := httptest.NewRecorder()
	server.CoverageHandler().ServeHTTP(recorder, authenticatedJSONRequest(http.MethodPost, "/api/v1/coverage/runs", `{"password":"`+activationTestPassword+`"}`, session, ""))
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("start returned %d", recorder.Code)
	}
	report := waitForCoverage(t, server)
	if report.State != coverage.StateFailed || !strings.Contains(report.Error, "virtual test lab could not be built") || report.CaptureSessionID != "" {
		t.Fatalf("report = %+v", report)
	}
}

func TestOnlyOneCoverageRunAtATime(t *testing.T) {
	server, session, _, _ := coverageTestServer(t)
	server.coverage.running = true
	recorder := httptest.NewRecorder()
	server.CoverageHandler().ServeHTTP(recorder, authenticatedJSONRequest(http.MethodPost, "/api/v1/coverage/runs", `{"password":"`+activationTestPassword+`"}`, session, ""))
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "coverage_running") {
		t.Fatalf("second run returned %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestForeignIPv6OnTheLabInterfaceIsDetected(t *testing.T) {
	inspection := gatewayprotocol.HostInspection{Interfaces: []gatewayprotocol.Interface{{Name: "ens18", Addresses: []string{"192.168.10.177/24", "fe80::1/64", "fd00:10::5/64"}}}}
	if labHasForeignIPv6(inspection, "ens18", "fd00:10::/64") {
		t.Fatal("ShakerProxy's own lab prefix is not foreign IPv6")
	}
	if !labHasForeignIPv6(inspection, "ens18", "") {
		t.Fatal("a unique-local address from another router is foreign IPv6")
	}
	inspection.Interfaces[0].Addresses = []string{"192.168.10.177/24", "fe80::1/64"}
	if labHasForeignIPv6(inspection, "ens18", "") {
		t.Fatal("link-local only is not an IPv6 path around ShakerProxy")
	}
	inspection.Interfaces[0].DefaultIPv6 = true
	if !labHasForeignIPv6(inspection, "ens18", "") {
		t.Fatal("an IPv6 default route on the lab interface is foreign IPv6")
	}
}
