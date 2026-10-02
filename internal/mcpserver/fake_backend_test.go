package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"shakerproxy.dev/shakerproxy/internal/agentapi"
	"shakerproxy.dev/shakerproxy/internal/analyzer"
	"shakerproxy.dev/shakerproxy/internal/coverage"
	"shakerproxy.dev/shakerproxy/internal/devicereport"
	"shakerproxy.dev/shakerproxy/internal/ingest"
	"shakerproxy.dev/shakerproxy/internal/testsession"
)

var fakeNow = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

const (
	tvID     = "device-0123456789abcdef0123456789abcdef"
	cameraID = "device-fedcba9876543210fedcba9876543210"
)

type fakeBackend struct {
	mu sync.Mutex

	overview     agentapi.SystemOverview
	devicePage   agentapi.DevicePage
	resolutions  map[string]agentapi.DeviceResolution
	report       devicereport.Report
	comparison   devicereport.Comparison
	sessions     agentapi.TestSessionList
	session      testsession.Session
	protocols    agentapi.ProtocolsPage
	protocolsErr error
	page         agentapi.EventPage
	httpPage     ingest.HTTPActivityPage
	detail       ingest.EventDetail
	coverage     coverage.Overview

	resolved        []string
	reportRequest   agentapi.DeviceReportRequest
	compareRequest  agentapi.CompareRequest
	sessionsRequest agentapi.TestSessionsRequest
	protocolRequest agentapi.ProtocolsRequest
	searches        []agentapi.TrafficSearchRequest
	httpRequest     agentapi.HTTPActivityRequest
	deviceRequest   agentapi.DeviceListRequest
}

func newFakeBackend() *fakeBackend {
	tv := agentapi.DeviceMatch{DeviceID: tvID, FriendlyName: "Living room TV", Vendor: "Samsung", Addresses: []string{"10.77.0.23"}, HardwareAddresses: []string{"52:54:00:aa:bb:23"}, Online: true, Match: "name"}
	camera := agentapi.DeviceMatch{DeviceID: cameraID, FriendlyName: "Bench camera", Addresses: []string{"10.77.0.30"}, HardwareAddresses: []string{}, Online: false, Match: "name_prefix"}
	camera2 := camera
	camera2.DeviceID, camera2.FriendlyName = "device-00000000000000000000000000000002", "Bench camera 2"
	return &fakeBackend{
		overview: readyOverview(),
		resolutions: map[string]agentapi.DeviceResolution{
			"tv":         {Schema: 1, Query: "tv", Unique: true, Matches: []agentapi.DeviceMatch{tv}},
			"10.77.0.23": {Schema: 1, Query: "10.77.0.23", Unique: true, Matches: []agentapi.DeviceMatch{tv}},
			tvID:         {Schema: 1, Query: tvID, Unique: true, Matches: []agentapi.DeviceMatch{tv}},
			"camera":     {Schema: 1, Query: "camera", Unique: true, Matches: []agentapi.DeviceMatch{camera}},
			"bench":      {Schema: 1, Query: "bench", Matches: []agentapi.DeviceMatch{camera, camera2}},
		},
		page:     agentapi.EventPage{RecentEventPage: ingest.RecentEventPage{Schema: 1, GeneratedAt: fakeNow}},
		httpPage: ingest.HTTPActivityPage{Schema: 1, GeneratedAt: fakeNow, QueryAnchor: fakeNow, Events: []ingest.HTTPActivityEvent{}},
	}
}

func readyOverview() agentapi.SystemOverview {
	return agentapi.SystemOverview{
		Schema: 1, GeneratedAt: fakeNow, Overall: "READY", EvidenceReady: true,
		Gateway: agentapi.GatewayOverview{Available: true, OperatingMode: "ROUTED", NetworkActivation: true, CaptureAvailable: true, TrafficPolicyAvailable: true, LabInterface: "lab0"},
		Ingest:  agentapi.IngestOverview{Available: true, GeneratedAt: fakeNow, DatabaseConfigured: true, DatabaseConnected: true},
		Analyzers: []agentapi.AnalyzerOverview{
			{Engine: string(analyzer.EngineZeek), Available: true, State: string(analyzer.HealthHealthy), Healthy: true},
			{Engine: string(analyzer.EngineSuricata), Available: true, State: string(analyzer.HealthHealthy), Healthy: true},
		},
		Capabilities: agentapi.CapabilityOverview{Features: []agentapi.CapabilityFeature{}},
		Limitations:  []string{},
	}
}

func (f *fakeBackend) SystemOverview(context.Context) (agentapi.SystemOverview, error) {
	return f.overview, nil
}

func (f *fakeBackend) VisibilityCoverage(context.Context) (coverage.Overview, error) {
	return f.coverage, nil
}

func (f *fakeBackend) DevicesList(_ context.Context, request agentapi.DeviceListRequest) (agentapi.DevicePage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deviceRequest = request
	return f.devicePage, nil
}

func (f *fakeBackend) ResolveDevice(_ context.Context, reference string) (agentapi.DeviceResolution, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolved = append(f.resolved, reference)
	if resolution, ok := f.resolutions[reference]; ok {
		return resolution, nil
	}
	return agentapi.DeviceResolution{Schema: 1, Query: reference, Matches: []agentapi.DeviceMatch{}}, nil
}

func (f *fakeBackend) DeviceReport(_ context.Context, request agentapi.DeviceReportRequest) (devicereport.Report, error) {
	f.reportRequest = request
	return f.report, nil
}

func (f *fakeBackend) CompareRuns(_ context.Context, request agentapi.CompareRequest) (devicereport.Comparison, error) {
	f.compareRequest = request
	return f.comparison, nil
}

func (f *fakeBackend) TestSessions(_ context.Context, request agentapi.TestSessionsRequest) (agentapi.TestSessionList, error) {
	f.sessionsRequest = request
	return f.sessions, nil
}

func (f *fakeBackend) TestSession(_ context.Context, id string) (testsession.Session, error) {
	if f.session.ID != id {
		return testsession.Session{}, &agentapi.APIError{Status: 404, Code: "test_session_not_found", Message: "No test session has that ID."}
	}
	return f.session, nil
}

func (f *fakeBackend) Protocols(_ context.Context, request agentapi.ProtocolsRequest) (agentapi.ProtocolsPage, error) {
	f.protocolRequest = request
	return f.protocols, f.protocolsErr
}

func (f *fakeBackend) TrafficSearch(_ context.Context, request agentapi.TrafficSearchRequest) (agentapi.EventPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.searches = append(f.searches, request)
	return f.page, nil
}

func (f *fakeBackend) HTTPActivity(_ context.Context, request agentapi.HTTPActivityRequest) (ingest.HTTPActivityPage, error) {
	f.httpRequest = request
	return f.httpPage, nil
}

func (f *fakeBackend) EventMetadata(_ context.Context, recordID string) (ingest.EventDetail, error) {
	if f.detail.Event.RecordID != recordID {
		return ingest.EventDetail{}, errors.New("not found")
	}
	return f.detail, nil
}

func (f *fakeBackend) lastSearch() agentapi.TrafficSearchRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.searches[len(f.searches)-1]
}

// decodeToolResult checks the safety envelope and decodes its data.
func decodeToolResult(t *testing.T, result *mcp.CallToolResult, data any) {
	t.Helper()
	if result == nil || len(result.Content) != 1 {
		t.Fatalf("unexpected tool result: %#v", result)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("tool result is not text: %#v", result.Content[0])
	}
	var envelope struct {
		Schema                     int             `json:"schema"`
		CapturedContentIsUntrusted bool            `json:"captured_content_is_untrusted"`
		PlaintextIncluded          bool            `json:"plaintext_included"`
		InstructionHandling        string          `json:"instruction_handling"`
		Data                       json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal([]byte(text.Text), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Schema != 1 || !envelope.CapturedContentIsUntrusted || envelope.PlaintextIncluded || envelope.InstructionHandling == "" {
		t.Fatalf("unsafe evidence envelope: %s", text.Text)
	}
	if err := json.Unmarshal(envelope.Data, data); err != nil {
		t.Fatalf("decode tool data: %v in %s", err, envelope.Data)
	}
}

func rawToolText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	return result.Content[0].(*mcp.TextContent).Text
}
