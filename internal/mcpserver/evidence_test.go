package mcpserver

import (
	"context"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/agentapi"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
)

func (f *fakeBackend) DeviceControls(_ context.Context, deviceID string) (agentapi.DeviceControls, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.controlsFor = append(f.controlsFor, deviceID)
	view := f.controls
	view.DeviceID = deviceID
	return view, nil
}

func (f *fakeBackend) Captures(_ context.Context, limit int) (agentapi.CapturePage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.captureLimit = limit
	return f.capturePage, f.capturesErr
}

func (f *fakeBackend) Cases(context.Context, int) (agentapi.CasePage, error) {
	return f.casePage, nil
}

func (f *fakeBackend) Case(_ context.Context, caseID string) (agentapi.CaseDetail, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.caseRequests = append(f.caseRequests, caseID)
	if f.caseDetail.Case.ID != caseID {
		return agentapi.CaseDetail{}, &agentapi.APIError{Status: 404, Code: "case_not_found", Message: "case was not found"}
	}
	return f.caseDetail, nil
}

func (f *fakeBackend) Diagnostics(context.Context) (agentapi.Diagnostics, error) {
	return f.diagnostics, nil
}

func TestDeviceControlsResolveTheDeviceAndSayWhetherTheyAreEnforced(t *testing.T) {
	backend := newFakeBackend()
	backend.controls = agentapi.DeviceControls{Schema: 1, DecryptHTTPS: true, Internet: "ALLOW", BlockedDomains: []string{"ads.example.com"}, Effective: false,
		Notes: []string{"Emergency bypass is on: controls are saved but not enforced until it is turned off."}}
	result, _, err := (&Service{backend: backend}).deviceControls(context.Background(), nil, DeviceControlsArgs{Device: "tv"})
	if err != nil {
		t.Fatal(err)
	}
	var data deviceControlsResult
	decodeToolResult(t, result, &data)
	if len(backend.controlsFor) != 1 || backend.controlsFor[0] != tvID || data.DeviceID != tvID || !data.DecryptHTTPS || data.Enforced {
		t.Fatalf("controls = %+v (asked for %v)", data, backend.controlsFor)
	}
	for _, fragment := range []string{"Living room TV: HTTPS is decrypted", "internet access is allowed", "blocked domains: ads.example.com", "not enforced now", "agents can only read them"} {
		if !strings.Contains(data.Summary, fragment) {
			t.Fatalf("summary %q lacks %q", data.Summary, fragment)
		}
	}
	if _, _, err := (&Service{backend: backend}).deviceControls(context.Background(), nil, DeviceControlsArgs{Device: "bench"}); err == nil || !strings.Contains(err.Error(), "matches 2 devices") {
		t.Fatalf("an ambiguous device was not refused: %v", err)
	}
}

func TestCapturesPutTheRecordingFirstAndNeverCarryPackets(t *testing.T) {
	backend := newFakeBackend()
	started := time.Date(2026, 10, 2, 13, 0, 0, 0, time.UTC)
	backend.capturePage = agentapi.CapturePage{Schema: 1, GeneratedAt: fakeNow, Total: 3, Returned: 2, Truncated: true, Recording: true, TotalBytes: 464_000_000, Captures: []agentapi.Capture{
		{ID: "capture-0000000000000000000000000000000a", Name: "Lab traffic", Kind: "automatic", State: "RUNNING", Active: true, Interface: "ens18", StartedAt: started, Segments: 120, Bytes: 400_000_000, PacketsCaptured: 9000, PacketsDropped: 3},
		{ID: "capture-0000000000000000000000000000000b", Name: "Phone test", Kind: "manual", State: "STOPPED", Interface: "ens18", StartedAt: started.Add(-time.Hour), Segments: 64, Bytes: 64_000_000, Finalized: true, Held: true, CaseID: "case-00000000000000000000000000000001"},
	}}
	result, _, err := (&Service{backend: backend}).captures(context.Background(), nil, CapturesArgs{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	var data capturesResult
	decodeToolResult(t, result, &data)
	if backend.captureLimit != 2 || !data.Recording || len(data.Captures) != 2 || !data.Captures[0].Recording || !data.Captures[1].Held {
		t.Fatalf("captures = %+v", data)
	}
	for _, fragment := range []string{"Recording now: Lab traffic (automatic on ens18, running): 120 segments, 400 MB, 3 packets dropped", "3 captures", "464 MB", "Showing 2"} {
		if !strings.Contains(data.Summary, fragment) {
			t.Fatalf("summary %q lacks %q", data.Summary, fragment)
		}
	}
	if !strings.Contains(data.Captures[1].Summary, "held as evidence") {
		t.Fatalf("held capture summary %q", data.Captures[1].Summary)
	}
	backend.capturesErr = &agentapi.APIError{Status: 403, Code: "insufficient_scope", Message: "API token does not grant the required scope"}
	if _, _, err := (&Service{backend: backend}).captures(context.Background(), nil, CapturesArgs{}); err == nil || !strings.Contains(err.Error(), "captures:read") {
		t.Fatalf("a missing scope does not say which one: %v", err)
	}
}

func TestCasesListAndShowOneCase(t *testing.T) {
	backend := newFakeBackend()
	summary := agentapi.CaseSummary{ID: "case-00000000000000000000000000000001", Name: "Smart TV", Status: "OPEN", HoldState: "ACTIVE", UpdatedAt: fakeNow,
		EvidenceCounts: agentapi.CaseEvidenceCounts{Total: 3, Captures: 2, QuerySnapshots: 1}}
	backend.casePage = agentapi.CasePage{Schema: 1, GeneratedAt: fakeNow, Total: 2, Returned: 2, Cases: []agentapi.CaseSummary{summary,
		{ID: "case-00000000000000000000000000000002", Name: "Router firmware", Status: "CLOSED", HoldState: "INACTIVE", UpdatedAt: fakeNow.Add(-time.Hour)}}}
	backend.caseDetail = agentapi.CaseDetail{Schema: 1, Case: summary, HoldFailed: 1,
		Evidence: []agentapi.CaseEvidence{{ID: "evidence-00000000000000000000000000000001", Kind: "QUERY_SNAPSHOT", ArtifactID: "qsnap-00000000000000000000000000000001", Query: "device.name:TV AND tls.state:FAILED", MatchedCount: 12, AddedBy: "admin", AddedAt: fakeNow}},
		Timeline: []agentapi.CaseTimelineEvent{{Revision: 4, Action: "HOLD_APPLIED", Actor: "admin", OccurredAt: fakeNow}}}
	service := &Service{backend: backend}
	listed, _, err := service.cases(context.Background(), nil, CasesArgs{})
	if err != nil {
		t.Fatal(err)
	}
	var list casesResult
	decodeToolResult(t, listed, &list)
	if list.Total != 2 || len(list.Cases) != 2 || !strings.Contains(list.Summary, "2 cases, 1 open") || list.Cases[0].Summary != "Smart TV (open): 3 evidence items (2 captures, 1 query snapshot); evidence hold active." {
		t.Fatalf("case list = %+v", list)
	}
	shown, _, err := service.cases(context.Background(), nil, CasesArgs{CaseID: summary.ID})
	if err != nil {
		t.Fatal(err)
	}
	var detail caseDetailResult
	decodeToolResult(t, shown, &detail)
	if len(detail.Evidence) != 1 || detail.Evidence[0].MatchedCount != 12 || len(detail.Timeline) != 1 || !strings.Contains(detail.Summary, "could not protect 1 capture") {
		t.Fatalf("case detail = %+v", detail)
	}
	if _, _, err := service.cases(context.Background(), nil, CasesArgs{CaseID: "case-ffffffffffffffffffffffffffffffff"}); err == nil || !strings.Contains(err.Error(), "case was not found") {
		t.Fatalf("an unknown case: %v", err)
	}
	if _, _, err := service.cases(context.Background(), nil, CasesArgs{CaseID: summary.ID, Limit: 5}); err == nil {
		t.Fatal("limit with case_id was accepted")
	}
}

func TestDiagnosticsPutProblemsFirst(t *testing.T) {
	backend := newFakeBackend()
	backend.diagnostics = agentapi.Diagnostics{Schema: 1, GeneratedAt: fakeNow, Overall: gatewayprotocol.DiagnosticFail, Checks: []gatewayprotocol.DiagnosticCheck{
		{Name: "interfaces", Status: gatewayprotocol.DiagnosticPass, Summary: "2 non-loopback interface(s) up; 0 down"},
		{Name: "firewall", Status: gatewayprotocol.DiagnosticFail, Summary: "Firewall backend and coexistence evidence inspected", Observations: []string{"blocking issues: DOCKER_USER_CHAIN_MISSING"}},
		{Name: "time_sync", Status: gatewayprotocol.DiagnosticWarning, Summary: "Clock synchronization is unknown"},
	}}
	result, _, err := (&Service{backend: backend}).diagnostics(context.Background(), nil, DiagnosticsArgs{})
	if err != nil {
		t.Fatal(err)
	}
	var data diagnosticsResult
	decodeToolResult(t, result, &data)
	if data.Overall != "FAIL" || data.Passed != 1 || data.Failed != 1 || data.Warnings != 1 || data.Checks[0].Name != "firewall" || data.Checks[2].Name != "interfaces" {
		t.Fatalf("diagnostics = %+v", data)
	}
	if !strings.HasPrefix(data.Summary, "ShakerProxy doctor: 1 passed, 1 warnings, 1 failed, 0 unknown. fail firewall:") {
		t.Fatalf("summary %q", data.Summary)
	}
}

func TestListDevicesSaysWhatEachDeviceIs(t *testing.T) {
	backend := newFakeBackend()
	backend.devicePage = agentapi.DevicePage{Schema: 1, GeneratedAt: fakeNow, Matched: 2, Returned: 2, Devices: []agentapi.Device{
		{Schema: 1, ID: tvID, DisplayName: "Pixel", Online: true, FirstSeen: fakeNow, LastSeen: fakeNow,
			Addresses: []agentapi.DeviceAddress{{Address: "192.168.10.201", Family: "IPv4", Active: true}},
			Platform:  &agentapi.DevicePlatform{Platform: "GrapheneOS phone", Source: "connectivity_check", Domain: "connectivitycheck.grapheneos.network", LastSeen: fakeNow}},
		{Schema: 1, ID: cameraID, DisplayName: "192.168.10.50", Vendor: "Espressif", FirstSeen: fakeNow, LastSeen: fakeNow, Addresses: []agentapi.DeviceAddress{},
			Platform: &agentapi.DevicePlatform{Platform: "Embedded Linux device", Source: "dhcp", Detail: "udhcp 1.36.1", LastSeen: fakeNow}},
	}}
	result, _, err := (&Service{backend: backend}).listDevices(context.Background(), nil, ListDevicesArgs{})
	if err != nil {
		t.Fatal(err)
	}
	var data deviceList
	decodeToolResult(t, result, &data)
	phone, camera := data.Devices[0], data.Devices[1]
	if phone.Platform != "GrapheneOS phone" || phone.PlatformEvidence != "its system traffic to connectivitycheck.grapheneos.network" || phone.Summary != "Pixel (GrapheneOS phone, 192.168.10.201, online)" {
		t.Fatalf("phone = %+v", phone)
	}
	if camera.PlatformEvidence != "its DHCP request: udhcp 1.36.1" || camera.Summary != "192.168.10.50 (Embedded Linux device, Espressif, offline)" {
		t.Fatalf("camera = %+v", camera)
	}
}
