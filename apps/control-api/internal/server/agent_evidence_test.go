package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/apitoken"
	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/casework"
	"shakerproxy.dev/shakerproxy/internal/ingest"
	"shakerproxy.dev/shakerproxy/internal/inventory"
)

func agentEvidenceToken(t *testing.T, store *apitoken.Store, restrictions apitoken.Restrictions, scopes ...apitoken.Scope) string {
	t.Helper()
	created, err := store.Create(apitoken.CreateRequest{Name: "agent", Creator: "admin", Scopes: scopes, Restrictions: restrictions, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return created.Secret
}

// The capture list for agents is a few kilobytes however many finished
// captures exist: no file lists, hashes or export links.
func TestAgentCapturesAreCompactAndNeedCapturesRead(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	started := time.Date(2026, 10, 2, 13, 0, 0, 0, time.UTC)
	running := capture.View{
		Session: capture.Session{ID: "capture-0000000000000000000000000000000a", StartedAt: started.Add(2 * time.Hour), Source: capture.Source{InterfaceName: "ens18"},
			Request: capture.StartRequest{Name: capture.LabRecordingName, Mode: capture.ModeFull, SegmentSeconds: 10, SegmentSizeMiB: 4, MaxFiles: 120, Automatic: true}},
		State: capture.StateRunning, Active: true, CurrentFiles: 120, CurrentBytes: 400 << 20,
		Worker: &capture.WorkerStatus{PacketsCaptured: 9000, KernelDrops: 2, DumpcapDrops: 1},
	}
	files := make([]capture.CaptureFile, 64)
	for index := range files {
		files[index] = capture.CaptureFile{Name: fmt.Sprintf("capture_%05d.pcapng", index), SizeBytes: 1 << 20, SHA256: strings.Repeat("b", 64)}
	}
	finished := capture.View{
		Session: capture.Session{ID: "capture-0000000000000000000000000000000b", StartedAt: started, Source: capture.Source{InterfaceName: "ens18"},
			Request: capture.StartRequest{Name: "Phone test", Description: "line one\nline two", Mode: capture.ModeFull, CaseID: "case-00000000000000000000000000000001"}},
		State: capture.StateStopped, CurrentFiles: 64,
		Worker:       &capture.WorkerStatus{EndedAt: started.Add(time.Hour), StopReason: "stopped by admin"},
		Manifest:     &capture.Manifest{Files: files, TotalSizeBytes: 64 << 20, PacketsCaptured: 5000, KernelDrops: 3},
		EvidenceHold: &capture.EvidenceHold{Active: true, CaseID: "case-00000000000000000000000000000001"},
	}
	coverage := capture.View{
		Session: capture.Session{ID: "capture-0000000000000000000000000000000c", StartedAt: started.Add(time.Hour), Request: capture.StartRequest{Name: "Visibility coverage check", CoverageLab: true}},
		State:   capture.StateStopped,
	}
	startGatewayStub(t, socketPath, []capture.View{finished, coverage, running})
	tokens := &apitoken.Store{Path: filepath.Join(t.TempDir(), "tokens.json")}
	server, _ := configuredAPIServerWithConfig(t, socketPath, func(config *Config) { config.APITokens = tokens })
	reader := agentEvidenceToken(t, tokens, apitoken.Restrictions{}, apitoken.ScopeCapturesRead)
	traffic := agentEvidenceToken(t, tokens, apitoken.Restrictions{}, apitoken.ScopeTrafficRead)

	denied := httptest.NewRecorder()
	server.Handler().ServeHTTP(denied, tokenRequest(http.MethodGet, "/api/v1/agent/captures", traffic))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("a traffic:read token read captures: %d %s", denied.Code, denied.Body.String())
	}
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, tokenRequest(http.MethodGet, "/api/v1/agent/captures?limit=2", reader))
	if recorder.Code != http.StatusOK {
		t.Fatalf("agent captures returned %d: %s", recorder.Code, recorder.Body.String())
	}
	if body := recorder.Body.String(); strings.Contains(body, "pcapng") || strings.Contains(body, strings.Repeat("b", 64)) || len(body) > 4096 {
		t.Fatalf("agent capture list carries file details or is not compact (%d bytes): %s", len(body), body)
	}
	var page agentCapturePage
	if err := json.Unmarshal(recorder.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 3 || page.Returned != 2 || !page.Truncated || !page.Recording || page.TotalBytes != 400<<20+64<<20 {
		t.Fatalf("page = %+v", page)
	}
	first, second := page.Captures[0], page.Captures[1]
	if first.Kind != "automatic" || !first.Active || first.Segments != 120 || first.PacketsDropped != 3 || first.Finalized || first.MaxSegments != 120 {
		t.Fatalf("running automatic recording = %+v", first)
	}
	if second.Kind != "coverage_check" {
		t.Fatalf("newest stopped capture = %+v", second)
	}
	held := projectAgentCapture(finished)
	if held.Kind != "manual" || !held.Finalized || held.Segments != 64 || held.Bytes != 64<<20 || !held.Held || held.CaseID != "case-00000000000000000000000000000001" || held.Description != "line one line two" || held.PacketsDropped != 3 {
		t.Fatalf("finished manual capture = %+v", held)
	}
	invalid := httptest.NewRecorder()
	server.Handler().ServeHTTP(invalid, tokenRequest(http.MethodGet, "/api/v1/agent/captures?limit=500", reader))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("limit=500 returned %d", invalid.Code)
	}
}

func TestAgentCasesSummarizeAndRespectCaseRestrictions(t *testing.T) {
	tokens := &apitoken.Store{Path: filepath.Join(t.TempDir(), "tokens.json")}
	cases := &casework.Store{Path: filepath.Join(t.TempDir(), "cases.json")}
	server, _ := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) {
		config.APITokens = tokens
		config.Cases = cases
	})
	older, err := cases.Create("Router firmware", "Before and after 1.3", "admin", "open")
	if err != nil {
		t.Fatal(err)
	}
	newer, err := cases.Create("Smart TV", "", "admin", "open")
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 3; index++ {
		newer, err = cases.AddEvidence(newer.ID, newer.Revision, casework.EvidenceCapture, fmt.Sprintf("capture-%032x", index+1), "lab window", "admin", "evidence")
		if err != nil {
			t.Fatal(err)
		}
	}
	reader := agentEvidenceToken(t, tokens, apitoken.Restrictions{}, apitoken.ScopeCasesRead)
	restricted := agentEvidenceToken(t, tokens, apitoken.Restrictions{CaseIDs: []string{older.ID}}, apitoken.ScopeCasesRead)
	traffic := agentEvidenceToken(t, tokens, apitoken.Restrictions{}, apitoken.ScopeTrafficRead)
	serve := func(target, token string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, tokenRequest(http.MethodGet, target, token))
		return recorder
	}

	list := serve("/api/v1/agent/cases", reader)
	if list.Code != http.StatusOK {
		t.Fatalf("agent cases returned %d: %s", list.Code, list.Body.String())
	}
	var page agentCasePage
	if err := json.Unmarshal(list.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 || page.Returned != 2 || page.Cases[0].ID != newer.ID || page.Cases[0].EvidenceCounts.Captures != 3 || page.Cases[0].HoldState != "INACTIVE" || page.Cases[0].LastAction == "" || page.Cases[1].Description != "Before and after 1.3" {
		t.Fatalf("case page = %+v", page)
	}
	detail := serve("/api/v1/agent/cases/"+newer.ID, reader)
	var item agentCaseDetail
	if detail.Code != http.StatusOK || json.Unmarshal(detail.Body.Bytes(), &item) != nil {
		t.Fatalf("case detail returned %d: %s", detail.Code, detail.Body.String())
	}
	if len(item.Evidence) != 3 || item.Evidence[0].ArtifactID != fmt.Sprintf("capture-%032x", 3) || len(item.Timeline) != 4 || item.Timeline[0].Revision < item.Timeline[3].Revision {
		t.Fatalf("case detail = %+v", item)
	}
	if code := serve("/api/v1/agent/cases", restricted).Code; code != http.StatusForbidden {
		t.Fatalf("a case-restricted token listed every case: %d", code)
	}
	if code := serve("/api/v1/agent/cases/"+older.ID, restricted).Code; code != http.StatusOK {
		t.Fatalf("a case-restricted token cannot read its case: %d", code)
	}
	if code := serve("/api/v1/agent/cases/"+newer.ID, restricted).Code; code != http.StatusForbidden {
		t.Fatalf("a case-restricted token read another case: %d", code)
	}
	if code := serve("/api/v1/agent/cases", traffic).Code; code != http.StatusForbidden {
		t.Fatalf("a traffic:read token listed cases: %d", code)
	}
	if code := serve("/api/v1/agent/cases/case-ffffffffffffffffffffffffffffffff", reader).Code; code != http.StatusNotFound {
		t.Fatalf("an unknown case returned %d", code)
	}
}

// Agents see what a device is, like the Devices page, when their token may
// read traffic.
func TestAgentDevicesCarryPlatformHintsForTrafficReaders(t *testing.T) {
	tokens := &apitoken.Store{Path: filepath.Join(t.TempDir(), "tokens.json")}
	server, _ := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) { config.APITokens = tokens })
	directory := t.TempDir()
	server.inventory = &inventory.Store{Path: filepath.Join(directory, "inventory.json")}
	server.keaLeasePath = filepath.Join(directory, "kea-leases4.csv")
	contents := fmt.Sprintf("address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n10.77.0.111,72:58:49:e8:e4:00,,600,%d,1,0,0,,0,,0\n", time.Now().Add(10*time.Minute).Unix())
	if err := os.WriteFile(server.keaLeasePath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := server.refreshInventory()
	if err != nil || len(snapshot.Devices) != 1 {
		t.Fatalf("inventory = %+v err=%v", snapshot, err)
	}
	phone := snapshot.Devices[0].ID
	at := time.Now().UTC().Truncate(time.Second)
	server.eventReader = &devicePlatformReaderStub{hints: ingest.DevicePlatformHints{Schema: ingest.DevicePlatformHintsSchema, GeneratedAt: at, Hints: []ingest.DevicePlatformHint{
		{DeviceID: phone, Platform: "GrapheneOS phone", Domain: "connectivitycheck.grapheneos.network", LastSeen: at},
	}}}
	handler := server.AgentDeviceHandler()
	read := func(target, token string) agentDevice {
		t.Helper()
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, tokenRequest(http.MethodGet, target, token))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s returned %d: %s", target, recorder.Code, recorder.Body.String())
		}
		if strings.HasSuffix(target, phone) {
			var device agentDevice
			if err := json.Unmarshal(recorder.Body.Bytes(), &device); err != nil {
				t.Fatal(err)
			}
			return device
		}
		var page agentDevicePage
		if err := json.Unmarshal(recorder.Body.Bytes(), &page); err != nil || len(page.Devices) != 1 {
			t.Fatalf("page = %s", recorder.Body.String())
		}
		return page.Devices[0]
	}
	investigator := agentEvidenceToken(t, tokens, apitoken.Restrictions{}, apitoken.ScopeDevicesRead, apitoken.ScopeTrafficRead)
	devicesOnly := agentEvidenceToken(t, tokens, apitoken.Restrictions{}, apitoken.ScopeDevicesRead)
	for _, target := range []string{"/api/v1/agent/devices", "/api/v1/agent/devices/" + phone} {
		device := read(target, investigator)
		if device.Platform == nil || device.Platform.Platform != "GrapheneOS phone" || device.Platform.Source != "connectivity_check" || device.Platform.Domain != "connectivitycheck.grapheneos.network" {
			t.Fatalf("%s platform = %+v", target, device.Platform)
		}
		if device := read(target, devicesOnly); device.Platform != nil {
			t.Fatalf("a devices:read token saw a traffic-derived platform on %s: %+v", target, device.Platform)
		}
	}
}
