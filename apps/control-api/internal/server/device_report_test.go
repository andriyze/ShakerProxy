package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/apitoken"
	"shakerproxy.dev/shakerproxy/internal/devicereport"
	"shakerproxy.dev/shakerproxy/internal/ingest"
)

type deviceActivityStub struct {
	mu      sync.Mutex
	queries []ingest.DeviceActivityQuery
	fill    func(*ingest.DeviceActivity)
	err     error
}

func (stub *deviceActivityStub) QueryRecent(context.Context, ingest.RecentEventQuery) (ingest.RecentEventPage, error) {
	return ingest.RecentEventPage{Schema: ingest.SchemaVersion, GeneratedAt: time.Now().UTC(), Events: []ingest.RecentEvent{}}, nil
}

func (stub *deviceActivityStub) QueryDeviceActivity(_ context.Context, query ingest.DeviceActivityQuery) (ingest.DeviceActivity, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.queries = append(stub.queries, query)
	if stub.err != nil {
		return ingest.DeviceActivity{}, stub.err
	}
	activity := ingest.DeviceActivity{
		Schema: ingest.SchemaVersion, GeneratedAt: query.End, DeviceID: query.DeviceID, Start: query.Start, End: query.End,
		Domains: []ingest.DeviceDomainObservation{}, FlowGroups: []ingest.DeviceFlowGroup{}, TLSHosts: []ingest.DeviceTLSHost{},
		TLSVersions: []ingest.DeviceTLSVersion{}, CleartextHTTP: []ingest.DeviceHTTPHost{}, HTTPStatus: []ingest.DeviceHTTPStatusCount{},
		Alerts: []ingest.DeviceAlertGroup{}, EncryptedDNS: []ingest.DeviceResolver{},
	}
	if stub.fill != nil {
		stub.fill(&activity)
	}
	return activity, nil
}

func (stub *deviceActivityStub) lastQuery() ingest.DeviceActivityQuery {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return stub.queries[len(stub.queries)-1]
}

func interceptedActivity(activity *ingest.DeviceActivity) {
	at := activity.End.Add(-time.Minute)
	activity.Counts.Events, activity.Counts.TLSIntercepted, activity.Counts.InterceptorTLS = 3, 1, 1
	activity.TLSHosts = []ingest.DeviceTLSHost{{Host: "api.samsungcloud.com", State: "INTERCEPTED", Events: 1, FirstSeen: at, LastSeen: at}}
	activity.Domains = []ingest.DeviceDomainObservation{{Domain: "log.samsungacr.com", Source: "dns", Events: 2, FirstSeen: at, LastSeen: at}}
}

func TestDeviceReportResolvesReferenceAndBuildsFindings(t *testing.T) {
	fixture := newIntelFixture(t)
	fixture.activity.fill = interceptedActivity
	recorder := fixture.do(t, http.MethodGet, "/api/v1/devices/"+url.PathEscape("Living room TV")+"/report?window=6h", "", fixture.session)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("report returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var report devicereport.Report
	if err := json.Unmarshal(recorder.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	query := fixture.activity.lastQuery()
	if query.DeviceID != fixture.tv || query.End.Sub(query.Start) != 6*time.Hour {
		t.Fatalf("activity query: %#v", query)
	}
	if report.Device.DeviceID != fixture.tv || report.Device.FriendlyName != "Living room TV" || report.CATrust != devicereport.CATrustUnknown || report.Session != nil {
		t.Fatalf("report header: %#v", report)
	}
	if len(report.Domains) != 1 || report.Domains[0].Organization != "Samsung" || report.Domains[0].Category != "telemetry" {
		t.Fatalf("report domains: %#v", report.Domains)
	}
	if len(report.Findings) != 0 || !strings.Contains(report.Summary, "record whether the ShakerProxy CA is installed") {
		t.Fatalf("unknown CA trust must not raise a finding: %#v %q", report.Findings, report.Summary)
	}
	for _, field := range []string{`"window_start"`, `"window_end"`, `"ca_trust":"UNKNOWN"`, `"totals"`, `"tls"`, `"http"`, `"truncated":false`} {
		if !strings.Contains(recorder.Body.String(), field) {
			t.Fatalf("report JSON lacks %s", field)
		}
	}

	// Recording that the CA is not installed turns the same traffic into a critical finding.
	caRecorder := fixture.do(t, http.MethodPut, "/api/v1/devices/10.77.0.23/ca-trust", `{"state":"NOT_INSTALLED"}`, fixture.session)
	if caRecorder.Code != http.StatusOK || !strings.Contains(caRecorder.Body.String(), `"ca_trust":"NOT_INSTALLED"`) || !strings.Contains(caRecorder.Body.String(), `"device_id":"`+fixture.tv+`"`) {
		t.Fatalf("CA trust update: %d %s", caRecorder.Code, caRecorder.Body.String())
	}
	recorder = fixture.do(t, http.MethodGet, "/api/v1/devices/"+fixture.tv+"/report", "", fixture.session)
	if err := json.Unmarshal(recorder.Body.Bytes(), &report); err != nil || len(report.Findings) != 1 || report.Findings[0].ID != devicereport.FindingAcceptsUntrustedCertificates || report.CATrust != devicereport.CATrustNotInstalled {
		t.Fatalf("CA trust finding: %d %s", recorder.Code, recorder.Body.String())
	}
	if query := fixture.activity.lastQuery(); query.End.Sub(query.Start) != 24*time.Hour {
		t.Fatalf("default window is not 24h: %#v", query)
	}
}

func TestDeviceReportScopesAndValidation(t *testing.T) {
	fixture := newIntelFixture(t)
	target := "/api/v1/devices/" + fixture.tv + "/report"
	devicesOnly := fixture.token(t, apitoken.ScopeDevicesRead)
	if recorder := fixture.do(t, http.MethodGet, target, "", devicesOnly); recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), "traffic:read") {
		t.Fatalf("devices-only token: %d %s", recorder.Code, recorder.Body.String())
	}
	both := fixture.token(t, apitoken.ScopeDevicesRead, apitoken.ScopeTrafficRead)
	if recorder := fixture.do(t, http.MethodGet, target, "", both); recorder.Code != http.StatusOK {
		t.Fatalf("devices+traffic token: %d %s", recorder.Code, recorder.Body.String())
	}
	restricted, err := fixture.tokens.Create(apitoken.CreateRequest{Name: "restricted", Creator: "admin", Scopes: []apitoken.Scope{apitoken.ScopeDevicesRead}, Restrictions: apitoken.Restrictions{DeviceIDs: []string{fixture.camera}}, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if recorder := fixture.do(t, http.MethodGet, target, "", restricted.Secret); recorder.Code != http.StatusForbidden {
		t.Fatalf("device-restricted token read another device: %d", recorder.Code)
	}
	for _, query := range []string{"?window=2y", "?window=1h&session=ts-000000000000000000000001", "?start=yesterday", "?start=2026-09-29T10:00:00Z&end=2026-09-29T09:00:00Z", "?start=2026-01-01T00:00:00Z&end=2026-03-01T00:00:00Z", "?color=blue", "?window=1h&window=6h"} {
		if recorder := fixture.do(t, http.MethodGet, target+query, "", fixture.session); recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s returned %d: %s", query, recorder.Code, recorder.Body.String())
		}
	}
	if recorder := fixture.do(t, http.MethodGet, target+"?session=ts-000000000000000000000001", "", fixture.session); recorder.Code != http.StatusNotFound || !strings.Contains(recorder.Body.String(), "test_session_not_found") {
		t.Fatalf("unknown session: %d %s", recorder.Code, recorder.Body.String())
	}
	fixture.activity.err = errors.New("pq: internal detail")
	recorder := fixture.do(t, http.MethodGet, target, "", fixture.session)
	if recorder.Code != http.StatusServiceUnavailable || strings.Contains(recorder.Body.String(), "internal detail") {
		t.Fatalf("storage failure: %d %s", recorder.Code, recorder.Body.String())
	}
	fixture.server.eventReader = nil
	if recorder := fixture.do(t, http.MethodGet, target, "", fixture.session); recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "traffic_unavailable") {
		t.Fatalf("missing reader: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestDeviceReportDefaultsToRunningSessionAndComparesRuns(t *testing.T) {
	fixture := newIntelFixture(t)
	clock := fixture.now.Add(-2 * time.Hour)
	fixture.server.testSessions().Now = func() time.Time { return clock }
	started := fixture.do(t, http.MethodPost, "/api/v1/test-sessions", `{"device":"living room tv","name":"Firmware 1.2"}`, fixture.session)
	var base testSessionResponse
	if started.Code != http.StatusCreated || json.Unmarshal(started.Body.Bytes(), &base) != nil {
		t.Fatalf("start session: %d %s", started.Code, started.Body.String())
	}
	recorder := fixture.do(t, http.MethodGet, "/api/v1/devices/"+fixture.tv+"/report", "", fixture.session)
	var report devicereport.Report
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &report) != nil || report.Session == nil || report.Session.ID != base.ID {
		t.Fatalf("report should default to the running session: %d %s", recorder.Code, recorder.Body.String())
	}
	if query := fixture.activity.lastQuery(); !query.Start.Equal(base.StartedAt) {
		t.Fatalf("session report window: %#v session=%#v", query, base)
	}
	// Sessions for another device are rejected.
	if recorder := fixture.do(t, http.MethodGet, "/api/v1/devices/"+fixture.camera+"/report?session="+base.ID, "", fixture.session); recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "session_device_mismatch") {
		t.Fatalf("mismatched session: %d %s", recorder.Code, recorder.Body.String())
	}

	clock = clock.Add(time.Hour)
	second := fixture.do(t, http.MethodPost, "/api/v1/test-sessions", `{"device":"10.77.0.23","name":"Firmware 1.3"}`, fixture.session)
	var next testSessionResponse
	if second.Code != http.StatusCreated || json.Unmarshal(second.Body.Bytes(), &next) != nil || len(next.Warnings) != 1 {
		t.Fatalf("second session: %d %s", second.Code, second.Body.String())
	}
	fixture.activity.fill = func(activity *ingest.DeviceActivity) {
		if activity.Start.Equal(next.StartedAt) {
			interceptedActivity(activity)
		}
	}
	recorder = fixture.do(t, http.MethodGet, "/api/v1/devices/"+fixture.tv+"/compare?base="+base.ID+"&compare="+next.ID, "", fixture.session)
	var comparison devicereport.Comparison
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &comparison) != nil {
		t.Fatalf("compare: %d %s", recorder.Code, recorder.Body.String())
	}
	if comparison.DeviceID != fixture.tv || comparison.Base.SessionID != base.ID || comparison.Compare.SessionID != next.ID || comparison.Base.Name != "Firmware 1.2" || strings.Join(comparison.Domains.Added, ",") != "log.samsungacr.com" || strings.Join(comparison.TLS.NewlyInterceptedHosts, ",") != "api.samsungcloud.com" {
		t.Fatalf("comparison: %#v", comparison)
	}
	for _, field := range []string{`"base":{`, `"compare":{`, `"domains":{"added":`, `"protocols":{"added":`, `"findings":{"new":`, `"newly_failed_hosts":`} {
		if !strings.Contains(recorder.Body.String(), field) {
			t.Fatalf("comparison JSON lacks %s: %s", field, recorder.Body.String())
		}
	}
	windowed := fixture.do(t, http.MethodGet, "/api/v1/devices/"+fixture.tv+"/compare?base_start=2026-09-01T00:00:00Z&base_end=2026-09-02T00:00:00Z&compare="+next.ID, "", fixture.session)
	if windowed.Code != http.StatusOK {
		t.Fatalf("time-range compare: %d %s", windowed.Code, windowed.Body.String())
	}
	if recorder := fixture.do(t, http.MethodGet, "/api/v1/devices/"+fixture.tv+"/compare?base="+base.ID, "", fixture.session); recorder.Code != http.StatusBadRequest {
		t.Fatalf("compare without a second run: %d", recorder.Code)
	}
}

func TestCATrustRequiresSessionAndValidState(t *testing.T) {
	fixture := newIntelFixture(t)
	target := "/api/v1/devices/" + fixture.camera + "/ca-trust"
	token := fixture.token(t, apitoken.ScopeDevicesRead, apitoken.ScopeTrafficRead)
	if recorder := fixture.do(t, http.MethodPut, target, `{"state":"INSTALLED"}`, token); recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), "insufficient_scope") {
		t.Fatalf("read-only token changed CA trust: %d %s", recorder.Code, recorder.Body.String())
	}
	labWriter := fixture.token(t, apitoken.ScopeLabWrite)
	if recorder := fixture.do(t, http.MethodPut, "/api/v1/devices/"+fixture.phone+"/ca-trust", `{"state":"NOT_INSTALLED"}`, labWriter); recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"ca_trust":"NOT_INSTALLED"`) {
		t.Fatalf("lab:write token: %d %s", recorder.Code, recorder.Body.String())
	}
	for _, body := range []string{`{"state":"MAYBE"}`, `{"state":"INSTALLED","extra":1}`, `not json`} {
		if recorder := fixture.do(t, http.MethodPut, target, body, fixture.session); recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s returned %d", body, recorder.Code)
		}
	}
	recorder := fixture.do(t, http.MethodPut, target, `{"state":"installed"}`, fixture.session)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"ca_trust":"INSTALLED"`) {
		t.Fatalf("set INSTALLED: %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder := fixture.do(t, http.MethodPut, target, `{"state":"INSTALLED"}`, fixture.session); recorder.Code != http.StatusOK {
		t.Fatalf("repeating the same state should succeed: %d %s", recorder.Code, recorder.Body.String())
	}
	events, err := fixture.server.inventory.AuditLog(20)
	if err != nil {
		t.Fatal(err)
	}
	audited := 0
	for _, event := range events {
		if event.Action == "DEVICE_CA_TRUST_UPDATED" && event.SourceDeviceIDs[0] == fixture.camera {
			audited++
		}
	}
	if audited != 1 {
		t.Fatalf("CA trust changes audited %d times", audited)
	}
	device, err := fixture.server.inventory.Get(fixture.camera)
	if err != nil || device.CATrustState() != "INSTALLED" {
		t.Fatalf("stored CA trust: %#v err=%v", device, err)
	}
}
