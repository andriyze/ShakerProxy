package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/analyzer"
	"shakerproxy.dev/shakerproxy/internal/apitoken"
	"shakerproxy.dev/shakerproxy/internal/capabilityregistry"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/ingest"
)

type overviewIngestStatusStub struct {
	stats ingest.Stats
	err   error
}

func (stub overviewIngestStatusStub) IngestStatus(context.Context) (ingest.Stats, error) {
	return stub.stats, stub.err
}

type overviewAnalyzerStatusStub struct {
	snapshot analyzer.HealthSnapshot
	err      error
}

func (stub overviewAnalyzerStatusStub) Status(context.Context) (analyzer.HealthSnapshot, error) {
	return stub.snapshot, stub.err
}

func TestAgentSystemOverviewIsReadyOnlyWithCompleteCurrentEvidence(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	gateway := gatewayprotocol.Status{
		APIVersion: "1", DaemonVersion: "test", OperatingMode: gatewayprotocol.ModeRouted,
		StartedAt: now.Add(-time.Hour).Format(time.RFC3339Nano), NetworkActivation: true,
		CaptureAvailable: true, TrafficPolicyAvailable: true, LabInterface: "lab0",
	}
	requests := startGatewayStub(t, socketPath, gateway)
	server, session := configuredAPIServer(t, socketPath)
	server.ingestStatus = overviewIngestStatusStub{stats: ingest.Stats{
		Schema: ingest.SchemaVersion, GeneratedAt: now, DatabaseConfigured: true, DatabaseConnected: true,
	}}
	server.zeekAnalyzerStatus = overviewAnalyzerStatusStub{snapshot: healthyOverviewAnalyzer(analyzer.EngineZeek, now)}
	server.suricataAnalyzerStatus = overviewAnalyzerStatusStub{snapshot: healthyOverviewAnalyzer(analyzer.EngineSuricata, now)}
	server.capabilities = overviewCapabilities()

	request := authenticatedJSONRequest(http.MethodGet, "/api/v1/agent/system-overview", "", session, "")
	recorder := httptest.NewRecorder()
	server.AgentSystemOverviewHandler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("system overview returned %d headers=%v body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	var overview agentSystemOverview
	if err := json.Unmarshal(recorder.Body.Bytes(), &overview); err != nil {
		t.Fatal(err)
	}
	if overview.Schema != 1 || overview.Overall != agentOverviewReady || !overview.EvidenceReady || len(overview.Limitations) != 0 || !overview.Gateway.Available || !overview.Ingest.Available || len(overview.Analyzers) != 2 || !overview.Analyzers[0].Healthy || !overview.Analyzers[1].Healthy || !overview.Capabilities.Available || len(overview.Capabilities.Features) != len(agentOverviewFeatureIDs) {
		t.Fatalf("unexpected ready overview: %#v", overview)
	}
	select {
	case rpc := <-requests:
		if rpc.Method != "GetManagedState" {
			t.Fatalf("unexpected gateway RPC %q", rpc.Method)
		}
	case <-time.After(time.Second):
		t.Fatal("system overview did not query gateway state")
	}
}

func TestAgentSystemOverviewReportsUnknownAndBacklogWithoutLeakingErrors(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "missing.sock"))
	server.ingestStatus = overviewIngestStatusStub{stats: ingest.Stats{
		Schema: ingest.SchemaVersion, GeneratedAt: now, PendingRecords: 3, PendingBytes: 1024,
		QuarantinedRecords: 1, QuarantinedBytes: 128, StoragePressure: true,
		DatabaseConfigured: true, DatabaseConnected: false,
	}}
	server.zeekAnalyzerStatus = overviewAnalyzerStatusStub{snapshot: staleOverviewAnalyzer(analyzer.EngineZeek, now)}
	server.suricataAnalyzerStatus = overviewAnalyzerStatusStub{err: errors.New("private analyzer path /var/lib/shakerproxy must not leak")}
	server.capabilities = nil

	request := authenticatedJSONRequest(http.MethodGet, "/api/v1/agent/system-overview", "", session, "")
	recorder := httptest.NewRecorder()
	server.AgentSystemOverviewHandler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("degraded overview returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var overview agentSystemOverview
	if err := json.Unmarshal(recorder.Body.Bytes(), &overview); err != nil {
		t.Fatal(err)
	}
	if overview.Overall != agentOverviewDegraded || overview.EvidenceReady || len(overview.Limitations) < 6 || overview.Gateway.Available || !overview.Ingest.Available || overview.Analyzers[0].Healthy || overview.Analyzers[1].Available || overview.Capabilities.Available {
		t.Fatalf("unexpected degraded overview: %#v", overview)
	}
	body := recorder.Body.String()
	for _, expected := range []string{"gateway status is unavailable", "normalized event database is unavailable", "normalized events are pending database commit", "quarantined records require review", "zeek analyzer is not healthy", "suricata analyzer status is unavailable", "capability registry projection is unavailable"} {
		if !strings.Contains(body, expected) {
			t.Fatalf("degraded overview is missing %q: %s", expected, body)
		}
	}
	for _, forbidden := range []string{"/var/lib/shakerproxy", "missing.sock", "private analyzer path"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("degraded overview leaked internal error %q: %s", forbidden, body)
		}
	}
}

func TestAgentSystemOverviewRequiresSystemReadScope(t *testing.T) {
	tokenStore := &apitoken.Store{Path: filepath.Join(t.TempDir(), "tokens.json")}
	server, _ := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "missing.sock"), func(config *Config) {
		config.APITokens = tokenStore
	})
	systemToken, err := tokenStore.Create(apitoken.CreateRequest{Name: "system agent", Creator: "admin", Scopes: []apitoken.Scope{apitoken.ScopeSystemRead}, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	trafficToken, err := tokenStore.Create(apitoken.CreateRequest{Name: "traffic agent", Creator: "admin", Scopes: []apitoken.Scope{apitoken.ScopeTrafficRead}, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		credential string
		want       int
	}{
		{credential: "", want: http.StatusUnauthorized},
		{credential: trafficToken.Secret, want: http.StatusForbidden},
		{credential: systemToken.Secret, want: http.StatusOK},
	} {
		request := tokenRequest(http.MethodGet, "/api/v1/agent/system-overview", item.credential)
		recorder := httptest.NewRecorder()
		server.AgentSystemOverviewHandler().ServeHTTP(recorder, request)
		if recorder.Code != item.want {
			t.Fatalf("credential %q returned %d want %d: %s", item.credential, recorder.Code, item.want, recorder.Body.String())
		}
	}
}

func healthyOverviewAnalyzer(engine analyzer.Engine, now time.Time) analyzer.HealthSnapshot {
	snapshot := analyzer.HealthSnapshot{
		Schema: analyzer.SchemaVersion, Engine: engine, State: analyzer.HealthHealthy, Healthy: true,
		SourceVersion: "test", CompletedCaptures: 2, DeliveredEvents: 10,
		LastSuccessAt: now.Add(-time.Second), HeartbeatAt: now.Add(-time.Second),
		HeartbeatAgeMillis: 1000, CheckedAt: now,
	}
	if engine == analyzer.EngineSuricata {
		snapshot.RulesetID = "shakerproxy-cleartext-policy"
		snapshot.RulesetVersion = "2026.09.01.1"
		snapshot.RulesetSHA256 = strings.Repeat("a", 64)
	}
	return snapshot
}

func staleOverviewAnalyzer(engine analyzer.Engine, now time.Time) analyzer.HealthSnapshot {
	snapshot := healthyOverviewAnalyzer(engine, now)
	snapshot.State = analyzer.HealthStale
	snapshot.Healthy = false
	snapshot.HeartbeatAt = now.Add(-3 * time.Minute)
	snapshot.HeartbeatAgeMillis = int64((3 * time.Minute) / time.Millisecond)
	return snapshot
}

func overviewCapabilities() *capabilityregistry.Bundle {
	features := make([]capabilityregistry.Feature, 0, len(agentOverviewFeatureIDs))
	for _, id := range agentOverviewFeatureIDs {
		features = append(features, capabilityregistry.Feature{ID: id, Status: "experimental", Badge: "EXPERIMENTAL", EnabledByDefault: id != "local_mcp_agent" && id != "tls_interception"})
	}
	return &capabilityregistry.Bundle{Schema: 1, Revision: "test-revision", Features: features}
}
