package agentapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/analyzer"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
)

func TestSystemOverviewClientAcceptsCompleteReadyProjection(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	overview := readySystemOverviewFixture(now)
	token := "lgt_" + strings.Repeat("s", 40)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/system-overview" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("Accept") != "application/json" {
			t.Fatalf("unexpected system overview request: path=%s query=%q headers=%v", r.URL.Path, r.URL.RawQuery, r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(overview)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.SystemOverview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Overall != "READY" || !result.EvidenceReady || len(result.Analyzers) != 2 || !result.Capabilities.Available {
		t.Fatalf("unexpected system overview: %#v", result)
	}
}

func TestSystemOverviewClientRejectsContradictoryAndUnknownResponses(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	fixtures := []SystemOverview{
		func() SystemOverview {
			value := readySystemOverviewFixture(now)
			value.Limitations = []string{"hidden degradation"}
			return value
		}(),
		func() SystemOverview {
			value := readySystemOverviewFixture(now)
			value.Analyzers[1].State = "UNKNOWN_HEALTH"
			return value
		}(),
		func() SystemOverview {
			value := readySystemOverviewFixture(now)
			value.Capabilities.Features = value.Capabilities.Features[:1]
			return value
		}(),
		func() SystemOverview {
			value := readySystemOverviewFixture(now)
			value.Overall = "DEGRADED"
			value.EvidenceReady = false
			value.Limitations = nil
			return value
		}(),
	}
	for index, fixture := range fixtures {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(fixture)
		}))
		client, err := NewClient(server.URL, "lgt_"+strings.Repeat("x", 40), server.Client())
		if err != nil {
			server.Close()
			t.Fatal(err)
		}
		if _, err := client.SystemOverview(context.Background()); err == nil {
			server.Close()
			t.Fatalf("invalid system overview fixture %d was accepted: %#v", index, fixture)
		}
		server.Close()
	}
}

func readySystemOverviewFixture(now time.Time) SystemOverview {
	features := make([]CapabilityFeature, 0, len(overviewFeatureIDs))
	for _, id := range []string{"bounded_packet_capture", "decrypted_http_retention", "device_inventory", "dns_visibility", "local_mcp_agent", "passive_analysis", "tls_interception"} {
		features = append(features, CapabilityFeature{ID: id, Status: "experimental", Badge: "EXPERIMENTAL", EnabledByDefault: id != "local_mcp_agent" && id != "tls_interception"})
	}
	return SystemOverview{
		Schema: 1, GeneratedAt: now, Overall: "READY", EvidenceReady: true,
		Gateway: GatewayOverview{
			Available: true, OperatingMode: gatewayprotocol.ModeRouted, NetworkActivation: true,
			CaptureAvailable: true, TrafficPolicyAvailable: true, LabInterface: "lab0",
		},
		Ingest: IngestOverview{Available: true, GeneratedAt: now, DatabaseConfigured: true, DatabaseConnected: true},
		Analyzers: []AnalyzerOverview{
			{Engine: string(analyzer.EngineZeek), Available: true, State: string(analyzer.HealthHealthy), Healthy: true, HeartbeatAgeMillis: 1000, LastSuccessAt: now.Add(-time.Second)},
			{Engine: string(analyzer.EngineSuricata), Available: true, State: string(analyzer.HealthHealthy), Healthy: true, HeartbeatAgeMillis: 1000, LastSuccessAt: now.Add(-time.Second)},
		},
		Capabilities: CapabilityOverview{Available: true, Revision: "test-revision", Features: features},
		Limitations:  []string{},
	}
}
