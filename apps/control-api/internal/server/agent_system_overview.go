package server

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"shakerproxy.dev/shakerproxy/internal/analyzer"
	"shakerproxy.dev/shakerproxy/internal/apitoken"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/ingest"
)

const (
	agentOverviewReady       = "READY"
	agentOverviewDegraded    = "DEGRADED"
	agentOverviewUnavailable = "UNAVAILABLE"
)

var agentOverviewFeatureIDs = []string{
	"bounded_packet_capture",
	"decrypted_http_retention",
	"device_inventory",
	"dns_visibility",
	"local_mcp_agent",
	"passive_analysis",
	"tls_interception",
}

type agentSystemOverview struct {
	Schema        int                     `json:"schema"`
	GeneratedAt   time.Time               `json:"generated_at"`
	Overall       string                  `json:"overall"`
	EvidenceReady bool                    `json:"evidence_ready"`
	Gateway       agentGatewayOverview    `json:"gateway"`
	Ingest        agentIngestOverview     `json:"ingest"`
	Analyzers     []agentAnalyzerOverview `json:"analyzers"`
	Capabilities  agentCapabilityOverview `json:"capabilities"`
	Limitations   []string                `json:"limitations"`
}

type agentGatewayOverview struct {
	Available              bool   `json:"available"`
	OperatingMode          string `json:"operating_mode,omitempty"`
	EmergencyBypass        bool   `json:"emergency_bypass"`
	NetworkActivation      bool   `json:"network_activation_available"`
	CaptureAvailable       bool   `json:"capture_available"`
	TrafficPolicyAvailable bool   `json:"traffic_policy_available"`
	ActiveCapture          bool   `json:"active_capture"`
	LabInterface           string `json:"lab_interface,omitempty"`
}

type agentIngestOverview struct {
	Available          bool      `json:"available"`
	GeneratedAt        time.Time `json:"generated_at,omitempty"`
	PendingRecords     int       `json:"pending_records"`
	PendingBytes       int64     `json:"pending_bytes"`
	QuarantinedRecords int       `json:"quarantined_records"`
	QuarantinedBytes   int64     `json:"quarantined_bytes"`
	IngestLagSeconds   float64   `json:"ingest_lag_seconds"`
	StoragePressure    bool      `json:"storage_pressure"`
	DatabaseConfigured bool      `json:"database_configured"`
	DatabaseConnected  bool      `json:"database_connected"`
}

type agentAnalyzerOverview struct {
	Engine             string    `json:"engine"`
	Available          bool      `json:"available"`
	State              string    `json:"state,omitempty"`
	Healthy            bool      `json:"healthy"`
	ScanInProgress     bool      `json:"scan_in_progress"`
	HeartbeatAgeMillis int64     `json:"heartbeat_age_millis,omitempty"`
	DeliveredEvents    uint64    `json:"delivered_events,omitempty"`
	CompletedCaptures  uint64    `json:"completed_captures,omitempty"`
	LastSuccessAt      time.Time `json:"last_success_at,omitempty"`
}

type agentCapabilityOverview struct {
	Available bool                     `json:"available"`
	Revision  string                   `json:"revision,omitempty"`
	Features  []agentCapabilityFeature `json:"features"`
}

type agentCapabilityFeature struct {
	ID               string `json:"id"`
	Status           string `json:"status"`
	Badge            string `json:"badge"`
	EnabledByDefault bool   `json:"enabled_by_default"`
}

// AgentSystemOverviewHandler returns a compact read-only trust preflight. It
// deliberately turns missing evidence into limitations instead of optimistic
// health and never exposes analyzer error strings or host diagnostics.
func (s *Server) AgentSystemOverviewHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/agent/system-overview", s.requireAuthOrScope(apitoken.ScopeSystemRead, http.HandlerFunc(s.getAgentSystemOverview)))
	return s.wrapMux(mux)
}

func (s *Server) getAgentSystemOverview(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "agent system overview does not accept query parameters")
		return
	}
	now := time.Now().UTC()
	var gatewayStatus gatewayprotocol.Status
	var gatewayErr error
	var ingestStats ingest.Stats
	var ingestErr error
	analyzerResults := make([]agentAnalyzerOverview, 2)

	var wait sync.WaitGroup
	wait.Add(4)
	go func() {
		defer wait.Done()
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		gatewayErr = s.gateway.Call(ctx, "GetManagedState", gatewayprotocol.EmptyParams{}, &gatewayStatus)
	}()
	go func() {
		defer wait.Done()
		if s.ingestStatus == nil {
			ingestErr = context.Canceled
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		ingestStats, ingestErr = s.ingestStatus.IngestStatus(ctx)
	}()
	go func() {
		defer wait.Done()
		analyzerResults[0] = readAgentAnalyzerOverview(r.Context(), analyzer.EngineZeek, s.zeekAnalyzerStatus)
	}()
	go func() {
		defer wait.Done()
		analyzerResults[1] = readAgentAnalyzerOverview(r.Context(), analyzer.EngineSuricata, s.suricataAnalyzerStatus)
	}()
	wait.Wait()

	overview := agentSystemOverview{
		Schema:       1,
		GeneratedAt:  now,
		Gateway:      projectAgentGatewayOverview(gatewayStatus, gatewayErr),
		Ingest:       projectAgentIngestOverview(ingestStats, ingestErr, now),
		Analyzers:    analyzerResults,
		Capabilities: projectAgentCapabilityOverview(s),
		Limitations:  make([]string, 0, 12),
	}
	overview.Limitations = agentOverviewLimitations(overview, now)
	overview.EvidenceReady = len(overview.Limitations) == 0
	switch {
	case overview.EvidenceReady:
		overview.Overall = agentOverviewReady
	case !overview.Gateway.Available && !overview.Ingest.Available && !overview.Analyzers[0].Available && !overview.Analyzers[1].Available:
		overview.Overall = agentOverviewUnavailable
	default:
		overview.Overall = agentOverviewDegraded
	}
	writeJSON(w, http.StatusOK, overview)
}

func projectAgentGatewayOverview(status gatewayprotocol.Status, callErr error) agentGatewayOverview {
	if callErr != nil || strings.TrimSpace(status.APIVersion) == "" || strings.TrimSpace(status.DaemonVersion) == "" {
		return agentGatewayOverview{}
	}
	switch status.OperatingMode {
	case gatewayprotocol.ModeSetupSafe, gatewayprotocol.ModeRouted, gatewayprotocol.ModeEmergency:
	default:
		return agentGatewayOverview{}
	}
	if _, err := time.Parse(time.RFC3339Nano, status.StartedAt); err != nil {
		return agentGatewayOverview{}
	}
	return agentGatewayOverview{
		Available: true, OperatingMode: status.OperatingMode, EmergencyBypass: status.EmergencyBypass,
		NetworkActivation: status.NetworkActivation, CaptureAvailable: status.CaptureAvailable,
		TrafficPolicyAvailable: status.TrafficPolicyAvailable, ActiveCapture: status.ActiveCaptureID != "",
		LabInterface: status.LabInterface,
	}
}

func projectAgentIngestOverview(stats ingest.Stats, callErr error, now time.Time) agentIngestOverview {
	if callErr != nil || stats.Schema != ingest.SchemaVersion || stats.GeneratedAt.IsZero() || stats.GeneratedAt.After(now.Add(5*time.Second)) || stats.PendingRecords < 0 || stats.PendingBytes < 0 || stats.QuarantinedRecords < 0 || stats.QuarantinedBytes < 0 || stats.IngestLagSeconds < 0 {
		return agentIngestOverview{}
	}
	return agentIngestOverview{
		Available: true, GeneratedAt: stats.GeneratedAt, PendingRecords: stats.PendingRecords,
		PendingBytes: stats.PendingBytes, QuarantinedRecords: stats.QuarantinedRecords,
		QuarantinedBytes: stats.QuarantinedBytes, IngestLagSeconds: stats.IngestLagSeconds,
		StoragePressure: stats.StoragePressure, DatabaseConfigured: stats.DatabaseConfigured,
		DatabaseConnected: stats.DatabaseConnected,
	}
}

func readAgentAnalyzerOverview(parent context.Context, engine analyzer.Engine, service analyzerStatusService) agentAnalyzerOverview {
	result := agentAnalyzerOverview{Engine: string(engine)}
	if service == nil {
		return result
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	snapshot, err := service.Status(ctx)
	if err != nil || snapshot.Engine != engine || snapshot.Validate() != nil {
		return result
	}
	result.Available = true
	result.State = string(snapshot.State)
	result.Healthy = snapshot.Healthy
	result.ScanInProgress = snapshot.ScanInProgress
	result.HeartbeatAgeMillis = snapshot.HeartbeatAgeMillis
	result.DeliveredEvents = snapshot.DeliveredEvents
	result.CompletedCaptures = snapshot.CompletedCaptures
	result.LastSuccessAt = snapshot.LastSuccessAt
	return result
}

func projectAgentCapabilityOverview(s *Server) agentCapabilityOverview {
	result := agentCapabilityOverview{Features: []agentCapabilityFeature{}}
	if s.capabilities == nil || s.capabilities.Schema != 1 || strings.TrimSpace(s.capabilities.Revision) == "" {
		return result
	}
	wanted := make(map[string]struct{}, len(agentOverviewFeatureIDs))
	for _, id := range agentOverviewFeatureIDs {
		wanted[id] = struct{}{}
	}
	for _, feature := range s.capabilities.Features {
		if _, ok := wanted[feature.ID]; !ok {
			continue
		}
		result.Features = append(result.Features, agentCapabilityFeature{
			ID: feature.ID, Status: feature.Status, Badge: feature.Badge,
			EnabledByDefault: feature.EnabledByDefault,
		})
	}
	sort.Slice(result.Features, func(i, j int) bool { return result.Features[i].ID < result.Features[j].ID })
	result.Available = len(result.Features) == len(agentOverviewFeatureIDs)
	if result.Available {
		result.Revision = s.capabilities.Revision
	}
	return result
}

func agentOverviewLimitations(overview agentSystemOverview, now time.Time) []string {
	limitations := make([]string, 0, 12)
	if !overview.Gateway.Available {
		limitations = append(limitations, "gateway status is unavailable")
	} else {
		if overview.Gateway.OperatingMode != gatewayprotocol.ModeRouted {
			limitations = append(limitations, "gateway is not in routed passthrough mode")
		}
		if overview.Gateway.EmergencyBypass || overview.Gateway.OperatingMode == gatewayprotocol.ModeEmergency {
			limitations = append(limitations, "emergency bypass can make traffic evidence incomplete")
		}
	}
	if !overview.Ingest.Available {
		limitations = append(limitations, "ingestion status is unavailable")
	} else {
		if now.Sub(overview.Ingest.GeneratedAt) > 30*time.Second {
			limitations = append(limitations, "ingestion status is stale")
		}
		if !overview.Ingest.DatabaseConfigured || !overview.Ingest.DatabaseConnected {
			limitations = append(limitations, "normalized event database is unavailable")
		}
		if overview.Ingest.StoragePressure {
			limitations = append(limitations, "ingestion storage pressure is active")
		}
		if overview.Ingest.PendingRecords > 0 {
			limitations = append(limitations, "normalized events are pending database commit")
		}
		if overview.Ingest.QuarantinedRecords > 0 {
			limitations = append(limitations, "quarantined records require review")
		}
	}
	for _, item := range overview.Analyzers {
		label := strings.ToLower(item.Engine)
		if !item.Available {
			limitations = append(limitations, label+" analyzer status is unavailable")
		} else if !item.Healthy {
			limitations = append(limitations, label+" analyzer is not healthy")
		}
	}
	if !overview.Capabilities.Available {
		limitations = append(limitations, "capability registry projection is unavailable")
	}
	return limitations
}
