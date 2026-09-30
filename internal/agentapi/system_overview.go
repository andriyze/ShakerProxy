package agentapi

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"shakerproxy.dev/shakerproxy/internal/analyzer"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
)

const maxAgentSystemOverviewBytes = 128 << 10

var overviewFeatureIDs = map[string]struct{}{
	"bounded_packet_capture": {}, "decrypted_http_retention": {}, "device_inventory": {},
	"dns_visibility": {}, "local_mcp_agent": {}, "passive_analysis": {}, "tls_interception": {},
}

type SystemOverview struct {
	Schema        int                `json:"schema"`
	GeneratedAt   time.Time          `json:"generated_at"`
	Overall       string             `json:"overall"`
	EvidenceReady bool               `json:"evidence_ready"`
	Gateway       GatewayOverview    `json:"gateway"`
	Ingest        IngestOverview     `json:"ingest"`
	Analyzers     []AnalyzerOverview `json:"analyzers"`
	Capabilities  CapabilityOverview `json:"capabilities"`
	Limitations   []string           `json:"limitations"`
}

type GatewayOverview struct {
	Available              bool   `json:"available"`
	OperatingMode          string `json:"operating_mode,omitempty"`
	EmergencyBypass        bool   `json:"emergency_bypass"`
	NetworkActivation      bool   `json:"network_activation_available"`
	CaptureAvailable       bool   `json:"capture_available"`
	TrafficPolicyAvailable bool   `json:"traffic_policy_available"`
	ActiveCapture          bool   `json:"active_capture"`
	LabInterface           string `json:"lab_interface,omitempty"`
}

type IngestOverview struct {
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

type AnalyzerOverview struct {
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

type CapabilityOverview struct {
	Available bool                `json:"available"`
	Revision  string              `json:"revision,omitempty"`
	Features  []CapabilityFeature `json:"features"`
}

type CapabilityFeature struct {
	ID               string `json:"id"`
	Status           string `json:"status"`
	Badge            string `json:"badge"`
	EnabledByDefault bool   `json:"enabled_by_default"`
}

func (c *Client) SystemOverview(ctx context.Context) (SystemOverview, error) {
	if c == nil || c.base == nil || c.client == nil {
		return SystemOverview{}, errors.New("agent API client is unavailable")
	}
	var overview SystemOverview
	if _, err := c.getJSON(ctx, "/api/v1/agent/system-overview", nil, maxAgentSystemOverviewBytes, &overview); err != nil {
		return SystemOverview{}, err
	}
	if err := validateSystemOverview(overview); err != nil {
		return SystemOverview{}, errors.New("agent system overview API returned an invalid bounded response")
	}
	return overview, nil
}

func validateSystemOverview(overview SystemOverview) error {
	if overview.Schema != 1 || !validAgentTime(overview.GeneratedAt) || len(overview.Limitations) > 16 || len(overview.Analyzers) != 2 {
		return errors.New("system overview boundary is invalid")
	}
	switch overview.Overall {
	case "READY":
		if !overview.EvidenceReady || len(overview.Limitations) != 0 {
			return errors.New("ready system overview has limitations")
		}
	case "DEGRADED", "UNAVAILABLE":
		if overview.EvidenceReady || len(overview.Limitations) == 0 {
			return errors.New("non-ready system overview lacks limitations")
		}
	default:
		return errors.New("system overview state is invalid")
	}
	for _, limitation := range overview.Limitations {
		if !validOverviewText(limitation, 160) {
			return errors.New("system overview limitation is invalid")
		}
	}
	if overview.Gateway.Available {
		switch overview.Gateway.OperatingMode {
		case gatewayprotocol.ModeSetupSafe, gatewayprotocol.ModeRouted, gatewayprotocol.ModeEmergency:
		default:
			return errors.New("system overview gateway mode is invalid")
		}
		if overview.Gateway.LabInterface != "" && !validOverviewText(overview.Gateway.LabInterface, 15) {
			return errors.New("system overview gateway interface is invalid")
		}
	} else if overview.Gateway.OperatingMode != "" || overview.Gateway.EmergencyBypass || overview.Gateway.NetworkActivation || overview.Gateway.CaptureAvailable || overview.Gateway.TrafficPolicyAvailable || overview.Gateway.ActiveCapture || overview.Gateway.LabInterface != "" {
		return errors.New("unavailable gateway contains asserted state")
	}
	if overview.Ingest.Available {
		if !validAgentTime(overview.Ingest.GeneratedAt) || overview.Ingest.GeneratedAt.After(overview.GeneratedAt.Add(5*time.Second)) || overview.Ingest.PendingRecords < 0 || overview.Ingest.PendingBytes < 0 || overview.Ingest.QuarantinedRecords < 0 || overview.Ingest.QuarantinedBytes < 0 || overview.Ingest.IngestLagSeconds < 0 {
			return errors.New("system overview ingestion state is invalid")
		}
	} else if !overview.Ingest.GeneratedAt.IsZero() || overview.Ingest.PendingRecords != 0 || overview.Ingest.PendingBytes != 0 || overview.Ingest.QuarantinedRecords != 0 || overview.Ingest.QuarantinedBytes != 0 || overview.Ingest.IngestLagSeconds != 0 || overview.Ingest.StoragePressure || overview.Ingest.DatabaseConfigured || overview.Ingest.DatabaseConnected {
		return errors.New("unavailable ingestion contains asserted state")
	}
	for index, expected := range []analyzer.Engine{analyzer.EngineZeek, analyzer.EngineSuricata} {
		item := overview.Analyzers[index]
		if item.Engine != string(expected) || item.HeartbeatAgeMillis < 0 {
			return errors.New("system overview analyzer identity is invalid")
		}
		if item.Available {
			switch analyzer.HealthState(item.State) {
			case analyzer.HealthHealthy, analyzer.HealthScanning, analyzer.HealthStale:
			default:
				return errors.New("system overview analyzer state is invalid")
			}
			if item.Healthy != (item.State == string(analyzer.HealthHealthy) || item.State == string(analyzer.HealthScanning)) || item.ScanInProgress != (item.State == string(analyzer.HealthScanning)) {
				return errors.New("system overview analyzer state is inconsistent")
			}
			if !item.LastSuccessAt.IsZero() && !validAgentTime(item.LastSuccessAt) {
				return errors.New("system overview analyzer success time is invalid")
			}
		} else if item.State != "" || item.Healthy || item.ScanInProgress || item.HeartbeatAgeMillis != 0 || item.DeliveredEvents != 0 || item.CompletedCaptures != 0 || !item.LastSuccessAt.IsZero() {
			return errors.New("unavailable analyzer contains asserted state")
		}
	}
	if len(overview.Capabilities.Features) > len(overviewFeatureIDs) {
		return errors.New("system overview capability projection exceeds its bound")
	}
	seen := make(map[string]struct{}, len(overview.Capabilities.Features))
	previous := ""
	for _, feature := range overview.Capabilities.Features {
		if _, ok := overviewFeatureIDs[feature.ID]; !ok || feature.ID <= previous || !validOverviewText(feature.Badge, 32) {
			return errors.New("system overview capability feature is invalid")
		}
		switch feature.Status {
		case "supported", "experimental", "capture-only", "unavailable":
		default:
			return errors.New("system overview capability status is invalid")
		}
		if _, duplicate := seen[feature.ID]; duplicate {
			return errors.New("system overview capability feature is duplicated")
		}
		seen[feature.ID] = struct{}{}
		previous = feature.ID
	}
	if overview.Capabilities.Available {
		if !validOverviewText(overview.Capabilities.Revision, 64) || len(overview.Capabilities.Features) != len(overviewFeatureIDs) {
			return errors.New("available capability projection is incomplete")
		}
	} else if overview.Capabilities.Revision != "" {
		return errors.New("unavailable capability projection contains a revision")
	}
	return nil
}

func validAgentTime(value time.Time) bool {
	return value.Year() >= 2000 && value.Year() <= 3000
}

func validOverviewText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}
