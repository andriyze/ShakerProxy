package agentapi

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
)

const (
	maxAgentControlsBytes    = 64 << 10
	maxAgentCapturesBytes    = 256 << 10
	maxAgentCasesBytes       = 256 << 10
	maxAgentCaseBytes        = 256 << 10
	maxAgentDiagnosticsBytes = 256 << 10
	maxAgentEvidenceLimit    = 100
)

var (
	agentCaptureIDPattern = regexp.MustCompile(`^capture-[a-f0-9]{32}$`)
	agentCaseIDPattern    = regexp.MustCompile(`^case-[a-f0-9]{32}$`)
)

// DeviceControls is GET /api/v1/devices/{id}/controls: whether ShakerProxy
// decrypts the device's HTTPS, blocks its internet access or blocks domains
// for it, and whether that is enforced now.
type DeviceControls struct {
	Schema         int       `json:"schema"`
	DeviceID       string    `json:"device_id"`
	DecryptHTTPS   bool      `json:"decrypt_https"`
	Internet       string    `json:"internet"`
	BlockedDomains []string  `json:"blocked_domains"`
	UpdatedAt      time.Time `json:"updated_at"`
	Effective      bool      `json:"effective"`
	Notes          []string  `json:"notes"`
}

func (c *Client) DeviceControls(ctx context.Context, deviceID string) (DeviceControls, error) {
	if c == nil || c.base == nil || c.client == nil {
		return DeviceControls{}, errors.New("agent API client is unavailable")
	}
	if !agentDeviceIDPattern.MatchString(deviceID) {
		return DeviceControls{}, errors.New("agent device ID is invalid")
	}
	var view DeviceControls
	if _, err := c.getJSONWith(ctx, "/api/v1/devices/"+deviceID+"/controls", nil, maxAgentControlsBytes, &view, false); err != nil {
		return DeviceControls{}, err
	}
	if view.Schema != 1 || view.DeviceID != deviceID || view.Internet != "ALLOW" && view.Internet != "BLOCK" || len(view.BlockedDomains) > 256 || len(view.Notes) > 16 {
		return DeviceControls{}, errors.New("agent device controls API returned an invalid bounded response")
	}
	for _, domain := range view.BlockedDomains {
		if !boundedAgentText(domain, 1, 253) {
			return DeviceControls{}, errors.New("agent device controls API returned an invalid domain")
		}
	}
	for _, note := range view.Notes {
		if !boundedAgentText(note, 1, 512) {
			return DeviceControls{}, errors.New("agent device controls API returned an invalid note")
		}
	}
	return view, nil
}

// Capture is one recording in GET /api/v1/agent/captures. It never carries
// file names, hashes or packet bytes.
type Capture struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Description     string    `json:"description,omitempty"`
	Kind            string    `json:"kind"`
	State           string    `json:"state"`
	Active          bool      `json:"active"`
	Mode            string    `json:"mode"`
	Interface       string    `json:"interface"`
	StartedAt       time.Time `json:"started_at"`
	StopAt          time.Time `json:"stop_at,omitzero"`
	EndedAt         time.Time `json:"ended_at,omitzero"`
	Segments        int       `json:"segments"`
	Bytes           int64     `json:"bytes"`
	SegmentSeconds  int       `json:"segment_seconds,omitempty"`
	SegmentSizeMiB  int       `json:"segment_size_mib,omitempty"`
	MaxSegments     int       `json:"max_segments,omitempty"`
	PacketsCaptured uint64    `json:"packets_captured"`
	PacketsDropped  uint64    `json:"packets_dropped"`
	Finalized       bool      `json:"finalized"`
	StopReason      string    `json:"stop_reason,omitempty"`
	Failure         string    `json:"failure,omitempty"`
	StoragePressure bool      `json:"storage_pressure"`
	CaseID          string    `json:"case_id,omitempty"`
	Held            bool      `json:"held"`
}

type CapturePage struct {
	Schema      int       `json:"schema"`
	GeneratedAt time.Time `json:"generated_at"`
	Total       int       `json:"total"`
	Returned    int       `json:"returned"`
	Truncated   bool      `json:"truncated"`
	Recording   bool      `json:"recording"`
	TotalBytes  int64     `json:"total_bytes"`
	Captures    []Capture `json:"captures"`
}

// Captures needs a token with captures:read.
func (c *Client) Captures(ctx context.Context, limit int) (CapturePage, error) {
	if c == nil || c.base == nil || c.client == nil {
		return CapturePage{}, errors.New("agent API client is unavailable")
	}
	if limit < 1 || limit > maxAgentEvidenceLimit {
		return CapturePage{}, errors.New("agent capture limit is invalid")
	}
	var page CapturePage
	if _, err := c.getJSON(ctx, "/api/v1/agent/captures", url.Values{"limit": {strconv.Itoa(limit)}}, maxAgentCapturesBytes, &page); err != nil {
		return CapturePage{}, err
	}
	if page.Schema != 1 || page.Returned != len(page.Captures) || page.Returned > limit || page.Total < page.Returned || page.Truncated != (page.Total > page.Returned) || page.TotalBytes < 0 {
		return CapturePage{}, errors.New("agent capture API returned an invalid bounded page")
	}
	for _, item := range page.Captures {
		if !agentCaptureIDPattern.MatchString(item.ID) || !boundedAgentText(item.Name, 0, 512) || !boundedAgentText(item.Description, 0, 512) || !boundedAgentText(item.StopReason, 0, 512) || !boundedAgentText(item.Failure, 0, 512) || !boundedAgentText(item.Interface, 0, 64) || item.Bytes < 0 || item.Segments < 0 || item.CaseID != "" && !boundedAgentText(item.CaseID, 1, 128) {
			return CapturePage{}, errors.New("agent capture API returned an invalid capture")
		}
		switch item.Kind {
		case "automatic", "coverage_check", "manual":
		default:
			return CapturePage{}, errors.New("agent capture API returned an invalid capture kind")
		}
	}
	return page, nil
}

type CaseEvidenceCounts struct {
	Total          int `json:"total"`
	Captures       int `json:"captures"`
	QuerySnapshots int `json:"query_snapshots"`
	CaptureExports int `json:"capture_exports"`
}

type CaseSummary struct {
	ID             string             `json:"id"`
	Name           string             `json:"name"`
	Description    string             `json:"description,omitempty"`
	Status         string             `json:"status"`
	Revision       uint64             `json:"revision"`
	CreatedBy      string             `json:"created_by"`
	CreatedAt      time.Time          `json:"created_at"`
	UpdatedAt      time.Time          `json:"updated_at"`
	EvidenceCounts CaseEvidenceCounts `json:"evidence_counts"`
	HoldState      string             `json:"hold_state"`
	HoldReason     string             `json:"hold_reason,omitempty"`
	LastAction     string             `json:"last_action,omitempty"`
	LastActionAt   time.Time          `json:"last_action_at,omitzero"`
}

type CasePage struct {
	Schema      int           `json:"schema"`
	GeneratedAt time.Time     `json:"generated_at"`
	Total       int           `json:"total"`
	Returned    int           `json:"returned"`
	Truncated   bool          `json:"truncated"`
	Cases       []CaseSummary `json:"cases"`
}

type CaseEvidence struct {
	ID           string    `json:"id"`
	Kind         string    `json:"kind"`
	ArtifactID   string    `json:"artifact_id"`
	Label        string    `json:"label,omitempty"`
	AddedBy      string    `json:"added_by"`
	AddedAt      time.Time `json:"added_at"`
	Query        string    `json:"query,omitempty"`
	MatchedCount int64     `json:"matched_count,omitempty"`
}

type CaseTimelineEvent struct {
	Revision   uint64    `json:"revision"`
	Action     string    `json:"action"`
	Actor      string    `json:"actor"`
	Reason     string    `json:"reason,omitempty"`
	OccurredAt time.Time `json:"occurred_at"`
}

type CaseDetail struct {
	Schema            int                 `json:"schema"`
	Case              CaseSummary         `json:"case"`
	Evidence          []CaseEvidence      `json:"evidence"`
	EvidenceTruncated bool                `json:"evidence_truncated"`
	Timeline          []CaseTimelineEvent `json:"timeline"`
	TimelineTruncated bool                `json:"timeline_truncated"`
	HoldProtected     int                 `json:"hold_protected"`
	HoldFailed        int                 `json:"hold_failed"`
}

// Cases needs a token with cases:read and no case restriction.
func (c *Client) Cases(ctx context.Context, limit int) (CasePage, error) {
	if c == nil || c.base == nil || c.client == nil {
		return CasePage{}, errors.New("agent API client is unavailable")
	}
	if limit < 1 || limit > maxAgentEvidenceLimit {
		return CasePage{}, errors.New("agent case limit is invalid")
	}
	var page CasePage
	if _, err := c.getJSON(ctx, "/api/v1/agent/cases", url.Values{"limit": {strconv.Itoa(limit)}}, maxAgentCasesBytes, &page); err != nil {
		return CasePage{}, err
	}
	if page.Schema != 1 || page.Returned != len(page.Cases) || page.Returned > limit || page.Total < page.Returned || page.Truncated != (page.Total > page.Returned) {
		return CasePage{}, errors.New("agent case API returned an invalid bounded page")
	}
	for _, item := range page.Cases {
		if err := validateCaseSummary(item); err != nil {
			return CasePage{}, err
		}
	}
	return page, nil
}

// Case needs a token with cases:read (restricted tokens: one of its cases).
func (c *Client) Case(ctx context.Context, caseID string) (CaseDetail, error) {
	if c == nil || c.base == nil || c.client == nil {
		return CaseDetail{}, errors.New("agent API client is unavailable")
	}
	caseID = strings.TrimSpace(caseID)
	if !agentCaseIDPattern.MatchString(caseID) {
		return CaseDetail{}, errors.New("case ID is invalid: it looks like case- followed by 32 hex characters (the cases tool lists them)")
	}
	var detail CaseDetail
	if _, err := c.getJSON(ctx, "/api/v1/agent/cases/"+caseID, nil, maxAgentCaseBytes, &detail); err != nil {
		return CaseDetail{}, err
	}
	if detail.Schema != 1 || detail.Case.ID != caseID || len(detail.Evidence) > 50 || len(detail.Timeline) > 20 || detail.HoldProtected < 0 || detail.HoldFailed < 0 {
		return CaseDetail{}, errors.New("agent case API returned an invalid bounded case")
	}
	if err := validateCaseSummary(detail.Case); err != nil {
		return CaseDetail{}, err
	}
	for _, entry := range detail.Evidence {
		if !boundedAgentText(entry.ID, 1, 64) || !boundedAgentText(entry.Kind, 1, 32) || !boundedAgentText(entry.ArtifactID, 1, 64) || !boundedAgentText(entry.Label, 0, 512) || !boundedAgentText(entry.AddedBy, 0, 512) || !boundedAgentText(entry.Query, 0, 512) {
			return CaseDetail{}, errors.New("agent case API returned invalid evidence")
		}
	}
	for _, event := range detail.Timeline {
		if !boundedAgentText(event.Action, 1, 64) || !boundedAgentText(event.Actor, 0, 512) || !boundedAgentText(event.Reason, 0, 512) {
			return CaseDetail{}, errors.New("agent case API returned an invalid timeline event")
		}
	}
	return detail, nil
}

func validateCaseSummary(item CaseSummary) error {
	if !agentCaseIDPattern.MatchString(item.ID) || !boundedAgentText(item.Name, 1, 512) || !boundedAgentText(item.Description, 0, 512) || item.Status != "OPEN" && item.Status != "CLOSED" || !boundedAgentText(item.CreatedBy, 0, 512) || !boundedAgentText(item.HoldState, 1, 16) || !boundedAgentText(item.HoldReason, 0, 512) || !boundedAgentText(item.LastAction, 0, 64) || item.EvidenceCounts.Total < 0 {
		return errors.New("agent case API returned an invalid case")
	}
	return nil
}

// Diagnostics is GET /api/v1/system/diagnostics: the checks `shakerproxy
// doctor` runs (system:read).
type Diagnostics = gatewayprotocol.DiagnosticReport

func (c *Client) Diagnostics(ctx context.Context) (Diagnostics, error) {
	if c == nil || c.base == nil || c.client == nil {
		return Diagnostics{}, errors.New("agent API client is unavailable")
	}
	var report Diagnostics
	if _, err := c.getJSONWith(ctx, "/api/v1/system/diagnostics", nil, maxAgentDiagnosticsBytes, &report, false); err != nil {
		return Diagnostics{}, err
	}
	if len(report.Checks) == 0 || len(report.Checks) > 64 {
		return Diagnostics{}, errors.New("agent diagnostics API returned an invalid bounded report")
	}
	for _, check := range report.Checks {
		switch check.Status {
		case gatewayprotocol.DiagnosticPass, gatewayprotocol.DiagnosticWarning, gatewayprotocol.DiagnosticFail, gatewayprotocol.DiagnosticUnknown:
		default:
			return Diagnostics{}, errors.New("agent diagnostics API returned an invalid check status")
		}
		if !boundedAgentText(check.Name, 1, 64) || !boundedAgentText(check.Summary, 1, 512) || len(check.Observations) > 16 {
			return Diagnostics{}, errors.New("agent diagnostics API returned an invalid check")
		}
		for _, observation := range check.Observations {
			if !boundedAgentText(observation, 0, 512) {
				return Diagnostics{}, errors.New("agent diagnostics API returned an invalid observation")
			}
		}
	}
	return report, nil
}
