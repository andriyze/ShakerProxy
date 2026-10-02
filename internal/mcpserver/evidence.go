package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"shakerproxy.dev/shakerproxy/internal/agentapi"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
)

type DeviceControlsArgs struct {
	Device string `json:"device" jsonschema:"friendly name, IP address, MAC address, or device ID, e.g. Pixel or 10.77.0.23"`
}

type deviceControlsResult struct {
	Summary        string    `json:"summary"`
	DeviceID       string    `json:"device_id"`
	Device         string    `json:"device"`
	DecryptHTTPS   bool      `json:"decrypt_https"`
	Internet       string    `json:"internet"`
	BlockedDomains []string  `json:"blocked_domains"`
	Enforced       bool      `json:"enforced"`
	UpdatedAt      time.Time `json:"updated_at,omitzero"`
	Notes          []string  `json:"notes"`
}

func (s *Service) deviceControls(ctx context.Context, _ *mcp.CallToolRequest, args DeviceControlsArgs) (*mcp.CallToolResult, any, error) {
	device, err := s.resolveDevice(ctx, args.Device)
	if err != nil {
		return nil, nil, err
	}
	view, err := s.backend.DeviceControls(ctx, device.DeviceID)
	if err != nil {
		return nil, nil, fmt.Errorf("read the lab controls of %s: %w", device.FriendlyName, err)
	}
	result := deviceControlsResult{
		DeviceID: device.DeviceID, Device: device.FriendlyName, DecryptHTTPS: view.DecryptHTTPS, Internet: view.Internet,
		BlockedDomains: append([]string{}, view.BlockedDomains...), Enforced: view.Effective, UpdatedAt: view.UpdatedAt, Notes: append([]string{}, view.Notes...),
	}
	parts := []string{}
	if view.DecryptHTTPS {
		parts = append(parts, "HTTPS is decrypted")
	} else {
		parts = append(parts, "HTTPS is not decrypted")
	}
	if view.Internet == "BLOCK" {
		parts = append(parts, "internet access is blocked")
	} else {
		parts = append(parts, "internet access is allowed")
	}
	switch count := len(view.BlockedDomains); {
	case count == 0:
		parts = append(parts, "no domains are blocked")
	case count <= 3:
		parts = append(parts, "blocked domains: "+strings.Join(view.BlockedDomains, ", "))
	default:
		parts = append(parts, fmt.Sprintf("%d domains are blocked, including %s", count, strings.Join(view.BlockedDomains[:3], ", ")))
	}
	result.Summary = fmt.Sprintf("%s: %s.", device.FriendlyName, strings.Join(parts, "; "))
	active := view.DecryptHTTPS || view.Internet == "BLOCK" || len(view.BlockedDomains) > 0
	if active && !view.Effective {
		result.Summary += " These controls are saved but not enforced now; see notes."
	}
	result.Summary += " Change them in the Web UI or CLI; agents can only read them."
	return textResult(result)
}

type CapturesArgs struct {
	Limit int `json:"limit,omitempty" jsonschema:"maximum captures to return, 1-100, default 50; recording captures come first, then the newest"`
}

type captureLine struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	State     string    `json:"state"`
	Recording bool      `json:"recording"`
	Interface string    `json:"interface,omitempty"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at,omitzero"`
	Segments  int       `json:"segments"`
	Bytes     int64     `json:"bytes"`
	Packets   uint64    `json:"packets_captured"`
	Dropped   uint64    `json:"packets_dropped"`
	Finalized bool      `json:"finalized"`
	CaseID    string    `json:"case_id,omitempty"`
	Held      bool      `json:"held"`
	Failure   string    `json:"failure,omitempty"`
	Summary   string    `json:"summary"`
}

type capturesResult struct {
	Summary    string        `json:"summary"`
	Recording  bool          `json:"recording"`
	Total      int           `json:"total"`
	TotalBytes int64         `json:"total_bytes"`
	Truncated  bool          `json:"truncated"`
	Captures   []captureLine `json:"captures"`
}

func (s *Service) captures(ctx context.Context, _ *mcp.CallToolRequest, args CapturesArgs) (*mcp.CallToolResult, any, error) {
	limit, err := normalizeLimit(args.Limit)
	if err != nil {
		return nil, nil, err
	}
	page, err := s.backend.Captures(ctx, limit)
	if err != nil {
		return nil, nil, fmt.Errorf("list packet captures (the token needs captures:read): %w", err)
	}
	result := capturesResult{Recording: page.Recording, Total: page.Total, TotalBytes: page.TotalBytes, Truncated: page.Truncated, Captures: make([]captureLine, 0, len(page.Captures))}
	recording := []string{}
	for _, item := range page.Captures {
		line := captureLine{
			ID: item.ID, Name: item.Name, Kind: item.Kind, State: item.State, Recording: item.Active, Interface: item.Interface,
			StartedAt: item.StartedAt, EndedAt: item.EndedAt, Segments: item.Segments, Bytes: item.Bytes, Packets: item.PacketsCaptured,
			Dropped: item.PacketsDropped, Finalized: item.Finalized, CaseID: item.CaseID, Held: item.Held, Failure: item.Failure,
		}
		line.Summary = captureSummary(item)
		if item.Active {
			recording = append(recording, line.Summary)
		}
		result.Captures = append(result.Captures, line)
	}
	switch {
	case page.Total == 0:
		result.Summary = "No packet captures exist. ShakerProxy records the lab automatically while a lab network routes."
	case len(recording) == 0:
		result.Summary = fmt.Sprintf("Nothing is being recorded now; %s kept, %s in all.", countNoun(page.Total, "capture is", "captures are"), formatBytes(page.TotalBytes))
	default:
		result.Summary = fmt.Sprintf("Recording now: %s. %s kept, %s in all.", strings.Join(recording, "; "), countNoun(page.Total, "capture", "captures"), formatBytes(page.TotalBytes))
	}
	if page.Truncated {
		result.Summary += fmt.Sprintf(" Showing %d; raise limit for more.", len(result.Captures))
	}
	return textResult(result)
}

func captureSummary(item agentapi.Capture) string {
	kind := map[string]string{"automatic": "automatic", "coverage_check": "coverage check", "manual": "manual"}[item.Kind]
	where := ""
	if item.Interface != "" {
		where = " on " + item.Interface
	}
	text := fmt.Sprintf("%s (%s%s, %s): %s, %s", item.Name, kind, where, strings.ToLower(item.State), countNoun(item.Segments, "segment", "segments"), formatBytes(item.Bytes))
	if item.PacketsDropped > 0 {
		text += fmt.Sprintf(", %d packets dropped", item.PacketsDropped)
	}
	if item.Held {
		text += ", held as evidence"
	}
	if item.Failure != "" {
		text += "; failed: " + item.Failure
	}
	return boundText(text, 400)
}

type CasesArgs struct {
	CaseID string `json:"case_id,omitempty" jsonschema:"one case to show in detail, e.g. case-0123456789abcdef0123456789abcdef; omit to list cases"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum cases to list, 1-100, default 50"`
}

type caseLine struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	UpdatedAt time.Time `json:"updated_at"`
	Evidence  int       `json:"evidence"`
	HoldState string    `json:"hold_state"`
	Summary   string    `json:"summary"`
}

type casesResult struct {
	Summary   string     `json:"summary"`
	Total     int        `json:"total"`
	Truncated bool       `json:"truncated"`
	Cases     []caseLine `json:"cases"`
}

type caseEvidenceLine struct {
	Kind         string    `json:"kind"`
	ArtifactID   string    `json:"artifact_id"`
	Label        string    `json:"label,omitempty"`
	AddedBy      string    `json:"added_by"`
	AddedAt      time.Time `json:"added_at"`
	Query        string    `json:"query,omitempty"`
	MatchedCount int64     `json:"matched_count,omitempty"`
}

type caseDetailResult struct {
	Summary           string                       `json:"summary"`
	Case              agentapi.CaseSummary         `json:"case"`
	Evidence          []caseEvidenceLine           `json:"evidence"`
	EvidenceTruncated bool                         `json:"evidence_truncated"`
	Timeline          []agentapi.CaseTimelineEvent `json:"timeline"`
	TimelineTruncated bool                         `json:"timeline_truncated"`
}

func (s *Service) cases(ctx context.Context, _ *mcp.CallToolRequest, args CasesArgs) (*mcp.CallToolResult, any, error) {
	if caseID := strings.TrimSpace(args.CaseID); caseID != "" {
		if args.Limit != 0 {
			return nil, nil, errors.New("limit applies to the case list; omit it with case_id")
		}
		detail, err := s.backend.Case(ctx, caseID)
		if err != nil {
			return nil, nil, fmt.Errorf("read case %s (the token needs cases:read): %w", caseID, err)
		}
		result := caseDetailResult{Case: detail.Case, Evidence: make([]caseEvidenceLine, 0, len(detail.Evidence)), EvidenceTruncated: detail.EvidenceTruncated, Timeline: detail.Timeline, TimelineTruncated: detail.TimelineTruncated}
		for _, entry := range detail.Evidence {
			result.Evidence = append(result.Evidence, caseEvidenceLine{Kind: entry.Kind, ArtifactID: entry.ArtifactID, Label: entry.Label, AddedBy: entry.AddedBy, AddedAt: entry.AddedAt, Query: entry.Query, MatchedCount: entry.MatchedCount})
		}
		result.Summary = caseSummary(detail.Case)
		if detail.HoldFailed > 0 {
			result.Summary += fmt.Sprintf(" The evidence hold could not protect %s.", countNoun(detail.HoldFailed, "capture", "captures"))
		}
		return textResult(result)
	}
	limit, err := normalizeLimit(args.Limit)
	if err != nil {
		return nil, nil, err
	}
	page, err := s.backend.Cases(ctx, limit)
	if err != nil {
		return nil, nil, fmt.Errorf("list cases (the token needs cases:read): %w", err)
	}
	result := casesResult{Total: page.Total, Truncated: page.Truncated, Cases: make([]caseLine, 0, len(page.Cases))}
	open := 0
	for _, item := range page.Cases {
		if item.Status == "OPEN" {
			open++
		}
		result.Cases = append(result.Cases, caseLine{ID: item.ID, Name: item.Name, Status: item.Status, UpdatedAt: item.UpdatedAt, Evidence: item.EvidenceCounts.Total, HoldState: item.HoldState, Summary: caseSummary(item)})
	}
	switch {
	case page.Total == 0:
		result.Summary = "No cases exist. Investigators create cases in the Web UI to keep captures and query snapshots together as evidence."
	case page.Truncated:
		result.Summary = fmt.Sprintf("Showing the %d most recently updated of %d cases (%d open shown); raise limit for more.", len(result.Cases), page.Total, open)
	default:
		result.Summary = fmt.Sprintf("%s, %d open. Pass case_id for one case's evidence and timeline.", countNoun(page.Total, "case", "cases"), open)
	}
	return textResult(result)
}

func caseSummary(item agentapi.CaseSummary) string {
	counts := item.EvidenceCounts
	evidence := countNoun(counts.Total, "evidence item", "evidence items")
	if counts.Total > 0 {
		kinds := []string{}
		for _, part := range []struct {
			count        int
			one, several string
		}{{counts.Captures, "capture", "captures"}, {counts.QuerySnapshots, "query snapshot", "query snapshots"}, {counts.CaptureExports, "capture export", "capture exports"}} {
			if part.count > 0 {
				kinds = append(kinds, countNoun(part.count, part.one, part.several))
			}
		}
		evidence += " (" + strings.Join(kinds, ", ") + ")"
	}
	text := fmt.Sprintf("%s (%s): %s", item.Name, strings.ToLower(item.Status), evidence)
	switch item.HoldState {
	case "ACTIVE":
		text += "; evidence hold active"
	case "PARTIAL":
		text += "; evidence hold only partly applied"
	}
	return boundText(text+".", 400)
}

type DiagnosticsArgs struct{}

type diagnosticLine struct {
	Name         string   `json:"name"`
	Status       string   `json:"status"`
	Summary      string   `json:"summary"`
	Observations []string `json:"observations,omitempty"`
}

type diagnosticsResult struct {
	Summary     string           `json:"summary"`
	Overall     string           `json:"overall"`
	GeneratedAt time.Time        `json:"generated_at"`
	Passed      int              `json:"passed"`
	Warnings    int              `json:"warnings"`
	Failed      int              `json:"failed"`
	Unknown     int              `json:"unknown"`
	Checks      []diagnosticLine `json:"checks"`
}

func (s *Service) diagnostics(ctx context.Context, _ *mcp.CallToolRequest, _ DiagnosticsArgs) (*mcp.CallToolResult, any, error) {
	report, err := s.backend.Diagnostics(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("run ShakerProxy diagnostics: %w", err)
	}
	result := diagnosticsResult{Overall: string(report.Overall), GeneratedAt: report.GeneratedAt, Checks: make([]diagnosticLine, 0, len(report.Checks))}
	problems := []string{}
	// Problems first, in the doctor's order, then the passing checks.
	for _, wantProblem := range []bool{true, false} {
		for _, check := range report.Checks {
			problem := check.Status != gatewayprotocol.DiagnosticPass
			if problem != wantProblem {
				continue
			}
			result.Checks = append(result.Checks, diagnosticLine{Name: check.Name, Status: string(check.Status), Summary: check.Summary, Observations: check.Observations})
			switch check.Status {
			case gatewayprotocol.DiagnosticPass:
				result.Passed++
			case gatewayprotocol.DiagnosticWarning:
				result.Warnings++
			case gatewayprotocol.DiagnosticFail:
				result.Failed++
			default:
				result.Unknown++
			}
			if problem {
				problems = append(problems, fmt.Sprintf("%s %s: %s", strings.ToLower(string(check.Status)), check.Name, check.Summary))
			}
		}
	}
	result.Summary = fmt.Sprintf("ShakerProxy doctor: %d passed, %d warnings, %d failed, %d unknown.", result.Passed, result.Warnings, result.Failed, result.Unknown)
	if len(problems) > 0 {
		result.Summary += " " + strings.Join(problems, "; ") + "."
	}
	result.Summary = boundText(result.Summary, 900)
	return textResult(result)
}
