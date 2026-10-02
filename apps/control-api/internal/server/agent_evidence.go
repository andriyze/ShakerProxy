package server

import (
	"errors"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"shakerproxy.dev/shakerproxy/internal/apitoken"
	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/casework"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
)

// Compact, bounded projections of captures and cases for API tokens and AI
// agents. GET /api/v1/captures returns every finished capture's file list
// (hundreds of kilobytes on a busy lab) and GET /api/v1/cases every case's
// full evidence and timeline; these routes answer "what is recorded, what
// is under investigation" in a few kilobytes. They never return PCAP bytes,
// file names, hashes or export links.
const (
	defaultAgentEvidenceLimit = 50
	maxAgentEvidenceLimit     = 100
	maxAgentCaseEvidence      = 50
	maxAgentCaseTimeline      = 20
	maxAgentEvidenceText      = 512
)

type agentCapture struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Kind is "automatic" (the "Lab traffic" or "VPN traffic" recording
	// ShakerProxy keeps while a lab routes), "coverage_check" or "manual".
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
	// Finalized is true once the capture stopped and its files were hashed.
	Finalized       bool   `json:"finalized"`
	StopReason      string `json:"stop_reason,omitempty"`
	Failure         string `json:"failure,omitempty"`
	StoragePressure bool   `json:"storage_pressure"`
	CaseID          string `json:"case_id,omitempty"`
	Held            bool   `json:"held"`
}

type agentCapturePage struct {
	Schema      int            `json:"schema"`
	GeneratedAt time.Time      `json:"generated_at"`
	Total       int            `json:"total"`
	Returned    int            `json:"returned"`
	Truncated   bool           `json:"truncated"`
	Recording   bool           `json:"recording"`
	TotalBytes  int64          `json:"total_bytes"`
	Captures    []agentCapture `json:"captures"`
}

type agentCaseEvidenceCounts struct {
	Total          int `json:"total"`
	Captures       int `json:"captures"`
	QuerySnapshots int `json:"query_snapshots"`
	CaptureExports int `json:"capture_exports"`
}

type agentCaseSummary struct {
	ID             string                  `json:"id"`
	Name           string                  `json:"name"`
	Description    string                  `json:"description,omitempty"`
	Status         string                  `json:"status"`
	Revision       uint64                  `json:"revision"`
	CreatedBy      string                  `json:"created_by"`
	CreatedAt      time.Time               `json:"created_at"`
	UpdatedAt      time.Time               `json:"updated_at"`
	EvidenceCounts agentCaseEvidenceCounts `json:"evidence_counts"`
	HoldState      string                  `json:"hold_state"`
	HoldReason     string                  `json:"hold_reason,omitempty"`
	LastAction     string                  `json:"last_action,omitempty"`
	LastActionAt   time.Time               `json:"last_action_at,omitzero"`
}

type agentCasePage struct {
	Schema      int                `json:"schema"`
	GeneratedAt time.Time          `json:"generated_at"`
	Total       int                `json:"total"`
	Returned    int                `json:"returned"`
	Truncated   bool               `json:"truncated"`
	Cases       []agentCaseSummary `json:"cases"`
}

type agentCaseEvidence struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	ArtifactID string    `json:"artifact_id"`
	Label      string    `json:"label,omitempty"`
	AddedBy    string    `json:"added_by"`
	AddedAt    time.Time `json:"added_at"`
	// Query and MatchedCount describe a query snapshot: what it matched
	// when it was attached.
	Query        string `json:"query,omitempty"`
	MatchedCount int64  `json:"matched_count,omitempty"`
}

type agentCaseTimelineEvent struct {
	Revision   uint64    `json:"revision"`
	Action     string    `json:"action"`
	Actor      string    `json:"actor"`
	Reason     string    `json:"reason,omitempty"`
	OccurredAt time.Time `json:"occurred_at"`
}

type agentCaseDetail struct {
	Schema            int                      `json:"schema"`
	Case              agentCaseSummary         `json:"case"`
	Evidence          []agentCaseEvidence      `json:"evidence"`
	EvidenceTruncated bool                     `json:"evidence_truncated"`
	Timeline          []agentCaseTimelineEvent `json:"timeline"`
	TimelineTruncated bool                     `json:"timeline_truncated"`
	HoldProtected     int                      `json:"hold_protected"`
	HoldFailed        int                      `json:"hold_failed"`
}

// registerAgentEvidenceRoutes adds the compact capture and case
// projections; they need the same read scopes as the full routes.
func (s *Server) registerAgentEvidenceRoutes(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/agent/captures", s.requireAuthOrScope(apitoken.ScopeCapturesRead, http.HandlerFunc(s.listAgentCaptures)))
	mux.Handle("GET /api/v1/agent/cases", s.requireAuthOrScope(apitoken.ScopeCasesRead, http.HandlerFunc(s.listAgentCases)))
	mux.Handle("GET /api/v1/agent/cases/{caseID}", s.requireAuthOrScope(apitoken.ScopeCasesRead, http.HandlerFunc(s.getAgentCase)))
}

func parseAgentEvidenceLimit(r *http.Request) (int, error) {
	values := r.URL.Query()
	for key, entries := range values {
		if key != "limit" || len(entries) != 1 {
			return 0, errors.New("only one limit query parameter is accepted")
		}
	}
	raw := values.Get("limit")
	if raw == "" {
		return defaultAgentEvidenceLimit, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 1 || limit > maxAgentEvidenceLimit {
		return 0, errors.New("limit must be between 1 and 100")
	}
	return limit, nil
}

func (s *Server) listAgentCaptures(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	limit, err := parseAgentEvidenceLimit(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_query", err.Error())
		return
	}
	var views []capture.View
	if err := s.gateway.Call(r.Context(), "ListCaptures", gatewayprotocol.EmptyParams{}, &views); err != nil {
		writeError(w, http.StatusServiceUnavailable, "capture_unavailable", "Capture status is temporarily unavailable.")
		return
	}
	page := agentCapturePage{Schema: 1, GeneratedAt: time.Now().UTC(), Total: len(views), Captures: []agentCapture{}}
	captures := make([]agentCapture, 0, len(views))
	for _, view := range views {
		projected := projectAgentCapture(view)
		page.TotalBytes += projected.Bytes
		page.Recording = page.Recording || projected.Active
		captures = append(captures, projected)
	}
	sort.SliceStable(captures, func(left, right int) bool {
		if captures[left].Active != captures[right].Active {
			return captures[left].Active
		}
		return captures[left].StartedAt.After(captures[right].StartedAt)
	})
	if len(captures) > limit {
		captures, page.Truncated = captures[:limit], true
	}
	page.Captures, page.Returned = captures, len(captures)
	writeJSON(w, http.StatusOK, page)
}

func projectAgentCapture(view capture.View) agentCapture {
	request := view.Session.Request
	kind := "manual"
	switch {
	case request.Automatic:
		kind = "automatic"
	case request.CoverageLab:
		kind = "coverage_check"
	}
	projected := agentCapture{
		ID: view.Session.ID, Name: agentEvidenceText(request.Name), Description: agentEvidenceText(request.Description),
		Kind: kind, State: string(view.State), Active: view.Active, Mode: string(request.Mode),
		Interface: view.Session.Source.InterfaceName, StartedAt: view.Session.StartedAt, StopAt: view.Session.StopAt,
		Segments: view.CurrentFiles, Bytes: view.CurrentBytes,
		SegmentSeconds: request.SegmentSeconds, SegmentSizeMiB: request.SegmentSizeMiB, MaxSegments: request.MaxFiles,
		StoragePressure: view.StoragePressure, CaseID: request.CaseID,
	}
	if worker := view.Worker; worker != nil {
		projected.EndedAt = worker.EndedAt
		projected.PacketsCaptured = worker.PacketsCaptured
		projected.PacketsDropped = worker.KernelDrops + worker.DumpcapDrops
		projected.StopReason = agentEvidenceText(worker.StopReason)
		projected.Failure = agentEvidenceText(worker.Failure)
	}
	if manifest := view.Manifest; manifest != nil {
		projected.Finalized = true
		projected.Segments = len(manifest.Files)
		projected.Bytes = manifest.TotalSizeBytes
		projected.PacketsCaptured = manifest.PacketsCaptured
		projected.PacketsDropped = manifest.KernelDrops + manifest.DumpcapDrops
	}
	if hold := view.EvidenceHold; hold != nil && hold.Active {
		projected.Held = true
		if projected.CaseID == "" {
			projected.CaseID = hold.CaseID
		}
	}
	return projected
}

func (s *Server) listAgentCases(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	limit, err := parseAgentEvidenceLimit(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_query", err.Error())
		return
	}
	if s.cases == nil {
		writeError(w, http.StatusServiceUnavailable, "cases_unavailable", "case storage is unavailable")
		return
	}
	items, err := s.cases.List()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "cases_unavailable", "cases are temporarily unavailable")
		return
	}
	sort.SliceStable(items, func(left, right int) bool { return items[left].UpdatedAt.After(items[right].UpdatedAt) })
	page := agentCasePage{Schema: 1, GeneratedAt: time.Now().UTC(), Total: len(items), Cases: []agentCaseSummary{}}
	if len(items) > limit {
		items, page.Truncated = items[:limit], true
	}
	for _, item := range items {
		page.Cases = append(page.Cases, projectAgentCaseSummary(item))
	}
	page.Returned = len(page.Cases)
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) getAgentCase(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "case detail does not accept query parameters")
		return
	}
	caseID := r.PathValue("caseID")
	if !casework.ValidCaseID(caseID) {
		writeError(w, http.StatusBadRequest, "invalid_case_id", "case ID is invalid; list cases with GET /api/v1/agent/cases")
		return
	}
	if s.cases == nil {
		writeError(w, http.StatusServiceUnavailable, "cases_unavailable", "case storage is unavailable")
		return
	}
	item, err := s.cases.Get(caseID)
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "case_not_found", "case was not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "cases_unavailable", "case is temporarily unavailable")
		return
	}
	detail := agentCaseDetail{Schema: 1, Case: projectAgentCaseSummary(item), Evidence: []agentCaseEvidence{}, Timeline: []agentCaseTimelineEvent{}}
	evidence := append([]casework.Evidence(nil), item.Evidence...)
	sort.SliceStable(evidence, func(left, right int) bool { return evidence[left].AddedAt.After(evidence[right].AddedAt) })
	if len(evidence) > maxAgentCaseEvidence {
		evidence, detail.EvidenceTruncated = evidence[:maxAgentCaseEvidence], true
	}
	for _, entry := range evidence {
		line := agentCaseEvidence{ID: entry.ID, Kind: string(entry.Kind), ArtifactID: entry.ArtifactID, Label: agentEvidenceText(entry.Label), AddedBy: agentEvidenceText(entry.AddedBy), AddedAt: entry.AddedAt}
		if entry.Query != nil {
			line.Query, line.MatchedCount = agentEvidenceText(entry.Query.CanonicalQuery), entry.Query.MatchedCount
		}
		detail.Evidence = append(detail.Evidence, line)
	}
	timeline := item.Timeline
	if len(timeline) > maxAgentCaseTimeline {
		timeline, detail.TimelineTruncated = timeline[len(timeline)-maxAgentCaseTimeline:], true
	}
	for index := len(timeline) - 1; index >= 0; index-- {
		event := timeline[index]
		detail.Timeline = append(detail.Timeline, agentCaseTimelineEvent{Revision: event.Revision, Action: event.Action, Actor: agentEvidenceText(event.Actor), Reason: agentEvidenceText(event.Reason), OccurredAt: event.OccurredAt})
	}
	for _, result := range item.Hold.Results {
		if result.Protected {
			detail.HoldProtected++
		} else if result.Failure != "" {
			detail.HoldFailed++
		}
	}
	writeJSON(w, http.StatusOK, detail)
}

func projectAgentCaseSummary(item casework.Case) agentCaseSummary {
	summary := agentCaseSummary{
		ID: item.ID, Name: agentEvidenceText(item.Name), Description: agentEvidenceText(item.Description), Status: string(item.Status),
		Revision: item.Revision, CreatedBy: agentEvidenceText(item.CreatedBy), CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt,
		HoldState: string(item.Hold.State), HoldReason: agentEvidenceText(item.Hold.Reason),
	}
	if summary.HoldState == "" {
		summary.HoldState = string(casework.HoldInactive)
	}
	for _, entry := range item.Evidence {
		summary.EvidenceCounts.Total++
		switch entry.Kind {
		case casework.EvidenceCapture:
			summary.EvidenceCounts.Captures++
		case casework.EvidenceQuerySnapshot:
			summary.EvidenceCounts.QuerySnapshots++
		case casework.EvidenceCaptureExport:
			summary.EvidenceCounts.CaptureExports++
		}
	}
	if count := len(item.Timeline); count > 0 {
		last := item.Timeline[count-1]
		summary.LastAction, summary.LastActionAt = last.Action, last.OccurredAt
	}
	return summary
}

// agentEvidenceText bounds administrator-entered text (names, descriptions,
// reasons) and drops control characters.
func agentEvidenceText(value string) string {
	value = strings.ToValidUTF8(value, "")
	var builder strings.Builder
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			character = ' '
		}
		if builder.Len()+utf8.RuneLen(character) > maxAgentEvidenceText {
			break
		}
		builder.WriteRune(character)
	}
	return strings.TrimSpace(builder.String())
}
