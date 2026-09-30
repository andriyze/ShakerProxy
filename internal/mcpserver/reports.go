package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"shakerproxy.dev/shakerproxy/internal/agentapi"
	"shakerproxy.dev/shakerproxy/internal/devicereport"
	"shakerproxy.dev/shakerproxy/internal/testsession"
)

const (
	maxReportDomains   = 60
	maxReportProtocols = 30
	maxReportTLSHosts  = 20
)

type DeviceReportArgs struct {
	Device  string `json:"device" jsonschema:"friendly name, IP address, MAC address, or device ID"`
	Window  string `json:"window,omitempty" jsonschema:"one of 15m, 1h, 6h, 24h, 7d, 30d; default: the device's running test session, otherwise 24h"`
	Session string `json:"session,omitempty" jsonschema:"test session ID (ts-…) from test_sessions; overrides window"`
}

type CompareRunsArgs struct {
	Base    string `json:"base" jsonschema:"test session ID of the earlier run, e.g. firmware 1.2"`
	Compare string `json:"compare" jsonschema:"test session ID of the later run, e.g. firmware 1.3"`
	Device  string `json:"device,omitempty" jsonschema:"optional device reference; defaults to the base session's device"`
}

type TestSessionsArgs struct {
	Device string `json:"device,omitempty" jsonschema:"optional friendly name, IP address, MAC address, or device ID"`
	State  string `json:"state,omitempty" jsonschema:"optional RUNNING or STOPPED"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum sessions, 1-100, default 50"`
}

type reportDevice struct {
	DeviceID  string   `json:"device_id"`
	Name      string   `json:"name"`
	Vendor    string   `json:"vendor,omitempty"`
	Category  string   `json:"category,omitempty"`
	Addresses []string `json:"addresses"`
	Online    bool     `json:"online"`
}

type domainLine struct {
	Domain       string   `json:"domain"`
	Organization string   `json:"organization,omitempty"`
	Category     string   `json:"category"`
	Events       int64    `json:"events"`
	Sources      []string `json:"sources"`
}

type protocolLine struct {
	Protocol   string `json:"protocol"`
	Label      string `json:"label"`
	Visibility string `json:"visibility"`
	Exotic     bool   `json:"exotic,omitempty"`
	Flows      int64  `json:"flows"`
	Bytes      int64  `json:"bytes"`
}

type sessionLine struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	DeviceID         string     `json:"device_id"`
	DeviceName       string     `json:"device_name,omitempty"`
	State            string     `json:"state"`
	StartedAt        time.Time  `json:"started_at"`
	EndedAt          *time.Time `json:"ended_at,omitempty"`
	CaptureSessionID string     `json:"capture_session_id,omitempty"`
	Notes            string     `json:"notes,omitempty"`
	Summary          string     `json:"summary"`
}

type reportResult struct {
	Summary           string                 `json:"summary"`
	NextSteps         []string               `json:"next_steps,omitempty"`
	Device            reportDevice           `json:"device"`
	WindowStart       time.Time              `json:"window_start"`
	WindowEnd         time.Time              `json:"window_end"`
	Session           *sessionLine           `json:"session,omitempty"`
	CATrust           string                 `json:"ca_trust"`
	Findings          []devicereport.Finding `json:"findings"`
	Totals            devicereport.Totals    `json:"totals"`
	DomainsByCategory map[string]int         `json:"domains_by_category"`
	Domains           []domainLine           `json:"domains"`
	OmittedDomains    int                    `json:"omitted_domains,omitempty"`
	Protocols         []protocolLine         `json:"protocols"`
	TLS               devicereport.TLS       `json:"tls"`
	HTTP              devicereport.HTTP      `json:"http"`
	Truncated         bool                   `json:"truncated"`
}

func (s *Service) deviceReport(ctx context.Context, _ *mcp.CallToolRequest, args DeviceReportArgs) (*mcp.CallToolResult, any, error) {
	device, err := s.resolveDevice(ctx, args.Device)
	if err != nil {
		return nil, nil, err
	}
	window := strings.ToLower(strings.TrimSpace(args.Window))
	session := strings.TrimSpace(args.Session)
	if window != "" && session != "" {
		return nil, nil, errors.New("give either window or session, not both")
	}
	report, err := s.backend.DeviceReport(ctx, agentapi.DeviceReportRequest{DeviceID: device.DeviceID, Window: window, Session: session})
	if err != nil {
		return nil, nil, fmt.Errorf("build report for %s: %w", device.FriendlyName, err)
	}
	return textResult(compactReport(report))
}

func compactReport(report devicereport.Report) reportResult {
	result := reportResult{
		Summary: report.Summary,
		Device: reportDevice{
			DeviceID: report.Device.DeviceID, Name: report.Device.FriendlyName, Vendor: report.Device.Vendor,
			Category: report.Device.Category, Addresses: report.Device.Addresses, Online: report.Device.Online,
		},
		WindowStart: report.WindowStart, WindowEnd: report.WindowEnd, CATrust: string(report.CATrust),
		Findings: report.Findings, Totals: report.Totals, DomainsByCategory: map[string]int{},
		Domains: []domainLine{}, Protocols: []protocolLine{}, TLS: report.TLS, HTTP: report.HTTP, Truncated: report.Truncated,
	}
	if result.Findings == nil {
		result.Findings = []devicereport.Finding{}
	}
	if report.Session != nil {
		line := newSessionLine(*report.Session)
		result.Session = &line
	}
	for _, domain := range report.Domains {
		result.DomainsByCategory[domain.Category]++
		if len(result.Domains) < maxReportDomains {
			result.Domains = append(result.Domains, domainLine{Domain: domain.Domain, Organization: domain.Organization, Category: domain.Category, Events: domain.Events, Sources: domain.Sources})
		}
	}
	result.OmittedDomains = len(report.Domains) - len(result.Domains)
	for _, protocol := range report.Protocols {
		if len(result.Protocols) == maxReportProtocols {
			break
		}
		result.Protocols = append(result.Protocols, protocolLine{Protocol: protocol.Protocol, Label: protocol.Label, Visibility: protocol.Visibility, Exotic: protocol.Exotic, Flows: protocol.Flows, Bytes: protocol.Bytes})
	}
	if len(result.TLS.FailedHosts) > maxReportTLSHosts {
		result.TLS.FailedHosts = result.TLS.FailedHosts[:maxReportTLSHosts]
	}
	if len(result.TLS.InterceptedHosts) > maxReportTLSHosts {
		result.TLS.InterceptedHosts = result.TLS.InterceptedHosts[:maxReportTLSHosts]
	}
	if report.Totals.Events == 0 {
		result.NextSteps = append(result.NextSteps, "No traffic was recorded in this range: check that the device is on the lab network, or try a longer window.")
	}
	if report.CATrust == devicereport.CATrustUnknown && report.TLS.Intercepted > 0 {
		result.NextSteps = append(result.NextSteps, "Ask the user whether the ShakerProxy CA is installed on this device. If it is not, the decrypted HTTPS means the device accepts untrusted certificates; the user can record the answer in ShakerProxy (Devices → CA trust) and re-run the report.")
	}
	if report.HTTP.CleartextRequests > 0 {
		result.NextSteps = append(result.NextSteps, "Use http_requests with the device to see the unencrypted requests.")
	}
	if report.TLS.Failed > 0 {
		result.NextSteps = append(result.NextSteps, "Use tls_issues with the device to see why HTTPS decryption failed.")
	}
	return result
}

func (s *Service) compareRuns(ctx context.Context, _ *mcp.CallToolRequest, args CompareRunsArgs) (*mcp.CallToolResult, any, error) {
	base, compare := strings.TrimSpace(args.Base), strings.TrimSpace(args.Compare)
	if base == "" || compare == "" {
		return nil, nil, errors.New("base and compare test session IDs are required; call test_sessions to find them")
	}
	deviceID := ""
	if strings.TrimSpace(args.Device) != "" {
		device, err := s.resolveDevice(ctx, args.Device)
		if err != nil {
			return nil, nil, err
		}
		deviceID = device.DeviceID
	} else {
		session, err := s.backend.TestSession(ctx, base)
		if err != nil {
			return nil, nil, fmt.Errorf("read base test session %s: %w", base, err)
		}
		deviceID = session.DeviceID
	}
	comparison, err := s.backend.CompareRuns(ctx, agentapi.CompareRequest{DeviceID: deviceID, Base: base, Compare: compare})
	if err != nil {
		return nil, nil, fmt.Errorf("compare runs: %w", err)
	}
	return textResult(comparison)
}

type sessionList struct {
	Summary   string        `json:"summary"`
	Sessions  []sessionLine `json:"sessions"`
	Total     int           `json:"total"`
	Truncated bool          `json:"truncated"`
}

func (s *Service) testSessions(ctx context.Context, _ *mcp.CallToolRequest, args TestSessionsArgs) (*mcp.CallToolResult, any, error) {
	limit, err := normalizeLimit(args.Limit)
	if err != nil {
		return nil, nil, err
	}
	request := agentapi.TestSessionsRequest{Limit: limit, State: strings.ToUpper(strings.TrimSpace(args.State))}
	if request.State != "" && request.State != "RUNNING" && request.State != "STOPPED" {
		return nil, nil, errors.New("state must be RUNNING or STOPPED")
	}
	name := ""
	if strings.TrimSpace(args.Device) != "" {
		device, err := s.resolveDevice(ctx, args.Device)
		if err != nil {
			return nil, nil, err
		}
		request.DeviceID, name = device.DeviceID, device.FriendlyName
	}
	list, err := s.backend.TestSessions(ctx, request)
	if err != nil {
		return nil, nil, fmt.Errorf("list test sessions: %w", err)
	}
	result := sessionList{Sessions: make([]sessionLine, 0, len(list.Sessions)), Total: list.Total, Truncated: list.Truncated}
	for _, session := range list.Sessions {
		result.Sessions = append(result.Sessions, newSessionLine(session))
	}
	scope := ""
	if name != "" {
		scope = " for " + name
	}
	switch {
	case len(result.Sessions) == 0:
		result.Summary = "No test sessions" + scope + ". A tester starts one in ShakerProxy (Tests) or with `shakerproxy test start <device>`."
	case list.Truncated:
		result.Summary = fmt.Sprintf("Showing the newest %d of %d test sessions%s.", len(result.Sessions), list.Total, scope)
	default:
		result.Summary = fmt.Sprintf("%s%s, newest first.", countNoun(len(result.Sessions), "test session", "test sessions"), scope)
	}
	return textResult(result)
}

func newSessionLine(session testsession.Session) sessionLine {
	line := sessionLine{
		ID: session.ID, Name: session.Name, DeviceID: session.DeviceID, DeviceName: session.DeviceName,
		State: string(session.State), StartedAt: session.StartedAt, EndedAt: session.EndedAt, Notes: truncateText(session.Notes, 300),
	}
	if session.CaptureSessionID != nil {
		line.CaptureSessionID = *session.CaptureSessionID
	}
	span := "started " + session.StartedAt.UTC().Format("2006-01-02 15:04 UTC") + ", still running"
	if session.EndedAt != nil {
		span = fmt.Sprintf("%s to %s (%s)", session.StartedAt.UTC().Format("2006-01-02 15:04"), session.EndedAt.UTC().Format("15:04 UTC"), humanDuration(session.EndedAt.Sub(session.StartedAt)))
	}
	device := session.DeviceName
	if device == "" {
		device = session.DeviceID
	}
	line.Summary = fmt.Sprintf("%q on %s, %s", session.Name, device, span)
	return line
}

func truncateText(value string, maximum int) string {
	if len(value) <= maximum {
		return value
	}
	cut := value[:maximum]
	for len(cut) > 0 && cut[len(cut)-1]&0xC0 == 0x80 {
		cut = cut[:len(cut)-1]
	}
	if len(cut) > 0 && cut[len(cut)-1] >= 0xC0 {
		cut = cut[:len(cut)-1]
	}
	return cut + "…"
}

// humanDuration renders a span as "under a minute", "35 min", or "2 h 5 min".
func humanDuration(value time.Duration) string {
	minutes := int(value.Round(time.Minute) / time.Minute)
	switch {
	case minutes < 1:
		return "under a minute"
	case minutes < 60:
		return fmt.Sprintf("%d min", minutes)
	case minutes%60 == 0:
		return fmt.Sprintf("%d h", minutes/60)
	default:
		return fmt.Sprintf("%d h %d min", minutes/60, minutes%60)
	}
}
