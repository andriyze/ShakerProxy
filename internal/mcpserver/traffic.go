package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"shakerproxy.dev/shakerproxy/internal/agentapi"
	"shakerproxy.dev/shakerproxy/internal/ingest"
)

var (
	recordIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	// dnsNamePattern mirrors the query language's hostname pattern so a name
	// can never inject query syntax.
	dnsNamePattern = regexp.MustCompile(`^[A-Za-z0-9.*-]{1,253}$`)
	searchWindows  = map[string]string{
		"5m": "last_5m", "15m": "last_15m", "1h": "last_1h", "6h": "last_6h",
		"24h": "last_24h", "7d": "last_7d", "30d": "last_30d",
	}
	windowNames = map[string]string{
		"5m": "5 minutes", "15m": "15 minutes", "1h": "hour", "6h": "6 hours",
		"24h": "24 hours", "7d": "7 days", "30d": "30 days",
	}
)

// Base filters for the convenience tools. DNS includes ShakerProxy's DNS
// forwarder lookups, Zeek and Suricata DNS logs, detected encrypted DNS, and
// DNS over HTTPS (interception audit #9).
const (
	dnsBaseQuery = "kind:shakerproxy.dns OR kind:zeek.dns OR kind:suricata.dns OR kind:encrypted_dns_detected OR service:doh OR kind:shakerproxy.blocked"
	tlsBaseQuery = "source:MITMPROXY AND (tls.state:FAILED OR tls.state:BYPASSED)"
)

// pinningReasons are the exact interception failure reasons that indicate
// probable pinning. The generic "ca_not_trusted_or_pinning" reason usually
// means the CA is simply not installed and is deliberately excluded (#11).
var pinningReasons = map[string]bool{}

func init() {
	for _, reason := range ingest.PinningFailureReasons {
		pinningReasons[reason] = true
	}
}

type DeviceActivityArgs struct {
	Device string `json:"device" jsonschema:"friendly name, IP address, MAC address, or device ID"`
	Window string `json:"window,omitempty" jsonschema:"one of 5m, 15m, 1h, 6h, 24h, 7d, 30d; default 24h"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum events, 1-100, default 50"`
	Cursor string `json:"cursor,omitempty" jsonschema:"next_cursor from a previous call"`
}

type SearchTrafficArgs struct {
	Query    string `json:"query,omitempty" jsonschema:"ShakerProxy query, e.g. time:last_1h AND device.name:\"Living room TV\" AND tls.state:FAILED"`
	Limit    int    `json:"limit,omitempty" jsonschema:"maximum events, 1-100, default 50"`
	Cursor   string `json:"cursor,omitempty" jsonschema:"next_cursor from a previous call"`
	RecordID string `json:"record_id,omitempty" jsonschema:"one event's 64-character record_id to read its metadata-only detail instead of searching"`
}

type DNSLookupsArgs struct {
	Device string `json:"device,omitempty" jsonschema:"optional friendly name, IP address, MAC address, or device ID"`
	Name   string `json:"name,omitempty" jsonschema:"optional domain; matches the name and its subdomains, e.g. samsungacr.com; a word without a dot matches any name containing it"`
	Window string `json:"window,omitempty" jsonschema:"one of 5m, 15m, 1h, 6h, 24h, 7d, 30d; default 24h"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum events, 1-100, default 50"`
	Cursor string `json:"cursor,omitempty" jsonschema:"next_cursor from a previous call"`
}

type TLSIssuesArgs struct {
	Device      string `json:"device,omitempty" jsonschema:"optional friendly name, IP address, MAC address, or device ID"`
	Window      string `json:"window,omitempty" jsonschema:"one of 5m, 15m, 1h, 6h, 24h, 7d, 30d; default 24h"`
	PinningOnly bool   `json:"pinning_only,omitempty" jsonschema:"only connections where certificate pinning is likely"`
	Limit       int    `json:"limit,omitempty" jsonschema:"maximum events to scan, 1-100, default 50"`
	Cursor      string `json:"cursor,omitempty" jsonschema:"next_cursor from a previous call"`
}

type HTTPRequestsArgs struct {
	Device string `json:"device,omitempty" jsonschema:"optional friendly name, IP address, MAC address, or device ID"`
	Host   string `json:"host,omitempty" jsonschema:"optional exact host, e.g. api.example.com (no scheme, port, or path)"`
	Method string `json:"method,omitempty" jsonschema:"optional HTTP method such as GET or POST"`
	Window string `json:"window,omitempty" jsonschema:"one of 5m, 15m, 1h, 6h, 24h; default 24h"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum requests, 1-100, default 50"`
	Cursor string `json:"cursor,omitempty" jsonschema:"next_cursor from a previous call"`
}

type ProtocolsArgs struct {
	Device     string `json:"device,omitempty" jsonschema:"optional friendly name, IP address, MAC address, or device ID"`
	Window     string `json:"window,omitempty" jsonschema:"one of 1h, 24h, 7d, 30d; default 24h"`
	Category   string `json:"category,omitempty" jsonschema:"optional protocol category such as iot-messaging, vpn-tunnel, remote-access, encrypted-dns"`
	ExoticOnly bool   `json:"exotic_only,omitempty" jsonschema:"only protocols that are unusual on a typical network"`
}

type eventLine struct {
	RecordID string    `json:"record_id"`
	Time     time.Time `json:"time"`
	Device   string    `json:"device,omitempty"`
	DeviceID string    `json:"device_id,omitempty"`
	Kind     string    `json:"kind"`
	Summary  string    `json:"summary"`
}

type eventList struct {
	Summary        string      `json:"summary"`
	Query          string      `json:"query"`
	CanonicalQuery string      `json:"canonical_query,omitempty"`
	Events         []eventLine `json:"events"`
	NextCursor     string      `json:"next_cursor,omitempty"`
}

func (s *Service) deviceActivity(ctx context.Context, _ *mcp.CallToolRequest, args DeviceActivityArgs) (*mcp.CallToolResult, any, error) {
	device, err := s.resolveDevice(ctx, args.Device)
	if err != nil {
		return nil, nil, err
	}
	limit, err := normalizeLimit(args.Limit)
	if err != nil {
		return nil, nil, err
	}
	window, relative, err := searchWindow(args.Window)
	if err != nil {
		return nil, nil, err
	}
	query := "time:" + relative + " AND device.id:" + device.DeviceID
	page, err := s.backend.TrafficSearch(ctx, agentapi.TrafficSearchRequest{Query: query, Limit: limit, Cursor: strings.TrimSpace(args.Cursor)})
	if err != nil {
		return nil, nil, fmt.Errorf("read activity for %s: %w", device.FriendlyName, err)
	}
	if err := checkPageBound(len(page.Events), limit); err != nil {
		return nil, nil, err
	}
	result := eventList{Query: query, CanonicalQuery: page.CanonicalQuery, Events: eventLines(page.Events), NextCursor: page.NextCursor}
	result.Summary = pageSummary(len(result.Events), "event", "events", fmt.Sprintf("for %s in the last %s", device.FriendlyName, windowNames[window]), page.NextCursor != "")
	return textResult(result)
}

func (s *Service) searchTraffic(ctx context.Context, _ *mcp.CallToolRequest, args SearchTrafficArgs) (*mcp.CallToolResult, any, error) {
	if recordID := strings.TrimSpace(args.RecordID); recordID != "" {
		if !recordIDPattern.MatchString(recordID) {
			return nil, nil, errors.New("record_id must be the 64-character lowercase hexadecimal record_id from a search result")
		}
		detail, err := s.backend.EventMetadata(ctx, recordID)
		if err != nil {
			return nil, nil, fmt.Errorf("read event %s: %w", recordID, err)
		}
		return textResult(struct {
			Summary string             `json:"summary"`
			Detail  ingest.EventDetail `json:"detail"`
		}{Summary: "Metadata for one event: " + recentEventSummary(agentapi.Event{RecentEvent: detail.Event}), Detail: detail})
	}
	limit, err := normalizeLimit(args.Limit)
	if err != nil {
		return nil, nil, err
	}
	query := strings.TrimSpace(args.Query)
	if len(query) > 2048 {
		return nil, nil, errors.New("query is limited to 2048 characters")
	}
	page, err := s.backend.TrafficSearch(ctx, agentapi.TrafficSearchRequest{Query: query, Limit: limit, Cursor: strings.TrimSpace(args.Cursor)})
	if err != nil {
		return nil, nil, fmt.Errorf("search traffic: %w (see the query syntax in this tool's description)", err)
	}
	if err := checkPageBound(len(page.Events), limit); err != nil {
		return nil, nil, err
	}
	result := eventList{Query: query, CanonicalQuery: page.CanonicalQuery, Events: eventLines(page.Events), NextCursor: page.NextCursor}
	result.Summary = pageSummary(len(result.Events), "event", "events", "matched", page.NextCursor != "")
	return textResult(result)
}

type dnsLine struct {
	eventLine
	Query        string `json:"query,omitempty"`
	RecordType   string `json:"record_type,omitempty"`
	ResponseCode string `json:"response_code,omitempty"`
	Answers      *int   `json:"answers,omitempty"`
	Encrypted    bool   `json:"encrypted,omitempty"`
}

func (s *Service) dnsLookups(ctx context.Context, _ *mcp.CallToolRequest, args DNSLookupsArgs) (*mcp.CallToolResult, any, error) {
	limit, err := normalizeLimit(args.Limit)
	if err != nil {
		return nil, nil, err
	}
	window, relative, err := searchWindow(args.Window)
	if err != nil {
		return nil, nil, err
	}
	parts := []string{"time:" + relative}
	scope := "in the last " + windowNames[window]
	if strings.TrimSpace(args.Device) != "" {
		device, err := s.resolveDevice(ctx, args.Device)
		if err != nil {
			return nil, nil, err
		}
		parts = append(parts, "device.id:"+device.DeviceID)
		scope = "for " + device.FriendlyName + " " + scope
	}
	parts = append(parts, "("+dnsBaseQuery+")")
	if name := strings.TrimSpace(args.Name); name != "" {
		filter, err := dnsNameFilter(name)
		if err != nil {
			return nil, nil, err
		}
		parts = append(parts, filter)
		scope = fmt.Sprintf("for %q %s", name, scope)
	}
	query := strings.Join(parts, " AND ")
	page, err := s.backend.TrafficSearch(ctx, agentapi.TrafficSearchRequest{Query: query, Limit: limit, Cursor: strings.TrimSpace(args.Cursor)})
	if err != nil {
		return nil, nil, fmt.Errorf("read DNS lookups: %w", err)
	}
	if err := checkPageBound(len(page.Events), limit); err != nil {
		return nil, nil, err
	}
	lines := make([]dnsLine, 0, len(page.Events))
	encrypted := 0
	for _, event := range page.Events {
		line := dnsLine{eventLine: newEventLine(event), Query: event.DNSQuery, RecordType: event.DNSRecordType, ResponseCode: event.DNSResponseCode, Answers: event.DNSAnswerCount}
		if event.Kind == "encrypted_dns_detected" || event.Service == "doh" {
			line.Encrypted = true
			encrypted++
		}
		lines = append(lines, line)
	}
	summary := pageSummary(len(lines), "DNS lookup", "DNS lookups", scope, page.NextCursor != "")
	if encrypted > 0 {
		summary += fmt.Sprintf(" %d used encrypted DNS, which bypasses the lab resolver.", encrypted)
	}
	return textResult(struct {
		Summary    string    `json:"summary"`
		Query      string    `json:"query"`
		Lookups    []dnsLine `json:"lookups"`
		NextCursor string    `json:"next_cursor,omitempty"`
	}{Summary: summary, Query: query, Lookups: lines, NextCursor: page.NextCursor})
}

// dnsNameFilter matches a domain and its subdomains, or a partial word.
func dnsNameFilter(name string) (string, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if !dnsNamePattern.MatchString(name) || strings.Count(name, "*") > 1 {
		return "", errors.New("name may contain only letters, digits, dots, hyphens, and one *")
	}
	switch {
	case strings.Contains(name, "*"):
		return "dns.query:" + name, nil
	case strings.Contains(name, "."):
		return "(dns.query:" + name + " OR dns.query:*." + name + ")", nil
	default:
		return "dns.query:*" + name + "*", nil
	}
}

type tlsLine struct {
	eventLine
	Host             string `json:"host,omitempty"`
	State            string `json:"state"`
	Reason           string `json:"reason,omitempty"`
	PinningLikely    bool   `json:"pinning_likely"`
	AutoBypassed     bool   `json:"auto_bypassed,omitempty"`
	RecentlyDecrypts *bool  `json:"client_recently_decrypted,omitempty"`
}

func (s *Service) tlsIssues(ctx context.Context, _ *mcp.CallToolRequest, args TLSIssuesArgs) (*mcp.CallToolResult, any, error) {
	limit, err := normalizeLimit(args.Limit)
	if err != nil {
		return nil, nil, err
	}
	window, relative, err := searchWindow(args.Window)
	if err != nil {
		return nil, nil, err
	}
	parts := []string{"time:" + relative}
	scope := "in the last " + windowNames[window]
	if strings.TrimSpace(args.Device) != "" {
		device, err := s.resolveDevice(ctx, args.Device)
		if err != nil {
			return nil, nil, err
		}
		parts = append(parts, "device.id:"+device.DeviceID)
		scope = "for " + device.FriendlyName + " " + scope
	}
	parts = append(parts, "("+tlsBaseQuery+")")
	query := strings.Join(parts, " AND ")
	page, err := s.backend.TrafficSearch(ctx, agentapi.TrafficSearchRequest{Query: query, Limit: limit, Cursor: strings.TrimSpace(args.Cursor)})
	if err != nil {
		return nil, nil, fmt.Errorf("read TLS issues: %w", err)
	}
	if err := checkPageBound(len(page.Events), limit); err != nil {
		return nil, nil, err
	}
	lines := make([]tlsLine, 0, len(page.Events))
	pinning := 0
	for _, event := range page.Events {
		likely := pinningLikely(event.RecentEvent)
		if likely {
			pinning++
		}
		if args.PinningOnly && !likely {
			continue
		}
		lines = append(lines, tlsLine{
			eventLine: newEventLine(event), Host: event.TLSServerName, State: event.TLSInterceptionState,
			Reason: event.TLSFailureReason, PinningLikely: likely, AutoBypassed: event.TLSBypassActivated, RecentlyDecrypts: event.TLSClientRecentSuccess,
		})
	}
	noun, plural := "TLS issue", "TLS issues"
	if args.PinningOnly {
		noun, plural = "likely pinning case", "likely pinning cases"
	}
	summary := pageSummary(len(lines), noun, plural, scope, page.NextCursor != "")
	if args.PinningOnly && len(page.Events) > len(lines) {
		summary += fmt.Sprintf(" Scanned %d events; use next_cursor to keep scanning.", len(page.Events))
	} else if !args.PinningOnly && pinning > 0 {
		summary += fmt.Sprintf(" %d look like certificate pinning.", pinning)
	}
	return textResult(struct {
		Summary    string    `json:"summary"`
		Query      string    `json:"query"`
		Scanned    int       `json:"scanned"`
		Issues     []tlsLine `json:"issues"`
		NextCursor string    `json:"next_cursor,omitempty"`
	}{Summary: summary, Query: query, Scanned: len(page.Events), Issues: lines, NextCursor: page.NextCursor})
}

// pinningLikely uses only exact pinning evidence, never the generic
// "ca_not_trusted_or_pinning" reason.
func pinningLikely(event ingest.RecentEvent) bool {
	return event.TLSPinningSuspected || pinningReasons[event.TLSFailureReason]
}

type httpLine struct {
	RecordID  string    `json:"record_id"`
	Time      time.Time `json:"time"`
	DeviceID  string    `json:"device_id,omitempty"`
	Method    string    `json:"method,omitempty"`
	Scheme    string    `json:"scheme,omitempty"`
	Host      string    `json:"host,omitempty"`
	Path      string    `json:"path,omitempty"`
	Status    int       `json:"status,omitempty"`
	Decrypted *bool     `json:"decrypted,omitempty"`
	Summary   string    `json:"summary"`
}

func (s *Service) httpRequests(ctx context.Context, _ *mcp.CallToolRequest, args HTTPRequestsArgs) (*mcp.CallToolResult, any, error) {
	limit, err := normalizeLimit(args.Limit)
	if err != nil {
		return nil, nil, err
	}
	window := strings.ToLower(strings.TrimSpace(args.Window))
	if window == "" {
		window = defaultWindow
	}
	if window == "7d" || window == "30d" {
		return nil, nil, errors.New("http_requests covers at most 24h; use search_traffic with http.host for longer ranges")
	}
	request := agentapi.HTTPActivityRequest{Window: window, Host: strings.TrimSpace(args.Host), Method: strings.TrimSpace(args.Method), Limit: limit, Cursor: strings.TrimSpace(args.Cursor)}
	scope := "in the last " + windowNames[window]
	if strings.TrimSpace(args.Device) != "" {
		device, err := s.resolveDevice(ctx, args.Device)
		if err != nil {
			return nil, nil, err
		}
		request.DeviceID = device.DeviceID
		scope = "for " + device.FriendlyName + " " + scope
	}
	page, err := s.backend.HTTPActivity(ctx, request)
	if err != nil {
		return nil, nil, fmt.Errorf("read HTTP requests: %w", err)
	}
	if err := checkPageBound(len(page.Events), limit); err != nil {
		return nil, nil, err
	}
	lines := make([]httpLine, 0, len(page.Events))
	for _, event := range page.Events {
		lines = append(lines, httpLine{
			RecordID: event.RecordID, Time: event.OccurredAt, DeviceID: event.DeviceID, Method: event.Method, Scheme: event.Scheme,
			Host: event.Host, Path: event.Path, Status: event.Status, Decrypted: event.Decrypted, Summary: httpSummary(event),
		})
	}
	return textResult(struct {
		Summary    string     `json:"summary"`
		Requests   []httpLine `json:"requests"`
		NextCursor string     `json:"next_cursor,omitempty"`
	}{Summary: pageSummary(len(lines), "HTTP request", "HTTP requests", scope, page.NextCursor != ""), Requests: lines, NextCursor: page.NextCursor})
}

type protocolEntry struct {
	Protocol    string `json:"protocol"`
	Label       string `json:"label"`
	Category    string `json:"category"`
	Visibility  string `json:"visibility"`
	Exotic      bool   `json:"exotic,omitempty"`
	Novel       bool   `json:"novel,omitempty"`
	Flows       int64  `json:"flows"`
	Bytes       int64  `json:"bytes"`
	DeviceCount int    `json:"device_count"`
	Description string `json:"description,omitempty"`
}

func (s *Service) protocols(ctx context.Context, _ *mcp.CallToolRequest, args ProtocolsArgs) (*mcp.CallToolResult, any, error) {
	window := strings.ToLower(strings.TrimSpace(args.Window))
	if window == "" {
		window = defaultWindow
	}
	request := agentapi.ProtocolsRequest{Window: window, Category: strings.ToLower(strings.TrimSpace(args.Category)), Exotic: args.ExoticOnly}
	scope := "on the lab network"
	if strings.TrimSpace(args.Device) != "" {
		device, err := s.resolveDevice(ctx, args.Device)
		if err != nil {
			return nil, nil, err
		}
		request.DeviceID = device.DeviceID
		scope = "for " + device.FriendlyName
	}
	page, err := s.backend.Protocols(ctx, request)
	if err != nil {
		var apiErr *agentapi.APIError
		if errors.As(err, &apiErr) && (apiErr.Status == 404 || apiErr.Status == 405) {
			return nil, nil, errors.New("this ShakerProxy version has no protocol discovery yet; use device_report, which lists protocols per device")
		}
		return nil, nil, fmt.Errorf("read protocols: %w", err)
	}
	entries := make([]protocolEntry, 0, len(page.Protocols))
	exotic, novel := []string{}, []string{}
	for _, protocol := range page.Protocols {
		entries = append(entries, protocolEntry{
			Protocol: protocol.Protocol, Label: protocol.Label, Category: protocol.Category, Visibility: protocol.Visibility,
			Exotic: protocol.Exotic, Novel: protocol.Novel, Flows: protocol.Flows, Bytes: protocol.Bytes, DeviceCount: protocol.DeviceCount,
			Description: truncateText(protocol.Description, 200),
		})
		if protocol.Exotic && len(exotic) < 8 {
			exotic = append(exotic, protocol.Label)
		}
		if protocol.Novel && len(novel) < 8 {
			novel = append(novel, protocol.Label)
		}
	}
	summary := fmt.Sprintf("%s %s in the last %s.", countNoun(len(entries), "protocol", "protocols"), scope, windowNames[window])
	if len(exotic) > 0 {
		summary += " Unusual: " + strings.Join(exotic, ", ") + "."
	}
	if len(novel) > 0 {
		summary += " First seen in this window: " + strings.Join(novel, ", ") + "."
	}
	if page.Coverage.TotalBytes > 0 {
		summary += fmt.Sprintf(" %.0f%% of bytes are opaque to ShakerProxy.", page.Coverage.OpaquePercent)
	}
	return textResult(struct {
		Summary   string                    `json:"summary"`
		Protocols []protocolEntry           `json:"protocols"`
		Coverage  agentapi.ProtocolCoverage `json:"coverage"`
		Truncated bool                      `json:"truncated"`
	}{Summary: summary, Protocols: entries, Coverage: page.Coverage, Truncated: page.Truncated})
}

func searchWindow(value string) (string, string, error) {
	window := strings.ToLower(strings.TrimSpace(value))
	if window == "" {
		window = defaultWindow
	}
	relative, ok := searchWindows[window]
	if !ok {
		return "", "", errors.New("window must be one of 5m, 15m, 1h, 6h, 24h, 7d, or 30d")
	}
	return window, relative, nil
}

func eventLines(events []agentapi.Event) []eventLine {
	lines := make([]eventLine, 0, len(events))
	for _, event := range events {
		lines = append(lines, newEventLine(event))
	}
	return lines
}

func newEventLine(event agentapi.Event) eventLine {
	return eventLine{
		RecordID: event.RecordID, Time: event.OccurredAt, Device: event.DeviceFriendlyName, DeviceID: event.DeviceID,
		Kind: event.Kind, Summary: recentEventSummary(event),
	}
}

func pageSummary(count int, singular, plural, scope string, more bool) string {
	summary := fmt.Sprintf("%s %s.", countNoun(count, singular, plural), scope)
	if count == 0 {
		summary = fmt.Sprintf("No %s %s.", plural, scope)
	}
	if more {
		summary += " More are available: call again with next_cursor."
	}
	return summary
}

// checkPageBound rejects a backend page larger than requested so a faulty
// backend cannot inflate agent output.
func checkPageBound(returned, limit int) error {
	if returned > limit {
		return errors.New("ShakerProxy returned more events than requested; refusing the page")
	}
	return nil
}
