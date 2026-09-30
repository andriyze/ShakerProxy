package agentapi

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"shakerproxy.dev/shakerproxy/internal/devicereport"
	"shakerproxy.dev/shakerproxy/internal/testsession"
)

const (
	maxDeviceResolutionBytes = 128 << 10
	maxDeviceReportBytes     = 1 << 20
	maxComparisonBytes       = 512 << 10
	maxTestSessionListBytes  = 512 << 10
	maxProtocolsBytes        = 1 << 20
	maxDeviceMatches         = 20
	maxProtocolEntries       = 256
	maxProtocolDevices       = 50
	maxProtocolPorts         = 20
)

var testSessionIDPattern = regexp.MustCompile(`^ts-[a-f0-9]{24}$`)

var reportWindows = map[string]bool{"15m": true, "1h": true, "6h": true, "24h": true, "7d": true, "30d": true}

// DeviceMatch is one device that matched a reference.
type DeviceMatch struct {
	DeviceID          string   `json:"device_id"`
	FriendlyName      string   `json:"friendly_name"`
	Vendor            string   `json:"vendor"`
	Addresses         []string `json:"addresses"`
	HardwareAddresses []string `json:"hardware_addresses"`
	Online            bool     `json:"online"`
	Match             string   `json:"match"`
}

type DeviceResolution struct {
	Schema  int           `json:"schema"`
	Query   string        `json:"query"`
	Unique  bool          `json:"unique"`
	Matches []DeviceMatch `json:"matches"`
}

// ResolveDevice resolves a friendly name, IP address, MAC address, or device
// ID through GET /api/v1/devices/resolve.
func (c *Client) ResolveDevice(ctx context.Context, reference string) (DeviceResolution, error) {
	if c == nil || c.base == nil || c.client == nil {
		return DeviceResolution{}, errors.New("agent API client is unavailable")
	}
	reference = strings.TrimSpace(reference)
	if !boundedAgentText(reference, 1, 128) {
		return DeviceResolution{}, errors.New("device reference must be 1-128 characters without control characters")
	}
	var resolution DeviceResolution
	if _, err := c.getJSON(ctx, "/api/v1/devices/resolve", url.Values{"q": {reference}}, maxDeviceResolutionBytes, &resolution); err != nil {
		return DeviceResolution{}, err
	}
	if resolution.Schema != 1 || len(resolution.Matches) > maxDeviceMatches || resolution.Unique != (len(resolution.Matches) == 1) {
		return DeviceResolution{}, errors.New("device resolution response is invalid")
	}
	for _, match := range resolution.Matches {
		if err := validateDeviceMatch(match); err != nil {
			return DeviceResolution{}, err
		}
	}
	return resolution, nil
}

func validateDeviceMatch(match DeviceMatch) error {
	if !agentDeviceIDPattern.MatchString(match.DeviceID) || !boundedAgentText(match.FriendlyName, 0, 256) || !boundedAgentText(match.Vendor, 0, 256) || len(match.Addresses) > 256 || len(match.HardwareAddresses) > 32 {
		return errors.New("device match is invalid")
	}
	switch match.Match {
	case "id", "mac", "ip", "name", "name_prefix", "name_contains":
	default:
		return errors.New("device match kind is invalid")
	}
	for _, value := range append(append([]string{}, match.Addresses...), match.HardwareAddresses...) {
		if !boundedAgentText(value, 1, 64) {
			return errors.New("device match address is invalid")
		}
	}
	return nil
}

type DeviceReportRequest struct {
	DeviceID string
	Window   string
	Session  string
}

// DeviceReport reads GET /api/v1/devices/{device}/report.
func (c *Client) DeviceReport(ctx context.Context, request DeviceReportRequest) (devicereport.Report, error) {
	if c == nil || c.base == nil || c.client == nil {
		return devicereport.Report{}, errors.New("agent API client is unavailable")
	}
	if !agentDeviceIDPattern.MatchString(request.DeviceID) {
		return devicereport.Report{}, errors.New("device report needs a resolved device ID")
	}
	values := url.Values{}
	if request.Window != "" {
		if !reportWindows[request.Window] {
			return devicereport.Report{}, errors.New("window must be one of 15m, 1h, 6h, 24h, 7d, or 30d")
		}
		values.Set("window", request.Window)
	}
	if request.Session != "" {
		if !testSessionIDPattern.MatchString(request.Session) {
			return devicereport.Report{}, errors.New("session must be a test session ID such as ts-0123456789abcdef01234567")
		}
		values.Set("session", request.Session)
	}
	var report devicereport.Report
	if _, err := c.getJSON(ctx, "/api/v1/devices/"+request.DeviceID+"/report", values, maxDeviceReportBytes, &report); err != nil {
		return devicereport.Report{}, err
	}
	if err := validateReport(report, request.DeviceID); err != nil {
		return devicereport.Report{}, err
	}
	return report, nil
}

func validateReport(report devicereport.Report, deviceID string) error {
	if report.Schema != devicereport.Schema || report.Device.DeviceID != deviceID || !validAgentTime(report.GeneratedAt) || !report.WindowEnd.After(report.WindowStart) || !devicereport.ValidCATrust(string(report.CATrust)) || len(report.Domains) > devicereport.MaxDomains || len(report.Protocols) > devicereport.MaxProtocols || len(report.Findings) > 32 {
		return errors.New("device report response is invalid")
	}
	if report.Session != nil {
		if err := report.Session.Validate(); err != nil || report.Session.DeviceID != deviceID {
			return errors.New("device report session is invalid")
		}
	}
	for _, finding := range report.Findings {
		if devicereport.SeverityRank(finding.Severity) == 0 || !boundedAgentText(finding.ID, 1, 64) || len(finding.Evidence) > 32 {
			return errors.New("device report finding is invalid")
		}
	}
	return nil
}

type CompareRequest struct {
	DeviceID string
	Base     string
	Compare  string
}

// CompareRuns reads GET /api/v1/devices/{device}/compare for two test sessions.
func (c *Client) CompareRuns(ctx context.Context, request CompareRequest) (devicereport.Comparison, error) {
	if c == nil || c.base == nil || c.client == nil {
		return devicereport.Comparison{}, errors.New("agent API client is unavailable")
	}
	if !agentDeviceIDPattern.MatchString(request.DeviceID) || !testSessionIDPattern.MatchString(request.Base) || !testSessionIDPattern.MatchString(request.Compare) {
		return devicereport.Comparison{}, errors.New("compare needs a resolved device ID and two test session IDs")
	}
	values := url.Values{"base": {request.Base}, "compare": {request.Compare}}
	var comparison devicereport.Comparison
	if _, err := c.getJSON(ctx, "/api/v1/devices/"+request.DeviceID+"/compare", values, maxComparisonBytes, &comparison); err != nil {
		return devicereport.Comparison{}, err
	}
	if comparison.Schema != devicereport.Schema || comparison.DeviceID != request.DeviceID || comparison.Base.SessionID != request.Base || comparison.Compare.SessionID != request.Compare {
		return devicereport.Comparison{}, errors.New("comparison response is invalid")
	}
	return comparison, nil
}

type TestSessionsRequest struct {
	DeviceID string
	State    string
	Limit    int
}

type TestSessionList struct {
	Schema    int                   `json:"schema"`
	Sessions  []testsession.Session `json:"sessions"`
	Total     int                   `json:"total"`
	Truncated bool                  `json:"truncated"`
}

// TestSessions lists test sessions, newest first.
func (c *Client) TestSessions(ctx context.Context, request TestSessionsRequest) (TestSessionList, error) {
	if c == nil || c.base == nil || c.client == nil {
		return TestSessionList{}, errors.New("agent API client is unavailable")
	}
	if request.Limit == 0 {
		request.Limit = 50
	}
	if request.Limit < 1 || request.Limit > 100 || request.DeviceID != "" && !agentDeviceIDPattern.MatchString(request.DeviceID) || request.State != "" && request.State != "RUNNING" && request.State != "STOPPED" {
		return TestSessionList{}, errors.New("test session filter is invalid")
	}
	values := url.Values{"limit": {strconv.Itoa(request.Limit)}}
	if request.DeviceID != "" {
		values.Set("device", request.DeviceID)
	}
	if request.State != "" {
		values.Set("state", request.State)
	}
	var list TestSessionList
	if _, err := c.getJSON(ctx, "/api/v1/test-sessions", values, maxTestSessionListBytes, &list); err != nil {
		return TestSessionList{}, err
	}
	if list.Schema != 1 || len(list.Sessions) > request.Limit || list.Total < len(list.Sessions) || list.Truncated != (list.Total > len(list.Sessions)) {
		return TestSessionList{}, errors.New("test session list response is invalid")
	}
	for _, session := range list.Sessions {
		if err := session.Validate(); err != nil {
			return TestSessionList{}, errors.New("test session list contains an invalid session")
		}
	}
	return list, nil
}

// TestSession reads one test session.
func (c *Client) TestSession(ctx context.Context, id string) (testsession.Session, error) {
	if c == nil || c.base == nil || c.client == nil {
		return testsession.Session{}, errors.New("agent API client is unavailable")
	}
	if !testSessionIDPattern.MatchString(id) {
		return testsession.Session{}, errors.New("test session ID must look like ts-0123456789abcdef01234567")
	}
	var session testsession.Session
	if _, err := c.getJSON(ctx, "/api/v1/test-sessions/"+id, nil, maxTestSessionListBytes, &session); err != nil {
		return testsession.Session{}, err
	}
	if session.ID != id || session.Validate() != nil {
		return testsession.Session{}, errors.New("test session response is invalid")
	}
	return session, nil
}

// ProtocolsRequest filters GET /api/v1/protocols.
type ProtocolsRequest struct {
	Window   string
	DeviceID string
	Category string
	Exotic   bool
}

type ProtocolsPage struct {
	Schema      int               `json:"schema"`
	GeneratedAt time.Time         `json:"generated_at"`
	Window      string            `json:"window"`
	WindowStart time.Time         `json:"window_start"`
	WindowEnd   time.Time         `json:"window_end"`
	DeviceID    string            `json:"device_id,omitempty"`
	Protocols   []ProtocolSummary `json:"protocols"`
	Coverage    ProtocolCoverage  `json:"coverage"`
	Truncated   bool              `json:"truncated"`
}

type ProtocolSummary struct {
	Protocol          string           `json:"protocol"`
	Label             string           `json:"label"`
	Category          string           `json:"category"`
	Visibility        string           `json:"visibility"`
	Evidence          string           `json:"evidence"`
	Exotic            bool             `json:"exotic"`
	Novel             bool             `json:"novel"`
	Description       string           `json:"description"`
	Flows             int64            `json:"flows"`
	Bytes             int64            `json:"bytes"`
	DeviceCount       int              `json:"device_count"`
	Devices           []ProtocolDevice `json:"devices"`
	UnattributedFlows int64            `json:"unattributed_flows"`
	FirstSeen         time.Time        `json:"first_seen"`
	LastSeen          time.Time        `json:"last_seen"`
	Ports             []ProtocolPort   `json:"ports"`
}

type ProtocolDevice struct {
	DeviceID   string    `json:"device_id"`
	DeviceName string    `json:"device_name"`
	Flows      int64     `json:"flows"`
	Bytes      int64     `json:"bytes"`
	LastSeen   time.Time `json:"last_seen"`
}

type ProtocolPort struct {
	Transport string `json:"transport"`
	Port      int    `json:"port"`
	Flows     int64  `json:"flows"`
}

type ProtocolCoverage struct {
	TotalBytes             int64   `json:"total_bytes"`
	DecryptedBytes         int64   `json:"decrypted_bytes"`
	CleartextBytes         int64   `json:"cleartext_bytes"`
	EncryptedMetadataBytes int64   `json:"encrypted_metadata_bytes"`
	OpaqueBytes            int64   `json:"opaque_bytes"`
	OpaquePercent          float64 `json:"opaque_percent"`
}

var protocolWindows = map[string]bool{"1h": true, "24h": true, "7d": true, "30d": true}

// Protocols reads protocol discovery (GET /api/v1/protocols). The endpoint
// belongs to protocol discovery, so unknown additive fields are tolerated.
func (c *Client) Protocols(ctx context.Context, request ProtocolsRequest) (ProtocolsPage, error) {
	if c == nil || c.base == nil || c.client == nil {
		return ProtocolsPage{}, errors.New("agent API client is unavailable")
	}
	values := url.Values{}
	if request.Window != "" {
		if !protocolWindows[request.Window] {
			return ProtocolsPage{}, errors.New("protocol window must be 1h, 24h, 7d, or 30d")
		}
		values.Set("window", request.Window)
	}
	if request.DeviceID != "" {
		if !agentDeviceIDPattern.MatchString(request.DeviceID) {
			return ProtocolsPage{}, errors.New("protocol device filter needs a resolved device ID")
		}
		values.Set("device", request.DeviceID)
	}
	if request.Category != "" {
		if !boundedAgentText(request.Category, 1, 64) || strings.ContainsAny(request.Category, " /?&#") {
			return ProtocolsPage{}, errors.New("protocol category is invalid")
		}
		values.Set("category", request.Category)
	}
	if request.Exotic {
		values.Set("exotic", "true")
	}
	var page ProtocolsPage
	if _, err := c.getJSONWith(ctx, "/api/v1/protocols", values, maxProtocolsBytes, &page, false); err != nil {
		return ProtocolsPage{}, err
	}
	if page.Schema != 1 || len(page.Protocols) > maxProtocolEntries || request.DeviceID != "" && page.DeviceID != "" && page.DeviceID != request.DeviceID {
		return ProtocolsPage{}, errors.New("protocol discovery response is invalid")
	}
	for _, protocol := range page.Protocols {
		if !boundedAgentText(protocol.Protocol, 1, 64) || !boundedAgentText(protocol.Label, 0, 128) || len(protocol.Devices) > maxProtocolDevices || len(protocol.Ports) > maxProtocolPorts || !utf8.ValidString(protocol.Description) || len(protocol.Description) > 512 {
			return ProtocolsPage{}, errors.New("protocol discovery response contains an invalid protocol")
		}
		for _, device := range protocol.Devices {
			if device.DeviceID != "" && !agentDeviceIDPattern.MatchString(device.DeviceID) || !boundedAgentText(device.DeviceName, 0, 256) {
				return ProtocolsPage{}, errors.New("protocol discovery response contains an invalid device")
			}
		}
	}
	return page, nil
}
