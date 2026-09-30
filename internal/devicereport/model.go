// Package devicereport turns one device's bounded traffic aggregation into a
// plain-language report: what the device talks to, which protocols it uses,
// how its TLS behaves, and evidence-backed security findings. It also
// compares two reports (for example firmware 1.2 versus 1.3). The package is
// pure: it performs no I/O, so the control API computes reports and API
// clients such as the MCP bridge decode the same types.
package devicereport

import (
	"time"

	"shakerproxy.dev/shakerproxy/internal/testsession"
)

const Schema = 1

// CATrust records whether the ShakerProxy interception CA is installed on the
// device. It decides whether a successful interception is expected (CA
// installed) or a certificate-validation vulnerability (CA not installed).
type CATrust string

const (
	CATrustUnknown      CATrust = "UNKNOWN"
	CATrustInstalled    CATrust = "INSTALLED"
	CATrustNotInstalled CATrust = "NOT_INSTALLED"
)

// NormalizeCATrust maps a stored value ("" for never set) onto a state.
func NormalizeCATrust(value string) CATrust {
	switch CATrust(value) {
	case CATrustInstalled, CATrustNotInstalled:
		return CATrust(value)
	default:
		return CATrustUnknown
	}
}

// ValidCATrust reports whether value is an accepted API state.
func ValidCATrust(value string) bool {
	switch CATrust(value) {
	case CATrustUnknown, CATrustInstalled, CATrustNotInstalled:
		return true
	}
	return false
}

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// SeverityRank orders severities; higher is more severe.
func SeverityRank(value Severity) int {
	switch value {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	}
	return 0
}

type Device struct {
	DeviceID          string   `json:"device_id"`
	FriendlyName      string   `json:"friendly_name"`
	Vendor            string   `json:"vendor"`
	Category          string   `json:"category"`
	Addresses         []string `json:"addresses"`
	HardwareAddresses []string `json:"hardware_addresses"`
	Online            bool     `json:"online"`
}

type Totals struct {
	Events         int64 `json:"events"`
	Flows          int64 `json:"flows"`
	Bytes          int64 `json:"bytes"`
	DNSQueries     int64 `json:"dns_queries"`
	TLSConnections int64 `json:"tls_connections"`
	HTTPRequests   int64 `json:"http_requests"`
	Alerts         int64 `json:"alerts"`
}

type Domain struct {
	Domain            string    `json:"domain"`
	RegistrableDomain string    `json:"registrable_domain"`
	Organization      string    `json:"organization"`
	Category          string    `json:"category"`
	Sources           []string  `json:"sources"`
	Events            int64     `json:"events"`
	FirstSeen         time.Time `json:"first_seen"`
	LastSeen          time.Time `json:"last_seen"`
}

// Protocol is one application protocol the device used, classified with
// internal/protocolclass from analyzer services and ports.
type Protocol struct {
	Protocol   string `json:"protocol"`
	Label      string `json:"label"`
	Category   string `json:"category"`
	Visibility string `json:"visibility"`
	Evidence   string `json:"evidence"`
	Exotic     bool   `json:"exotic"`
	Flows      int64  `json:"flows"`
	Bytes      int64  `json:"bytes"`
}

type OldTLSVersion struct {
	Version string   `json:"version"`
	Hosts   []string `json:"hosts"`
}

type TLS struct {
	Intercepted      int64           `json:"intercepted"`
	Bypassed         int64           `json:"bypassed"`
	Failed           int64           `json:"failed"`
	PinningSuspected int64           `json:"pinning_suspected"`
	FailedHosts      []string        `json:"failed_hosts"`
	InterceptedHosts []string        `json:"intercepted_hosts"`
	OldVersions      []OldTLSVersion `json:"old_versions"`
}

type StatusClasses struct {
	C2xx int64 `json:"2xx"`
	C3xx int64 `json:"3xx"`
	C4xx int64 `json:"4xx"`
	C5xx int64 `json:"5xx"`
}

type HTTP struct {
	Requests          int64         `json:"requests"`
	Hosts             int64         `json:"hosts"`
	CleartextRequests int64         `json:"cleartext_requests"`
	StatusClasses     StatusClasses `json:"status_classes"`
}

type Finding struct {
	ID             string   `json:"id"`
	Severity       Severity `json:"severity"`
	Title          string   `json:"title"`
	Detail         string   `json:"detail"`
	Recommendation string   `json:"recommendation"`
	Evidence       []string `json:"evidence"`
}

type Report struct {
	Schema      int                  `json:"schema"`
	GeneratedAt time.Time            `json:"generated_at"`
	Device      Device               `json:"device"`
	WindowStart time.Time            `json:"window_start"`
	WindowEnd   time.Time            `json:"window_end"`
	Session     *testsession.Session `json:"session"`
	CATrust     CATrust              `json:"ca_trust"`
	Summary     string               `json:"summary"`
	Totals      Totals               `json:"totals"`
	Domains     []Domain             `json:"domains"`
	Protocols   []Protocol           `json:"protocols"`
	TLS         TLS                  `json:"tls"`
	HTTP        HTTP                 `json:"http"`
	Findings    []Finding            `json:"findings"`
	Truncated   bool                 `json:"truncated"`
}

type CompareSide struct {
	Start     time.Time `json:"start"`
	End       time.Time `json:"end"`
	SessionID string    `json:"session_id,omitempty"`
	Name      string    `json:"name,omitempty"`
	Totals    Totals    `json:"totals"`
}

type Change struct {
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
}

type FindingChange struct {
	New      []Finding `json:"new"`
	Resolved []Finding `json:"resolved"`
}

type TLSChange struct {
	NewlyFailedHosts      []string `json:"newly_failed_hosts"`
	NewlyInterceptedHosts []string `json:"newly_intercepted_hosts"`
}

type Comparison struct {
	Schema      int           `json:"schema"`
	GeneratedAt time.Time     `json:"generated_at"`
	DeviceID    string        `json:"device_id"`
	Summary     string        `json:"summary"`
	Base        CompareSide   `json:"base"`
	Compare     CompareSide   `json:"compare"`
	Domains     Change        `json:"domains"`
	Protocols   Change        `json:"protocols"`
	Findings    FindingChange `json:"findings"`
	TLS         TLSChange     `json:"tls"`
	// Truncated is true when either report reached a list bound, so some
	// added or removed domains and hosts may only reflect ranking.
	Truncated bool `json:"truncated"`
}
