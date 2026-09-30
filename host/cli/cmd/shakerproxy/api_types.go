package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// These types mirror the control API contracts. Decoding is lenient (unknown
// fields ignored, timestamps kept as RFC 3339 strings) so the CLI keeps
// working when the server adds fields.

// deviceMatch is one entry of GET /api/v1/devices/resolve and of the
// candidates list in a 409 device_ambiguous error.
type deviceMatch struct {
	DeviceID          string   `json:"device_id"`
	FriendlyName      string   `json:"friendly_name"`
	Vendor            string   `json:"vendor"`
	Addresses         []string `json:"addresses"`
	HardwareAddresses []string `json:"hardware_addresses"`
	Online            bool     `json:"online"`
	Match             string   `json:"match"`
}

type resolveResponse struct {
	Schema  int           `json:"schema"`
	Query   string        `json:"query"`
	Unique  bool          `json:"unique"`
	Matches []deviceMatch `json:"matches"`
}

// inventoryDevice is the subset of the inventory device record the CLI shows.
type inventoryDevice struct {
	ID            string `json:"id"`
	FriendlyName  string `json:"friendly_name"`
	AliasRevision uint64 `json:"alias_revision"`
	Category      string `json:"category"`
	Owner         string `json:"owner"`
	Location      string `json:"location"`
	Tags          []string
	Vendor        *struct {
		Name string `json:"name"`
	} `json:"vendor"`
	Identities []struct {
		Kind  string `json:"kind"`
		Value string `json:"value"`
	} `json:"identities"`
	Addresses []struct {
		Address   string `json:"address"`
		Family    string `json:"family"`
		Active    bool   `json:"active"`
		Interface string `json:"interface"`
	} `json:"addresses"`
	Hostnames []struct {
		Hostname string `json:"hostname"`
		Name     string `json:"name"`
	} `json:"hostnames"`
	FirstSeen             string   `json:"first_seen"`
	LastSeen              string   `json:"last_seen"`
	Online                bool     `json:"online"`
	AttributionConfidence int      `json:"attribution_confidence"`
	AttributionWarnings   []string `json:"attribution_warnings"`
}

func (d inventoryDevice) name() string {
	if d.FriendlyName != "" {
		return sanitize(d.FriendlyName)
	}
	for _, hostname := range d.Hostnames {
		if value := firstNonEmpty(hostname.Hostname, hostname.Name); value != "" {
			return sanitize(value)
		}
	}
	return "(unnamed)"
}

func (d inventoryDevice) vendor() string {
	if d.Vendor != nil {
		return sanitize(d.Vendor.Name)
	}
	return ""
}

func (d inventoryDevice) ipAddresses(activeOnly bool) []string {
	var result []string
	for _, address := range d.Addresses {
		if activeOnly && !address.Active {
			continue
		}
		result = appendUnique(result, address.Address)
	}
	return result
}

func (d inventoryDevice) macAddresses() []string {
	var result []string
	for _, identity := range d.Identities {
		kind := strings.ToLower(identity.Kind)
		if strings.Contains(kind, "mac") {
			result = appendUnique(result, strings.ToLower(identity.Value))
		}
	}
	return result
}

func (d inventoryDevice) toMatch() deviceMatch {
	return deviceMatch{DeviceID: d.ID, FriendlyName: d.FriendlyName, Vendor: d.vendor(), Addresses: d.ipAddresses(false), HardwareAddresses: d.macAddresses(), Online: d.Online}
}

type deviceList struct {
	Schema      int               `json:"schema"`
	GeneratedAt string            `json:"generated_at"`
	Devices     []inventoryDevice `json:"devices"`
}

type eventRecord struct {
	RecordID             string `json:"record_id"`
	Source               string `json:"source"`
	Kind                 string `json:"kind"`
	OccurredAt           string `json:"occurred_at"`
	ReceivedAt           string `json:"received_at"`
	DeviceID             string `json:"device_id"`
	DeviceFriendlyName   string `json:"device_friendly_name"`
	SourceIP             string `json:"source_ip"`
	DestinationIP        string `json:"destination_ip"`
	SourcePort           int    `json:"source_port"`
	DestinationPort      int    `json:"destination_port"`
	Protocol             string `json:"protocol"`
	Service              string `json:"service"`
	NetworkBytes         int64  `json:"network_bytes"`
	DNSQuery             string `json:"dns_query"`
	DNSRecordType        string `json:"dns_record_type"`
	DNSResponseCode      string `json:"dns_response_code"`
	DNSAnswerCount       *int   `json:"dns_answer_count"`
	DetectionSeverity    string `json:"detection_severity"`
	DetectionSummary     string `json:"detection_summary"`
	TLSServerName        string `json:"tls_server_name"`
	TLSInterceptionState string `json:"tls_interception_state"`
	TLSPinningSuspected  bool   `json:"tls_pinning_suspected"`
	AppProtocol          string `json:"app_protocol"`
	ProtocolVisibility   string `json:"protocol_visibility"`
	HTTPMethod           string `json:"http_method"`
	HTTPHost             string `json:"http_host"`
	HTTPPath             string `json:"http_path"`
	HTTPStatus           int    `json:"http_status"`
	Summary              string `json:"summary"`
}

type eventPage struct {
	Schema     int           `json:"schema"`
	Events     []eventRecord `json:"events"`
	NextCursor string        `json:"next_cursor"`
}

// summaryLine returns the server's plain-language summary, or builds a
// similar line from the raw fields for control APIs that predate it.
func (e eventRecord) summaryLine() string {
	if e.Summary != "" {
		return sanitize(e.Summary)
	}
	destination := e.DestinationIP
	if e.DestinationPort > 0 && destination != "" {
		destination = fmt.Sprintf("%s:%d", destination, e.DestinationPort)
	}
	switch {
	case e.DetectionSummary != "":
		return sanitize(fmt.Sprintf("Alert (%s): %s", orText(e.DetectionSeverity, "UNKNOWN"), e.DetectionSummary))
	case e.DNSQuery != "":
		line := "DNS lookup " + e.DNSQuery
		if e.DNSRecordType != "" {
			line += " (" + e.DNSRecordType + ")"
		}
		if e.DNSResponseCode != "" && e.DNSResponseCode != "NOERROR" {
			line += " → " + e.DNSResponseCode
		} else if e.DNSAnswerCount != nil {
			line += " → " + plural(*e.DNSAnswerCount, "answer", "answers")
		}
		return sanitize(line)
	case e.HTTPMethod != "" && e.HTTPHost != "":
		line := e.HTTPMethod + " " + e.HTTPHost + e.HTTPPath
		if e.HTTPStatus > 0 {
			line += fmt.Sprintf(" → %d", e.HTTPStatus)
		}
		return sanitize(line)
	case e.TLSServerName != "":
		line := "HTTPS " + e.TLSServerName
		switch strings.ToUpper(e.TLSInterceptionState) {
		case "INTERCEPTED":
			line += " — decrypted"
		case "FAILED":
			line += " — decryption failed"
			if e.TLSPinningSuspected {
				line += " (pinned?)"
			}
		case "BYPASSED":
			line += " — not decrypted"
		}
		return sanitize(line)
	}
	protocol := strings.ToUpper(firstNonEmpty(e.AppProtocol, e.Service, e.Protocol))
	if protocol == "" {
		protocol = "Traffic"
	}
	line := protocol
	if destination != "" {
		line += " to " + destination
	}
	if e.NetworkBytes > 0 {
		line += " · " + humanBytes(e.NetworkBytes)
	}
	return sanitize(line)
}

type finding struct {
	ID             string   `json:"id"`
	Severity       string   `json:"severity"`
	Title          string   `json:"title"`
	Detail         string   `json:"detail"`
	Recommendation string   `json:"recommendation"`
	Evidence       []string `json:"evidence"`
}

type reportTotals struct {
	Events         int64 `json:"events"`
	Flows          int64 `json:"flows"`
	Bytes          int64 `json:"bytes"`
	DNSQueries     int64 `json:"dns_queries"`
	TLSConnections int64 `json:"tls_connections"`
	HTTPRequests   int64 `json:"http_requests"`
	Alerts         int64 `json:"alerts"`
}

type reportDomain struct {
	Domain            string   `json:"domain"`
	RegistrableDomain string   `json:"registrable_domain"`
	Organization      string   `json:"organization"`
	Category          string   `json:"category"`
	Sources           []string `json:"sources"`
	Events            int64    `json:"events"`
	FirstSeen         string   `json:"first_seen"`
	LastSeen          string   `json:"last_seen"`
}

type reportTLS struct {
	Intercepted      int64    `json:"intercepted"`
	Bypassed         int64    `json:"bypassed"`
	Failed           int64    `json:"failed"`
	PinningSuspected int64    `json:"pinning_suspected"`
	FailedHosts      []string `json:"failed_hosts"`
	OldVersions      []struct {
		Version string   `json:"version"`
		Hosts   []string `json:"hosts"`
	} `json:"old_versions"`
}

type reportHTTP struct {
	Requests          int64            `json:"requests"`
	Hosts             int64            `json:"hosts"`
	CleartextRequests int64            `json:"cleartext_requests"`
	StatusClasses     map[string]int64 `json:"status_classes"`
}

type reportDevice struct {
	DeviceID          string   `json:"device_id"`
	FriendlyName      string   `json:"friendly_name"`
	Vendor            string   `json:"vendor"`
	Category          string   `json:"category"`
	Addresses         []string `json:"addresses"`
	HardwareAddresses []string `json:"hardware_addresses"`
	Online            bool     `json:"online"`
}

type deviceReport struct {
	Schema      int            `json:"schema"`
	GeneratedAt string         `json:"generated_at"`
	Device      reportDevice   `json:"device"`
	WindowStart string         `json:"window_start"`
	WindowEnd   string         `json:"window_end"`
	Session     *testSession   `json:"session"`
	CATrust     string         `json:"ca_trust"`
	Totals      reportTotals   `json:"totals"`
	Domains     []reportDomain `json:"domains"`
	Protocols   []struct {
		Protocol string `json:"protocol"`
		Flows    int64  `json:"flows"`
	} `json:"protocols"`
	TLS       reportTLS  `json:"tls"`
	HTTP      reportHTTP `json:"http"`
	Findings  []finding  `json:"findings"`
	Truncated bool       `json:"truncated"`
}

type testSession struct {
	Schema           int      `json:"schema"`
	ID               string   `json:"id"`
	DeviceID         string   `json:"device_id"`
	DeviceName       string   `json:"device_name"`
	Name             string   `json:"name"`
	Notes            string   `json:"notes"`
	State            string   `json:"state"`
	StartedAt        string   `json:"started_at"`
	EndedAt          *string  `json:"ended_at"`
	CaptureSessionID *string  `json:"capture_session_id"`
	CreatedBy        string   `json:"created_by"`
	Warnings         []string `json:"warnings"`
}

type compareSide struct {
	Start     string       `json:"start"`
	End       string       `json:"end"`
	SessionID string       `json:"session_id"`
	Totals    reportTotals `json:"totals"`
}

type compareResult struct {
	Schema   int         `json:"schema"`
	DeviceID string      `json:"device_id"`
	Base     compareSide `json:"base"`
	Compare  compareSide `json:"compare"`
	Domains  struct {
		Added   []string `json:"added"`
		Removed []string `json:"removed"`
	} `json:"domains"`
	Protocols struct {
		Added   []string `json:"added"`
		Removed []string `json:"removed"`
	} `json:"protocols"`
	Findings struct {
		New      []finding `json:"new"`
		Resolved []finding `json:"resolved"`
	} `json:"findings"`
	TLS struct {
		NewlyFailedHosts      []string `json:"newly_failed_hosts"`
		NewlyInterceptedHosts []string `json:"newly_intercepted_hosts"`
	} `json:"tls"`
}

type protocolDevice struct {
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
	Flows      int64  `json:"flows"`
	Bytes      int64  `json:"bytes"`
	LastSeen   string `json:"last_seen"`
}

type protocolUsage struct {
	Protocol    string           `json:"protocol"`
	Label       string           `json:"label"`
	Category    string           `json:"category"`
	Visibility  string           `json:"visibility"`
	Evidence    string           `json:"evidence"`
	Exotic      bool             `json:"exotic"`
	Novel       bool             `json:"novel"`
	Description string           `json:"description"`
	Flows       int64            `json:"flows"`
	Bytes       int64            `json:"bytes"`
	DeviceCount int              `json:"device_count"`
	Devices     []protocolDevice `json:"devices"`
	FirstSeen   string           `json:"first_seen"`
	LastSeen    string           `json:"last_seen"`
	Ports       []struct {
		Transport string `json:"transport"`
		Port      int    `json:"port"`
		Flows     int64  `json:"flows"`
	} `json:"ports"`
}

type protocolReport struct {
	Schema      int             `json:"schema"`
	Window      string          `json:"window"`
	WindowStart string          `json:"window_start"`
	WindowEnd   string          `json:"window_end"`
	DeviceID    string          `json:"device_id"`
	Protocols   []protocolUsage `json:"protocols"`
	Coverage    struct {
		TotalBytes             int64   `json:"total_bytes"`
		DecryptedBytes         int64   `json:"decrypted_bytes"`
		CleartextBytes         int64   `json:"cleartext_bytes"`
		EncryptedMetadataBytes int64   `json:"encrypted_metadata_bytes"`
		OpaqueBytes            int64   `json:"opaque_bytes"`
		OpaquePercent          float64 `json:"opaque_percent"`
	} `json:"coverage"`
	Truncated bool `json:"truncated"`
}

type deviceControls struct {
	Schema         int      `json:"schema"`
	DeviceID       string   `json:"device_id"`
	DecryptHTTPS   bool     `json:"decrypt_https"`
	Internet       string   `json:"internet"`
	BlockedDomains []string `json:"blocked_domains"`
	UpdatedAt      string   `json:"updated_at"`
	Effective      *bool    `json:"effective"`
	Notes          []string `json:"notes"`
}

type caOnboarding struct {
	Schema            int    `json:"schema"`
	Available         bool   `json:"available"`
	Reason            string `json:"reason"`
	SHA256Fingerprint string `json:"sha256_fingerprint"`
	CommonName        string `json:"common_name"`
	NotAfter          string `json:"not_after"`
	URLs              []struct {
		Label string `json:"label"`
		URL   string `json:"url"`
	} `json:"urls"`
	Instructions []struct {
		Platform    string   `json:"platform"`
		Title       string   `json:"title"`
		Steps       []string `json:"steps"`
		Limitations []string `json:"limitations"`
	} `json:"instructions"`
}

// decodeListField reads a list that may be a bare array or wrapped in an
// object under one of several names (list envelopes are not fixed by the
// contract).
func decodeListField(raw []byte, out any, names ...string) error {
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "[") {
		return json.Unmarshal(raw, out)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return err
	}
	for _, name := range names {
		if value, ok := envelope[name]; ok {
			return json.Unmarshal(value, out)
		}
	}
	return fmt.Errorf("response has none of the fields %s", strings.Join(names, ", "))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func appendUnique(values []string, value string) []string {
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
