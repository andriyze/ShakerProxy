package ingest

import (
	"bytes"
	"encoding/json"
	"net"
	"strings"
	"unicode/utf8"
)

// ProjectionVersion identifies the column projection written at ingest. Rows
// stored before it existed (NULL) or by an older projection are backfilled.
// Bump it whenever derived columns change meaning, for example when the
// protocol classifier learns to name more protocols.
const ProjectionVersion = 3

// MaxEventHTTPPathBytes bounds the HTTP path stored with every event. Query
// strings and fragments are never stored.
const MaxEventHTTPPathBytes = 256

// HTTPColumns are the plain-language HTTP fields stored for any source that
// saw an HTTP request: mitmproxy, Zeek http.log, or Suricata http.
type HTTPColumns struct {
	Method string
	Host   string
	Path   string
	Status int
}

// AlertProjection is the bounded Suricata alert metadata.
type AlertProjection struct {
	Signature string
	Severity  int
	Category  string
}

// EventProjection is every column derived from an envelope at ingest.
type EventProjection struct {
	Network   NetworkProjection
	DNS       DNSProjection
	Detection DetectionProjection
	TLS       TLSProjection
	HTTP      HTTPColumns
	Alert     AlertProjection
	Protocol  ProtocolProjection
}

// ProjectEvent computes every stored projection for one envelope. The same
// function serves inserts and the backfill of rows written before a column
// existed, so both paths always agree.
func ProjectEvent(envelope Envelope) EventProjection {
	projection := EventProjection{
		Network:   ProjectNetworkFields(envelope),
		DNS:       ProjectDNSFields(envelope),
		Detection: ProjectDetectionFields(envelope),
		TLS:       ProjectTLSFields(envelope),
		HTTP:      ProjectHTTPColumns(envelope),
		Alert:     ProjectAlertFields(envelope),
	}
	projection.Network.Service = projectedService(envelope, projection.Network)
	projection.Protocol = ProjectProtocolFields(envelope, projection.Network, projection.TLS)
	return projection
}

// ProjectHTTPColumns extracts method, host, path (without query string), and
// status from mitmproxy HTTP events, Zeek http.log, or Suricata http records.
// It never stores headers, bodies, cookies, or query strings.
func ProjectHTTPColumns(envelope Envelope) HTTPColumns {
	switch envelope.Source {
	case SourceMitmproxy:
		if envelope.Kind != "http_request" && envelope.Kind != "http_response" {
			return HTTPColumns{}
		}
		projection := ProjectHTTPFields(envelope)
		return boundedHTTPColumns(projection.Method, projection.Host, projection.Path, projection.Status)
	case SourceZeek:
		if zeekLogPath(envelope.Kind) != "http" {
			return HTTPColumns{}
		}
		var record struct {
			Method any `json:"method"`
			Host   any `json:"host"`
			URI    any `json:"uri"`
			Status any `json:"status_code"`
		}
		if decodeUseNumber(envelope.Payload, &record) != nil {
			return HTTPColumns{}
		}
		return passiveHTTPColumns(record.Method, record.Host, record.URI, record.Status)
	case SourceSuricata:
		var record struct {
			HTTP *struct {
				Method any `json:"http_method"`
				Host   any `json:"hostname"`
				URL    any `json:"url"`
				Status any `json:"status"`
			} `json:"http"`
		}
		if decodeUseNumber(envelope.Payload, &record) != nil || record.HTTP == nil {
			return HTTPColumns{}
		}
		return passiveHTTPColumns(record.HTTP.Method, record.HTTP.Host, record.HTTP.URL, record.HTTP.Status)
	}
	return HTTPColumns{}
}

func passiveHTTPColumns(method, host, uri, status any) HTTPColumns {
	methodText, _ := normalizeHTTPMethod(method)
	if !httpMethodPattern.MatchString(methodText) {
		methodText = ""
	}
	hostText := ""
	if raw, ok := host.(string); ok {
		hostText = stripHTTPPort(raw)
	}
	pathText := ""
	if raw, ok := uri.(string); ok {
		// Absolute-form request targets (proxies) carry scheme and host.
		if index := strings.Index(raw, "://"); index >= 0 {
			rest := raw[index+3:]
			if slash := strings.IndexByte(rest, '/'); slash >= 0 {
				raw = rest[slash:]
			} else {
				raw = "/"
			}
		}
		pathText = raw
	}
	statusCode, ok := normalizeHTTPInteger(status, 100, 599)
	if !ok {
		statusCode = 0
	}
	return boundedHTTPColumns(methodText, hostText, pathText, statusCode)
}

func boundedHTTPColumns(method, host, path string, status int) HTTPColumns {
	columns := HTTPColumns{Status: status}
	if canonical, ok := normalizeHTTPMethod(method); ok {
		columns.Method = canonical
	}
	if host != "" {
		if canonical, ok := normalizeHTTPHost(host); ok {
			columns.Host = canonical
		}
	}
	if path != "" {
		if canonical, ok, _ := normalizeHTTPPath(path); ok {
			columns.Path = truncateUTF8(canonical, MaxEventHTTPPathBytes)
		}
	}
	if columns.Status < 100 || columns.Status > 599 {
		columns.Status = 0
	}
	return columns
}

// stripHTTPPort removes a ":port" suffix from a Host header value while
// leaving bare and bracketed IPv6 literals intact.
func stripHTTPPort(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "[") {
		if end := strings.Index(value, "]"); end > 0 {
			return value[:end+1]
		}
		return value
	}
	if strings.Count(value, ":") == 1 {
		if host, _, err := net.SplitHostPort(value); err == nil {
			return host
		}
	}
	return value
}

// ProjectAlertFields extracts the signature, severity (1 high .. 4 info), and
// category of a Suricata alert.
func ProjectAlertFields(envelope Envelope) AlertProjection {
	if envelope.Source != SourceSuricata || envelope.Kind != "suricata.alert" {
		return AlertProjection{}
	}
	var record struct {
		Alert *struct {
			Signature any `json:"signature"`
			Severity  any `json:"severity"`
			Category  any `json:"category"`
		} `json:"alert"`
	}
	if decodeUseNumber(envelope.Payload, &record) != nil || record.Alert == nil {
		return AlertProjection{}
	}
	projection := AlertProjection{
		Signature: boundedDisplayText(record.Alert.Signature, 256),
		Category:  boundedDisplayText(record.Alert.Category, 128),
	}
	if severity, ok := normalizeHTTPInteger(record.Alert.Severity, 1, 4); ok {
		projection.Severity = severity
	}
	return projection
}

// boundedDisplayText returns a single-line, control-free, length-bounded
// string suitable for summaries and columns.
func boundedDisplayText(value any, maxBytes int) string {
	text, ok := value.(string)
	if !ok || !utf8.ValidString(text) {
		return ""
	}
	text = strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f || character >= 0x80 && character < 0xa0 {
			return ' '
		}
		return character
	}, text)
	text = strings.Join(strings.Fields(text), " ")
	return truncateUTF8(text, maxBytes)
}

func truncateUTF8(value string, maxBytes int) string {
	if len(value) <= maxBytes {
		return value
	}
	value = value[:maxBytes]
	for value != "" && !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

func validEventHTTPColumns(event RecentEvent) bool {
	if event.HTTPMethod != "" && !httpMethodPattern.MatchString(event.HTTPMethod) {
		return false
	}
	if event.HTTPHost != "" {
		if canonical, ok := normalizeHTTPHost(event.HTTPHost); !ok || canonical != event.HTTPHost {
			return false
		}
	}
	if event.HTTPPath != "" {
		canonical, ok, truncated := normalizeHTTPPath(event.HTTPPath)
		if !ok || truncated || canonical != event.HTTPPath || len(event.HTTPPath) > MaxEventHTTPPathBytes {
			return false
		}
	}
	return event.HTTPStatus == 0 || event.HTTPStatus >= 100 && event.HTTPStatus <= 599
}

func validEventAlert(event RecentEvent) bool {
	if event.AlertSignature != "" && boundedDisplayText(event.AlertSignature, 256) != event.AlertSignature {
		return false
	}
	if event.AlertCategory != "" && boundedDisplayText(event.AlertCategory, 128) != event.AlertCategory {
		return false
	}
	return event.AlertSeverity >= 0 && event.AlertSeverity <= 4
}

func decodeUseNumber(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	return decoder.Decode(target)
}
