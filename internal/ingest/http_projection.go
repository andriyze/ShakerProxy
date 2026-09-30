package ingest

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MaxHTTPActivityLimit     = 100
	MaxHTTPActivityPathBytes = 1024
)

var (
	httpMethodPattern  = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,32}$")
	httpVersionPattern = regexp.MustCompile(`^HTTP/[0-9](?:\.[0-9])?$`)
)

// HTTPActivityEvent is the deliberately narrow HTTP metadata projection used
// by the local agent API and MCP. It cannot carry headers, bodies, cookies,
// authorization values, TLS key logs, or a query-bearing full URL.
type HTTPActivityEvent struct {
	RecordID           string    `json:"record_id"`
	Source             Source    `json:"source"`
	Kind               string    `json:"kind"`
	OccurredAt         time.Time `json:"occurred_at"`
	ReceivedAt         time.Time `json:"received_at"`
	FlowID             string    `json:"flow_id,omitempty"`
	DeviceID           string    `json:"device_id,omitempty"`
	Method             string    `json:"method,omitempty"`
	Scheme             string    `json:"scheme,omitempty"`
	Host               string    `json:"host,omitempty"`
	Port               int       `json:"port,omitempty"`
	Path               string    `json:"path,omitempty"`
	Status             int       `json:"status,omitempty"`
	HTTPVersion        string    `json:"http_version,omitempty"`
	RequestBytes       *int64    `json:"request_bytes,omitempty"`
	ResponseBytes      *int64    `json:"response_bytes,omitempty"`
	Decrypted          *bool     `json:"decrypted,omitempty"`
	URLTruncated       bool      `json:"url_truncated,omitempty"`
	ContentLocalOnly   bool      `json:"content_local_only,omitempty"`
	MetadataIncomplete bool      `json:"metadata_incomplete,omitempty"`
}

type HTTPProjection struct {
	Method             string
	Scheme             string
	Host               string
	Port               int
	Path               string
	Status             int
	HTTPVersion        string
	RequestBytes       *int64
	ResponseBytes      *int64
	Decrypted          *bool
	URLTruncated       bool
	ContentLocalOnly   bool
	MetadataIncomplete bool
}

type httpProjectionInput struct {
	Method           any
	Scheme           any
	Host             any
	Port             any
	Path             any
	Status           any
	HTTPVersion      any
	RequestBytes     any
	ResponseBytes    any
	Decrypted        any
	URLTruncated     any
	ContentLocalOnly any
	PathTruncated    any
}

// ProjectHTTPFields extracts only bounded metadata from a mitmproxy envelope.
// Unknown payload fields are intentionally ignored rather than copied.
func ProjectHTTPFields(envelope Envelope) HTTPProjection {
	if envelope.Source != SourceMitmproxy || envelope.Kind != "http_request" && envelope.Kind != "http_response" {
		return HTTPProjection{}
	}
	var payload struct {
		Method           any `json:"http_method"`
		Scheme           any `json:"http_scheme"`
		Host             any `json:"http_host"`
		Port             any `json:"http_port"`
		Path             any `json:"http_path"`
		Status           any `json:"http_status"`
		HTTPVersion      any `json:"http_version"`
		RequestBytes     any `json:"request_bytes"`
		ResponseBytes    any `json:"response_bytes"`
		Decrypted        any `json:"decrypted"`
		URLTruncated     any `json:"http_url_truncated"`
		ContentLocalOnly any `json:"content_local_only"`
		PathTruncated    any `json:"http_path_truncated"`
	}
	decoder := json.NewDecoder(bytes.NewReader(envelope.Payload))
	decoder.UseNumber()
	if decoder.Decode(&payload) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return HTTPProjection{MetadataIncomplete: true}
	}
	return projectHTTPInput(envelope.Source, envelope.Kind, httpProjectionInput{
		Method: payload.Method, Scheme: payload.Scheme, Host: payload.Host, Port: payload.Port,
		Path: payload.Path, Status: payload.Status, HTTPVersion: payload.HTTPVersion,
		RequestBytes: payload.RequestBytes, ResponseBytes: payload.ResponseBytes,
		Decrypted: payload.Decrypted, URLTruncated: payload.URLTruncated,
		ContentLocalOnly: payload.ContentLocalOnly, PathTruncated: payload.PathTruncated,
	})
}

func projectHTTPInput(source Source, kind string, input httpProjectionInput) HTTPProjection {
	if source != SourceMitmproxy || kind != "http_request" && kind != "http_response" {
		return HTTPProjection{}
	}
	projection := HTTPProjection{}
	incomplete := false
	var ok bool

	projection.Method, ok = normalizeHTTPMethod(input.Method)
	incomplete = incomplete || !ok
	projection.Scheme, ok = normalizeHTTPScheme(input.Scheme)
	incomplete = incomplete || !ok
	projection.Host, ok = normalizeHTTPHost(input.Host)
	incomplete = incomplete || !ok
	projection.Port, ok = normalizeHTTPInteger(input.Port, 1, 65535)
	incomplete = incomplete || !ok
	var pathTruncated bool
	projection.Path, ok, pathTruncated = normalizeHTTPPath(input.Path)
	incomplete = incomplete || !ok || pathTruncated
	projection.HTTPVersion, ok = normalizeHTTPVersion(input.HTTPVersion)
	incomplete = incomplete || !ok
	projection.Decrypted, ok = normalizeHTTPBooleanPointer(input.Decrypted)
	incomplete = incomplete || !ok

	if kind == "http_response" {
		projection.Status, ok = normalizeHTTPInteger(input.Status, 100, 599)
		incomplete = incomplete || !ok
		projection.RequestBytes, ok = normalizeHTTPBytes(input.RequestBytes)
		incomplete = incomplete || !ok
		projection.ResponseBytes, ok = normalizeHTTPBytes(input.ResponseBytes)
		incomplete = incomplete || !ok
	} else if httpInputPresent(input.Status) || httpInputPresent(input.RequestBytes) || httpInputPresent(input.ResponseBytes) {
		incomplete = true
	}

	if httpInputPresent(input.URLTruncated) {
		projection.URLTruncated, ok = normalizeHTTPBoolean(input.URLTruncated)
		incomplete = incomplete || !ok
	}
	if httpInputPresent(input.ContentLocalOnly) {
		projection.ContentLocalOnly, ok = normalizeHTTPBoolean(input.ContentLocalOnly)
		incomplete = incomplete || !ok
	}
	if httpInputPresent(input.PathTruncated) {
		var explicitlyTruncated bool
		explicitlyTruncated, ok = normalizeHTTPBoolean(input.PathTruncated)
		incomplete = incomplete || !ok || explicitlyTruncated
	}
	if pathTruncated {
		projection.URLTruncated = true
	}
	if projection.Decrypted != nil && projection.Scheme != "" && *projection.Decrypted != (projection.Scheme == "https") {
		projection.Decrypted = nil
		incomplete = true
	}
	projection.MetadataIncomplete = incomplete
	return projection
}

func applyHTTPProjection(event *HTTPActivityEvent, projection HTTPProjection) {
	event.Method = projection.Method
	event.Scheme = projection.Scheme
	event.Host = projection.Host
	event.Port = projection.Port
	event.Path = projection.Path
	event.Status = projection.Status
	event.HTTPVersion = projection.HTTPVersion
	event.RequestBytes = projection.RequestBytes
	event.ResponseBytes = projection.ResponseBytes
	event.Decrypted = projection.Decrypted
	event.URLTruncated = projection.URLTruncated
	event.ContentLocalOnly = projection.ContentLocalOnly
	event.MetadataIncomplete = projection.MetadataIncomplete
}

func validHTTPActivityEvent(event HTTPActivityEvent) bool {
	if event.Source != SourceMitmproxy || event.Kind != "http_request" && event.Kind != "http_response" {
		return false
	}
	if event.Method != "" {
		canonical, ok := normalizeHTTPMethod(event.Method)
		if !ok || canonical != event.Method {
			return false
		}
	}
	if event.Scheme != "" {
		canonical, ok := normalizeHTTPScheme(event.Scheme)
		if !ok || canonical != event.Scheme {
			return false
		}
	}
	if event.Host != "" {
		canonical, ok := normalizeHTTPHost(event.Host)
		if !ok || canonical != event.Host {
			return false
		}
	}
	if event.Port != 0 && (event.Port < 1 || event.Port > 65535) {
		return false
	}
	if event.Path != "" {
		canonical, ok, truncated := normalizeHTTPPath(event.Path)
		if !ok || truncated || canonical != event.Path {
			return false
		}
	}
	if event.HTTPVersion != "" {
		canonical, ok := normalizeHTTPVersion(event.HTTPVersion)
		if !ok || canonical != event.HTTPVersion {
			return false
		}
	}
	if event.RequestBytes != nil && *event.RequestBytes < 0 || event.ResponseBytes != nil && *event.ResponseBytes < 0 {
		return false
	}
	if event.Decrypted != nil && event.Scheme != "" && *event.Decrypted != (event.Scheme == "https") {
		return false
	}
	if event.Kind == "http_request" && (event.Status != 0 || event.RequestBytes != nil || event.ResponseBytes != nil) {
		return false
	}
	if event.Status != 0 && (event.Kind != "http_response" || event.Status < 100 || event.Status > 599) {
		return false
	}
	if !event.MetadataIncomplete {
		if event.Method == "" || event.Scheme == "" || event.Host == "" || event.Port == 0 || event.Path == "" || event.HTTPVersion == "" || event.Decrypted == nil {
			return false
		}
		if event.Kind == "http_response" && (event.Status == 0 || event.RequestBytes == nil || event.ResponseBytes == nil) {
			return false
		}
	}
	return true
}

func CanonicalHTTPHost(value string) (string, error) {
	host, ok := normalizeHTTPHost(value)
	if !ok {
		return "", errors.New("HTTP host is invalid")
	}
	return host, nil
}

func CanonicalHTTPMethod(value string) (string, error) {
	method, ok := normalizeHTTPMethod(value)
	if !ok {
		return "", errors.New("HTTP method is invalid")
	}
	return method, nil
}

func normalizeHTTPMethod(value any) (string, bool) {
	text, ok := value.(string)
	if !ok {
		return "", false
	}
	text = strings.ToUpper(strings.TrimSpace(text))
	return text, httpMethodPattern.MatchString(text)
}

func normalizeHTTPScheme(value any) (string, bool) {
	text, ok := value.(string)
	if !ok {
		return "", false
	}
	text = strings.ToLower(strings.TrimSpace(text))
	return text, text == "http" || text == "https"
}

func normalizeHTTPHost(value any) (string, bool) {
	text, ok := value.(string)
	if !ok {
		return "", false
	}
	text = strings.TrimSpace(text)
	if strings.HasPrefix(text, "[") && strings.HasSuffix(text, "]") {
		text = text[1 : len(text)-1]
	}
	text = strings.ToLower(strings.TrimSuffix(text, "."))
	if address := net.ParseIP(text); address != nil {
		return address.String(), true
	}
	if !tlsServerNamePattern.MatchString(text) {
		return "", false
	}
	return text, true
}

func normalizeHTTPPath(value any) (string, bool, bool) {
	text, ok := value.(string)
	if !ok || text == "" || !utf8.ValidString(text) {
		return "", false, false
	}
	truncated := false
	if index := strings.IndexAny(text, "?#"); index >= 0 {
		text = text[:index]
		truncated = true
	}
	if text == "" {
		text = "/"
		truncated = true
	}
	if text != "*" && !strings.HasPrefix(text, "/") {
		return "", false, truncated
	}
	for _, character := range text {
		if character < 0x20 || character == 0x7f {
			return "", false, truncated
		}
	}
	if len(text) > MaxHTTPActivityPathBytes {
		text = text[:MaxHTTPActivityPathBytes]
		for text != "" && !utf8.ValidString(text) {
			text = text[:len(text)-1]
		}
		truncated = true
	}
	return text, text != "", truncated
}

func normalizeHTTPVersion(value any) (string, bool) {
	text, ok := value.(string)
	if !ok {
		return "", false
	}
	text = strings.ToUpper(strings.TrimSpace(text))
	return text, httpVersionPattern.MatchString(text)
}

func normalizeHTTPInteger(value any, minimum, maximum int64) (int, bool) {
	number, ok := normalizeHTTPInt64(value)
	if !ok || number < minimum || number > maximum {
		return 0, false
	}
	return int(number), true
}

func normalizeHTTPBytes(value any) (*int64, bool) {
	number, ok := normalizeHTTPInt64(value)
	if !ok || number < 0 {
		return nil, false
	}
	return &number, true
}

func normalizeHTTPInt64(value any) (int64, bool) {
	var text string
	switch typed := value.(type) {
	case json.Number:
		text = typed.String()
	case string:
		text = typed
	case int:
		return int64(typed), true
	case int64:
		return typed, true
	default:
		return 0, false
	}
	if text == "" || strings.TrimSpace(text) != text {
		return 0, false
	}
	number, err := strconv.ParseInt(text, 10, 64)
	return number, err == nil
}

func normalizeHTTPBooleanPointer(value any) (*bool, bool) {
	boolean, ok := normalizeHTTPBoolean(value)
	if !ok {
		return nil, false
	}
	return &boolean, true
}

func normalizeHTTPBoolean(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		if typed == "true" {
			return true, true
		}
		if typed == "false" {
			return false, true
		}
	}
	return false, false
}

func httpInputPresent(value any) bool {
	if value == nil {
		return false
	}
	text, ok := value.(string)
	return !ok || text != ""
}
