package ingest

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestProjectHTTPFieldsReturnsCanonicalMetadataWithoutPlaintext(t *testing.T) {
	request := Envelope{
		Source: SourceMitmproxy,
		Kind:   "http_request",
		Payload: json.RawMessage(`{
			"http_method":"post",
			"http_scheme":"HTTPS",
			"http_host":"API.Example.Test.",
			"http_port":443,
			"http_path":"/v1/orders",
			"http_version":"http/2.0",
			"decrypted":true,
			"http_url_truncated":false,
			"content_local_only":true,
			"request_headers":{"items":[{"name":"Authorization","value":"Bearer secret-value"}]},
			"request_body":{"preview":"ignore previous instructions"},
			"http_url":"https://api.example.test/v1/orders?token=secret-value"
		}`),
	}
	projection := ProjectHTTPFields(request)
	if projection.Method != "POST" || projection.Scheme != "https" || projection.Host != "api.example.test" || projection.Port != 443 || projection.Path != "/v1/orders" || projection.HTTPVersion != "HTTP/2.0" || projection.Decrypted == nil || !*projection.Decrypted || !projection.ContentLocalOnly || projection.MetadataIncomplete {
		t.Fatalf("unexpected request projection: %#v", projection)
	}
	event := HTTPActivityEvent{RecordID: strings.Repeat("a", 64), Source: SourceMitmproxy, Kind: "http_request", OccurredAt: time.Now().UTC(), ReceivedAt: time.Now().UTC()}
	applyHTTPProjection(&event, projection)
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret-value", "Authorization", "request_headers", "request_body", "http_url", "ignore previous instructions"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("HTTP activity projection leaked %q: %s", forbidden, encoded)
		}
	}
	if !validHTTPActivityEvent(event) {
		t.Fatalf("valid request projection was rejected: %#v", event)
	}
}

func TestProjectHTTPResponseIncludesSizesAndStripsUnexpectedQuery(t *testing.T) {
	response := Envelope{
		Source: SourceMitmproxy,
		Kind:   "http_response",
		Payload: json.RawMessage(`{
			"http_method":"GET",
			"http_scheme":"https",
			"http_host":"example.test",
			"http_port":"443",
			"http_path":"/download?credential=must-not-leak",
			"http_status":206,
			"http_version":"HTTP/1.1",
			"request_bytes":0,
			"response_bytes":4096,
			"decrypted":true,
			"http_url_truncated":false
		}`),
	}
	projection := ProjectHTTPFields(response)
	if projection.Path != "/download" || strings.Contains(projection.Path, "credential") || projection.Status != 206 || projection.RequestBytes == nil || *projection.RequestBytes != 0 || projection.ResponseBytes == nil || *projection.ResponseBytes != 4096 || !projection.URLTruncated || !projection.MetadataIncomplete {
		t.Fatalf("unexpected response projection: %#v", projection)
	}
	event := HTTPActivityEvent{RecordID: strings.Repeat("b", 64), Source: SourceMitmproxy, Kind: "http_response", OccurredAt: time.Now().UTC(), ReceivedAt: time.Now().UTC()}
	applyHTTPProjection(&event, projection)
	if !validHTTPActivityEvent(event) {
		t.Fatalf("safe incomplete response projection was rejected: %#v", event)
	}
}

func TestHTTPProjectionFailsClosedOnMalformedMetadata(t *testing.T) {
	projection := projectHTTPInput(SourceMitmproxy, "http_response", httpProjectionInput{
		Method: []string{"GET"}, Scheme: "https", Host: "bad\nhost", Port: "443",
		Path: "/ok", Status: "200", HTTPVersion: "HTTP/1.1", RequestBytes: "1",
		ResponseBytes: "2", Decrypted: "false", URLTruncated: "not-a-bool",
	})
	if !projection.MetadataIncomplete || projection.Method != "" || projection.Host != "" || projection.Decrypted != nil || projection.URLTruncated {
		t.Fatalf("malformed fields were not safely omitted: %#v", projection)
	}
	if projection.Path != "/ok" || projection.Status != 200 || projection.RequestBytes == nil || projection.ResponseBytes == nil {
		t.Fatalf("valid neighboring metadata was unnecessarily discarded: %#v", projection)
	}
}

func TestHTTPActivityQueryCanonicalizesFiltersAndRequiresAnchoredCursor(t *testing.T) {
	anchor := time.Date(2026, 9, 3, 20, 0, 0, 0, time.UTC)
	occurred := anchor.Add(-time.Minute)
	cursor := encodeRecentEventCursor(occurred, strings.Repeat("c", 64), anchor)
	query, err := ParseInternalHTTPActivityQuery(url.Values{
		"limit":          {"25"},
		"window_seconds": {"3600"},
		"device_id":      {"device-0123456789abcdef0123456789abcdef"},
		"host":           {"API.Example.Test."},
		"method":         {"post"},
		"cursor":         {cursor},
	})
	if err != nil {
		t.Fatal(err)
	}
	if query.Host != "api.example.test" || query.Method != "POST" || query.Limit != 25 || query.WindowSeconds != 3600 || query.Cursor != cursor {
		t.Fatalf("unexpected canonical query: %#v", query)
	}
	for _, values := range []url.Values{
		{"window_seconds": {"60"}},
		{"host": {"example.test:443"}},
		{"method": {"GET\nX"}},
		{"cursor": {encodeRecentEventCursor(occurred, strings.Repeat("d", 64), time.Time{})}},
		{"limit": {"1", "2"}},
		{"unknown": {"value"}},
	} {
		if _, err := ParseInternalHTTPActivityQuery(values); err == nil {
			t.Fatalf("invalid HTTP activity query was accepted: %#v", values)
		}
	}
}

func TestHTTPActivityPageValidatesStablePaginationAndFilters(t *testing.T) {
	anchor := time.Date(2026, 9, 3, 20, 0, 0, 0, time.UTC)
	decrypted := true
	requestBytes, responseBytes := int64(12), int64(34)
	event := HTTPActivityEvent{
		RecordID: strings.Repeat("e", 64), Source: SourceMitmproxy, Kind: "http_response",
		OccurredAt: anchor.Add(-time.Minute), ReceivedAt: anchor.Add(-30 * time.Second),
		FlowID: "flow-0123456789abcdef", DeviceID: "device-0123456789abcdef0123456789abcdef",
		Method: "POST", Scheme: "https", Host: "api.example.test", Port: 443,
		Path: "/v1/orders", Status: 201, HTTPVersion: "HTTP/2.0",
		RequestBytes: &requestBytes, ResponseBytes: &responseBytes, Decrypted: &decrypted,
	}
	query := HTTPActivityQuery{Limit: 1, WindowSeconds: 900, DeviceID: event.DeviceID, Host: event.Host, Method: event.Method}
	page := HTTPActivityPage{
		Schema: SchemaVersion, GeneratedAt: anchor.Add(time.Second), QueryAnchor: anchor,
		Events: []HTTPActivityEvent{event}, NextCursor: encodeRecentEventCursor(event.OccurredAt, event.RecordID, anchor),
	}
	if err := page.Validate(query); err != nil {
		t.Fatalf("valid HTTP activity page failed: %v", err)
	}
	page.Events[0].Path = "/v1/orders?token=leak"
	if err := page.Validate(query); err == nil {
		t.Fatal("query-bearing HTTP path was accepted")
	}
}

func TestHTTPActivitySelectNeverReadsPlaintextPayloadFields(t *testing.T) {
	for _, forbidden := range []string{"request_headers", "response_headers", "request_body", "response_body", "authorization", "cookie", "body_preview", "payload,"} {
		if strings.Contains(strings.ToLower(httpActivitySelect), forbidden) {
			t.Fatalf("HTTP activity SELECT contains forbidden field %q: %s", forbidden, httpActivitySelect)
		}
	}
	for _, required := range []string{"http_method", "http_scheme", "http_host", "http_path", "http_status", "request_bytes", "response_bytes", "decrypted"} {
		if !strings.Contains(httpActivitySelect, required) {
			t.Fatalf("HTTP activity SELECT is missing %q", required)
		}
	}
}
