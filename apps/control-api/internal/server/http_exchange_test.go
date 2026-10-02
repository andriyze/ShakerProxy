package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/apitoken"
	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/ingest"
	"shakerproxy.dev/shakerproxy/internal/pcapng/pcapngtest"
)

const (
	exchangeRecordID  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	exchangeRecordID2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	exchangeCaptureID = "capture-00112233445566778899aabbccddeeff"
)

// exchangeEvents serves event details by record ID and a recent-events page.
type exchangeEvents struct {
	details map[string]ingest.EventDetail
	page    ingest.RecentEventPage
	queries []ingest.RecentEventQuery
}

func (e *exchangeEvents) QueryRecent(_ context.Context, query ingest.RecentEventQuery) (ingest.RecentEventPage, error) {
	e.queries = append(e.queries, query)
	return e.page, nil
}

func (e *exchangeEvents) GetEventDetail(_ context.Context, recordID string) (ingest.EventDetail, error) {
	detail, ok := e.details[recordID]
	if !ok {
		return ingest.EventDetail{}, ingest.ErrEventNotFound
	}
	return detail, nil
}

var exchangeAt = time.Date(2026, 10, 2, 3, 30, 0, 30_000_000, time.UTC)

func zeekHTTPEvent() ingest.EventDetail {
	return ingest.EventDetail{Schema: 1, Event: ingest.RecentEvent{
		RecordID: exchangeRecordID, Source: ingest.SourceZeek, Kind: "zeek.http", OccurredAt: exchangeAt, CaptureSessionID: exchangeCaptureID,
		SourceIP: "192.168.10.201", SourcePort: 41234, DestinationIP: "93.184.216.34", DestinationPort: 80, Protocol: "tcp",
		HTTPMethod: "POST", HTTPHost: "device.example", HTTPPath: "/upload",
	}, Payload: json.RawMessage(`{}`)}
}

func exchangeServer(t *testing.T, flow func(capture.FlowRequest) capture.FlowResult) (*Server, string, *exchangeEvents, *labGatewayStub) {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	stub := startLabGatewayStub(t, socketPath, func(request gatewayprotocol.Request) (any, *gatewayprotocol.RPCError) {
		if request.Method != "ReadCaptureFlow" {
			return nil, &gatewayprotocol.RPCError{Code: -32601, Message: "method not found"}
		}
		var params gatewayprotocol.ReadCaptureFlowParams
		if gatewayprotocol.DecodeParams(request.Params, &params) != nil || params.Request.Validate() != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		return flow(params.Request), nil
	})
	server, session := configuredAPIServerWithConfig(t, socketPath, func(config *Config) {
		config.APITokens = &apitoken.Store{Path: filepath.Join(t.TempDir(), "api-tokens.json")}
	})
	events := &exchangeEvents{details: map[string]ingest.EventDetail{exchangeRecordID: zeekHTTPEvent()}}
	server.eventReader = events
	return server, session, events, stub
}

func getExchange(t *testing.T, server *Server, request *http.Request) httpExchangeResponse {
	t.Helper()
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("HTTP exchange returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var response httpExchangeResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestHTTPExchangeIsReadBackFromTheRecording(t *testing.T) {
	conversation := pcapngtest.NewKeepAliveHTTP(exchangeAt.Add(-30 * time.Millisecond))
	server, session, _, stub := exchangeServer(t, func(request capture.FlowRequest) capture.FlowResult {
		return capture.FlowResult{Schema: 1, SessionID: request.SessionID, Client: request.Client, Server: request.Server, SegmentsRead: 2, PacketsMatched: len(conversation.Packets), ClientData: conversation.Client, ServerData: conversation.Server, FromStart: true, Closed: true}
	})
	response := getExchange(t, server, authenticatedJSONRequest(http.MethodGet, "/api/v1/events/"+exchangeRecordID+"/http-exchange", "", session, ""))
	if response.State != "AVAILABLE" || response.Source != "CAPTURE" || len(response.Exchanges) != 2 || response.Matched != 1 {
		t.Fatalf("exchange = %+v", response)
	}
	if response.Exchanges[0].Response.Body.Preview != conversation.JSON || response.Exchanges[1].Request.Body.Preview != "name=phone&value=42" {
		t.Fatalf("bodies were not decoded: %+v", response.Exchanges)
	}
	var params gatewayprotocol.ReadCaptureFlowParams
	if err := gatewayprotocol.DecodeParams(stub.last("ReadCaptureFlow").Params, &params); err != nil {
		t.Fatal(err)
	}
	if params.Request.SessionID != exchangeCaptureID || params.Request.Client != "192.168.10.201:41234" || params.Request.Server != "93.184.216.34:80" || !params.Request.At.Equal(exchangeAt) || params.Request.BeforeSeconds != 300 || params.Request.AfterSeconds != 120 {
		t.Fatalf("flow request = %+v", params.Request)
	}
}

// HTTP content is plaintext evidence: sessions see it as recorded, a
// traffic:read token never does, and only the sensitive traffic:content
// scope reads it, with credentials removed on the server.
func TestHTTPExchangeContentNeedsASessionOrTheContentScope(t *testing.T) {
	conversation := pcapngtest.NewKeepAliveHTTP(exchangeAt.Add(-30 * time.Millisecond))
	server, session, _, stub := exchangeServer(t, func(request capture.FlowRequest) capture.FlowResult {
		return capture.FlowResult{Schema: 1, SessionID: request.SessionID, Client: request.Client, Server: request.Server, SegmentsRead: 2, PacketsMatched: len(conversation.Packets), ClientData: conversation.Client, ServerData: conversation.Server, FromStart: true, Closed: true}
	})
	createToken := func(body string) (int, apitoken.Created) {
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, authenticatedJSONRequest(http.MethodPost, "/api/v1/auth/tokens", body, session, ""))
		var created apitoken.Created
		_ = json.Unmarshal(recorder.Body.Bytes(), &created)
		return recorder.Code, created
	}
	code, metadataOnly := createToken(`{"name":"robot","scopes":["traffic:read"],"expires_in_seconds":3600,"password":"` + activationTestPassword + `"}`)
	if code != http.StatusCreated {
		t.Fatalf("traffic:read token create returned %d", code)
	}
	if code, _ := createToken(`{"name":"agent","scopes":["traffic:read","traffic:content"],"expires_in_seconds":3600,"password":"` + activationTestPassword + `"}`); code != http.StatusBadRequest {
		t.Fatalf("traffic:content was granted without the sensitive-scope acknowledgement: %d", code)
	}
	code, content := createToken(`{"name":"agent","scopes":["traffic:read","traffic:content"],"expires_in_seconds":3600,"password":"` + activationTestPassword + `","sensitive_scope_acknowledged":true}`)
	if code != http.StatusCreated {
		t.Fatalf("traffic:content token create returned %d", code)
	}
	for name, request := range map[string]*http.Request{
		"anonymous":          httptest.NewRequest(http.MethodGet, "/api/v1/events/"+exchangeRecordID+"/http-exchange", nil),
		"traffic:read token": tokenRequest(http.MethodGet, "/api/v1/events/"+exchangeRecordID+"/http-exchange", metadataOnly.Secret),
	} {
		request.Host = "shakerproxy.test"
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized && recorder.Code != http.StatusForbidden {
			t.Fatalf("%s read plaintext HTTP content: %d %s", name, recorder.Code, recorder.Body.String())
		}
	}
	if len(stub.requests) != 0 {
		t.Fatal("an unauthorized request reached the recording")
	}

	request := tokenRequest(http.MethodGet, "/api/v1/events/"+exchangeRecordID+"/http-exchange", content.Secret)
	request.Host = "shakerproxy.test"
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	var redacted httpExchangeResponse
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &redacted) != nil || recorder.Header().Get("X-ShakerProxy-HTTP-Exchange") != "credentials-redacted" {
		t.Fatalf("traffic:content token returned %d %v: %s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "session=secret") || redacted.State != "AVAILABLE" || len(redacted.Exchanges) != 2 || redacted.Exchanges[1].Request.Body.Preview != "name=phone&value=42" {
		t.Fatalf("token exchange was not redacted or lost content: %+v", redacted.Exchanges)
	}
	cookie := redacted.Exchanges[0].Request.Headers.Items[2]
	if cookie.Name != "Cookie" || cookie.Value != "[redacted]" || !cookie.Sensitive {
		t.Fatalf("cookie header = %#v", cookie)
	}
	asAdministrator := httptest.NewRecorder()
	server.Handler().ServeHTTP(asAdministrator, authenticatedJSONRequest(http.MethodGet, "/api/v1/events/"+exchangeRecordID+"/http-exchange", "", session, ""))
	if !strings.Contains(asAdministrator.Body.String(), "session=secret") || asAdministrator.Header().Get("X-ShakerProxy-HTTP-Exchange") != "" {
		t.Fatal("the administrator session no longer sees the exchange as recorded")
	}

	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, authenticatedJSONRequest(http.MethodGet, "/api/v1/events/"+exchangeRecordID+"/http-exchange?x=1", "", session, ""))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("query parameters were accepted: %d", recorder.Code)
	}
}

func TestHTTPExchangeExplainsWhyContentIsMissing(t *testing.T) {
	cases := map[string]struct {
		flow   capture.FlowResult
		event  func(*ingest.EventDetail)
		state  string
		reason string
	}{
		"headers-only capture": {flow: capture.FlowResult{PacketsMatched: 4, HeadersOnly: true}, state: "UNAVAILABLE", reason: "headers only"},
		"still recording":      {flow: capture.FlowResult{OpenSegment: true}, state: "RETRY", reason: "still being written"},
		"rotated away":         {flow: capture.FlowResult{SegmentsMissing: 3}, state: "UNAVAILABLE", reason: "already replaced"},
		"encrypted":            {event: func(detail *ingest.EventDetail) { detail.Event.DestinationPort, detail.Event.HTTPMethod = 443, "" }, state: "UNAVAILABLE", reason: "encrypted (TLS)"},
		"no recording":         {event: func(detail *ingest.EventDetail) { detail.Event.CaptureSessionID = "" }, state: "UNAVAILABLE", reason: "No packet recording"},
	}
	for name, test := range cases {
		server, session, events, _ := exchangeServer(t, func(request capture.FlowRequest) capture.FlowResult {
			result := test.flow
			result.Schema, result.SessionID, result.Client, result.Server = 1, request.SessionID, request.Client, request.Server
			return result
		})
		if test.event != nil {
			detail := events.details[exchangeRecordID]
			test.event(&detail)
			events.details[exchangeRecordID] = detail
		}
		response := getExchange(t, server, authenticatedJSONRequest(http.MethodGet, "/api/v1/events/"+exchangeRecordID+"/http-exchange", "", session, ""))
		if response.State != test.state || !strings.Contains(response.Reason, test.reason) || len(response.Exchanges) != 0 {
			t.Fatalf("%s: %+v", name, response)
		}
	}
}

func TestDecryptedHTTPSExchangePairsTheRequestAndResponseEvents(t *testing.T) {
	server, session, events, stub := exchangeServer(t, func(capture.FlowRequest) capture.FlowResult { return capture.FlowResult{} })
	base := ingest.RecentEvent{Source: ingest.SourceMitmproxy, OccurredAt: exchangeAt, FlowID: "flow-mitm-1", SourceIP: "192.168.10.201", SourcePort: 52000, DestinationIP: "140.82.121.4", DestinationPort: 443, Protocol: "tcp"}
	response := base
	response.RecordID, response.Kind = exchangeRecordID, "http_response"
	request := base
	request.RecordID, request.Kind = exchangeRecordID2, "http_request"
	events.details[exchangeRecordID] = ingest.EventDetail{Schema: 1, Event: response, Payload: json.RawMessage(`{"http_method":"GET","http_path":"/","http_url":"https://github.com/","http_status":200,"http_version":"HTTP/2.0",
		"response_headers":{"items":[{"name":"set-cookie","value":"sid=secret","sensitive":true}],"bytes":20,"truncated":false},
		"response_body":{"content_type":"image/gif","body_bytes":6,"preview_bytes":6,"preview_encoding":"base64","preview":"R0lGODlh","truncated":false}}`)}
	events.details[exchangeRecordID2] = ingest.EventDetail{Schema: 1, Event: request, Payload: json.RawMessage(`{"http_method":"GET","http_path":"/","http_url":"https://github.com/","http_version":"HTTP/2.0",
		"request_headers":{"items":[{"name":"user-agent","value":"phone"}],"bytes":15,"truncated":false},
		"request_body":{"content_type":"","body_bytes":0,"preview_bytes":0,"preview_encoding":"utf-8","preview":"","truncated":false}}`)}
	events.page = ingest.RecentEventPage{Events: []ingest.RecentEvent{response, request}}
	exchange := getExchange(t, server, authenticatedJSONRequest(http.MethodGet, "/api/v1/events/"+exchangeRecordID+"/http-exchange", "", session, ""))
	if exchange.Source != "DECRYPTED" || exchange.State != "AVAILABLE" || len(exchange.Exchanges) != 1 {
		t.Fatalf("decrypted exchange = %+v", exchange)
	}
	pair := exchange.Exchanges[0]
	if pair.Request.Target != "https://github.com/" || pair.Request.Headers.Items[0].Name != "user-agent" || pair.Response.StatusCode != 200 || !pair.Response.Headers.Items[0].Sensitive {
		t.Fatalf("pair = %+v / %+v", pair.Request, pair.Response)
	}
	if pair.Response.Body.PreviewEncoding != "hex" || !strings.HasPrefix(pair.Response.Body.Preview, "00000000  47 49 46 38 39 61") {
		t.Fatalf("binary decrypted body = %+v", pair.Response.Body)
	}
	if len(stub.requests) != 0 {
		t.Fatal("a decrypted exchange read the packet recording")
	}
	if len(events.queries) != 1 || events.queries[0].Source != ingest.SourceMitmproxy {
		t.Fatalf("pairing query = %+v", events.queries)
	}
}
