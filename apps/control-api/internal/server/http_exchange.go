package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/httpexchange"
	"shakerproxy.dev/shakerproxy/internal/ingest"
)

// An HTTP event's request and response, like Wireshark's "Follow HTTP
// stream": read back from the packet recording for cleartext HTTP, or from
// the decrypted events mitmproxy recorded for intercepted HTTPS. Headers and
// bodies are plaintext evidence, so like the event detail payload they are
// for signed-in administrators only, never API tokens.

const (
	httpExchangeSchema = 1
	// The HTTP event marks the request; the connection may have opened
	// earlier (keep-alive) and carried later exchanges.
	httpExchangeBefore = 5 * time.Minute
	httpExchangeAfter  = 2 * time.Minute
)

type httpExchangeCapture struct {
	SessionID       string     `json:"session_id"`
	SegmentsRead    int        `json:"segments_read"`
	SegmentsMissing int        `json:"segments_missing"`
	Packets         int        `json:"packets"`
	FirstPacketAt   *time.Time `json:"first_packet_at,omitempty"`
	LastPacketAt    *time.Time `json:"last_packet_at,omitempty"`
	FromStart       bool       `json:"from_start"`
	Closed          bool       `json:"closed"`
	Incomplete      bool       `json:"incomplete"`
}

type httpExchangeResponse struct {
	Schema   int    `json:"schema"`
	RecordID string `json:"record_id"`
	// Source is CAPTURE (cleartext from the packet recording) or DECRYPTED
	// (intercepted HTTPS).
	Source string `json:"source"`
	// State is AVAILABLE, UNAVAILABLE (Reason says why) or RETRY (the part
	// of the recording is still being written).
	State     string                  `json:"state"`
	Reason    string                  `json:"reason,omitempty"`
	Matched   int                     `json:"matched"`
	Exchanges []httpexchange.Exchange `json:"exchanges"`
	Notes     []string                `json:"notes,omitempty"`
	Capture   *httpExchangeCapture    `json:"capture,omitempty"`
}

func (s *Server) getHTTPExchange(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	recordID := r.PathValue("recordID")
	if !eventDetailRecordIDPattern.MatchString(recordID) || r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "HTTP exchange takes one event record ID and no query parameters")
		return
	}
	reader, ok := s.eventReader.(ingest.EventDetailReader)
	if !ok || reader == nil {
		writeError(w, http.StatusServiceUnavailable, "event_detail_unavailable", "normalized event detail storage is unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	detail, err := reader.GetEventDetail(ctx, recordID)
	if errors.Is(err, ingest.ErrEventNotFound) {
		writeError(w, http.StatusNotFound, "event_not_found", "normalized event was not found")
		return
	}
	if err != nil {
		s.logger.Warn("HTTP exchange event lookup failed", "record_id", recordID, "error", err)
		writeError(w, http.StatusServiceUnavailable, "event_detail_unavailable", "normalized event detail is temporarily unavailable")
		return
	}
	var response httpExchangeResponse
	if detail.Event.Source == ingest.SourceMitmproxy {
		response = s.decryptedHTTPExchange(ctx, reader, detail)
	} else {
		response = s.capturedHTTPExchange(ctx, detail.Event)
	}
	response.Schema, response.RecordID = httpExchangeSchema, recordID
	if response.Exchanges == nil {
		response.Exchanges = []httpexchange.Exchange{}
	}
	s.logger.Info("HTTP exchange viewed", "username", sessionUsername(r.Context()), "record_id", recordID, "source", response.Source, "state", response.State, "capture_id", detail.Event.CaptureSessionID, "exchanges", len(response.Exchanges))
	writeJSON(w, http.StatusOK, response)
}

const headersOnlyNote = "This recording kept only the start of each packet (headers only), so parts of these messages were not recorded. Full-packet recordings show everything."

func unavailableExchange(source, reason string) httpExchangeResponse {
	return httpExchangeResponse{Source: source, State: "UNAVAILABLE", Reason: reason, Matched: -1}
}

func (s *Server) capturedHTTPExchange(ctx context.Context, event ingest.RecentEvent) httpExchangeResponse {
	if !strings.EqualFold(event.Protocol, "tcp") && event.Protocol != "" {
		return unavailableExchange("CAPTURE", "This event is not a TCP connection, so it has no HTTP exchange.")
	}
	if event.DestinationPort == 443 && event.HTTPMethod == "" {
		return unavailableExchange("CAPTURE", "This connection is encrypted (TLS). Its requests and responses are visible only with HTTPS decryption for this device.")
	}
	if event.CaptureSessionID == "" || !capture.ValidSessionID(event.CaptureSessionID) {
		return unavailableExchange("CAPTURE", "No packet recording covers this connection.")
	}
	client, clientErr := netip.ParseAddr(event.SourceIP)
	server, serverErr := netip.ParseAddr(event.DestinationIP)
	if clientErr != nil || serverErr != nil || event.SourcePort <= 0 || event.SourcePort > 65535 || event.DestinationPort <= 0 || event.DestinationPort > 65535 {
		return unavailableExchange("CAPTURE", "This event does not record both ends of the connection, so it cannot be found in the recording.")
	}
	request := capture.FlowRequest{
		Schema:        capture.FlowRequestSchema,
		SessionID:     event.CaptureSessionID,
		Client:        netip.AddrPortFrom(client.Unmap(), uint16(event.SourcePort)).String(),
		Server:        netip.AddrPortFrom(server.Unmap(), uint16(event.DestinationPort)).String(),
		At:            event.OccurredAt.UTC(),
		BeforeSeconds: int(httpExchangeBefore / time.Second),
		AfterSeconds:  int(httpExchangeAfter / time.Second),
	}
	var flow capture.FlowResult
	if err := s.gateway.Call(ctx, "ReadCaptureFlow", gatewayprotocol.ReadCaptureFlowParams{Request: request}, &flow); err != nil {
		s.logger.Warn("HTTP exchange capture read failed", "capture_id", event.CaptureSessionID, "error", err)
		return unavailableExchange("CAPTURE", "The packet recording could not be read right now; try again.")
	}
	summary := &httpExchangeCapture{
		SessionID: flow.SessionID, SegmentsRead: flow.SegmentsRead, SegmentsMissing: flow.SegmentsMissing, Packets: flow.PacketsMatched,
		FirstPacketAt: flow.FirstPacketAt, LastPacketAt: flow.LastPacketAt, FromStart: flow.FromStart, Closed: flow.Closed,
		Incomplete: flow.ClientGap || flow.ServerGap || flow.ClientTruncated || flow.ServerTruncated || flow.LimitReached,
	}
	switch {
	case flow.PacketsMatched == 0 && flow.OpenSegment:
		return httpExchangeResponse{Source: "CAPTURE", State: "RETRY", Reason: "This part of the recording is still being written. It can be read once the current file closes, usually within half a minute.", Matched: -1, Capture: summary}
	case flow.PacketsMatched == 0 && flow.SegmentsMissing > 0:
		response := unavailableExchange("CAPTURE", "The recording files for this time were already replaced: the recording keeps only its most recent files.")
		response.Capture = summary
		return response
	case flow.PacketsMatched == 0:
		response := unavailableExchange("CAPTURE", "This connection's packets are not in the recording.")
		response.Capture = summary
		return response
	}
	parsed := httpexchange.Parse(flow.ClientData, flow.ServerData)
	response := httpExchangeResponse{Source: "CAPTURE", State: "AVAILABLE", Exchanges: parsed.Exchanges, Notes: parsed.Notes, Capture: summary, Matched: matchExchange(parsed.Exchanges, event)}
	if flow.HeadersOnly {
		// A headers-only recording keeps the start of each packet: usually
		// the request line and headers, but not the rest.
		response.Notes = append([]string{headersOnlyNote}, response.Notes...)
		if len(parsed.Exchanges) == 0 {
			response.State, response.Reason = "UNAVAILABLE", headersOnlyNote
			response.Notes = nil
		}
		return response
	}
	if flow.ClientGap || flow.ServerGap {
		response.Notes = append(response.Notes, "Some packets of this connection are missing from the recording; exchanges after the gap are not shown.")
	}
	if flow.ClientTruncated || flow.ServerTruncated || flow.LimitReached {
		response.Notes = append(response.Notes, fmt.Sprintf("Only the first %d KiB of each direction are shown.", capture.MaxFlowStreamBytes>>10))
	}
	if flow.OpenSegment {
		response.Notes = append(response.Notes, "Part of this connection may still be in the file being recorded; reopen this event shortly to see the rest.")
	}
	if len(parsed.Exchanges) == 0 {
		response.State = "UNAVAILABLE"
		response.Reason = "The recorded packets of this connection do not contain a readable HTTP/1.x request or response."
	}
	return response
}

// matchExchange finds the exchange the clicked event describes: same method
// and path, otherwise the first one.
func matchExchange(exchanges []httpexchange.Exchange, event ingest.RecentEvent) int {
	if len(exchanges) == 0 {
		return -1
	}
	for index, exchange := range exchanges {
		if exchange.Request == nil {
			continue
		}
		path, _, _ := strings.Cut(exchange.Request.Target, "?")
		if parsed, err := url.Parse(exchange.Request.Target); err == nil && parsed.IsAbs() {
			path = parsed.Path
		}
		if (event.HTTPMethod == "" || strings.EqualFold(exchange.Request.Method, event.HTTPMethod)) && (event.HTTPPath == "" || path == event.HTTPPath) {
			return index
		}
	}
	return 0
}

// mitmHeaders and mitmBody are the shapes the mitmproxy addon records
// (apps/mitmproxy/shakerproxy_addon.py _header_snapshot and _body_snapshot).
type mitmHeaders struct {
	Items     []httpexchange.Header `json:"items"`
	Bytes     int                   `json:"bytes"`
	Truncated bool                  `json:"truncated"`
}

type mitmBody struct {
	ContentType     string `json:"content_type"`
	ContentEncoding string `json:"content_encoding"`
	DecodedPreview  bool   `json:"decoded_preview"`
	BodyBytes       *int64 `json:"body_bytes"`
	PreviewBytes    int    `json:"preview_bytes"`
	PreviewEncoding string `json:"preview_encoding"`
	Preview         string `json:"preview"`
	Truncated       bool   `json:"truncated"`
	Streamed        bool   `json:"streamed"`
}

type mitmHTTPPayload struct {
	HTTPMethod      string       `json:"http_method"`
	HTTPPath        string       `json:"http_path"`
	HTTPURL         string       `json:"http_url"`
	HTTPVersion     string       `json:"http_version"`
	HTTPStatus      int          `json:"http_status"`
	RequestHeaders  *mitmHeaders `json:"request_headers"`
	RequestBody     *mitmBody    `json:"request_body"`
	ResponseHeaders *mitmHeaders `json:"response_headers"`
	ResponseBody    *mitmBody    `json:"response_body"`
}

func (s *Server) decryptedHTTPExchange(ctx context.Context, reader ingest.EventDetailReader, detail ingest.EventDetail) httpExchangeResponse {
	event := detail.Event
	if event.Kind != "http_request" && event.Kind != "http_response" {
		return unavailableExchange("DECRYPTED", "This decrypted event is not a web request.")
	}
	var clicked mitmHTTPPayload
	if err := json.Unmarshal(detail.Payload, &clicked); err != nil {
		return unavailableExchange("DECRYPTED", "The stored decrypted request could not be read.")
	}
	request, response := mitmHTTPPayload{}, mitmHTTPPayload{}
	hasRequest, hasResponse := false, false
	if event.Kind == "http_request" {
		request, hasRequest = clicked, true
	} else {
		response, hasResponse = clicked, true
	}
	// The other half of the exchange is a separate event with the same flow.
	if other, ok := s.pairedMitmEvent(ctx, reader, event); ok {
		var payload mitmHTTPPayload
		if json.Unmarshal(other.Payload, &payload) == nil {
			if other.Event.Kind == "http_request" && !hasRequest {
				request, hasRequest = payload, true
			} else if other.Event.Kind == "http_response" && !hasResponse {
				response, hasResponse = payload, true
			}
		}
	}
	exchange := httpexchange.Exchange{}
	notes := []string{}
	retained := false
	if hasRequest || hasResponse {
		source := request
		if !hasRequest {
			source = response
		}
		target := source.HTTPURL
		if target == "" {
			target = source.HTTPPath
		}
		exchange.Request = &httpexchange.Request{Method: source.HTTPMethod, Target: target, Proto: request.HTTPVersion, Headers: mitmHeadersToExchange(request.RequestHeaders), Body: mitmBodyToExchange(request.RequestBody)}
		retained = retained || request.RequestHeaders != nil
	}
	if hasResponse {
		exchange.Response = &httpexchange.Response{Proto: response.HTTPVersion, StatusCode: response.HTTPStatus, Status: http.StatusText(response.HTTPStatus), Headers: mitmHeadersToExchange(response.ResponseHeaders), Body: mitmBodyToExchange(response.ResponseBody)}
		retained = retained || response.ResponseHeaders != nil
	} else {
		notes = append(notes, "No response was recorded for this request.")
	}
	if !retained {
		notes = append(notes, "Decrypted headers and bodies are not kept (content retention is off), so only the request line and status are shown.")
	}
	return httpExchangeResponse{Source: "DECRYPTED", State: "AVAILABLE", Exchanges: []httpexchange.Exchange{exchange}, Matched: 0, Notes: notes}
}

func (s *Server) pairedMitmEvent(ctx context.Context, reader ingest.EventDetailReader, event ingest.RecentEvent) (ingest.EventDetail, bool) {
	if event.FlowID == "" || event.SourceIP == "" || event.SourcePort <= 0 || s.eventReader == nil {
		return ingest.EventDetail{}, false
	}
	start := event.OccurredAt.Add(-10 * time.Minute).UTC().Format(time.RFC3339Nano)
	end := event.OccurredAt.Add(10 * time.Minute).UTC().Format(time.RFC3339Nano)
	values := url.Values{
		"limit":  {"50"},
		"source": {string(ingest.SourceMitmproxy)},
		"q":      {fmt.Sprintf("src.ip:%s AND src.port:%s AND time>=%s AND time<=%s", event.SourceIP, strconv.Itoa(event.SourcePort), start, end)},
	}
	query, err := ingest.ParseRecentEventQuery(values)
	if err != nil {
		return ingest.EventDetail{}, false
	}
	page, err := s.eventReader.QueryRecent(ctx, query)
	if err != nil {
		return ingest.EventDetail{}, false
	}
	want := "http_response"
	if event.Kind == "http_response" {
		want = "http_request"
	}
	for _, candidate := range page.Events {
		if candidate.FlowID == event.FlowID && candidate.Kind == want && candidate.RecordID != event.RecordID {
			detail, err := reader.GetEventDetail(ctx, candidate.RecordID)
			return detail, err == nil
		}
	}
	return ingest.EventDetail{}, false
}

func mitmHeadersToExchange(headers *mitmHeaders) httpexchange.Headers {
	if headers == nil {
		return httpexchange.Headers{Items: []httpexchange.Header{}}
	}
	items := headers.Items
	if items == nil {
		items = []httpexchange.Header{}
	}
	return httpexchange.Headers{Items: items, Bytes: headers.Bytes, Truncated: headers.Truncated}
}

func mitmBodyToExchange(body *mitmBody) httpexchange.Body {
	if body == nil {
		return httpexchange.Body{PreviewEncoding: "utf-8", Complete: true, Note: "The body was not kept."}
	}
	result := httpexchange.Body{ContentType: body.ContentType, ContentEncoding: body.ContentEncoding, DecodedPreview: body.DecodedPreview, PreviewBytes: body.PreviewBytes, Truncated: body.Truncated, Complete: !body.Streamed, PreviewEncoding: "utf-8", Preview: body.Preview}
	if body.BodyBytes != nil {
		result.BodyBytes = *body.BodyBytes
	}
	if body.Streamed {
		result.Note = "The body was too large to keep; it was passed through without a copy."
	}
	if body.PreviewEncoding == "base64" {
		decoded, err := base64.StdEncoding.DecodeString(body.Preview)
		if err != nil {
			result.Preview, result.PreviewBytes = "", 0
			result.Note = "The stored body preview could not be read."
			return result
		}
		result = httpexchange.HexPreview(result, decoded)
	}
	return result
}
