package mcpserver

// The tools here close the gaps between what the web UI shows and what an
// agent can read (docs/api-mcp-parity.md): one event's essentials, an HTTP
// event's request and response, following traffic live in order, and
// encrypted DNS.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"shakerproxy.dev/shakerproxy/internal/agentapi"
	"shakerproxy.dev/shakerproxy/internal/httpexchange"
	"shakerproxy.dev/shakerproxy/internal/ingest"
)

const (
	defaultExchangeBodyBytes = 4 << 10
	maxExchangeBodyBytes     = 16 << 10
	maxExchangesShown        = 8
	maxExchangeHeaders       = 64
	maxExchangeHeaderValue   = 512
	defaultFollowWait        = 10
)

type EventDetailArgs struct {
	RecordID string `json:"record_id" jsonschema:"the 64-character record_id from a search_traffic, device_activity or follow_traffic result"`
}

type HTTPExchangeArgs struct {
	RecordID  string `json:"record_id" jsonschema:"record_id of an HTTP event (zeek.http, http_request or http_response)"`
	BodyBytes int    `json:"body_bytes,omitempty" jsonschema:"how much of each body to show, 0-16384 bytes, default 4096"`
}

type FollowTrafficArgs struct {
	Query       string `json:"query,omitempty" jsonschema:"optional ShakerProxy query (search_traffic syntax); keep it the same on every call with a cursor"`
	Device      string `json:"device,omitempty" jsonschema:"optional friendly name, IP address, MAC address, or device ID"`
	Cursor      string `json:"cursor,omitempty" jsonschema:"next_cursor from the previous follow_traffic call, or live_cursor from search_traffic; omit to start with the newest events"`
	WaitSeconds *int   `json:"wait_seconds,omitempty" jsonschema:"how long to wait for new events, 0-25 seconds, default 10"`
	Limit       int    `json:"limit,omitempty" jsonschema:"maximum events, 1-100, default 50"`
}

type EncryptedDNSArgs struct {
	Device string `json:"device,omitempty" jsonschema:"optional friendly name, IP address, MAC address, or device ID"`
	Window string `json:"window,omitempty" jsonschema:"one of 5m, 15m, 1h, 6h, 24h, 7d, 30d; default 24h"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum events, 1-100, default 50"`
	Cursor string `json:"cursor,omitempty" jsonschema:"next_cursor from a previous call"`
}

type eventFact struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// eventDetail is one event as the event detail drawer shows it: the line,
// its type, the facts that matter for that type, and the metadata-only
// record underneath.
func (s *Service) eventDetail(ctx context.Context, _ *mcp.CallToolRequest, args EventDetailArgs) (*mcp.CallToolResult, any, error) {
	recordID := strings.TrimSpace(args.RecordID)
	if !recordIDPattern.MatchString(recordID) {
		return nil, nil, errors.New("record_id must be the 64-character lowercase hexadecimal record_id from a search result")
	}
	detail, err := s.backend.EventMetadata(ctx, recordID)
	if err != nil {
		return nil, nil, fmt.Errorf("read event %s: %w", recordID, err)
	}
	var payload map[string]any
	_ = json.Unmarshal(detail.Payload, &payload)
	event := agentapi.Event{RecentEvent: detail.Event}
	streamType := ingest.StreamType(detail.Event)
	result := struct {
		Summary string             `json:"summary"`
		Type    string             `json:"type"`
		Event   eventLine          `json:"event"`
		Facts   []eventFact        `json:"facts"`
		Next    string             `json:"next,omitempty"`
		Detail  ingest.EventDetail `json:"detail"`
	}{Summary: recentEventSummary(event), Type: streamType, Event: newEventLine(event), Facts: eventFacts(detail.Event, payload, streamType), Detail: detail}
	if streamType == ingest.StreamHTTP || detail.Event.HTTPMethod != "" {
		result.Next = "Call http_exchange with this record_id to read the request and response."
	}
	return textResult(result)
}

// eventFacts mirrors the web UI's EventEssentials: only what is known, by
// event type.
func eventFacts(event ingest.RecentEvent, payload map[string]any, streamType string) []eventFact {
	facts := []eventFact{}
	add := func(label, value string) {
		if value = strings.TrimSpace(value); value != "" && len(facts) < 24 {
			facts = append(facts, eventFact{Label: label, Value: truncateText(value, 512)})
		}
	}
	destination := hostPort(event.DestinationIP, event.DestinationPort)
	add("Device", firstNonEmpty(event.DeviceFriendlyName, event.DeviceID))
	add("From", hostPort(event.SourceIP, event.SourcePort))
	if event.Blocked {
		add("Blocked", "yes, by ShakerProxy: "+blockReasonLabel(event.BlockedReason))
	}
	switch streamType {
	case ingest.StreamDNS, ingest.StreamDiscovery, ingest.StreamBlocked:
		if label := encryptedDNSLabel(event); label != "" && event.DNSQuery == "" {
			add("Encrypted DNS", label+": the names looked up are hidden inside the connection")
			add("Resolver", firstNonEmpty(event.TLSServerName, event.DNSName, destination))
			break
		}
		add("Looked up", event.DNSQuery)
		add("Sent to", destination)
		add("Type", firstNonEmpty(event.DNSRecordType, payloadText(payload, "qtype_name")))
		add("Result", firstNonEmpty(event.DNSResponseCode, payloadText(payload, "rcode_name")))
		if event.Kind == "shakerproxy.dns" {
			add("Answered by", "ShakerProxy")
		}
		answers := append([]string(nil), event.DNSAnswers...)
		if len(answers) == 0 {
			answers = payloadAnswers(payload)
		}
		if len(answers) > 0 {
			add("Answers", strings.Join(answers[:min(len(answers), 16)], ", "))
		}
	case ingest.StreamAlert:
		add("Alert", firstNonEmpty(event.AlertSignature, event.DetectionSummary))
		add("Category", event.AlertCategory)
		if event.AlertSeverity > 0 {
			add("Severity", strconv.Itoa(event.AlertSeverity))
		} else {
			add("Severity", event.DetectionSeverity)
		}
		add("Destination", destination)
	case ingest.StreamHTTP:
		add("Request", strings.TrimSpace(event.HTTPMethod+" "+event.HTTPHost+event.HTTPPath))
		if event.HTTPStatus > 0 {
			add("Status", strconv.Itoa(event.HTTPStatus))
		}
		add("Destination", destination)
		add("Decryption", strings.ToLower(event.TLSInterceptionState))
	case ingest.StreamWiFi:
		wifiFacts(event.WiFi, add)
	default:
		add("Server name", firstNonEmpty(event.TLSServerName, event.DNSName))
		add("Destination", destination)
		add("Owner", destinationOwnerLabel(event))
		protocol := strings.ToUpper(event.Protocol)
		if event.AppProtocol != "" {
			protocol = strings.TrimSpace(strings.ToUpper(event.AppProtocol) + " over " + protocol)
		}
		add("Protocol", strings.TrimSuffix(protocol, " over "))
		if event.BytesSent != nil {
			add("Sent", formatBytes(*event.BytesSent))
		}
		if event.BytesReceived != nil {
			add("Received", formatBytes(*event.BytesReceived))
		}
		if event.BytesSent == nil && event.BytesReceived == nil && event.NetworkBytes > 0 {
			add("Total", formatBytes(event.NetworkBytes))
		}
		add("TLS version", firstNonEmpty(payloadText(payload, "tls_version"), payloadText(payload, "version")))
		add("Decryption", strings.ToLower(event.TLSInterceptionState))
		add("Decryption failure", event.TLSFailureReason)
	}
	return facts
}

func wifiFacts(wifi *ingest.WiFiFields, add func(string, string)) {
	if wifi == nil {
		return
	}
	switch {
	case wifi.SSID != "":
		add("Network", wifi.SSID)
	case wifi.Wildcard:
		add("Network", "any network (scan)")
	case wifi.Hidden:
		add("Network", "hidden network")
	}
	add("Access point", wifi.BSSID)
	if wifi.ClientMAC != "" {
		mac := wifi.ClientMAC
		if wifi.Randomized {
			mac += " (randomized)"
		}
		add("Device address", mac)
	}
	if wifi.PossibleMAC != "" {
		add("Possibly", wifi.PossibleMAC+": same radio fingerprint and sequence numbers, not proof")
	}
	switch wifi.Direction {
	case "from_ap":
		add("Sent by", "the access point")
	case "from_client":
		add("Sent by", "the device")
	}
	switch {
	case wifi.NoResponse:
		add("Outcome", "no answer from the access point")
	case wifi.Success != nil && *wifi.Success:
		add("Outcome", "success")
	case wifi.Success != nil:
		add("Outcome", "refused: "+firstNonEmpty(wifi.Status, "unknown"))
	}
	add("Authentication", wifi.Algorithm)
	if wifi.Reassociation {
		add("Roamed from", wifi.PreviousBSSID)
	}
	if wifi.Protected {
		add("Reason", "hidden (management frame protection encrypted it)")
	} else if wifi.Reason != "" && wifi.ReasonCode != nil {
		add("Reason", fmt.Sprintf("%s (%d)", wifi.Reason, *wifi.ReasonCode))
	}
	add("Security", wifi.Security)
	if wifi.Channel > 0 {
		channel := strconv.Itoa(wifi.Channel)
		if wifi.FrequencyMHz > 0 {
			channel += fmt.Sprintf(" (%d MHz)", wifi.FrequencyMHz)
		}
		add("Channel", channel)
	}
	if wifi.SignalMinDBM != nil && wifi.SignalMaxDBM != nil && *wifi.SignalMinDBM != *wifi.SignalMaxDBM {
		add("Signal", fmt.Sprintf("%d to %d dBm", *wifi.SignalMinDBM, *wifi.SignalMaxDBM))
	} else if wifi.SignalDBM != nil {
		add("Signal", fmt.Sprintf("%d dBm", *wifi.SignalDBM))
	}
	if wifi.Scope == "nearby" {
		add("Recorded as", "nearby, not part of the lab (deleted after 24 hours)")
	}
}

func payloadText(payload map[string]any, key string) string {
	switch value := payload[key].(type) {
	case string:
		return value
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64)
	case bool:
		if value {
			return "yes"
		}
		return "no"
	}
	return ""
}

// payloadAnswers reads DNS answers from any source: Zeek stores strings, the
// ShakerProxy forwarder and Suricata store records.
func payloadAnswers(payload map[string]any) []string {
	raw, _ := payload["answers"].([]any)
	answers := []string{}
	for _, answer := range raw {
		switch value := answer.(type) {
		case string:
			answers = append(answers, value)
		case map[string]any:
			data := firstNonEmpty(payloadText(value, "data"), payloadText(value, "rdata"), payloadText(value, "value"), payloadText(value, "address"))
			text := strings.TrimSpace(strings.Join([]string{firstNonEmpty(payloadText(value, "type"), payloadText(value, "rrtype")), data}, " "))
			if text != "" {
				answers = append(answers, text)
			}
		}
		if len(answers) == 16 {
			break
		}
	}
	return answers
}

type exchangeHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type exchangeBody struct {
	ContentType string `json:"content_type,omitempty"`
	Bytes       int64  `json:"bytes"`
	Text        string `json:"text,omitempty"`
	Shown       int    `json:"shown_bytes"`
	Truncated   bool   `json:"truncated,omitempty"`
	Note        string `json:"note,omitempty"`
}

type exchangeMessage struct {
	Line    string           `json:"line"`
	Headers []exchangeHeader `json:"headers"`
	Body    *exchangeBody    `json:"body,omitempty"`
}

type exchangePair struct {
	Request  *exchangeMessage `json:"request,omitempty"`
	Response *exchangeMessage `json:"response,omitempty"`
	Matches  bool             `json:"matches_event,omitempty"`
}

func (s *Service) httpExchange(ctx context.Context, _ *mcp.CallToolRequest, args HTTPExchangeArgs) (*mcp.CallToolResult, any, error) {
	recordID := strings.TrimSpace(args.RecordID)
	if !recordIDPattern.MatchString(recordID) {
		return nil, nil, errors.New("record_id must be the 64-character lowercase hexadecimal record_id of an HTTP event")
	}
	bodyBytes := args.BodyBytes
	if bodyBytes == 0 {
		bodyBytes = defaultExchangeBodyBytes
	}
	if bodyBytes < 0 || bodyBytes > maxExchangeBodyBytes {
		return nil, nil, fmt.Errorf("body_bytes must be between 0 and %d", maxExchangeBodyBytes)
	}
	exchange, err := s.backend.HTTPExchange(ctx, recordID)
	if err != nil {
		var apiErr *agentapi.APIError
		if errors.As(err, &apiErr) && apiErr.Status == 403 {
			return nil, nil, errors.New("this agent's ShakerProxy token cannot read HTTP content: it needs the traffic:content scope. An administrator can create one in Integrations → API tokens (traffic:content is a sensitive scope; credentials stay redacted). http_requests and event_detail work without it")
		}
		return nil, nil, fmt.Errorf("read the HTTP exchange of %s: %w", recordID, err)
	}
	pairs := make([]exchangePair, 0, min(len(exchange.Exchanges), maxExchangesShown))
	for index, pair := range exchange.Exchanges {
		if index == maxExchangesShown {
			break
		}
		shown := exchangePair{Matches: index == exchange.Matched}
		if pair.Request != nil {
			shown.Request = exchangeRequestMessage(pair.Request, bodyBytes)
		}
		if pair.Response != nil {
			shown.Response = exchangeResponseMessage(pair.Response, bodyBytes)
		}
		pairs = append(pairs, shown)
	}
	summary := ""
	switch exchange.State {
	case "AVAILABLE":
		summary = fmt.Sprintf("%s on this connection, read from %s; credentials are redacted.", countNoun(len(exchange.Exchanges), "HTTP exchange", "HTTP exchanges"), exchangeSourceLabel(exchange.Source))
		if len(exchange.Exchanges) > maxExchangesShown {
			summary += fmt.Sprintf(" Showing the first %d.", maxExchangesShown)
		}
	case "RETRY":
		summary = "Not readable yet: " + exchange.Reason + " Call again shortly."
	default:
		summary = "No HTTP content: " + exchange.Reason
	}
	notes := make([]string, 0, len(exchange.Notes))
	for _, note := range exchange.Notes {
		notes = append(notes, truncateText(note, 300))
	}
	return contentResult(struct {
		Summary   string         `json:"summary"`
		State     string         `json:"state"`
		Source    string         `json:"source"`
		Exchanges []exchangePair `json:"exchanges"`
		Notes     []string       `json:"notes,omitempty"`
	}{Summary: boundText(summary, 600), State: exchange.State, Source: exchange.Source, Exchanges: pairs, Notes: notes})
}

func exchangeSourceLabel(source string) string {
	if source == "DECRYPTED" {
		return "decrypted HTTPS"
	}
	return "the packet recording"
}

func exchangeRequestMessage(request *httpexchange.Request, bodyBytes int) *exchangeMessage {
	return &exchangeMessage{
		Line:    truncateText(strings.TrimSpace(request.Method+" "+request.Target+" "+request.Proto), 1024),
		Headers: exchangeHeaders(request.Headers),
		Body:    exchangeBodyPreview(request.Body, bodyBytes),
	}
}

func exchangeResponseMessage(response *httpexchange.Response, bodyBytes int) *exchangeMessage {
	line := strings.TrimSpace(response.Proto + " " + strconv.Itoa(response.StatusCode) + " " + strings.TrimSpace(strings.TrimPrefix(response.Status, strconv.Itoa(response.StatusCode))))
	return &exchangeMessage{Line: truncateText(line, 256), Headers: exchangeHeaders(response.Headers), Body: exchangeBodyPreview(response.Body, bodyBytes)}
}

func exchangeHeaders(headers httpexchange.Headers) []exchangeHeader {
	shown := make([]exchangeHeader, 0, min(len(headers.Items), maxExchangeHeaders))
	for _, header := range headers.Items {
		if len(shown) == maxExchangeHeaders {
			break
		}
		value := header.Value
		if header.Sensitive || httpexchange.IsSensitiveHeader(header.Name) {
			value = httpexchange.Redacted
		}
		shown = append(shown, exchangeHeader{Name: truncateText(header.Name, 128), Value: truncateText(value, maxExchangeHeaderValue)})
	}
	return shown
}

func exchangeBodyPreview(body httpexchange.Body, limit int) *exchangeBody {
	if body.BodyBytes == 0 && body.Preview == "" {
		return nil
	}
	shown := &exchangeBody{ContentType: body.ContentType, Bytes: body.BodyBytes, Note: truncateText(body.Note, 200)}
	if body.PreviewEncoding != "" && body.PreviewEncoding != "utf-8" {
		shown.Note = strings.TrimSpace("Binary body (" + body.PreviewEncoding + " preview not shown to agents). " + shown.Note)
		shown.Truncated = body.BodyBytes > 0
		return shown
	}
	text := body.Preview
	if len(text) > limit {
		text = text[:limit]
		for len(text) > 0 && !utf8.ValidString(text) {
			text = text[:len(text)-1]
		}
		shown.Truncated = true
	}
	shown.Text, shown.Shown = text, len(text)
	shown.Truncated = shown.Truncated || body.Truncated || !body.Complete
	return shown
}

func (s *Service) followTraffic(ctx context.Context, _ *mcp.CallToolRequest, args FollowTrafficArgs) (*mcp.CallToolResult, any, error) {
	limit, err := normalizeLimit(args.Limit)
	if err != nil {
		return nil, nil, err
	}
	wait := defaultFollowWait
	if args.WaitSeconds != nil {
		wait = *args.WaitSeconds
	}
	if wait < 0 || time.Duration(wait)*time.Second > agentapi.MaxFollowWait {
		return nil, nil, fmt.Errorf("wait_seconds must be between 0 and %d", int(agentapi.MaxFollowWait/time.Second))
	}
	query := strings.TrimSpace(args.Query)
	if len(query) > 1900 {
		return nil, nil, errors.New("query is limited to 1900 characters")
	}
	scope := "on the lab"
	if strings.TrimSpace(args.Device) != "" {
		device, err := s.resolveDevice(ctx, args.Device)
		if err != nil {
			return nil, nil, err
		}
		scope = "for " + device.FriendlyName
		if query == "" {
			query = "device.id:" + device.DeviceID
		} else {
			query = "device.id:" + device.DeviceID + " AND (" + query + ")"
		}
	}
	type followResult struct {
		Summary    string      `json:"summary"`
		Query      string      `json:"query"`
		Started    bool        `json:"started,omitempty"`
		Events     []eventLine `json:"events"`
		NextCursor string      `json:"next_cursor"`
	}
	cursor := strings.TrimSpace(args.Cursor)
	if cursor == "" {
		// Start with the newest events, oldest first, and a cursor that
		// continues exactly after them.
		page, err := s.backend.TrafficSearch(ctx, agentapi.TrafficSearchRequest{Query: query, Limit: limit})
		if err != nil {
			return nil, nil, fmt.Errorf("start following traffic: %w (see the query syntax in search_traffic)", err)
		}
		if err := checkPageBound(len(page.Events), limit); err != nil {
			return nil, nil, err
		}
		if page.LiveCursor == "" {
			return nil, nil, errors.New("this ShakerProxy version does not offer live cursors; use search_traffic")
		}
		lines := eventLines(page.Events)
		for left, right := 0, len(lines)-1; left < right; left, right = left+1, right-1 {
			lines[left], lines[right] = lines[right], lines[left]
		}
		summary := fmt.Sprintf("Following traffic %s: the %s, oldest first. Call follow_traffic again with next_cursor and the same query and device to get what arrives next.", scope, countNoun(len(lines), "newest event", "newest events"))
		return textResult(followResult{Summary: summary, Query: query, Started: true, Events: lines, NextCursor: page.LiveCursor})
	}
	batch, err := s.backend.FollowTraffic(ctx, agentapi.FollowRequest{Query: query, Cursor: cursor, Limit: limit, Wait: time.Duration(wait) * time.Second})
	if err != nil {
		return nil, nil, fmt.Errorf("follow traffic: %w (pass the same query and device you started with)", err)
	}
	if len(batch.Events) > limit {
		return nil, nil, errors.New("ShakerProxy returned more events than requested; refusing the batch")
	}
	summary := fmt.Sprintf("%s arrived %s, in the order ShakerProxy received them. Call again with next_cursor to keep following.", countNoun(len(batch.Events), "new event", "new events"), scope)
	if len(batch.Events) == 0 {
		summary = fmt.Sprintf("Nothing new %s in %d seconds. Call again with the same next_cursor to keep waiting.", scope, wait)
	}
	return textResult(followResult{Summary: summary, Query: query, Events: eventLines(batch.Events), NextCursor: batch.NextCursor})
}

type encryptedDNSLine struct {
	eventLine
	Protocol string `json:"protocol,omitempty"`
	Resolver string `json:"resolver,omitempty"`
}

func (s *Service) encryptedDNS(ctx context.Context, _ *mcp.CallToolRequest, args EncryptedDNSArgs) (*mcp.CallToolResult, any, error) {
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
	parts = append(parts, "("+encryptedDNSQuery+")")
	query := strings.Join(parts, " AND ")
	page, err := s.backend.TrafficSearch(ctx, agentapi.TrafficSearchRequest{Query: query, Limit: limit, Cursor: strings.TrimSpace(args.Cursor)})
	if err != nil {
		return nil, nil, fmt.Errorf("read encrypted DNS: %w", err)
	}
	if err := checkPageBound(len(page.Events), limit); err != nil {
		return nil, nil, err
	}
	counts := map[string]int{}
	blocked := 0
	lines := make([]encryptedDNSLine, 0, len(page.Events))
	for _, event := range page.Events {
		line := encryptedDNSLine{eventLine: newEventLine(event), Protocol: encryptedDNSLabel(event.RecentEvent), Resolver: firstNonEmpty(event.TLSServerName, event.DNSName, event.DNSQuery, hostPort(event.DestinationIP, event.DestinationPort))}
		if event.Blocked {
			blocked++
			if line.Protocol == "" {
				line.Protocol = blockReasonLabel(event.BlockedReason)
			}
		} else if line.Protocol != "" {
			counts[line.Protocol]++
		}
		lines = append(lines, line)
	}
	used := []string{}
	for _, protocol := range []string{"DoH", "DoT", "DoQ"} {
		if counts[protocol] > 0 {
			used = append(used, fmt.Sprintf("%s %d", protocol, counts[protocol]))
		}
	}
	summary := fmt.Sprintf("No encrypted DNS %s.", scope)
	if len(lines) > 0 {
		summary = fmt.Sprintf("%s %s", countNoun(len(lines)-blocked, "encrypted DNS connection", "encrypted DNS connections"), scope)
		if len(used) > 0 {
			summary += " (" + strings.Join(used, ", ") + ")"
		}
		summary += fmt.Sprintf("; ShakerProxy blocked %d attempts.", blocked)
	}
	if view, err := s.backend.DNSVisibility(ctx); err == nil {
		if view.BlockEncryptedDNS {
			summary += " Blocking is on: devices fall back to plain DNS, which ShakerProxy records."
		} else {
			summary += " Blocking is off (the default): ShakerProxy identifies encrypted DNS, but the names looked up inside it stay hidden; dns_visibility explains the option."
		}
	}
	if page.NextCursor != "" {
		summary += " More are available: call again with next_cursor."
	}
	return textResult(struct {
		Summary    string             `json:"summary"`
		Query      string             `json:"query"`
		Events     []encryptedDNSLine `json:"events"`
		NextCursor string             `json:"next_cursor,omitempty"`
	}{Summary: summary, Query: query, Events: lines, NextCursor: page.NextCursor})
}
