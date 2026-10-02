package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"shakerproxy.dev/shakerproxy/internal/agentapi"
	"shakerproxy.dev/shakerproxy/internal/httpexchange"
	"shakerproxy.dev/shakerproxy/internal/ingest"
)

var (
	parityDNSRecord  = strings.Repeat("1", 64)
	parityHTTPRecord = strings.Repeat("2", 64)
)

func callParityTool(t *testing.T, backend *fakeBackend, name, arguments string) *mcp.CallToolResult {
	t.Helper()
	session := connect(t, backend)
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: json.RawMessage(arguments)})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestEventDetailGivesTheFactsTheUIShows(t *testing.T) {
	backend := newFakeBackend()
	answers := 2
	backend.detail = ingest.EventDetail{Schema: 1, Event: ingest.RecentEvent{
		RecordID: parityDNSRecord, Source: ingest.SourceHost, Kind: "shakerproxy.dns", OccurredAt: fakeNow, DeviceID: tvID, DeviceFriendlyName: "Living room TV",
		SourceIP: "10.77.0.23", SourcePort: 53000, DestinationIP: "10.77.0.1", DestinationPort: 53, Protocol: "udp",
		DNSQuery: "samsungacr.com", DNSRecordType: "A", DNSResponseCode: "NOERROR", DNSAnswerCount: &answers, DNSAnswers: []string{"A 52.1.2.3", "A 52.1.2.4"},
	}, Payload: json.RawMessage(`{"qtype_name":"A"}`)}
	result := callParityTool(t, backend, toolEventDetail, `{"record_id":"`+parityDNSRecord+`"}`)
	if result.IsError {
		t.Fatalf("event_detail failed: %s", rawToolText(t, result))
	}
	var detail struct {
		Type  string      `json:"type"`
		Facts []eventFact `json:"facts"`
		Next  string      `json:"next"`
	}
	decodeToolResult(t, result, &detail)
	facts := map[string]string{}
	for _, fact := range detail.Facts {
		facts[fact.Label] = fact.Value
	}
	if detail.Type != "dns" || facts["Looked up"] != "samsungacr.com" || facts["Answered by"] != "ShakerProxy" || facts["Answers"] != "A 52.1.2.3, A 52.1.2.4" || facts["Device"] != "Living room TV" || detail.Next != "" {
		t.Fatalf("detail = %+v", detail)
	}
	bad := callParityTool(t, backend, toolEventDetail, `{"record_id":"nope"}`)
	if !bad.IsError {
		t.Fatal("an invalid record_id was accepted")
	}
}

func TestHTTPExchangeShowsRedactedContentAndSaysSo(t *testing.T) {
	backend := newFakeBackend()
	longBody := strings.Repeat("é", 3000) // 6000 bytes, cut on a rune boundary
	backend.exchange = agentapi.HTTPExchange{Schema: 1, RecordID: parityHTTPRecord, Source: "CAPTURE", State: "AVAILABLE", Matched: 0, Exchanges: []httpexchange.Exchange{{
		Request: &httpexchange.Request{Method: "POST", Target: "/upload?token=%5Bredacted%5D", Proto: "HTTP/1.1", Headers: httpexchange.Headers{Items: []httpexchange.Header{
			{Name: "Host", Value: "device.example"}, {Name: "Cookie", Value: httpexchange.Redacted, Sensitive: true},
		}}, Body: httpexchange.Body{ContentType: "text/plain", BodyBytes: 6000, PreviewEncoding: "utf-8", Preview: longBody, Complete: true}},
		Response: &httpexchange.Response{Proto: "HTTP/1.1", StatusCode: 200, Status: "200 OK", Headers: httpexchange.Headers{Items: []httpexchange.Header{{Name: "Content-Type", Value: "image/png"}}},
			Body: httpexchange.Body{ContentType: "image/png", BodyBytes: 900, PreviewEncoding: "hex", Preview: "89504e47", Complete: true}},
	}}}
	result := callParityTool(t, backend, toolHTTPExchange, `{"record_id":"`+parityHTTPRecord+`"}`)
	if result.IsError {
		t.Fatalf("http_exchange failed: %s", rawToolText(t, result))
	}
	text := rawToolText(t, result)
	var envelope struct {
		PlaintextIncluded bool `json:"plaintext_included"`
		Data              struct {
			Summary   string         `json:"summary"`
			Exchanges []exchangePair `json:"exchanges"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(text), &envelope); err != nil {
		t.Fatal(err)
	}
	pair := envelope.Data.Exchanges[0]
	if !envelope.PlaintextIncluded || !strings.Contains(envelope.Data.Summary, "credentials are redacted") || !pair.Matches {
		t.Fatalf("envelope = %s", text)
	}
	if pair.Request.Line != "POST /upload?token=%5Bredacted%5D HTTP/1.1" || pair.Request.Headers[1].Value != "[redacted]" || pair.Response.Line != "HTTP/1.1 200 OK" {
		t.Fatalf("pair = %+v", pair)
	}
	if body := pair.Request.Body; body.Shown > 4096 || !body.Truncated || body.Bytes != 6000 || !strings.HasPrefix(longBody, body.Text) {
		t.Fatalf("request body = %+v", body)
	}
	if body := pair.Response.Body; body.Text != "" || !strings.Contains(body.Note, "Binary body") {
		t.Fatalf("binary response body = %+v", body)
	}

	backend.exchangeErr = &agentapi.APIError{Status: 403, Code: "insufficient_scope", Message: "API token does not grant the required scope"}
	denied := callParityTool(t, backend, toolHTTPExchange, `{"record_id":"`+parityHTTPRecord+`"}`)
	if !denied.IsError || !strings.Contains(rawToolText(t, denied), "traffic:content") {
		t.Fatalf("missing scope error: %s", rawToolText(t, denied))
	}
}

func TestFollowTrafficStartsWithTheNewestAndContinuesFromTheCursor(t *testing.T) {
	backend := newFakeBackend()
	backend.page = agentapi.EventPage{Events: []agentapi.Event{
		{RecentEvent: ingest.RecentEvent{RecordID: strings.Repeat("b", 64), Kind: "zeek.dns", OccurredAt: fakeNow, DNSQuery: "newer.example"}},
		{RecentEvent: ingest.RecentEvent{RecordID: strings.Repeat("a", 64), Kind: "zeek.dns", OccurredAt: fakeNow.Add(-time.Second), DNSQuery: "older.example"}},
	}}
	backend.page.LiveCursor = "live-1"
	started := callParityTool(t, backend, toolFollowTraffic, `{"device":"tv","query":"service:dns","limit":10}`)
	var first struct {
		Started    bool        `json:"started"`
		Query      string      `json:"query"`
		Events     []eventLine `json:"events"`
		NextCursor string      `json:"next_cursor"`
	}
	decodeToolResult(t, started, &first)
	if !first.Started || first.NextCursor != "live-1" || len(first.Events) != 2 || first.Events[0].RecordID != strings.Repeat("a", 64) || first.Query != "device.id:"+tvID+" AND (service:dns)" {
		t.Fatalf("first = %+v", first)
	}
	backend.followBatch = agentapi.FollowBatch{NextCursor: "live-2", Events: []agentapi.Event{{RecentEvent: ingest.RecentEvent{RecordID: strings.Repeat("c", 64), Kind: "zeek.ssl", OccurredAt: fakeNow, TLSServerName: "dns.google", AppProtocol: "doh"}}}}
	next := callParityTool(t, backend, toolFollowTraffic, `{"device":"tv","query":"service:dns","cursor":"live-1","wait_seconds":3,"limit":10}`)
	var second struct {
		Events     []eventLine `json:"events"`
		NextCursor string      `json:"next_cursor"`
	}
	decodeToolResult(t, next, &second)
	follow := backend.follows[len(backend.follows)-1]
	if second.NextCursor != "live-2" || len(second.Events) != 1 || second.Events[0].EncryptedDNS != "DoH" || follow.Cursor != "live-1" || follow.Wait != 3*time.Second || follow.Query != first.Query {
		t.Fatalf("second = %+v follow = %+v", second, follow)
	}
	tooLong := callParityTool(t, backend, toolFollowTraffic, `{"cursor":"live-2","wait_seconds":60}`)
	if !tooLong.IsError {
		t.Fatal("an unbounded wait was accepted")
	}
}

func TestEncryptedDNSNamesTheProtocolsResolversAndBlocks(t *testing.T) {
	backend := newFakeBackend()
	backend.page = agentapi.EventPage{Events: []agentapi.Event{
		{RecentEvent: ingest.RecentEvent{RecordID: strings.Repeat("d", 64), Kind: "zeek.ssl", OccurredAt: fakeNow, AppProtocol: "dot", DestinationIP: "1.1.1.1", DestinationPort: 853}},
		{RecentEvent: ingest.RecentEvent{RecordID: strings.Repeat("e", 64), Kind: "zeek.ssl", OccurredAt: fakeNow, AppProtocol: "doh", TLSServerName: "dns.google"}},
		{RecentEvent: ingest.RecentEvent{RecordID: strings.Repeat("f", 64), Kind: "shakerproxy.blocked", OccurredAt: fakeNow, Blocked: true, BlockedReason: "doq", DestinationIP: "94.140.14.14", DestinationPort: 853}},
	}}
	result := callParityTool(t, backend, toolEncryptedDNS, `{"device":"tv","window":"1h"}`)
	var view struct {
		Summary string             `json:"summary"`
		Query   string             `json:"query"`
		Events  []encryptedDNSLine `json:"events"`
	}
	decodeToolResult(t, result, &view)
	if !strings.Contains(view.Query, "app.protocol:dot") || !strings.Contains(view.Query, "device.id:"+tvID) || !strings.Contains(view.Query, "time:last_1h") {
		t.Fatalf("query = %s", view.Query)
	}
	if view.Events[0].Protocol != "DoT" || view.Events[0].Resolver != "1.1.1.1:853" || view.Events[1].Resolver != "dns.google" || !view.Events[2].Blocked || view.Events[2].BlockedReason != "DNS over QUIC" {
		t.Fatalf("events = %+v", view.Events)
	}
	if !strings.HasPrefix(view.Summary, "2 encrypted DNS connections for Living room TV in the last hour (DoH 1, DoT 1); ShakerProxy blocked 1 attempts.") || !strings.Contains(view.Summary, "Blocking is on") {
		t.Fatalf("summary = %q", view.Summary)
	}
}

func TestListDevicesShowsPinnedAddressesAndMergedRecords(t *testing.T) {
	backend := newFakeBackend()
	backend.devicePage = agentapi.DevicePage{Schema: 1, Matched: 1, Returned: 1, Devices: []agentapi.Device{{
		Schema: 1, ID: tvID, DisplayName: "Pixel", Addresses: []agentapi.DeviceAddress{{Address: "192.168.10.201", Family: "IPv4", Active: true}},
		Online: true, LastSeen: fakeNow, FirstSeen: fakeNow, PinnedAddress: "192.168.10.201", FormerIDs: []string{cameraID},
	}}}
	result := callParityTool(t, backend, toolListDevices, `{}`)
	var list deviceList
	decodeToolResult(t, result, &list)
	device := list.Devices[0]
	if device.PinnedAddress != "192.168.10.201" || len(device.FormerIDs) != 1 || !strings.Contains(device.Summary, "named by IP address 192.168.10.201") || !strings.Contains(device.Summary, "1 earlier record merged") {
		t.Fatalf("device = %+v", device)
	}
}
