package ingest

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The live Traffic stream shows what a lookup resolved to on one line, so
// every DNS source's answers come back with list rows, live batches, and rows
// written before the column existed.
func TestDNSAnswersPostgresAreReturnedWithEventRows(t *testing.T) {
	database, sink, ctx := openProtocolTestDatabase(t)
	now := time.Now().UTC().Truncate(time.Second)
	forwarder := Envelope{Schema: SchemaVersion, EventID: "forwarder-lookup-answers-0001", Source: SourceHost, Kind: HostDNSKind, OccurredAt: now.Add(-3 * time.Minute), SourceVersion: "test", ParserVersion: "shakerproxy-test-v1", DeviceID: protocolTestTV, Confidence: 90,
		Payload: json.RawMessage(`{"source_ip":"10.77.0.50","source_port":40000,"destination_port":53,"protocol":"udp","service":"dns","query":"maps.google.com","query_type":"A","response_code":"NOERROR","answer_count":2,"answers":[{"name":"maps.google.com","type":"A","ttl":60,"data":"142.250.1.1"},{"name":"maps.google.com","type":"A","ttl":60,"data":"142.250.1.2"}],"blocked":false}`)}
	envelopes := []Envelope{
		forwarder,
		zeekTestEnvelope(t, protocolTestZeekCapture, protocolTestCamera, now.Add(-2*time.Minute), map[string]any{"_path": "dns", "uid": "CdnsAnswers00001", "id.orig_h": "10.77.0.40", "id.orig_p": 5353, "id.resp_h": "10.77.0.1", "id.resp_p": 53, "proto": "udp", "query": "fonts.gstatic.com", "qtype_name": "AAAA", "rcode_name": "NOERROR", "answers": []string{"2a00:1450:4001:80b::200e"}}),
		suricataTestEnvelope(t, protocolTestSuriCapture, protocolTestCamera, now.Add(-time.Minute), map[string]any{"event_type": "dns", "src_ip": "10.77.0.40", "src_port": 5353, "dest_ip": "10.77.0.1", "dest_port": 53, "proto": "UDP", "dns": map[string]any{"version": 3, "type": "response", "rrname": "edge.example", "rrtype": "A", "rcode": "NOERROR", "grouped": map[string]any{"CNAME": []string{"cdn.example."}, "A": []string{"192.0.2.7"}}}}),
	}
	writeTestEnvelopes(t, ctx, sink, now, envelopes)

	want := map[string][]string{
		"maps.google.com":   {"142.250.1.1", "142.250.1.2"},
		"fonts.gstatic.com": {"2a00:1450:4001:80b::200e"},
		"edge.example":      {"cdn.example", "192.0.2.7"},
	}
	check := func(label string, events []RecentEvent) {
		t.Helper()
		got := map[string][]string{}
		for _, event := range events {
			if event.DNSQuery != "" {
				got[event.DNSQuery] = event.DNSAnswers
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: answers = %q, want %q", label, got, want)
		}
	}
	page, err := sink.QueryRecent(ctx, RecentEventQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	check("recent page", page.Events)
	encoded, err := json.Marshal(page.Events)
	if err != nil || !strings.Contains(string(encoded), `"dns_answers":["142.250.1.1","142.250.1.2"]`) {
		t.Fatalf("encoded events lack dns_answers: %s err=%v", encoded, err)
	}
	for _, event := range page.Events {
		if !validEventDNSAnswers(event.DNSAnswers) {
			t.Fatalf("stored answers fail validation: %#v", event.DNSAnswers)
		}
	}
	live, err := sink.QueryAfter(ctx, LiveEventQuery{RecentEventQuery: RecentEventQuery{Limit: 100}, AfterReceivedAt: now.Add(-time.Hour), AfterRecordID: strings.Repeat("0", 64)})
	if err != nil {
		t.Fatal(err)
	}
	check("live batch", live.Events)

	// Rows written before the column existed get their answers from the
	// projection backfill.
	if _, err := database.ExecContext(ctx, `UPDATE normalized_events SET dns_answers = NULL, projection_version = 3 WHERE dns_query IS NOT NULL`); err != nil {
		t.Fatal(err)
	}
	backfilled, err := sink.BackfillProjection(ctx, now.Add(-ProjectionBackfillHorizon), 100)
	if err != nil || backfilled != len(envelopes) {
		t.Fatalf("backfill projected %d rows: %v", backfilled, err)
	}
	page, err = sink.QueryRecent(ctx, RecentEventQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	check("after backfill", page.Events)

	// The column refuses more than eight answers.
	if _, err := database.ExecContext(ctx, `UPDATE normalized_events SET dns_answers = ARRAY['1','2','3','4','5','6','7','8','9'] WHERE dns_query = 'maps.google.com'`); err == nil {
		t.Fatal("the dns_answers column accepted nine answers")
	}
}
