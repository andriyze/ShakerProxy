package ingest

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"shakerproxy.dev/shakerproxy/internal/querylang"
)

const (
	protocolTestCamera       = "device-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	protocolTestTV           = "device-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	protocolTestZeekCapture  = "capture-11111111111111111111111111111111"
	protocolTestSuriCapture  = "capture-22222222222222222222222222222222"
	protocolTestSourceZeek   = "8.2.1"
	protocolTestSourceSuri   = "8.0.6"
	protocolTestSourceMitm   = "mitmproxy-12.2.3"
	protocolTestParserVerion = "shakerproxy-test-v1"
)

func openProtocolTestDatabase(t *testing.T) (*sql.DB, PostgresSink, context.Context) {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("SHAKERPROXY_TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("SHAKERPROXY_TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	database.SetMaxOpenConns(4)
	sink := PostgresSink{DB: database}
	if err := sink.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, "TRUNCATE TABLE normalized_events, normalized_event_identities CASCADE"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_, _ = database.ExecContext(cleanup, "TRUNCATE TABLE normalized_events, normalized_event_identities CASCADE")
	})
	return database, sink, ctx
}

func zeekTestEnvelope(t *testing.T, capture, deviceID string, occurredAt time.Time, fields map[string]any) Envelope {
	t.Helper()
	fields["ts"] = float64(occurredAt.UnixNano()) / 1e9
	raw, _ := json.Marshal(fields)
	envelope, err := NormalizeZeekJSON(raw, protocolTestSourceZeek, capture)
	if err != nil {
		t.Fatal(err)
	}
	envelope.DeviceID = deviceID
	return envelope
}

func suricataTestEnvelope(t *testing.T, capture, deviceID string, occurredAt time.Time, fields map[string]any) Envelope {
	t.Helper()
	fields["timestamp"] = occurredAt.UTC().Format("2006-01-02T15:04:05.000000-0700")
	raw, _ := json.Marshal(fields)
	envelope, err := NormalizeSuricataEVE(raw, protocolTestSourceSuri, capture)
	if err != nil {
		t.Fatal(err)
	}
	envelope.DeviceID = deviceID
	return envelope
}

func mitmTestEnvelope(eventID, kind, deviceID string, occurredAt time.Time, payload string) Envelope {
	return Envelope{Schema: SchemaVersion, EventID: eventID, Source: SourceMitmproxy, Kind: kind, OccurredAt: occurredAt, SourceVersion: protocolTestSourceMitm, ParserVersion: protocolTestParserVerion, DeviceID: deviceID, Confidence: 100, Payload: json.RawMessage(payload)}
}

func writeTestEnvelopes(t *testing.T, ctx context.Context, sink PostgresSink, now time.Time, envelopes []Envelope) {
	t.Helper()
	spool := &Spool{Root: t.TempDir(), MaxBytes: 16 << 20, ReserveBytes: 1, Now: func() time.Time { return now }}
	for _, envelope := range envelopes {
		raw, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		if result, err := spool.Accept(raw); err != nil || !result.Accepted || result.Quarantined {
			t.Fatalf("seed event %s was not accepted: %#v err=%v", envelope.Kind, result, err)
		}
	}
	batch, err := spool.PendingBatch(len(envelopes))
	if err != nil || len(batch) != len(envelopes) {
		t.Fatalf("seed batch=%d err=%v", len(batch), err)
	}
	if err := sink.WriteBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
}

func TestProtocolDiscoveryPostgresClassifiesDedupesAndSummarizes(t *testing.T) {
	database, sink, ctx := openProtocolTestDatabase(t)
	now := time.Now().UTC().Truncate(time.Second)
	envelopes := []Envelope{
		// One MQTT connection seen by both Zeek and Suricata in the same capture.
		zeekTestEnvelope(t, protocolTestZeekCapture, protocolTestCamera, now.Add(-10*time.Minute), map[string]any{"_path": "conn", "uid": "CmqttFlow0000001", "id.orig_h": "10.77.0.40", "id.orig_p": 40000, "id.resp_h": "3.4.5.6", "id.resp_p": 1883, "proto": "tcp", "service": "mqtt", "orig_ip_bytes": 1000, "resp_ip_bytes": 2000}),
		suricataTestEnvelope(t, protocolTestZeekCapture, protocolTestCamera, now.Add(-10*time.Minute), map[string]any{"event_type": "flow", "flow_id": 1234567890123, "src_ip": "10.77.0.40", "src_port": 40000, "dest_ip": "3.4.5.6", "dest_port": 1883, "proto": "TCP", "app_proto": "mqtt", "flow": map[string]any{"bytes_toserver": 1000, "bytes_toclient": 2000}}),
		// A TLS flow ShakerProxy intercepted: Zeek sees it, mitmproxy decrypted it.
		zeekTestEnvelope(t, protocolTestZeekCapture, protocolTestTV, now.Add(-9*time.Minute), map[string]any{"_path": "conn", "uid": "CtlsFlow00000001", "id.orig_h": "10.77.0.50", "id.orig_p": 51000, "id.resp_h": "1.2.3.4", "id.resp_p": 443, "proto": "tcp", "service": "ssl", "orig_ip_bytes": 4000, "resp_ip_bytes": 5000}),
		mitmTestEnvelope("mitm-tls-intercepted-0001", "tls_intercepted", protocolTestTV, now.Add(-9*time.Minute+2*time.Second), `{"source_ip":"10.77.0.50","source_port":51000,"destination_ip":"1.2.3.4","destination_port":443,"protocol":"tcp","service":"tls","sni":"api.example.com","decrypted":true}`),
		// An intercepted connection no capture saw counts as its own flow.
		mitmTestEnvelope("mitm-tls-intercepted-0002", "tls_intercepted", protocolTestTV, now.Add(-8*time.Minute), `{"source_ip":"10.77.0.50","source_port":52000,"destination_ip":"5.6.7.8","destination_port":443,"protocol":"tcp","service":"tls","sni":"cdn.example.com","decrypted":true}`),
		// Suricata-only capture: its flows count because no Zeek flows exist for it.
		suricataTestEnvelope(t, protocolTestSuriCapture, protocolTestCamera, now.Add(-7*time.Minute), map[string]any{"event_type": "flow", "flow_id": 2234567890123, "src_ip": "10.77.0.40", "src_port": 40001, "dest_ip": "9.9.9.9", "dest_port": 34567, "proto": "UDP", "app_proto": "failed", "flow": map[string]any{"bytes_toserver": 1024, "bytes_toclient": 1024}}),
		// Application-layer evidence never adds flows.
		zeekTestEnvelope(t, protocolTestZeekCapture, protocolTestCamera, now.Add(-6*time.Minute), map[string]any{"_path": "dns", "uid": "CdnsFlow00000001", "id.orig_h": "10.77.0.40", "id.orig_p": 5353, "id.resp_h": "10.77.0.1", "id.resp_p": 53, "proto": "udp", "query": "api.example.com", "qtype_name": "A", "rcode_name": "NOERROR", "answers": []string{"1.2.3.4", "1.2.3.5"}}),
		mitmTestEnvelope("mitm-doh-detected-0001", "encrypted_dns_detected", protocolTestTV, now.Add(-5*time.Minute), `{"source_ip":"10.77.0.50","source_port":53000,"destination_ip":"8.8.8.8","destination_port":443,"protocol":"tcp","service":"doh","hostname":"dns.google","http_method":"POST","http_path":"/dns-query","decrypted":true,"query_name":"tracker.example","query_type":"AAAA"}`),
		mitmTestEnvelope("mitm-http-response-0001", "http_response", protocolTestTV, now.Add(-4*time.Minute), `{"source_ip":"10.77.0.50","source_port":51000,"destination_ip":"1.2.3.4","destination_port":443,"protocol":"tcp","service":"https","http_method":"GET","http_scheme":"https","http_host":"api.example.com","http_port":443,"http_path":"/v1/status?token=secret","http_status":200,"http_version":"HTTP/1.1","request_bytes":10,"response_bytes":20,"decrypted":true}`),
		// TLS was already seen long ago, so it is not novel in the last 24 h.
		zeekTestEnvelope(t, protocolTestZeekCapture, protocolTestTV, now.Add(-40*24*time.Hour), map[string]any{"_path": "conn", "uid": "CtlsFlowOld00001", "id.orig_h": "10.77.0.50", "id.orig_p": 50999, "id.resp_h": "1.2.3.4", "id.resp_p": 443, "proto": "tcp", "service": "ssl", "orig_ip_bytes": 1, "resp_ip_bytes": 1}),
	}
	writeTestEnvelopes(t, ctx, sink, now, envelopes)

	summary, err := sink.QueryProtocolSummary(ctx, ProtocolSummaryQuery{WindowSeconds: 86400})
	if err != nil {
		t.Fatal(err)
	}
	usage := map[string]ProtocolUsage{}
	for _, protocol := range summary.Protocols {
		usage[protocol.Protocol] = protocol
	}
	mqtt, tls, unknown, dns, doh := usage["mqtt"], usage["tls"], usage["unknown-udp"], usage["dns"], usage["doh"]
	if mqtt.Flows != 1 || mqtt.Bytes != 3000 || mqtt.Events != 2 || !mqtt.Novel || !mqtt.Exotic || mqtt.Evidence != "ANALYZER" || len(mqtt.Ports) != 1 || mqtt.Ports[0].Port != 1883 || len(mqtt.Devices) != 1 || mqtt.Devices[0].DeviceID != protocolTestCamera {
		t.Fatalf("MQTT was double counted or mis-attributed: %#v", mqtt)
	}
	if tls.Flows != 2 || tls.Bytes != 9000 || tls.Visibility != "DECRYPTED" || tls.Novel || tls.DeviceCount != 1 {
		t.Fatalf("TLS dedupe or decryption correlation failed: %#v", tls)
	}
	if unknown.Flows != 1 || unknown.Bytes != 2048 || unknown.Visibility != "OPAQUE" || unknown.Evidence != "UNCLASSIFIED" {
		t.Fatalf("Suricata-only capture flow was not counted: %#v", unknown)
	}
	if dns.Flows != 0 || dns.Events != 1 || doh.Flows != 0 || doh.Events != 1 || doh.Visibility != "DECRYPTED" {
		t.Fatalf("application-layer evidence added flows: dns=%#v doh=%#v", dns, doh)
	}
	if summary.Coverage.TotalBytes != 3000+9000+2048 || summary.Coverage.DecryptedBytes != 9000 || summary.Coverage.OpaqueBytes != 2048 || summary.Coverage.CleartextBytes != 3000 {
		t.Fatalf("coverage is wrong: %#v", summary.Coverage)
	}
	if len(summary.Sources) != 3 || summary.Truncated {
		t.Fatalf("unexpected sources or truncation: %#v %v", summary.Sources, summary.Truncated)
	}

	camera, err := sink.QueryProtocolSummary(ctx, ProtocolSummaryQuery{WindowSeconds: 3600, DeviceID: protocolTestCamera})
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range camera.Protocols {
		if protocol.Protocol == "tls" || protocol.Protocol == "doh" {
			t.Fatalf("device-scoped summary included another device's protocol: %#v", protocol)
		}
	}
	exotic := true
	exoticOnly, err := sink.QueryProtocolSummary(ctx, ProtocolSummaryQuery{WindowSeconds: 3600, Exotic: &exotic})
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range exoticOnly.Protocols {
		if !protocol.Exotic {
			t.Fatalf("exotic filter returned %s", protocol.Protocol)
		}
	}

	for query, want := range map[string]int{
		`proto:mqtt`:                       2,
		`app.protocol:tls`:                 5,
		`service:dns`:                      1,
		`app.protocol:dns`:                 1,
		`dns.query:tracker.example`:        1,
		`protocol.exotic:true`:             4,
		`protocol.visibility:OPAQUE`:       1,
		`protocol.visibility:DECRYPTED`:    4,
		`NOT proto:tls`:                    5,
		`api.example`:                      3,
		`tls.sni:api.example.com`:          1,
		`http.status:200`:                  1,
		`time:` + now.Format("2006-01-02"): len(envelopes) - 1,
	} {
		filter, err := querylang.Parse(query)
		if err != nil {
			t.Fatalf("Parse(%q): %v", query, err)
		}
		page, err := sink.QueryRecent(ctx, RecentEventQuery{Limit: 100, Filter: filter})
		if err != nil {
			t.Fatalf("QueryRecent(%q): %v", query, err)
		}
		if query == `time:`+now.Format("2006-01-02") && now.Hour() < 1 {
			continue
		}
		if len(page.Events) != want {
			kinds := make([]string, 0, len(page.Events))
			for _, event := range page.Events {
				kinds = append(kinds, event.Kind+"/"+event.AppProtocol)
			}
			t.Fatalf("QueryRecent(%q) returned %d events, want %d: %v", query, len(page.Events), want, kinds)
		}
	}
	page, err := sink.QueryRecent(ctx, RecentEventQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	summaries := map[string]RecentEvent{}
	for _, event := range page.Events {
		if event.Summary == "" || !validEventSummary(event.Summary) {
			t.Fatalf("event %s has an invalid summary %q", event.Kind, event.Summary)
		}
		summaries[event.Kind+"/"+event.AppProtocol] = event
	}
	if got := summaries["zeek.dns/dns"].Summary; got != "DNS lookup api.example.com (A) → 2 answers" {
		t.Fatalf("DNS summary = %q", got)
	}
	if got := summaries["http_response/tls"]; got.Summary != "GET api.example.com/v1/status → 200" || got.HTTPPath != "/v1/status" || got.HTTPMethod != "GET" || got.ProtocolVisibility != "DECRYPTED" {
		t.Fatalf("HTTP event fields = %#v", got)
	}
	if got := summaries["encrypted_dns_detected/doh"]; got.DNSQuery != "tracker.example" || got.Summary != "Encrypted DNS (DoH) lookup tracker.example (AAAA)" {
		t.Fatalf("DoH event fields = %#v", got)
	}
	encoded, _ := json.Marshal(page)
	if strings.Contains(string(encoded), "token=secret") {
		t.Fatalf("event page leaked a query string: %s", encoded)
	}

	// Rows written before the projection existed are backfilled once.
	if _, err := database.ExecContext(ctx, `UPDATE normalized_events SET app_protocol=NULL, protocol_category=NULL, protocol_visibility=NULL, protocol_evidence=NULL, protocol_exotic=NULL, http_method=NULL, http_host=NULL, http_path=NULL, http_status=NULL, projection_version=NULL, service=NULL WHERE kind='zeek.dns'`); err != nil {
		t.Fatal(err)
	}
	backfilled, err := sink.BackfillProjection(ctx, now.Add(-ProjectionBackfillHorizon), 100)
	if err != nil || backfilled != 1 {
		t.Fatalf("backfill projected %d rows: %v", backfilled, err)
	}
	if again, err := sink.BackfillProjection(ctx, now.Add(-ProjectionBackfillHorizon), 100); err != nil || again != 0 {
		t.Fatalf("backfill is not idempotent: %d %v", again, err)
	}
	var service, appProtocol string
	if err := database.QueryRowContext(ctx, "SELECT COALESCE(service,''), COALESCE(app_protocol,'') FROM normalized_events WHERE kind='zeek.dns'").Scan(&service, &appProtocol); err != nil || service != "dns" || appProtocol != "dns" {
		t.Fatalf("backfill did not restore the projection: service=%q app=%q err=%v", service, appProtocol, err)
	}
}

func TestProtocolDiscoveryPostgresPartitionsAreUTCOnNonUTCServers(t *testing.T) {
	database, sink, ctx := openProtocolTestDatabase(t)
	var timezone string
	if err := database.QueryRowContext(ctx, "SHOW TimeZone").Scan(&timezone); err != nil {
		t.Fatal(err)
	}
	// Just after midnight UTC on the first of a month is still the previous
	// month in America/New_York; the row must land in the UTC month partition.
	boundary := time.Date(time.Now().UTC().Year(), time.Now().UTC().Month(), 1, 2, 0, 0, 0, time.UTC)
	envelope := zeekTestEnvelope(t, protocolTestZeekCapture, protocolTestCamera, boundary, map[string]any{"_path": "conn", "uid": "CboundaryFlow001", "id.orig_h": "10.77.0.40", "id.orig_p": 40100, "id.resp_h": "3.4.5.6", "id.resp_p": 1883, "proto": "tcp"})
	writeTestEnvelopes(t, ctx, sink, time.Now().UTC(), []Envelope{envelope})
	var partition string
	if err := database.QueryRowContext(ctx, "SELECT tableoid::regclass::text FROM normalized_events WHERE kind='zeek.conn' AND occurred_at=$1", boundary).Scan(&partition); err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("normalized_events_%s", boundary.Format("200601")); partition != want {
		t.Fatalf("session TimeZone %s placed the row in %s, want %s", timezone, partition, want)
	}
}
