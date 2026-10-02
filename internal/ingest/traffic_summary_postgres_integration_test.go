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
	summaryPhone = "device-cccccccccccccccccccccccccccccccc"
	summaryTV    = "device-dddddddddddddddddddddddddddddddd"
)

func openTrafficSummaryDatabase(t *testing.T) (*sql.DB, PostgresSink, context.Context) {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("SHAKERPROXY_TEST_DATABASE_URL"))
	if databaseURL == "" {
		databaseURL = strings.TrimSpace(os.Getenv("SHAKERPROXY_POSTGRES_TEST_URL"))
	}
	if databaseURL == "" {
		t.Skip("SHAKERPROXY_TEST_DATABASE_URL or SHAKERPROXY_POSTGRES_TEST_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
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
	truncate := func(ctx context.Context) error {
		_, err := database.ExecContext(ctx, "TRUNCATE TABLE normalized_events, normalized_event_identities CASCADE")
		return err
	}
	if err := truncate(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		_ = truncate(cleanup)
	})
	return database, sink, ctx
}

// summaryRow is one normalized event written straight to the table, so the
// SQL classifier sees exactly the columns the fixture names.
type summaryRow struct {
	RecordID   string
	Source     Source
	Kind       string
	OccurredAt time.Time
	DeviceID   string
	SourceIP   string
	Event      RecentEvent
	Payload    map[string]any
}

func insertSummaryRows(t *testing.T, ctx context.Context, database *sql.DB, rows []summaryRow) {
	t.Helper()
	for index, row := range rows {
		ensureSummaryPartition(t, ctx, database, row.OccurredAt)
		if row.RecordID == "" {
			row.RecordID = fmt.Sprintf("%064x", 0x5000+index)
		}
		payload := row.Payload
		if payload == nil {
			payload = map[string]any{}
		}
		raw, _ := json.Marshal(payload)
		event := row.Event
		_, err := database.ExecContext(ctx, `INSERT INTO normalized_events(record_id,event_sha256,source,kind,occurred_at,received_at,source_version,parser_version,confidence,
device_id,source_ip,destination_port,protocol,dns_query,dns_name,tls_server_name,http_method,http_host,app_protocol,protocol_category,alert_signature,payload)
VALUES ($1,$1,$2,$3,$4,$4,'summary-test','summary-test',80,NULLIF($5,''),NULLIF($6,'')::inet,NULLIF($7,0),NULLIF($8,''),NULLIF($9,''),NULLIF($10,''),NULLIF($11,''),
NULLIF($12,''),NULLIF($13,''),NULLIF($14,''),NULLIF($15,''),NULLIF($16,''),$17::jsonb)`,
			row.RecordID, row.Source, row.Kind, row.OccurredAt, row.DeviceID, row.SourceIP, event.DestinationPort, event.Protocol, event.DNSQuery, event.DNSName,
			event.TLSServerName, event.HTTPMethod, event.HTTPHost, event.AppProtocol, event.ProtocolCategory, event.AlertSignature, string(raw))
		if err != nil {
			t.Fatalf("insert %s: %v", row.Kind, err)
		}
	}
}

func ensureSummaryPartition(t *testing.T, ctx context.Context, database *sql.DB, at time.Time) {
	t.Helper()
	month := monthStart(at)
	statement := fmt.Sprintf("CREATE TABLE IF NOT EXISTS normalized_events_%s PARTITION OF normalized_events FOR VALUES FROM ('%s') TO ('%s')", month.Format("200601"), month.Format("2006-01-02 15:04:05+00"), month.AddDate(0, 1, 0).Format("2006-01-02 15:04:05+00"))
	if _, err := database.ExecContext(ctx, statement); err != nil {
		t.Fatal(err)
	}
}

func summaryFacet(t *testing.T, summary TrafficSummary, field string) TrafficSummaryFacet {
	t.Helper()
	for _, facet := range summary.Facets {
		if facet.Field == field {
			return facet
		}
	}
	t.Fatalf("summary has no %s facet", field)
	return TrafficSummaryFacet{}
}

func facetCounts(facet TrafficSummaryFacet) string {
	parts := make([]string, 0, len(facet.Values))
	for _, value := range facet.Values {
		parts = append(parts, fmt.Sprintf("%s=%d", value.Value, value.Count))
	}
	return strings.Join(parts, " ")
}

func TestPostgresStreamTypeSQLMatchesSharedFixtures(t *testing.T) {
	database, sink, ctx := openTrafficSummaryDatabase(t)
	base := time.Date(2026, 9, 20, 9, 0, 0, 0, time.UTC)
	fixtures := loadStreamTypeFixtures(t)
	rows := make([]summaryRow, 0, len(fixtures))
	byRecord := map[string]streamTypeFixture{}
	want := StreamTypeCounts{}
	for index, fixture := range fixtures {
		var envelope struct {
			Source  string         `json:"source"`
			Kind    string         `json:"kind"`
			Payload map[string]any `json:"payload"`
		}
		if err := json.Unmarshal(fixture.Event, &envelope); err != nil {
			t.Fatal(err)
		}
		row := summaryRow{RecordID: fmt.Sprintf("%064x", 0x9000+index), Source: Source(envelope.Source), Kind: envelope.Kind, OccurredAt: base.Add(time.Duration(index) * time.Second), Event: fixture.event(t), Payload: envelope.Payload}
		rows = append(rows, row)
		byRecord[row.RecordID] = fixture
		if envelope.Kind != "zeek.ssl" && envelope.Kind != "zeek.quic" {
			*want.slot(fixture.Type)++
		}
	}
	insertSummaryRows(t, ctx, database, rows)
	result, err := database.QueryContext(ctx, `SELECT record_id, `+streamTypeSQL+` FROM normalized_events`)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	seen := 0
	for result.Next() {
		var recordID, streamType string
		if err := result.Scan(&recordID, &streamType); err != nil {
			t.Fatal(err)
		}
		seen++
		if fixture := byRecord[recordID]; streamType != fixture.Type {
			t.Errorf("%s: SQL stream type = %q, want %q", fixture.Name, streamType, fixture.Type)
		}
	}
	if err := result.Err(); err != nil || seen != len(fixtures) {
		t.Fatalf("classified %d of %d fixtures: %v", seen, len(fixtures), err)
	}
	// The summary leaves out the analyzers' duplicate TLS and QUIC records.
	summary, err := sink.QueryTrafficSummary(ctx, TrafficSummaryQuery{From: base, To: base.Add(time.Minute), Buckets: 6})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Totals.Types != want || summary.Totals.Events != want.Total() {
		t.Fatalf("summary types %+v, want %+v", summary.Totals.Types, want)
	}
}

func TestPostgresTrafficSummaryAggregates(t *testing.T) {
	database, sink, ctx := openTrafficSummaryDatabase(t)
	base := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	tls := RecentEvent{Protocol: "tcp", DestinationPort: 443, TLSServerName: "www.apple.com"}
	dns := RecentEvent{Protocol: "udp", DestinationPort: 53, DNSQuery: "www.google.com"}
	insertSummaryRows(t, ctx, database, []summaryRow{
		{Source: SourceZeek, Kind: "zeek.conn", OccurredAt: base.Add(30 * time.Second), DeviceID: summaryPhone, SourceIP: "10.77.0.20", Event: tls, Payload: map[string]any{"orig_bytes": 100, "resp_bytes": 1000}},
		{Source: SourceHost, Kind: HostDNSKind, OccurredAt: base.Add(time.Minute), DeviceID: summaryPhone, SourceIP: "10.77.0.20", Event: dns},
		{Source: SourceHost, Kind: HostDNSKind, OccurredAt: base.Add(9*time.Minute + 30*time.Second), DeviceID: summaryPhone, SourceIP: "10.77.0.20", Event: dns},
		{Source: SourceZeek, Kind: "zeek.conn", OccurredAt: base.Add(5 * time.Minute), SourceIP: "10.77.0.50", Event: RecentEvent{Protocol: "udp", DestinationPort: 1900, AppProtocol: "ssdp"}, Payload: map[string]any{"orig_bytes": 50, "resp_bytes": 0}},
		{Source: SourceSuricata, Kind: "suricata.alert", OccurredAt: base.Add(3 * time.Minute), DeviceID: summaryTV, SourceIP: "10.77.0.30", Event: RecentEvent{Protocol: "tcp", DestinationPort: 443, AlertSignature: "ET POLICY test"}},
		// Analyzer duplicates and events outside the window are not counted.
		{Source: SourceSuricata, Kind: "suricata.flow", OccurredAt: base.Add(2 * time.Minute), DeviceID: summaryPhone, SourceIP: "10.77.0.20", Event: tls, Payload: map[string]any{"flow": map[string]any{"bytes_toserver": 999999, "bytes_toclient": 999999}}},
		{Source: SourceZeek, Kind: "zeek.conn", OccurredAt: base.Add(2 * time.Minute), DeviceID: summaryPhone, SourceIP: "10.77.0.20", Event: RecentEvent{Protocol: "udp", DestinationPort: 53}, Payload: map[string]any{"orig_bytes": 999999}},
		{Source: SourceZeek, Kind: "zeek.conn", OccurredAt: base.Add(-time.Second), DeviceID: summaryPhone, SourceIP: "10.77.0.20", Event: tls},
		{Source: SourceZeek, Kind: "zeek.conn", OccurredAt: base.Add(10 * time.Minute), DeviceID: summaryPhone, SourceIP: "10.77.0.20", Event: tls},
	})
	query := TrafficSummaryQuery{From: base, To: base.Add(10 * time.Minute), Buckets: 10}
	summary, err := sink.QueryTrafficSummary(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateTrafficSummary(summary, query); err != nil {
		t.Fatalf("summary is invalid: %v\n%+v", err, summary)
	}
	if summary.Totals.Events != 5 || summary.Totals.BytesSent != 150 || summary.Totals.BytesReceived != 1000 {
		t.Fatalf("totals: %+v", summary.Totals)
	}
	if want := (StreamTypeCounts{TLS: 1, DNS: 2, Discovery: 1, Alert: 1}); summary.Totals.Types != want {
		t.Fatalf("types: %+v", summary.Totals.Types)
	}
	if summary.BucketSeconds != 60 || !summary.Buckets[3].Start.Equal(base.Add(3*time.Minute)) {
		t.Fatalf("bucket layout: %v %s", summary.BucketSeconds, summary.Buckets[3].Start)
	}
	for index, want := range map[int]StreamTypeCounts{0: {TLS: 1}, 1: {DNS: 1}, 3: {Alert: 1}, 5: {Discovery: 1}, 9: {DNS: 1}} {
		if summary.Buckets[index].Counts != want {
			t.Errorf("bucket %d: %+v, want %+v", index, summary.Buckets[index].Counts, want)
		}
	}
	devices := summaryFacet(t, summary, SummaryFacetDevice)
	if got := facetCounts(devices); got != summaryPhone+"=3 "+summaryTV+"=1 ip:10.77.0.50=1" || devices.Values[2].Label != "10.77.0.50" || !devices.Exact || devices.OtherCount != 0 {
		t.Fatalf("device facet: %s %+v", got, devices)
	}
	if got := facetCounts(summaryFacet(t, summary, SummaryFacetDestinationPort)); got != "443=2 53=2 1900=1" {
		t.Fatalf("port facet: %s", got)
	}
	apps := summaryFacet(t, summary, SummaryFacetAppProtocol)
	if got := facetCounts(apps); got != "ssdp=1" || apps.OtherCount != 4 {
		t.Fatalf("app protocol facet: %s other %d", got, apps.OtherCount)
	}
	if got := facetCounts(summaryFacet(t, summary, SummaryFacetType)); got != "dns=2 tls=1 discovery=1 alert=1" {
		t.Fatalf("type facet: %s", got)
	}
	googleOwner, _ := destinationOwner(RecentEvent{DNSQuery: "www.google.com"})
	appleOwner, _ := destinationOwner(RecentEvent{TLSServerName: "www.apple.com"})
	if googleOwner == "" || appleOwner == "" {
		t.Fatalf("the domain table no longer names Google or Apple: %q %q", googleOwner, appleOwner)
	}
	organizations := summaryFacet(t, summary, SummaryFacetOrganization)
	if got := facetCounts(organizations); got != googleOwner+"=2 "+appleOwner+"=1" || !organizations.Exact || organizations.SampledEvents != 0 || organizations.OtherCount != 2 {
		t.Fatalf("organization facet: %s %+v", got, organizations)
	}
	categories := summaryFacet(t, summary, SummaryFacetCategory)
	var categorized int64
	for _, value := range categories.Values {
		categorized += value.Count
	}
	if categorized != 3 || categories.OtherCount != 2 {
		t.Fatalf("category facet: %+v", categories)
	}

	filter, err := querylang.Parse("device.id:" + summaryPhone)
	if err != nil {
		t.Fatal(err)
	}
	phone, err := sink.QueryTrafficSummary(ctx, TrafficSummaryQuery{From: base, To: base.Add(10 * time.Minute), Buckets: 10, Events: RecentEventQuery{Filter: filter}})
	if err != nil || phone.Totals.Events != 3 || phone.CanonicalQuery != filter.Canonical {
		t.Fatalf("filtered summary: %+v %v", phone.Totals, err)
	}
	relative, err := querylang.Parse("time:last_5m")
	if err != nil {
		t.Fatal(err)
	}
	recent, err := sink.QueryTrafficSummary(ctx, TrafficSummaryQuery{Buckets: 5, Events: RecentEventQuery{Filter: relative}})
	if err != nil || recent.To.Sub(recent.From) != 5*time.Minute || recent.Totals.Events != 0 || time.Since(recent.To) > time.Minute {
		t.Fatalf("relative window: %s – %s %+v %v", recent.From, recent.To, recent.Totals, err)
	}
}

func TestPostgresTrafficSummarySamplesOwners(t *testing.T) {
	database, sink, ctx := openTrafficSummaryDatabase(t)
	base := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	ensureSummaryPartition(t, ctx, database, base)
	total := MaxTrafficSummarySample + 1
	if _, err := database.ExecContext(ctx, `INSERT INTO normalized_events(record_id,event_sha256,source,kind,occurred_at,received_at,source_version,parser_version,confidence,device_id,destination_port,protocol,tls_server_name,payload)
SELECT lpad(to_hex(7000000 + value),64,'0'),lpad(to_hex(7000000 + value),64,'0'),'ZEEK','zeek.conn',
       $1::timestamptz + value * interval '10 milliseconds', $1::timestamptz, 'summary-test','summary-test',80,$2,443,'tcp','www.apple.com','{}'::jsonb
FROM generate_series(1,$3::int) AS value`, base, summaryPhone, total); err != nil {
		t.Fatal(err)
	}
	query := TrafficSummaryQuery{From: base, To: base.Add(5 * time.Minute), Buckets: 60}
	summary, err := sink.QueryTrafficSummary(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateTrafficSummary(summary, query); err != nil {
		t.Fatal(err)
	}
	organizations := summaryFacet(t, summary, SummaryFacetOrganization)
	devices := summaryFacet(t, summary, SummaryFacetDevice)
	if summary.Totals.Events != int64(total) || summary.Totals.Types.TLS != int64(total) || organizations.Exact || organizations.SampledEvents != MaxTrafficSummarySample || len(organizations.Values) != 1 || organizations.Values[0].Count != MaxTrafficSummarySample || !devices.Exact || devices.Values[0].Count != int64(total) {
		t.Fatalf("sampled summary: totals %+v organizations %+v devices %+v", summary.Totals, organizations, devices)
	}
}
