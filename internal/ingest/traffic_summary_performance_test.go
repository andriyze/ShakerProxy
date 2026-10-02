package ingest

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/querylang"
)

// TestPostgresTrafficSummaryPerformance loads 200,000 synthetic events over
// the last 24 hours and times typical summaries. It runs only with
// SHAKERPROXY_SUMMARY_PERF=1 and a test database:
//
//	SHAKERPROXY_SUMMARY_PERF=1 SHAKERPROXY_TEST_DATABASE_URL=… go test ./internal/ingest -run Performance -v
func TestPostgresTrafficSummaryPerformance(t *testing.T) {
	if os.Getenv("SHAKERPROXY_SUMMARY_PERF") != "1" {
		t.Skip("set SHAKERPROXY_SUMMARY_PERF=1 to measure the events summary")
	}
	database, sink, ctx := openTrafficSummaryDatabase(t)
	now := time.Now().UTC()
	ensureSummaryPartition(t, ctx, database, now)
	ensureSummaryPartition(t, ctx, database, now.Add(-24*time.Hour))
	const rows = 200_000
	started := time.Now()
	// A lab-like mix: lookups, TLS and QUIC to a few dozen names, cleartext
	// HTTP, discovery chatter, alerts, other traffic, and the analyzers'
	// duplicate records the summary leaves out, from 30 devices and some
	// unattributed addresses.
	conn, err := database.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "SELECT setseed(0.42)"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO normalized_events(record_id,event_sha256,source,kind,occurred_at,received_at,source_version,parser_version,confidence,
device_id,source_ip,destination_port,protocol,dns_query,tls_server_name,http_method,http_host,app_protocol,alert_signature,payload)
SELECT lpad(to_hex(10000000 + n),64,'0'), lpad(to_hex(10000000 + n),64,'0'),
  CASE WHEN mix < 40 THEN 'HOST' WHEN mix < 94 THEN 'ZEEK' ELSE 'SURICATA' END,
  CASE WHEN mix < 40 THEN 'shakerproxy.dns' WHEN mix < 85 THEN 'zeek.conn' WHEN mix < 88 THEN 'zeek.http' WHEN mix < 94 THEN 'zeek.ssl'
       WHEN mix < 99 THEN 'suricata.flow' ELSE 'suricata.alert' END,
  at, at, 'perf','perf',80,
  CASE WHEN n % 10 = 0 THEN NULL ELSE 'device-' || lpad(to_hex(n % 30), 32, '0') END,
  ('10.77.0.' || (n % 200 + 2))::inet,
  CASE WHEN mix < 40 THEN 53 WHEN mix < 65 THEN 443 WHEN mix < 75 THEN 443 WHEN mix < 80 THEN 1900 WHEN mix < 85 THEN 22 WHEN mix < 88 THEN 80 ELSE 443 END,
  CASE WHEN mix < 40 OR (mix >= 65 AND mix < 80) THEN 'udp' ELSE 'tcp' END,
  CASE WHEN mix < 40 THEN 'host' || (n % 50) || '.example' || (n % 7) || '.com' END,
  CASE WHEN mix >= 40 AND mix < 75 THEN (ARRAY['www.google.com','www.apple.com','www.netflix.com','graph.facebook.com','api.amazon.com','cdn.cloudflare.net'])[1 + n % 6] END,
  CASE WHEN mix >= 85 AND mix < 88 THEN 'GET' END,
  CASE WHEN mix >= 85 AND mix < 88 THEN 'connectivitycheck.example.org' END,
  CASE WHEN mix >= 75 AND mix < 80 THEN 'ssdp' END,
  CASE WHEN mix >= 99 THEN 'ET POLICY test' END,
  CASE WHEN mix >= 40 AND mix < 85 THEN jsonb_build_object('orig_bytes', n % 5000, 'resp_bytes', n % 70000)
       WHEN mix >= 94 AND mix < 99 THEN jsonb_build_object('flow', jsonb_build_object('bytes_toserver', 100, 'bytes_toclient', 200))
       ELSE '{}'::jsonb END
FROM (SELECT n, floor(random() * 100)::int AS mix, $1::timestamptz - random() * interval '24 hours' AS at FROM generate_series(1, $2::int) AS n) generated`, now, rows); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, "ANALYZE normalized_events"); err != nil {
		t.Fatal(err)
	}
	t.Logf("loaded %d rows in %s", rows, time.Since(started).Round(time.Millisecond))
	parse := func(text string) querylang.Query {
		parsed, err := querylang.Parse(text)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	cases := []struct {
		name  string
		query TrafficSummaryQuery
	}{
		{"last 15 minutes (live default)", TrafficSummaryQuery{Buckets: 60}},
		{"last 1 hour", TrafficSummaryQuery{Buckets: 60, Events: RecentEventQuery{Filter: parse("time:last_1h")}}},
		{"last 24 hours, all 200k", TrafficSummaryQuery{Buckets: 96, Events: RecentEventQuery{Filter: parse("time:last_24h")}}},
		{"last 24 hours, one device", TrafficSummaryQuery{Buckets: 96, Events: RecentEventQuery{Filter: parse("time:last_24h AND device.id:device-" + strings.Repeat("0", 31) + "7")}}},
		{"last 24 hours, NOT dns, udp", TrafficSummaryQuery{Buckets: 96, Events: RecentEventQuery{Filter: parse("time:last_24h AND NOT service:dns AND protocol:udp")}}},
	}
	for _, tc := range cases {
		var timings []time.Duration
		var summary TrafficSummary
		for range 5 {
			began := time.Now()
			var err error
			summary, err = sink.QueryTrafficSummary(ctx, tc.query)
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			timings = append(timings, time.Since(began))
		}
		slices.Sort(timings)
		organizations := summaryFacet(t, summary, SummaryFacetOrganization)
		t.Logf("%-32s events=%-7d min=%-8s median=%-8s max=%-8s owners exact=%t sampled=%d", tc.name, summary.Totals.Events, timings[0].Round(100*time.Microsecond), timings[2].Round(100*time.Microsecond), timings[4].Round(100*time.Microsecond), organizations.Exact, organizations.SampledEvents)
		if timings[2] > 2*time.Second {
			t.Errorf("%s: median %s exceeds the 2 s budget", tc.name, timings[2])
		}
	}
	for _, window := range []time.Duration{15 * time.Minute, 24 * time.Hour} {
		clauses, args, err := buildEventWhere(RecentEventQuery{Limit: 1}, true)
		if err != nil {
			t.Fatal(err)
		}
		duplicates, err := compileEventFilter(analyzerDuplicates.Root, nil, nil, time.Time{}, true, &args)
		if err != nil {
			t.Fatal(err)
		}
		args = append(args, now.Add(-window), now)
		clauses = append(clauses, duplicates, fmt.Sprintf("occurred_at >= $%d AND occurred_at < $%d", len(args)-1, len(args)))
		plan, err := database.QueryContext(ctx, "EXPLAIN SELECT count(*) FROM normalized_events WHERE "+strings.Join(clauses, " AND "), args...)
		if err != nil {
			t.Fatal(err)
		}
		var lines []string
		for plan.Next() {
			var line string
			if err := plan.Scan(&line); err != nil {
				t.Fatal(err)
			}
			lines = append(lines, strings.TrimSpace(line))
		}
		plan.Close()
		t.Logf("plan for a %s window:\n  %s", window, strings.Join(lines, "\n  "))
		if window == 15*time.Minute && !strings.Contains(strings.Join(lines, " "), "Index") {
			t.Errorf("a 15-minute window did not use the occurred_at index")
		}
	}
}
