package ingest

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/querylang"
)

func openPipelineTestDatabase(t *testing.T, parameters string) (*sql.DB, PostgresSink) {
	t.Helper()
	databaseURL := os.Getenv("SHAKERPROXY_POSTGRES_TEST_URL")
	if databaseURL == "" {
		t.Skip("SHAKERPROXY_POSTGRES_TEST_URL is not set")
	}
	if parameters != "" {
		separator := "?"
		if strings.Contains(databaseURL, "?") {
			separator = "&"
		}
		databaseURL += separator + parameters
	}
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	sink := PostgresSink{DB: database}
	if err := sink.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	return database, sink
}

func TestPostgresPartitionBoundsIgnoreSessionTimeZone(t *testing.T) {
	database, sink := openPipelineTestDatabase(t, "timezone=America/New_York")
	for _, partition := range []string{"normalized_events_203012", "normalized_events_203101"} {
		if _, err := database.ExecContext(t.Context(), "DROP TABLE IF EXISTS "+partition); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = database.ExecContext(t.Context(), "DROP TABLE IF EXISTS "+partition) })
	}
	spool := &Spool{Root: filepath.Join(t.TempDir(), "timezone-spool"), MaxBytes: 8 << 20, ReserveBytes: 1}
	// 02:00 UTC on the first of the month is still the previous month in New York.
	if _, err := spool.Accept([]byte(selectionEventJSON("timezone-boundary-0001", "", "10.77.0.50", time.Date(2031, 1, 1, 2, 0, 0, 0, time.UTC)))); err != nil {
		t.Fatal(err)
	}
	if result, err := DrainOnce(t.Context(), spool, sink, 10); err != nil || result.Committed != 1 {
		t.Fatalf("month-boundary event was not stored under a non-UTC session: %#v err=%v", result, err)
	}
}

func TestPostgresDrainSetsAsideConflictingIdentityAndKeepsDraining(t *testing.T) {
	database, sink := openPipelineTestDatabase(t, "")
	if _, err := database.ExecContext(t.Context(), "TRUNCATE normalized_events, normalized_event_identities"); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	first := &Spool{Root: filepath.Join(t.TempDir(), "first"), MaxBytes: 8 << 20, ReserveBytes: 1}
	if _, err := first.Accept([]byte(selectionEventJSON("identity-conflict-0001", "", "10.77.0.51", at))); err != nil {
		t.Fatal(err)
	}
	if result, err := DrainOnce(t.Context(), first, sink, 10); err != nil || result.Committed != 1 {
		t.Fatalf("seed event was not stored: %#v err=%v", result, err)
	}
	root := filepath.Join(t.TempDir(), "second")
	second := &Spool{Root: root, MaxBytes: 8 << 20, ReserveBytes: 1}
	conflicting, err := second.Accept([]byte(selectionEventJSON("identity-conflict-0001", "", "10.77.0.52", at)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Accept([]byte(selectionEventJSON("identity-conflict-0002", "", "10.77.0.53", at))); err != nil {
		t.Fatal(err)
	}
	result, err := DrainOnce(t.Context(), second, sink, 10)
	if err != nil || result.Rejected != 1 || result.Committed != 0 {
		t.Fatalf("conflicting identity was not set aside: %#v err=%v", result, err)
	}
	if _, err := os.Stat(filepath.Join(root, "rejected", conflicting.RecordID+".json")); err != nil {
		t.Fatalf("rejected record was not retained for inspection: %v", err)
	}
	if result, err := DrainOnce(t.Context(), second, sink, 10); err != nil || result.Committed != 1 {
		t.Fatalf("backlog behind a poison record did not drain: %#v err=%v", result, err)
	}
}

func TestPostgresFiltersCoverPassiveAnalyzersAndNegation(t *testing.T) {
	database, sink := openPipelineTestDatabase(t, "")
	if _, err := database.ExecContext(t.Context(), "TRUNCATE normalized_events, normalized_event_identities"); err != nil {
		t.Fatal(err)
	}
	spool := &Spool{Root: filepath.Join(t.TempDir(), "passive"), MaxBytes: 8 << 20, ReserveBytes: 1}
	accept := func(envelope Envelope, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(envelope)
		if _, err := spool.Accept(encoded); err != nil {
			t.Fatal(err)
		}
	}
	accept(NormalizeZeekJSON([]byte(`{"_path":"http","ts":1790000000.07,"uid":"CkwEze28Lpdsqx4AU1","id.orig_h":"10.77.0.23","id.orig_p":50000,"id.resp_h":"93.184.216.34","id.resp_p":80,"method":"GET","host":"Example.com:8080","uri":"/api/v1/items?token=secret","status_code":404}`), "zeek-8.2.1", ""))
	accept(NormalizeZeekJSON([]byte(`{"_path":"ssl","ts":1790000000.15,"uid":"CNBUD125J84HhWBWMf","id.orig_h":"10.77.0.23","id.orig_p":50001,"id.resp_h":"93.184.216.34","id.resp_p":443,"server_name":"api.example.com"}`), "zeek-8.2.1", ""))
	accept(NormalizeZeekJSON([]byte(`{"_path":"conn","ts":1790000000.0,"uid":"CVohcE1fiJb5814Jfb","id.orig_h":"10.77.0.23","id.orig_p":40000,"id.resp_h":"10.77.0.1","id.resp_p":53,"proto":"udp","service":"dns"}`), "zeek-8.2.1", ""))
	accept(NormalizeSuricataEVE([]byte(`{"timestamp":"2026-09-21T14:13:20.090000+0000","flow_id":171800015157452,"event_type":"http","src_ip":"10.77.0.23","src_port":50000,"dest_ip":"93.184.216.34","dest_port":80,"proto":"TCP","http":{"hostname":"example.com","url":"/api/v1/items?token=secret","http_method":"GET","status":404}}`), "suricata-8.0.6", ""))
	accept(NormalizeSuricataEVE([]byte(`{"timestamp":"2026-09-21T14:13:20.120000+0000","flow_id":233922551997896,"event_type":"tls","src_ip":"10.77.0.23","src_port":50001,"dest_ip":"93.184.216.34","dest_port":443,"proto":"TCP","tls":{"sni":"api.example.com"}}`), "suricata-8.0.6", ""))
	accept(DecodeEnvelope([]byte(`{"schema":1,"event_id":"evt_0123456789abcdef0123456789abcd03","source":"MITMPROXY","kind":"tls_intercepted","occurred_at":"2026-09-21T14:13:21Z","source_version":"12.2.3","parser_version":"shakerproxy-addon-1.0.0","confidence":100,"payload":{"sni":"api.example.com","source_ip":"10.77.0.23","destination_ip":"93.184.216.34","source_port":50004,"destination_port":443,"protocol":"tcp"}}`)))
	if result, err := DrainOnce(t.Context(), spool, sink, 10); err != nil || result.Committed != 6 {
		t.Fatalf("passive fixtures were not stored: %#v err=%v", result, err)
	}
	for query, expected := range map[string]int{
		"http.host:example.com":   2,
		"http.method:GET":         2,
		"http.path:/api/v1/items": 2,
		"http.status>=400":        2,
		"tls.sni:api.example.com": 3,
		"service:dns":             1,
		"NOT service:dns":         5,
		"service!=dns":            5,
		"tls.pinning:false":       1,
		"tls.pinning:true":        0,
		// A bare address finds traffic from or to it; a fragment does not.
		"10.77.0.23":        6,
		"10.77.0.1":         1,
		"93.184.216.34":     5,
		"NOT 93.184.216.34": 1,
		"10.77.0.0/24":      6,
		"10.77.0.":          0,
	} {
		filter, err := querylang.Parse(query)
		if err != nil {
			t.Fatal(err)
		}
		page, err := sink.QueryRecent(t.Context(), RecentEventQuery{Limit: 100, Filter: filter})
		if err != nil || len(page.Events) != expected {
			t.Fatalf("%s returned %d events, want %d (err=%v)", query, len(page.Events), expected, err)
		}
	}
}
