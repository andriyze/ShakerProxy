package ingest

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// The gateway reports a connection within a second, before any capture is
// analyzed; ingest names it from the same client's own DNS answers.
func TestGatewayConnectionsAreNamedFromTheClientsDNSAnswers(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("SHAKERPROXY_TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("SHAKERPROXY_TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	sink := PostgresSink{DB: database}
	if err := sink.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	truncate := func(ctx context.Context) {
		_, _ = database.ExecContext(ctx, "TRUNCATE TABLE normalized_events, normalized_event_identities CASCADE")
	}
	truncate(ctx)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		truncate(cleanup)
	})
	now := time.Now().UTC().Truncate(time.Second)
	at := now.Add(-10 * time.Minute)
	spool := &Spool{Root: t.TempDir(), MaxBytes: 16 << 20, ReserveBytes: 1, Now: func() time.Time { return now }}
	sequence := 0
	accept := func(kind string, occurredAt time.Time, payload string) {
		t.Helper()
		sequence++
		raw, err := json.Marshal(Envelope{
			Schema: SchemaVersion, EventID: fmt.Sprintf("gateway-connection-event-%04d", sequence), Source: SourceHost, Kind: kind,
			OccurredAt: occurredAt, SourceVersion: "test", ParserVersion: "shakerproxy-test-v1", Confidence: 100, Payload: json.RawMessage(payload),
		})
		if err != nil {
			t.Fatal(err)
		}
		if result, err := spool.Accept(raw); err != nil || !result.Accepted {
			t.Fatalf("event %d was not accepted: %#v err=%v", sequence, result, err)
		}
	}
	write := func() {
		t.Helper()
		batch, err := spool.PendingBatch(100)
		if err != nil {
			t.Fatal(err)
		}
		if err := sink.WriteBatch(ctx, batch); err != nil {
			t.Fatal(err)
		}
		recordIDs := make([]string, 0, len(batch))
		for _, pending := range batch {
			recordIDs = append(recordIDs, pending.RecordID)
		}
		if err := spool.Acknowledge(recordIDs); err != nil {
			t.Fatal(err)
		}
	}
	connection := func(source, destination string, port int) string {
		return fmt.Sprintf(`{"source_ip":%q,"source_port":37064,"destination_ip":%q,"destination_port":%d,"protocol":"tcp"}`, source, destination, port)
	}
	// One batch: the phone looks up github.com, then connects to it; it also
	// connects to an address it never looked up, and another device
	// connects to github.com's address without having looked it up.
	accept(HostDNSKind, at, `{"source_ip":"192.168.10.201","source_port":40000,"destination_port":53,"protocol":"udp","service":"dns","query":"github.com","query_type":"A","response_code":"NOERROR","answer_count":1,"answers":[{"name":"github.com","type":"A","ttl":60,"data":"140.82.121.4"}],"blocked":false}`)
	accept(HostConnKind, at.Add(time.Second), connection("192.168.10.201", "140.82.121.4", 443))
	accept(HostConnKind, at.Add(2*time.Second), connection("192.168.10.201", "151.101.1.1", 443))
	accept(HostConnKind, at.Add(3*time.Second), connection("192.168.10.50", "140.82.121.4", 443))
	write()
	// A later batch: the phone reuses the answer five minutes on.
	accept(HostConnKind, at.Add(5*time.Minute), strings.Replace(connection("192.168.10.201", "140.82.121.4", 443), "37064", "37099", 1))
	write()

	query, err := ParseRecentEventQuery(url.Values{"limit": {"100"}, "q": {"kind:shakerproxy.conn"}})
	if err != nil {
		t.Fatal(err)
	}
	page, err := sink.QueryRecent(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	for _, event := range page.Events {
		names[fmt.Sprintf("%s>%s@%s", event.SourceIP, event.DestinationIP, event.OccurredAt.Sub(at))] = event.DNSName
		if event.DestinationPort != 443 || event.Protocol != "tcp" || event.SourcePort != 37064 && event.SourcePort != 37099 {
			t.Fatalf("connection projection = %#v", event)
		}
	}
	want := map[string]string{
		"192.168.10.201>140.82.121.4@1s":   "github.com",
		"192.168.10.201>151.101.1.1@2s":    "",
		"192.168.10.50>140.82.121.4@3s":    "",
		"192.168.10.201>140.82.121.4@5m0s": "github.com",
	}
	if len(names) != len(want) {
		t.Fatalf("connections = %v", names)
	}
	for key, name := range want {
		if names[key] != name {
			t.Fatalf("%s named %q, want %q (all: %v)", key, names[key], name, names)
		}
	}
	// A plain search for the name finds the phone's connections too.
	search, err := ParseRecentEventQuery(url.Values{"limit": {"100"}, "q": {"github"}})
	if err != nil {
		t.Fatal(err)
	}
	found, err := sink.QueryRecent(ctx, search)
	if err != nil {
		t.Fatal(err)
	}
	connections := 0
	for _, event := range found.Events {
		if event.Kind == HostConnKind {
			connections++
		}
	}
	if connections != 2 {
		t.Fatalf("searching github found %d connections, want 2", connections)
	}
	// Top domains count the named connections right away: the lookup and
	// the two connections the phone opened to github.com.
	if found.Facets == nil {
		t.Fatal("the first page has no facets")
	}
	counts := map[string]int64{}
	for _, value := range found.Facets.Domains.Values {
		counts[value.Domain] = value.Count
	}
	if counts["github.com"] != 3 {
		t.Fatalf("domains = %#v", found.Facets.Domains.Values)
	}
}
