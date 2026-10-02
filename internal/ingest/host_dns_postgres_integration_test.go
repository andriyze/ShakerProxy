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
)

// A capture records the same lookups the DNS forwarder already reported. The
// device report counts each forwarded lookup once and keeps Zeek's lookups
// only for names the forwarder never saw (for example another resolver).
func TestDeviceActivityPostgresPrefersForwarderLookups(t *testing.T) {
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
	device := "device-0123456789abcdef0123456789abcdef"
	forwarded := func(name string) string {
		return fmt.Sprintf(`{"source_ip":"192.168.10.201","source_port":40000,"destination_port":53,"protocol":"udp","service":"dns","query":%q,"query_type":"A","response_code":"NOERROR","answer_count":1,"answers":[],"blocked":false}`, name)
	}
	seeds := []struct {
		source  Source
		kind    string
		payload string
	}{
		{SourceHost, HostDNSKind, forwarded("api.example.com")},
		{SourceZeek, "zeek.dns", `{"query":"api.example.com","qtype_name":"A","rcode_name":"NOERROR","answers":["203.0.113.20"]}`},
		{SourceZeek, "zeek.dns", `{"query":"API.Example.com.","qtype_name":"A","rcode_name":"NOERROR","answers":["203.0.113.20"]}`},
		{SourceZeek, "zeek.dns", `{"query":"other-resolver.example.com","qtype_name":"A","rcode_name":"NOERROR","answers":[]}`},
	}
	spool := &Spool{Root: t.TempDir(), MaxBytes: 16 << 20, ReserveBytes: 1, Now: func() time.Time { return now }}
	for index, seed := range seeds {
		raw, err := json.Marshal(Envelope{
			Schema: SchemaVersion, EventID: fmt.Sprintf("forwarder-lookup-event-%04d", index), Source: seed.source, Kind: seed.kind,
			OccurredAt: at, SourceVersion: "test", ParserVersion: "shakerproxy-test-v1", DeviceID: device, Confidence: 90,
			Payload: json.RawMessage(seed.payload),
		})
		if err != nil {
			t.Fatal(err)
		}
		if result, err := spool.Accept(raw); err != nil || !result.Accepted {
			t.Fatalf("seed %d was not accepted: %#v err=%v", index, result, err)
		}
	}
	batch, err := spool.PendingBatch(100)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.WriteBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	activity, err := sink.QueryDeviceActivity(ctx, DeviceActivityQuery{DeviceID: device, Start: now.Add(-time.Hour), End: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if activity.Counts.ForwarderDNS != 1 || activity.Counts.ZeekDNS != 3 {
		t.Fatalf("unexpected DNS counts: %#v", activity.Counts)
	}
	lookups := map[string]int64{}
	for _, item := range activity.Domains {
		if item.Source == "dns" {
			lookups[item.Domain] = item.Events
		}
	}
	if lookups["api.example.com"] != 1 || lookups["other-resolver.example.com"] != 1 || len(lookups) != 2 {
		t.Fatalf("lookups per domain = %v", lookups)
	}
}
