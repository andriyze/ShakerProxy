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

// Refused lookups (dnsd) and refused connections (the gateway) come back
// from the event store marked blocked, with why, so Traffic can show them.
func TestPostgresMarksBlockedLookupsAndAttempts(t *testing.T) {
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
	seeds := []struct {
		kind    string
		payload string
	}{
		{HostBlockedKind, `{"source_ip":"192.168.10.201","source_port":40123,"destination_ip":"8.8.8.8","destination_port":443,"protocol":"tcp","service":"dns","blocked":true,"reason":"doh-ip","resolver":"Google Public DNS"}`},
		{HostBlockedKind, `{"source_ip":"192.168.10.201","source_port":40124,"destination_ip":"1.1.1.1","destination_port":853,"protocol":"tcp","service":"dns","blocked":true,"reason":"dot"}`},
		{HostDNSKind, `{"source_ip":"192.168.10.201","source_port":40000,"destination_port":53,"protocol":"udp","service":"dns","query":"dns.google","query_type":"A","response_code":"NXDOMAIN","answer_count":0,"answers":[],"blocked":true,"blocked_domain":"dns.google","blocked_reason":"doh-name"}`},
		{HostDNSKind, `{"source_ip":"192.168.10.201","source_port":40001,"destination_port":53,"protocol":"udp","service":"dns","query":"ads.example","query_type":"A","response_code":"NXDOMAIN","answer_count":0,"answers":[],"blocked":true,"blocked_domain":"ads.example"}`},
		{HostDNSKind, `{"source_ip":"192.168.10.201","source_port":40002,"destination_port":53,"protocol":"udp","service":"dns","query":"example.com","query_type":"A","response_code":"NOERROR","answer_count":0,"answers":[],"blocked":false}`},
		// An unexpected reason never reaches clients.
		{HostBlockedKind, `{"source_ip":"192.168.10.201","destination_ip":"9.9.9.9","destination_port":443,"protocol":"tcp","service":"dns","blocked":true,"reason":"<script>"}`},
	}
	spool := &Spool{Root: t.TempDir(), MaxBytes: 16 << 20, ReserveBytes: 1, Now: func() time.Time { return now }}
	for index, seed := range seeds {
		raw, err := json.Marshal(Envelope{
			Schema: SchemaVersion, EventID: fmt.Sprintf("blocked-attempt-event-%04d", index), Source: SourceHost, Kind: seed.kind,
			OccurredAt: now.Add(-time.Duration(len(seeds)-index) * time.Minute), SourceVersion: "test", ParserVersion: "shakerproxy-test-v1", Confidence: 100,
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
	page, err := sink.QueryRecent(ctx, RecentEventQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != len(seeds) {
		t.Fatalf("events = %d", len(page.Events))
	}
	byPort := map[int]RecentEvent{}
	for _, event := range page.Events {
		byPort[event.SourcePort*1000+event.DestinationPort] = event
		if event.Kind == HostBlockedKind && event.DestinationIP == "9.9.9.9" {
			if !event.Blocked || event.BlockedReason != "" {
				t.Fatalf("an unknown reason leaked: %+v", event)
			}
		}
	}
	doh := byPort[40123*1000+443]
	if !doh.Blocked || doh.BlockedReason != "doh-ip" || doh.DestinationIP != "8.8.8.8" || doh.SourceIP != "192.168.10.201" || !strings.Contains(doh.Summary, "Blocked DNS over HTTPS to 8.8.8.8:443") {
		t.Fatalf("DoH attempt = %+v", doh)
	}
	if dot := byPort[40124*1000+853]; !dot.Blocked || dot.BlockedReason != "dot" || !strings.Contains(dot.Summary, "DNS over TLS") {
		t.Fatalf("DoT attempt = %+v", dot)
	}
	if name := byPort[40000*1000+53]; !name.Blocked || name.BlockedReason != "doh-name" || !strings.Contains(name.Summary, "blocked (encrypted DNS resolver name)") {
		t.Fatalf("refused resolver name = %+v", name)
	}
	if device := byPort[40001*1000+53]; !device.Blocked || device.BlockedReason != "device-domain" {
		t.Fatalf("device domain block = %+v", device)
	}
	if plain := byPort[40002*1000+53]; plain.Blocked || plain.BlockedReason != "" {
		t.Fatalf("an answered lookup is marked blocked: %+v", plain)
	}
	// The query client accepts the projection it receives.
	encoded, _ := json.Marshal(page)
	var decoded RecentEventPage
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
}
