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

// A GrapheneOS phone on the test VM made GrapheneOS's own connectivity check
// (as a lookup and as an HTTPS server name) and Google's; the appliance's own
// Ubuntu check has no device and must not name anything.
func TestDevicePlatformHintsPostgresNameTheGrapheneOSPhone(t *testing.T) {
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
	lookup := func(name string) string {
		return fmt.Sprintf(`{"source_ip":"192.168.10.201","source_port":40000,"destination_port":53,"protocol":"udp","service":"dns","query":%q,"query_type":"A","response_code":"NOERROR","answer_count":0,"answers":[],"blocked":false}`, name)
	}
	seeds := []struct {
		source  Source
		kind    string
		device  string
		at      time.Time
		payload string
	}{
		{SourceHost, HostDNSKind, platformPhone, now.Add(-time.Hour), lookup("connectivitycheck.grapheneos.network")},
		{SourceHost, HostDNSKind, platformPhone, now.Add(-time.Minute), lookup("connectivitycheck.gstatic.com")},
		{SourceZeek, "zeek.ssl", platformLaptop, now.Add(-2 * time.Hour), `{"id.orig_h":"192.168.10.50","id.orig_p":50000,"id.resp_h":"203.0.113.9","id.resp_p":443,"server_name":"captive.apple.com"}`},
		// Older than the window.
		{SourceHost, HostDNSKind, platformLaptop, now.Add(-8 * 24 * time.Hour), lookup("www.msftconnecttest.com")},
		// The appliance itself: no device.
		{SourceHost, HostDNSKind, "", now.Add(-time.Minute), lookup("connectivity-check.ubuntu.com")},
	}
	spool := &Spool{Root: t.TempDir(), MaxBytes: 16 << 20, ReserveBytes: 1, Now: func() time.Time { return now }}
	for index, seed := range seeds {
		envelope := Envelope{
			Schema: SchemaVersion, EventID: fmt.Sprintf("platform-hint-event-%04d", index), Source: seed.source, Kind: seed.kind,
			OccurredAt: seed.at, SourceVersion: "test", ParserVersion: "shakerproxy-test-v1", Payload: json.RawMessage(seed.payload),
		}
		if seed.device != "" {
			envelope.DeviceID, envelope.Confidence = seed.device, 90
		}
		raw, err := json.Marshal(envelope)
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
	hints, err := sink.QueryDevicePlatformHints(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, hint := range hints.Hints {
		got[hint.DeviceID] = hint.Platform + " via " + hint.Domain
	}
	want := map[string]string{
		platformPhone:  "GrapheneOS phone via connectivitycheck.grapheneos.network",
		platformLaptop: "Apple device via captive.apple.com",
	}
	if len(got) != len(want) || got[platformPhone] != want[platformPhone] || got[platformLaptop] != want[platformLaptop] {
		t.Fatalf("hints = %v, want %v", got, want)
	}
}
