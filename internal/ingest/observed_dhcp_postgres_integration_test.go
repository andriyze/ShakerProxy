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

// The router serves the lab's DHCP; the recording saw the phone's exchange
// (Zeek), the router's acknowledgement (Suricata) and an iPad asking. A week
// old exchange is outside the window.
func TestObservedDHCPPostgresMergesZeekAndSuricata(t *testing.T) {
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
		source  Source
		kind    string
		at      time.Time
		payload string
	}{
		{SourceZeek, "zeek.dhcp", now.Add(-time.Hour), `{"ts":0,"mac":"b6:53:83:65:54:a2","host_name":"Pixel-7","client_software":"android-dhcp-14","client_param_list":[1,3,6,15,26,28,51,58,59,43,114,108],"requested_addr":"192.168.10.201","msg_types":["DISCOVER","REQUEST"]}`},
		{SourceSuricata, "suricata.dhcp", now.Add(-time.Hour + time.Second), `{"src_ip":"192.168.10.1","dhcp":{"type":"reply","client_mac":"b6:53:83:65:54:a2","assigned_ip":"192.168.10.201","dhcp_type":"ack","lease_time":86400,"routers":["192.168.10.1"]}}`},
		{SourceZeek, "zeek.dhcp", now.Add(-time.Minute), `{"ts":0,"mac":"0e:47:eb:9f:1b:6a","host_name":"iPad","requested_addr":"192.168.100.196","msg_types":["REQUEST"],"client_param_list":[1,121,3,6,15,108,114,119,252,95,44,46]}`},
		// Older than the window.
		{SourceZeek, "zeek.dhcp", now.Add(-8 * 24 * time.Hour), `{"ts":0,"mac":"02:00:00:00:00:01","host_name":"old-laptop","msg_types":["REQUEST"]}`},
		// Not DHCP.
		{SourceZeek, "zeek.conn", now.Add(-time.Minute), `{"ts":0,"orig_l2_addr":"02:00:00:00:00:02"}`},
	}
	spool := &Spool{Root: t.TempDir(), MaxBytes: 16 << 20, ReserveBytes: 1, Now: func() time.Time { return now }}
	for index, seed := range seeds {
		envelope := Envelope{
			Schema: SchemaVersion, EventID: fmt.Sprintf("observed-dhcp-event-%04d", index), Source: seed.source, Kind: seed.kind,
			OccurredAt: seed.at, SourceVersion: "test", ParserVersion: "shakerproxy-test-v1", Payload: json.RawMessage(seed.payload),
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
	observed, err := sink.QueryObservedDHCP(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(observed.Clients) != 2 {
		t.Fatalf("clients = %+v", observed.Clients)
	}
	ipad, phone := observed.Clients[0], observed.Clients[1]
	if ipad.HostName != "iPad" || ipad.AssignedAddr != "" {
		t.Fatalf("iPad = %+v", ipad)
	}
	if phone.HostName != "Pixel-7" || phone.VendorClass != "android-dhcp-14" || phone.AssignedAddr != "192.168.10.201" || phone.Server != "192.168.10.1" || phone.Router != "192.168.10.1" ||
		phone.LeaseSeconds != 86400 || !phone.AssignedAt.Equal(now.Add(-time.Hour+time.Second)) || !phone.FirstSeen.Equal(now.Add(-time.Hour)) {
		t.Fatalf("phone = %+v", phone)
	}
}
