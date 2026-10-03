package ingest

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// The single-arm lab on the test VM: the iPhone took the router's DHCP and
// only its DHCP request and mDNS were recorded; the Pixel's traffic went to
// ShakerProxy; the iPad asked for an address on a neighbouring network.
func TestLabPresencePostgresSeparatesVisibleTraffic(t *testing.T) {
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
	conn := func(origin, responder string, originPort, responderPort int, protocol, service, mac string) string {
		return fmt.Sprintf(`{"ts":0,"uid":"C1","id.orig_h":%q,"id.orig_p":%d,"id.resp_h":%q,"id.resp_p":%d,"proto":%q,"service":%q,"orig_l2_addr":%q,"orig_bytes":100,"resp_bytes":0}`,
			origin, originPort, responder, responderPort, protocol, service, mac)
	}
	seeds := []struct {
		kind    string
		at      time.Time
		payload string
	}{
		{"zeek.dhcp", now.Add(-4 * time.Minute), `{"ts":0,"mac":"62:bc:f1:bc:1d:8d","host_name":"iPhone","msg_types":["DISCOVER","REQUEST"],"requested_addr":"192.168.10.130"}`},
		{"zeek.conn", now.Add(-3 * time.Minute), conn("192.168.10.130", "224.0.0.251", 5353, 5353, "udp", "dns", "62:bc:f1:bc:1d:8d")},
		{"zeek.conn", now.Add(-time.Minute), conn("192.168.10.130", "224.0.0.251", 5353, 5353, "udp", "dns", "62:bc:f1:bc:1d:8d")},
		{"zeek.conn", now.Add(-5 * time.Minute), conn("192.168.10.201", "142.250.1.1", 50000, 443, "tcp", "ssl", "b6:53:83:65:54:a2")},
		{"zeek.conn", now.Add(-2 * time.Minute), conn("192.168.10.201", "192.168.10.177", 50001, 53, "udp", "dns", "b6:53:83:65:54:a2")},
		{"zeek.dhcp", now.Add(-time.Minute), `{"ts":0,"mac":"0e:47:eb:9f:1b:6a","host_name":"iPad","msg_types":["REQUEST"],"requested_addr":"192.168.100.196"}`},
		// Older than the window.
		{"zeek.conn", now.Add(-time.Hour), conn("192.168.10.77", "224.0.0.251", 5353, 5353, "udp", "dns", "02:00:00:00:00:77")},
	}
	spool := &Spool{Root: t.TempDir(), MaxBytes: 16 << 20, ReserveBytes: 1, Now: func() time.Time { return now }}
	for index, seed := range seeds {
		envelope := Envelope{
			Schema: SchemaVersion, EventID: fmt.Sprintf("lab-presence-event-%04d", index), Source: SourceZeek, Kind: seed.kind,
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
	presence, err := sink.QueryLabPresence(ctx, netip.MustParsePrefix("192.168.10.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	byAddress := map[string]LabPresenceHost{}
	for _, host := range presence.Hosts {
		byAddress[host.Address] = host
	}
	if len(byAddress) != 2 {
		t.Fatalf("hosts = %+v", presence.Hosts)
	}
	iphone := byAddress["192.168.10.130"]
	if iphone.HostName != "iPhone" || len(iphone.HardwareAddrs) != 1 || iphone.HardwareAddrs[0] != "62:bc:f1:bc:1d:8d" || iphone.VisibleEvents != 0 || iphone.Events != 3 ||
		!iphone.DHCPLastSeen.Equal(now.Add(-4*time.Minute)) || !iphone.FirstSeen.Equal(now.Add(-4*time.Minute)) || !iphone.LastSeen.Equal(now.Add(-time.Minute)) {
		t.Fatalf("iPhone = %+v", iphone)
	}
	pixel := byAddress["192.168.10.201"]
	if pixel.VisibleEvents != 2 || !pixel.VisibleFirstSeen.Equal(now.Add(-5*time.Minute)) || !pixel.VisibleLastSeen.Equal(now.Add(-2*time.Minute)) || len(pixel.HardwareAddrs) != 1 {
		t.Fatalf("Pixel = %+v", pixel)
	}
}
