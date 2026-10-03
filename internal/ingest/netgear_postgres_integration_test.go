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

// The router serves DHCP and sends its logs to ShakerProxy. A single-arm lab
// never captures the router's unicast acknowledgement, but its syslog carries
// the lease. The collector's netgear.dhcp_lease event must enrich the
// inventory through the same path as a captured exchange, so the iPhone is
// named even though none of its traffic reaches ShakerProxy.
func TestNetgearDHCPPostgresNamesTheBypassingDevice(t *testing.T) {
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
	payload := map[string]any{
		"mac":           "62:bc:f1:bc:1d:8d",
		"host_name":     "iPhone",
		"assigned_addr": "192.168.10.130",
		"server":        "192.168.10.1",
		"router":        "192.168.10.1",
		"lease_seconds": 3600,
		"reported_by":   "192.168.10.1",
	}
	envelope, err := NormalizeNetworkGearEvent(NetworkGearDHCPKind, now.Add(-time.Minute), payload)
	if err != nil {
		t.Fatal(err)
	}
	spool := &Spool{Root: t.TempDir(), MaxBytes: 16 << 20, ReserveBytes: 1, Now: func() time.Time { return now }}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := spool.Accept(raw); err != nil || !result.Accepted {
		t.Fatalf("lease event was not accepted: %#v err=%v", result, err)
	}
	batch, err := spool.PendingBatch(10)
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
	if len(observed.Clients) != 1 {
		t.Fatalf("clients = %+v", observed.Clients)
	}
	client := observed.Clients[0]
	if client.HostName != "iPhone" || client.AssignedAddr != "192.168.10.130" || client.HardwareAddr != "62:bc:f1:bc:1d:8d" ||
		client.Server != "192.168.10.1" || client.Router != "192.168.10.1" || client.LeaseSeconds != 3600 {
		t.Fatalf("client = %+v", client)
	}
	// The event is searchable as a NETWORK_GEAR discovery event too.
	var count int
	if err := database.QueryRowContext(ctx, fmt.Sprintf("SELECT count(*) FROM normalized_events WHERE source = '%s' AND kind = '%s'", SourceNetworkGear, NetworkGearDHCPKind)).Scan(&count); err != nil || count != 1 {
		t.Fatalf("stored netgear events = %d err=%v", count, err)
	}
}

// A router-logged firewall event has the device as source and a real internet
// destination, but it is not evidence the traffic reached ShakerProxy. Lab
// presence must count it toward the device's presence while leaving its
// visible count at zero, so the bypass classifier still reports it bypassing.
func TestNetgearEventsCountAsPresenceNotVisibility(t *testing.T) {
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
	firewall := map[string]any{
		"source_ip": "192.168.10.130", "destination_ip": "203.0.113.9",
		"protocol": "tcp", "source_port": 40000, "destination_port": 23,
		"action": "drop", "chain": "WAN_LOCAL-default-D", "reported_by": "192.168.10.1",
	}
	envelope, err := NormalizeNetworkGearEvent(NetworkGearFirewallKind, now.Add(-2*time.Minute), firewall)
	if err != nil {
		t.Fatal(err)
	}
	spool := &Spool{Root: t.TempDir(), MaxBytes: 16 << 20, ReserveBytes: 1, Now: func() time.Time { return now }}
	raw, _ := json.Marshal(envelope)
	if result, err := spool.Accept(raw); err != nil || !result.Accepted {
		t.Fatalf("firewall event not accepted: %#v err=%v", result, err)
	}
	batch, err := spool.PendingBatch(10)
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
	if len(presence.Hosts) != 1 {
		t.Fatalf("hosts = %+v", presence.Hosts)
	}
	host := presence.Hosts[0]
	if host.Address != "192.168.10.130" || host.Events != 1 || host.VisibleEvents != 0 {
		t.Fatalf("host = %+v (want present, not visible)", host)
	}
}
