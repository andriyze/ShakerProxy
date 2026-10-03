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

// A phone broadcasting _rdlink mDNS is an Apple device; a caster browsing
// Google Cast and Spotify Connect is a Chromecast. The meta browse name and
// an un-attributed broadcast name nothing.
func TestDeviceServicesPostgresIdentifyFromMDNS(t *testing.T) {
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
	mdns := func(src, name string) string {
		return fmt.Sprintf(`{"id.orig_h":%q,"id.orig_p":5353,"id.resp_h":"224.0.0.251","id.resp_p":5353,"proto":"udp","query":%q,"qtype_name":"PTR","rcode_name":"NOERROR"}`, src, name)
	}
	seeds := []struct {
		device  string
		at      time.Time
		payload string
	}{
		{platformPhone, now.Add(-2 * time.Minute), mdns("192.168.10.130", "_rdlink._tcp.local")},
		{platformPhone, now.Add(-time.Minute), mdns("192.168.10.130", "_rdlink._tcp.local")},
		{platformLaptop, now.Add(-3 * time.Minute), mdns("192.168.10.60", "_spotify-connect._tcp.local")},
		{platformLaptop, now.Add(-2 * time.Minute), mdns("192.168.10.60", "_googlecast._tcp.local")},
		// Meta browse name: never a type signal.
		{platformLaptop, now.Add(-time.Minute), mdns("192.168.10.60", "_services._dns-sd._udp.local")},
		// Older than the window.
		{platformPhone, now.Add(-8 * 24 * time.Hour), mdns("192.168.10.130", "_airplay._tcp.local")},
		// No device: names nothing.
		{"", now.Add(-time.Minute), mdns("192.168.10.1", "_googlecast._tcp.local")},
	}
	spool := &Spool{Root: t.TempDir(), MaxBytes: 16 << 20, ReserveBytes: 1, Now: func() time.Time { return now }}
	for index, seed := range seeds {
		envelope := Envelope{
			Schema: SchemaVersion, EventID: fmt.Sprintf("device-service-event-%04d", index), Source: SourceZeek, Kind: "zeek.dns",
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
	hints, err := sink.QueryDeviceServices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]DeviceServiceHint{}
	for _, hint := range hints.Hints {
		byID[hint.DeviceID] = hint
	}
	if len(byID) != 2 {
		t.Fatalf("got %d devices with services, want 2: %#v", len(byID), hints.Hints)
	}
	if got := byID[platformPhone]; got.Type != "Apple device" || len(got.Services) != 1 || got.Services[0].Service != "_rdlink._tcp" {
		t.Fatalf("phone services = %#v", got)
	}
	cast := byID[platformLaptop]
	if cast.Type != "Chromecast / Google Cast device" {
		t.Fatalf("caster type = %q", cast.Type)
	}
	services := map[string]bool{}
	for _, service := range cast.Services {
		services[service.Service] = true
	}
	if !services["_googlecast._tcp"] || !services["_spotify-connect._tcp"] || services["_services._dns-sd"] || len(cast.Services) != 2 {
		t.Fatalf("caster services = %#v", cast.Services)
	}
}
