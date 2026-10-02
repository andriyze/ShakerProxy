package ingest

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// One phone HTTPS connection to www.amazon.com outlived its 30-second capture
// segment and was stored as three unrelated rows: the named one, an unnamed
// one with most of the bytes, and the final reset.
func TestSplitConnectionRecordsShareTheFirstRecordsFlowAndName(t *testing.T) {
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
	database.SetMaxOpenConns(2)
	sink := PostgresSink{DB: database}
	if err := sink.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, "TRUNCATE TABLE normalized_events, normalized_event_identities CASCADE"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_, _ = database.ExecContext(cleanup, "TRUNCATE TABLE normalized_events, normalized_event_identities CASCADE")
	})

	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	capture := "capture-49b166b089e01ba02a6383e32287b082"
	other := "capture-a2a6b8ec23b47a31ac3c02c94fe61886"
	// Written one segment at a time, as the analyzer delivers them.
	segments := [][]Envelope{
		{zeekConnEnvelope("CDStDS3JdzMOd0IFVb", capture, "tcp", "ShADadtt", 38320, "www.amazon.com", start),
			zeekConnEnvelope("Cquic0000000000001", capture, "udp", "Dd", 37829, "", start.Add(5*time.Second))},
		{zeekConnEnvelope("CeUbWM27bHWicMaNM5", capture, "tcp", "DadtAt", 38320, "", start.Add(9*time.Second)),
			zeekConnEnvelope("Cquic0000000000002", capture, "udp", "Dd", 37829, "", start.Add(35*time.Second)),
			zeekConnEnvelope("Cother000000000001", other, "tcp", "DadtAt", 38320, "", start.Add(10*time.Second))},
		{zeekConnEnvelope("CQwaNO2wZCkzW2Eted", capture, "tcp", "R", 38320, "", start.Add(86*time.Second))},
		{zeekConnEnvelope("Creuse000000000001", capture, "tcp", "ShAD", 38320, "", start.Add(20*time.Minute)),
			zeekConnEnvelope("Cquic0000000000003", capture, "udp", "Dd", 37829, "", start.Add(20*time.Minute))},
	}
	spool := &Spool{Root: t.TempDir(), MaxBytes: 16 << 20, ReserveBytes: 1, Now: func() time.Time { return start }}
	for _, segment := range segments {
		for _, envelope := range segment {
			raw, err := json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			if result, err := spool.Accept(raw); err != nil || !result.Accepted || result.Quarantined {
				t.Fatalf("seed event was not accepted: %#v err=%v", result, err)
			}
		}
		batch, err := spool.PendingBatch(10)
		if err != nil || len(batch) != len(segment) {
			t.Fatalf("segment batch=%d err=%v", len(batch), err)
		}
		if err := sink.WriteBatch(ctx, batch); err != nil {
			t.Fatal(err)
		}
		delivered := make([]string, 0, len(batch))
		for _, pending := range batch {
			delivered = append(delivered, pending.RecordID)
		}
		if err := spool.Acknowledge(delivered); err != nil {
			t.Fatal(err)
		}
	}

	rows, err := database.QueryContext(ctx, "SELECT payload->>'uid', COALESCE(flow_id, ''), COALESCE(tls_server_name, '') FROM normalized_events ORDER BY occurred_at, payload->>'uid'")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string][2]string{}
	for rows.Next() {
		var uid, flowID, serverName string
		if err := rows.Scan(&uid, &flowID, &serverName); err != nil {
			t.Fatal(err)
		}
		got[uid] = [2]string{flowID, serverName}
	}
	want := map[string][2]string{
		"CDStDS3JdzMOd0IFVb": {"flow-zeek-CDStDS3JdzMOd0IFVb", "www.amazon.com"},
		"CeUbWM27bHWicMaNM5": {"flow-zeek-CDStDS3JdzMOd0IFVb", "www.amazon.com"},
		"CQwaNO2wZCkzW2Eted": {"flow-zeek-CDStDS3JdzMOd0IFVb", "www.amazon.com"},
		// A SYN starts a new connection even on the same 5-tuple.
		"Creuse000000000001": {"flow-zeek-Creuse000000000001", ""},
		// Another capture is another recording.
		"Cother000000000001": {"flow-zeek-Cother000000000001", ""},
		// UDP continues only from an adjacent segment.
		"Cquic0000000000001": {"flow-zeek-Cquic0000000000001", ""},
		"Cquic0000000000002": {"flow-zeek-Cquic0000000000001", ""},
		"Cquic0000000000003": {"flow-zeek-Cquic0000000000003", ""},
	}
	for uid, expected := range want {
		if got[uid] != expected {
			t.Errorf("%s: flow/name = %v, want %v", uid, got[uid], expected)
		}
	}
}
