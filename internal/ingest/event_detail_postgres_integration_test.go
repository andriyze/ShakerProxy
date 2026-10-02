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

// The event inspector failed for every event: PostgreSQL renders jsonb with
// spaces, and payload_bytes measured that text instead of the payload sent.
func TestEventDetailPostgresRoundTripsThroughTheQueryClient(t *testing.T) {
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

	now := time.Now().UTC().Truncate(time.Second)
	spool := &Spool{Root: t.TempDir(), MaxBytes: 16 << 20, ReserveBytes: 1, Now: func() time.Time { return now }}
	recordIDs := []string{}
	for index, payload := range []string{storedConnPayload, storedHTTPPayload} {
		envelope := Envelope{
			Schema:        SchemaVersion,
			EventID:       []string{"zeek-conn-detail-0001", "zeek-http-detail-0002"}[index],
			Source:        SourceZeek,
			Kind:          []string{"zeek.conn", "zeek.http"}[index],
			OccurredAt:    now.Add(-time.Duration(index+1) * time.Minute),
			SourceVersion: "zeek-test",
			ParserVersion: "shakerproxy-test-v1",
			Confidence:    100,
			Payload:       json.RawMessage(payload),
		}
		raw, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		result, err := spool.Accept(raw)
		if err != nil || !result.Accepted || result.Quarantined {
			t.Fatalf("seed event was not accepted: %#v err=%v", result, err)
		}
		recordIDs = append(recordIDs, result.RecordID)
	}
	batch, err := spool.PendingBatch(10)
	if err != nil || len(batch) != len(recordIDs) {
		t.Fatalf("seed batch=%d err=%v", len(batch), err)
	}
	if err := sink.WriteBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	for index, recordID := range recordIDs {
		detail, err := sink.GetEventDetail(ctx, recordID)
		if err != nil {
			t.Fatal(err)
		}
		got, err := serveEventDetail(t, detail).GetEventDetail(ctx, recordID)
		if err != nil {
			t.Fatalf("stored event %d detail was rejected by the query client: %v", index, err)
		}
		if got.PayloadBytes != len(got.Payload) || !sameJSON(t, got.Payload, []byte([]string{storedConnPayload, storedHTTPPayload}[index])) {
			t.Fatalf("stored event %d payload changed: bytes=%d payload=%s", index, got.PayloadBytes, got.Payload)
		}
	}
}
