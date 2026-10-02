package ingest

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// A batch accepted with one round of disk syncs drains into PostgreSQL like
// one-by-one events, and a retried batch stores nothing twice.
func TestPostgresStoresABatchOnceEvenWhenTheAnalyzerRetries(t *testing.T) {
	database, sink := openPipelineTestDatabase(t, "")
	spool := &Spool{Root: filepath.Join(t.TempDir(), "batch-spool"), MaxBytes: 64 << 20, ReserveBytes: 1}
	base := time.Date(2026, 10, 2, 3, 34, 44, 0, time.UTC)
	raws := make([][]byte, 300)
	ids := make([]string, len(raws))
	for index := range raws {
		ids[index] = fmt.Sprintf("batch-integration-%04d-%d", index, base.UnixNano())
		raws[index] = []byte(selectionEventJSON(ids[index], "", "192.168.10.201", base.Add(time.Duration(index)*time.Millisecond)))
	}
	recordIDs := []string{}
	for _, part := range [][][]byte{raws[:256], raws[256:]} {
		results, err := spool.AcceptBatch(part)
		if err != nil {
			t.Fatal(err)
		}
		for _, result := range results {
			recordIDs = append(recordIDs, result.RecordID)
		}
	}
	committed := 0
	for {
		result, err := DrainOnce(t.Context(), spool, sink, 256)
		if err != nil {
			t.Fatal(err)
		}
		if result.Committed == 0 {
			break
		}
		committed += result.Committed
	}
	if committed != len(raws) {
		t.Fatalf("drained %d of %d batched events", committed, len(raws))
	}
	// The analyzer retries the whole first batch after a lost response; the
	// spool takes it again, and the database keeps one row per event.
	if _, err := spool.AcceptBatch(raws[:256]); err != nil {
		t.Fatal(err)
	}
	for {
		result, err := DrainOnce(t.Context(), spool, sink, 256)
		if err != nil {
			t.Fatal(err)
		}
		if result.Committed == 0 {
			break
		}
	}
	var stored int
	if err := database.QueryRowContext(t.Context(), `SELECT count(*) FROM normalized_events WHERE record_id = ANY($1)`, recordIDs).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != len(raws) {
		t.Fatalf("stored %d rows for %d events", stored, len(raws))
	}
}
