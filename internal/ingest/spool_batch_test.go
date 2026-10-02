package ingest

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func numberedEvent(index int) []byte {
	return []byte(strings.Replace(validEvent, `"event_id":"zeek-event-00000001"`, fmt.Sprintf(`"event_id":"zeek-event-%08d"`, index+100), 1))
}

func pendingFiles(t *testing.T, root string) (records, temporaries int) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, "pending"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".event-") {
			temporaries++
		} else if strings.HasSuffix(entry.Name(), ".json") {
			records++
		}
	}
	return records, temporaries
}

// One segment's events used to cost a file sync each (about 3 events/s on the
// test VM); a batch shares the syncs but keeps one pending file per record.
func TestSpoolAcceptBatchStoresEachRecordWithDedupeAndQuarantine(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 1, 0, 0, time.UTC)
	root := filepath.Join(t.TempDir(), "spool")
	spool := &Spool{Root: root, MaxBytes: 8 << 20, ReserveBytes: 1, Now: func() time.Time { return now }}
	changed := spool.Changed()
	raws := [][]byte{}
	for index := 0; index < 40; index++ {
		raws = append(raws, numberedEvent(index))
	}
	conflict := strings.Replace(string(raws[3]), `"proto":"tcp"`, `"proto":"udp"`, 1)
	raws = append(raws, raws[0], []byte(conflict), []byte(`{"not":"an event"}`))
	results, err := spool.AcceptBatch(raws)
	if err != nil || len(results) != len(raws) {
		t.Fatalf("batch was not accepted: results=%d err=%v", len(results), err)
	}
	for index := 0; index < 40; index++ {
		if !results[index].Accepted || results[index].Duplicate || len(results[index].RecordID) != 64 {
			t.Fatalf("event %d: %#v", index, results[index])
		}
	}
	if !results[40].Duplicate || results[40].RecordID != results[0].RecordID {
		t.Fatalf("a repeat inside the batch was not a duplicate: %#v", results[40])
	}
	if !results[41].Quarantined || !results[42].Quarantined {
		t.Fatalf("conflicting and malformed events were not quarantined: %#v %#v", results[41], results[42])
	}
	if records, temporaries := pendingFiles(t, root); records != 40 || temporaries != 0 {
		t.Fatalf("pending directory has %d records and %d temporary files", records, temporaries)
	}
	select {
	case <-changed:
	default:
		t.Fatal("the drain was not woken after the batch")
	}
	stats, err := spool.Stats()
	if err != nil || stats.PendingRecords != 40 || stats.QuarantinedRecords != 2 {
		t.Fatalf("unexpected stats: %#v err=%v", stats, err)
	}
	// A retried batch only finds duplicates.
	again, err := spool.AcceptBatch(raws[:40])
	if err != nil {
		t.Fatal(err)
	}
	for index, result := range again {
		if !result.Duplicate {
			t.Fatalf("retried event %d was stored twice: %#v", index, result)
		}
	}
	batch, err := spool.PendingBatch(100)
	if err != nil || len(batch) != 40 {
		t.Fatalf("drain read %d records: %v", len(batch), err)
	}
}

func TestSpoolAcceptBatchCommitsEventsBeforeATombstonedOne(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 5, 0, 0, time.UTC)
	root := filepath.Join(t.TempDir(), "spool")
	spool := &Spool{Root: root, MaxBytes: 8 << 20, ReserveBytes: 1, Now: func() time.Time { return now }}
	deleted := "capture-fedcba9876543210fedcba9876543210"
	if _, err := spool.PutCaptureTombstone(CaptureTombstone{Schema: CaptureTombstoneSchemaVersion, CaptureSessionID: deleted, OperationID: "capture-delete-operation-0003", Actor: "admin", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	tombstoned := strings.Replace(string(numberedEvent(9)), "capture-0123456789abcdef0123456789abcdef", deleted, 1)
	results, err := spool.AcceptBatch([][]byte{numberedEvent(1), numberedEvent(2), []byte(tombstoned), numberedEvent(3)})
	if !errors.Is(err, ErrCaptureTombstoned) || len(results) != 2 {
		t.Fatalf("results=%#v err=%v", results, err)
	}
	if records, temporaries := pendingFiles(t, root); records != 2 || temporaries != 0 {
		t.Fatalf("pending directory has %d records and %d temporary files", records, temporaries)
	}
}

func TestSpoolAcceptBatchRespectsBackpressureForTheWholeBatch(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 1, 0, 0, time.UTC)
	// Size the spool for two and a half records.
	probeRoot := filepath.Join(t.TempDir(), "probe")
	probe, err := (&Spool{Root: probeRoot, MaxBytes: 8 << 20, ReserveBytes: 1, Now: func() time.Time { return now }}).Accept(numberedEvent(0))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(probeRoot, "pending", probe.RecordID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "spool")
	spool := &Spool{Root: root, MaxBytes: info.Size()*5/2 + 1, ReserveBytes: 1, Now: func() time.Time { return now }}
	results, err := spool.AcceptBatch([][]byte{numberedEvent(1), numberedEvent(2), numberedEvent(3), numberedEvent(4)})
	if err == nil || !strings.Contains(err.Error(), "backpressure") {
		t.Fatalf("an over-full batch was accepted: results=%d err=%v", len(results), err)
	}
	records, temporaries := pendingFiles(t, root)
	if records != len(results) || records == 0 || records == 4 || temporaries != 0 {
		t.Fatalf("records=%d results=%d temporaries=%d", records, len(results), temporaries)
	}
	if _, err := spool.AcceptBatch(nil); err == nil {
		t.Fatal("an empty batch was accepted")
	}
	if _, err := spool.AcceptBatch(make([][]byte, MaxAcceptBatchRecords+1)); err == nil {
		t.Fatal("an over-long batch was accepted")
	}
}

func benchmarkSpool(b *testing.B, batchSize int) {
	now := time.Date(2026, 9, 1, 12, 1, 0, 0, time.UTC)
	spool := &Spool{Root: filepath.Join(b.TempDir(), "spool"), MaxBytes: 1 << 30, ReserveBytes: 1, Now: func() time.Time { return now }}
	b.ResetTimer()
	for done := 0; done < b.N; {
		count := min(batchSize, b.N-done)
		raws := make([][]byte, count)
		for index := range raws {
			raws[index] = numberedEvent(done + index)
		}
		if batchSize == 1 {
			if _, err := spool.Accept(raws[0]); err != nil {
				b.Fatal(err)
			}
		} else if _, err := spool.AcceptBatch(raws); err != nil {
			b.Fatal(err)
		}
		done += count
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "events/s")
}

// go test -run XXX -bench SpoolAccept -benchtime 1024x ./internal/ingest/
func BenchmarkSpoolAcceptOneByOne(b *testing.B) { benchmarkSpool(b, 1) }
func BenchmarkSpoolAcceptBatch256(b *testing.B) { benchmarkSpool(b, 256) }
