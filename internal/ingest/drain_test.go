package ingest

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type recordingSink struct {
	batches [][]PendingRecord
	err     error
}

func (s *recordingSink) WriteBatch(_ context.Context, batch []PendingRecord) error {
	s.batches = append(s.batches, append([]PendingRecord(nil), batch...))
	return s.err
}

func TestDrainAcknowledgesOnlyAfterSinkCommit(t *testing.T) {
	spool := &Spool{Root: filepath.Join(t.TempDir(), "spool"), MaxBytes: 8 << 20, ReserveBytes: 1}
	accepted, err := spool.Accept([]byte(validEvent))
	if err != nil {
		t.Fatal(err)
	}
	failing := &recordingSink{err: errors.New("database unavailable")}
	result, err := DrainOnce(t.Context(), spool, failing, 100)
	if err == nil || result.Attempted != 1 || result.Committed != 0 {
		t.Fatalf("unexpected failed drain result: %#v, %v", result, err)
	}
	batch, err := spool.PendingBatch(100)
	if err != nil || len(batch) != 1 || batch[0].RecordID != accepted.RecordID {
		t.Fatalf("database failure lost pending work: %#v, %v", batch, err)
	}
	success := &recordingSink{}
	result, err = DrainOnce(t.Context(), spool, success, 100)
	if err != nil || result.Attempted != 1 || result.Committed != 1 {
		t.Fatalf("unexpected successful drain result: %#v, %v", result, err)
	}
	batch, err = spool.PendingBatch(100)
	if err != nil || len(batch) != 0 {
		t.Fatalf("committed work remained pending: %#v, %v", batch, err)
	}
}

func TestDrainEmptySpoolDoesNotCallSink(t *testing.T) {
	spool := &Spool{Root: filepath.Join(t.TempDir(), "spool"), MaxBytes: 8 << 20, ReserveBytes: 1}
	sink := &recordingSink{}
	result, err := DrainOnce(t.Context(), spool, sink, 10)
	if err != nil || result != (DrainResult{}) || len(sink.batches) != 0 {
		t.Fatalf("unexpected empty drain: %#v %#v %v", result, sink.batches, err)
	}
}

type poisonSink struct {
	poison  string
	purge   bool
	batches [][]PendingRecord
}

func (s *poisonSink) WriteBatch(_ context.Context, batch []PendingRecord) error {
	s.batches = append(s.batches, append([]PendingRecord(nil), batch...))
	for _, pending := range batch {
		if pending.RecordID == s.poison {
			return &RecordError{RecordIDs: []string{pending.RecordID}, Purge: s.purge, Err: errors.New("normalized event identity conflicts with stored content")}
		}
	}
	return nil
}

func TestDrainSetsAsidePoisonRecordAndDrainsTheRest(t *testing.T) {
	for _, purge := range []bool{false, true} {
		root := filepath.Join(t.TempDir(), "spool")
		spool := &Spool{Root: root, MaxBytes: 8 << 20, ReserveBytes: 1}
		poison, err := spool.Accept([]byte(validEvent))
		if err != nil {
			t.Fatal(err)
		}
		healthy, err := spool.Accept([]byte(strings.Replace(validEvent, "zeek-event-00000001", "zeek-event-00000002", 1)))
		if err != nil {
			t.Fatal(err)
		}
		sink := &poisonSink{poison: poison.RecordID, purge: purge}
		result, err := DrainOnce(t.Context(), spool, sink, 100)
		if err != nil || result.Committed != 0 || result.Rejected+result.Purged != 1 || result.SetAsideReason == "" || (purge && result.Purged != 1) || (!purge && result.Rejected != 1) {
			t.Fatalf("poison record was not set aside: %#v err=%v", result, err)
		}
		_, rejectedErr := os.Stat(filepath.Join(root, "rejected", poison.RecordID+".json"))
		if purge != errors.Is(rejectedErr, os.ErrNotExist) {
			t.Fatalf("set-aside record retention was wrong for purge=%v: %v", purge, rejectedErr)
		}
		result, err = DrainOnce(t.Context(), spool, sink, 100)
		if err != nil || result.Committed != 1 || len(sink.batches[len(sink.batches)-1]) != 1 || sink.batches[len(sink.batches)-1][0].RecordID != healthy.RecordID {
			t.Fatalf("healthy backlog did not drain after poison set-aside: %#v err=%v", result, err)
		}
		stats, err := spool.QuickStats()
		expectedQuarantine := 1
		if purge {
			expectedQuarantine = 0
		}
		if err != nil || stats.PendingRecords != 0 || stats.QuarantinedRecords != expectedQuarantine {
			t.Fatalf("unexpected spool usage after set-aside: %#v err=%v", stats, err)
		}
	}
}
