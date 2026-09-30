package server

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCaptureDeletionLedgerPrunesOldestFinishedJobs(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	ledger := coordinatedCaptureDeletionLedger{Schema: coordinatedCaptureDeletionLedgerSchema}
	for index := 0; index < maxCoordinatedCaptureDeletions; index++ {
		finished := now.Add(-time.Duration(maxCoordinatedCaptureDeletions-index) * time.Minute)
		record := coordinatedCaptureDeletionRecord{Job: coordinatedCaptureDeletionJob{ID: fmt.Sprintf("job-%04d", index), State: coordinatedDeletionCompleted, UpdatedAt: finished, CompletedAt: &finished}}
		switch {
		case index%10 == 0:
			record.Job.State = coordinatedDeletionRunning
		case index%10 == 1:
			record.Job.State = coordinatedDeletionFailed
		case index%10 == 2:
			record.Retries = []captureDeletionRetryRecord{{IdempotencyKey: "retry"}}
		}
		ledger.Records = append(ledger.Records, record)
	}
	if err := pruneCoordinatedCaptureDeletionsLocked(&ledger, now); err != nil {
		t.Fatal(err)
	}
	if len(ledger.Records) != maxCoordinatedCaptureDeletions-ledgerPruneHeadroom {
		t.Fatalf("ledger has %d records after pruning", len(ledger.Records))
	}
	kept := map[string]bool{}
	for _, record := range ledger.Records {
		kept[record.Job.ID] = true
	}
	for index := 0; index < maxCoordinatedCaptureDeletions; index++ {
		id := fmt.Sprintf("job-%04d", index)
		if index%10 <= 2 && !kept[id] {
			t.Fatalf("running, recent-failed or retrying job %s was pruned", id)
		}
	}
	if kept["job-0003"] {
		t.Fatal("the oldest completed job was kept while newer ones were pruned")
	}

	// A ledger full of running jobs cannot make room and says what to do.
	busy := coordinatedCaptureDeletionLedger{Schema: coordinatedCaptureDeletionLedgerSchema}
	for index := 0; index < maxCoordinatedCaptureDeletions; index++ {
		busy.Records = append(busy.Records, coordinatedCaptureDeletionRecord{Job: coordinatedCaptureDeletionJob{State: coordinatedDeletionRunning, UpdatedAt: now.Add(-48 * time.Hour)}})
	}
	if err := pruneCoordinatedCaptureDeletionsLocked(&busy, now); !errors.Is(err, errCaptureDeletionLedgerFull) {
		t.Fatalf("busy ledger returned %v", err)
	}
	// Recently completed jobs are protected for an hour.
	recent := coordinatedCaptureDeletionLedger{Schema: coordinatedCaptureDeletionLedgerSchema}
	for index := 0; index < maxCoordinatedCaptureDeletions; index++ {
		finished := now.Add(-time.Minute)
		recent.Records = append(recent.Records, coordinatedCaptureDeletionRecord{Job: coordinatedCaptureDeletionJob{State: coordinatedDeletionCompleted, UpdatedAt: finished, CompletedAt: &finished}})
	}
	if err := pruneCoordinatedCaptureDeletionsLocked(&recent, now); !errors.Is(err, errCaptureDeletionLedgerFull) {
		t.Fatalf("recent ledger returned %v", err)
	}
	// Old failed jobs become prunable after a week.
	stale := coordinatedCaptureDeletionLedger{Schema: coordinatedCaptureDeletionLedgerSchema}
	for index := 0; index < maxCoordinatedCaptureDeletions; index++ {
		stale.Records = append(stale.Records, coordinatedCaptureDeletionRecord{Job: coordinatedCaptureDeletionJob{State: coordinatedDeletionPartial, UpdatedAt: now.Add(-8 * 24 * time.Hour)}})
	}
	if err := pruneCoordinatedCaptureDeletionsLocked(&stale, now); err != nil || len(stale.Records) >= maxCoordinatedCaptureDeletions {
		t.Fatalf("stale failed jobs were not pruned: %v len=%d", err, len(stale.Records))
	}
}

func TestDeviceTrafficDeletionLedgerPrunesFinishedJobs(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	ledger := deviceTrafficDeletionLedger{Schema: deviceTrafficDeletionJobSchema}
	for index := 0; index < maxDeviceTrafficDeletionJobs; index++ {
		finished := now.Add(-2 * time.Hour)
		state := deviceTrafficDeletionCompleted
		if index%2 == 0 {
			state = deviceTrafficDeletionPending
		}
		ledger.Records = append(ledger.Records, deviceTrafficDeletionRecord{Job: deviceTrafficDeletionJob{State: state, UpdatedAt: finished, CompletedAt: &finished}})
	}
	if err := pruneDeviceTrafficDeletionsLocked(&ledger, now); err != nil || len(ledger.Records) != maxDeviceTrafficDeletionJobs-ledgerPruneHeadroom {
		t.Fatalf("prune returned %v len=%d", err, len(ledger.Records))
	}
	pending := 0
	for _, record := range ledger.Records {
		if record.Job.State == deviceTrafficDeletionPending {
			pending++
		}
	}
	if pending != maxDeviceTrafficDeletionJobs/2 {
		t.Fatalf("pending jobs were pruned: %d remain", pending)
	}
	full := deviceTrafficDeletionLedger{Schema: deviceTrafficDeletionJobSchema}
	for index := 0; index < maxDeviceTrafficDeletionJobs; index++ {
		full.Records = append(full.Records, deviceTrafficDeletionRecord{Job: deviceTrafficDeletionJob{State: deviceTrafficDeletionRunning, UpdatedAt: now}})
	}
	if err := pruneDeviceTrafficDeletionsLocked(&full, now); !errors.Is(err, errDeviceTrafficDeletionLedgerFull) {
		t.Fatalf("busy ledger returned %v", err)
	}
}

func TestCaptureRetentionPreviewLedgerPrunesOnlyExpiredPreviews(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	ledger := coordinatedCaptureRetentionPreviewLedger{Schema: coordinatedCaptureRetentionLedgerSchema}
	for index := 0; index < maxCoordinatedCaptureRetentionPreviews; index++ {
		expires := now.Add(time.Hour)
		if index < 100 {
			expires = now.Add(-48 * time.Hour)
		}
		ledger.Records = append(ledger.Records, coordinatedCaptureRetentionPreviewRecord{Preview: coordinatedCaptureRetentionPreview{PreviewSHA256: fmt.Sprintf("%064d", index), ExpiresAt: expires}})
	}
	if err := pruneCoordinatedCaptureRetentionPreviewsLocked(&ledger, now); err != nil || len(ledger.Records) != maxCoordinatedCaptureRetentionPreviews-ledgerPruneHeadroom {
		t.Fatalf("prune returned %v len=%d", err, len(ledger.Records))
	}
	for _, record := range ledger.Records {
		if !record.Preview.ExpiresAt.After(now) && record.Preview.PreviewSHA256 < fmt.Sprintf("%064d", ledgerPruneHeadroom) {
			t.Fatalf("an old expired preview survived while newer ones were pruned: %s", record.Preview.PreviewSHA256)
		}
	}
	live := coordinatedCaptureRetentionPreviewLedger{Schema: coordinatedCaptureRetentionLedgerSchema}
	for index := 0; index < maxCoordinatedCaptureRetentionPreviews; index++ {
		live.Records = append(live.Records, coordinatedCaptureRetentionPreviewRecord{Preview: coordinatedCaptureRetentionPreview{ExpiresAt: now.Add(time.Hour)}})
	}
	if err := pruneCoordinatedCaptureRetentionPreviewsLocked(&live, now); !errors.Is(err, errCaptureRetentionPreviewLedgerFull) {
		t.Fatalf("unexpired previews returned %v", err)
	}
}

func TestCaptureExportLedgerArchivesOldestRecordsWhenFull(t *testing.T) {
	dataDirectory := t.TempDir()
	store := NewStore(dataDirectory, filepath.Join(dataDirectory, "unused-token"))
	old := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	ledger := captureExportLedger{Schema: 1}
	for index := 0; index < maxCaptureExportRecords; index++ {
		id := make([]byte, 16)
		id[0], id[1] = byte(index>>8), byte(index)
		ledger.Records = append(ledger.Records, CaptureExportRecord{Schema: 1, ID: "export-" + hex.EncodeToString(id), SessionID: captureTestID, FileName: "segment.pcap", SHA256: strings.Repeat("a", 64), Username: "admin", RangeEnd: 9, BytesSent: 10, Complete: true, ExportedAt: old.Add(time.Duration(index) * time.Second)})
	}
	encoded, err := json.Marshal(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDirectory, "capture-exports.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	started, err := store.BeginCaptureExport(CaptureExportRecord{SessionID: captureTestID, FileName: "segment.pcap", SHA256: strings.Repeat("b", 64), Username: "admin", RangeEnd: 9})
	if err != nil {
		t.Fatalf("full export ledger was not pruned: %v", err)
	}
	records, err := store.ListCaptureExports("")
	if err != nil || len(records) != maxCaptureExportRecords-maxCaptureExportRecords/4+1 || records[len(records)-1].ID != started.ID || records[0].ID != ledger.Records[maxCaptureExportRecords/4].ID {
		t.Fatalf("unexpected ledger after pruning: len=%d err=%v", len(records), err)
	}
	archive, err := os.Open(filepath.Join(dataDirectory, captureExportArchiveName))
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	lines := 0
	scanner := bufio.NewScanner(archive)
	for scanner.Scan() {
		var record CaptureExportRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil || record.ID != ledger.Records[lines].ID {
			t.Fatalf("archive line %d is wrong: %v %s", lines, err, scanner.Text())
		}
		lines++
	}
	if lines != maxCaptureExportRecords/4 {
		t.Fatalf("archive has %d lines", lines)
	}
}
