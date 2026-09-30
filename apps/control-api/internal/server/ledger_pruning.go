package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"golang.org/x/sys/unix"
)

// The control API keeps several bounded, durable ledgers. Instead of failing
// once a ledger is full, the oldest records that can no longer influence an
// operation are pruned (or, for audit-like export history, archived) when a
// new record would not fit.
const (
	// ledgerPruneMinimumAge protects recently finished records that a
	// retry, replay or in-flight request may still look up.
	ledgerPruneMinimumAge = time.Hour
	// ledgerPruneFailedAge is how long failed or partial jobs (which can be
	// retried or superseded) stay before they become prunable.
	ledgerPruneFailedAge = 7 * 24 * time.Hour
	// ledgerPruneHeadroom is how many free slots pruning creates so it does
	// not run on every insert.
	ledgerPruneHeadroom = 64
	// expiredPreviewGrace keeps expired retention previews that an in-flight
	// manual retention run may still need to resume.
	expiredPreviewGrace = 24 * time.Hour

	captureExportArchiveName     = "capture-exports-archive.jsonl"
	maxCaptureExportArchiveBytes = 32 << 20
)

var (
	errCaptureDeletionLedgerFull         = errors.New("capture deletion history is full of running or recently finished jobs; wait for them to finish, retry or supersede failed jobs, then try again")
	errDeviceTrafficDeletionLedgerFull   = errors.New("device deletion history is full of running or recently finished jobs; wait for them to finish or retry partial jobs, then try again")
	errCaptureRetentionPreviewLedgerFull = errors.New("too many capture retention previews are still valid; wait a few minutes for them to expire and calculate again")
	errCaptureExportLedgerFull           = errors.New("capture export history is full of exports from the last hour; wait and try again")
)

type pruneCandidate struct {
	index int
	tier  int
	at    time.Time
}

// pruneIndices chooses up to excess candidates, lowest tier first and oldest
// first within a tier, and returns the set of indices to drop.
func pruneIndices(candidates []pruneCandidate, excess int) map[int]struct{} {
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].tier != candidates[j].tier {
			return candidates[i].tier < candidates[j].tier
		}
		return candidates[i].at.Before(candidates[j].at)
	})
	drop := make(map[int]struct{}, excess)
	for _, candidate := range candidates {
		if len(drop) >= excess {
			break
		}
		drop[candidate.index] = struct{}{}
	}
	return drop
}

func captureDeletionPruneCandidates(records []coordinatedCaptureDeletionRecord, now time.Time) []pruneCandidate {
	candidates := make([]pruneCandidate, 0)
	for index, record := range records {
		if hasUnfinishedCaptureDeletionRetry(record.Retries) {
			continue
		}
		finished := record.Job.UpdatedAt
		if record.Job.CompletedAt != nil {
			finished = *record.Job.CompletedAt
		}
		switch record.Job.State {
		case coordinatedDeletionCompleted, coordinatedDeletionCancelled:
			if now.Sub(finished) >= ledgerPruneMinimumAge {
				candidates = append(candidates, pruneCandidate{index: index, tier: 0, at: finished})
			}
		case coordinatedDeletionPartial, coordinatedDeletionFailed:
			if now.Sub(record.Job.UpdatedAt) >= ledgerPruneFailedAge {
				candidates = append(candidates, pruneCandidate{index: index, tier: 1, at: record.Job.UpdatedAt})
			}
		}
	}
	return candidates
}

// pruneCoordinatedCaptureDeletionsLocked makes room for one more record.
func pruneCoordinatedCaptureDeletionsLocked(ledger *coordinatedCaptureDeletionLedger, now time.Time) error {
	if len(ledger.Records) < maxCoordinatedCaptureDeletions {
		return nil
	}
	excess := len(ledger.Records) - (maxCoordinatedCaptureDeletions - ledgerPruneHeadroom)
	drop := pruneIndices(captureDeletionPruneCandidates(ledger.Records, now), excess)
	if len(ledger.Records)-len(drop) >= maxCoordinatedCaptureDeletions {
		return errCaptureDeletionLedgerFull
	}
	kept := make([]coordinatedCaptureDeletionRecord, 0, len(ledger.Records)-len(drop))
	for index, record := range ledger.Records {
		if _, dropped := drop[index]; !dropped {
			kept = append(kept, record)
		}
	}
	ledger.Records = kept
	return nil
}

func deviceTrafficDeletionPruneCandidates(records []deviceTrafficDeletionRecord, now time.Time) []pruneCandidate {
	candidates := make([]pruneCandidate, 0)
	for index, record := range records {
		unfinishedRetry := false
		for _, retry := range record.Retries {
			if retry.CompletedAt == nil {
				unfinishedRetry = true
			}
		}
		if unfinishedRetry {
			continue
		}
		finished := record.Job.UpdatedAt
		if record.Job.CompletedAt != nil {
			finished = *record.Job.CompletedAt
		}
		switch record.Job.State {
		case deviceTrafficDeletionCompleted, deviceTrafficDeletionCancelled:
			if now.Sub(finished) >= ledgerPruneMinimumAge {
				candidates = append(candidates, pruneCandidate{index: index, tier: 0, at: finished})
			}
		case deviceTrafficDeletionPartial:
			if now.Sub(record.Job.UpdatedAt) >= ledgerPruneFailedAge {
				candidates = append(candidates, pruneCandidate{index: index, tier: 1, at: record.Job.UpdatedAt})
			}
		}
	}
	return candidates
}

func pruneDeviceTrafficDeletionsLocked(ledger *deviceTrafficDeletionLedger, now time.Time) error {
	if len(ledger.Records) < maxDeviceTrafficDeletionJobs {
		return nil
	}
	excess := len(ledger.Records) - (maxDeviceTrafficDeletionJobs - ledgerPruneHeadroom)
	drop := pruneIndices(deviceTrafficDeletionPruneCandidates(ledger.Records, now), excess)
	if len(ledger.Records)-len(drop) >= maxDeviceTrafficDeletionJobs {
		return errDeviceTrafficDeletionLedgerFull
	}
	kept := make([]deviceTrafficDeletionRecord, 0, len(ledger.Records)-len(drop))
	for index, record := range ledger.Records {
		if _, dropped := drop[index]; !dropped {
			kept = append(kept, record)
		}
	}
	ledger.Records = kept
	return nil
}

// pruneCoordinatedCaptureRetentionPreviewsLocked drops expired previews:
// first those expired longer than the resume grace period, then any expired
// preview. Unexpired previews are never pruned.
func pruneCoordinatedCaptureRetentionPreviewsLocked(ledger *coordinatedCaptureRetentionPreviewLedger, now time.Time) error {
	if len(ledger.Records) < maxCoordinatedCaptureRetentionPreviews {
		return nil
	}
	candidates := make([]pruneCandidate, 0)
	for index, record := range ledger.Records {
		expiresAt := record.Preview.ExpiresAt
		if now.Before(expiresAt) {
			continue
		}
		tier := 1
		if now.Sub(expiresAt) >= expiredPreviewGrace {
			tier = 0
		}
		candidates = append(candidates, pruneCandidate{index: index, tier: tier, at: expiresAt})
	}
	excess := len(ledger.Records) - (maxCoordinatedCaptureRetentionPreviews - ledgerPruneHeadroom)
	drop := pruneIndices(candidates, excess)
	if len(ledger.Records)-len(drop) >= maxCoordinatedCaptureRetentionPreviews {
		return errCaptureRetentionPreviewLedgerFull
	}
	kept := make([]coordinatedCaptureRetentionPreviewRecord, 0, len(ledger.Records)-len(drop))
	for index, record := range ledger.Records {
		if _, dropped := drop[index]; !dropped {
			kept = append(kept, record)
		}
	}
	ledger.Records = kept
	return nil
}

// pruneCaptureExportsLocked archives the oldest export records (older than
// ledgerPruneMinimumAge, so in-flight downloads can still finish) to an
// append-only JSON-lines file before dropping them from the live ledger.
func (s *Store) pruneCaptureExportsLocked(ledger *captureExportLedger, now time.Time) error {
	if len(ledger.Records) < maxCaptureExportRecords {
		return nil
	}
	candidates := make([]pruneCandidate, 0)
	for index, record := range ledger.Records {
		if now.Sub(record.ExportedAt) >= ledgerPruneMinimumAge {
			candidates = append(candidates, pruneCandidate{index: index, at: record.ExportedAt})
		}
	}
	excess := len(ledger.Records) - (maxCaptureExportRecords - maxCaptureExportRecords/4)
	drop := pruneIndices(candidates, excess)
	if len(ledger.Records)-len(drop) >= maxCaptureExportRecords {
		return errCaptureExportLedgerFull
	}
	archived := make([]CaptureExportRecord, 0, len(drop))
	kept := make([]CaptureExportRecord, 0, len(ledger.Records)-len(drop))
	for index, record := range ledger.Records {
		if _, dropped := drop[index]; dropped {
			archived = append(archived, record)
		} else {
			kept = append(kept, record)
		}
	}
	if err := s.appendCaptureExportArchive(archived); err != nil {
		return err
	}
	ledger.Records = kept
	return nil
}

func (s *Store) appendCaptureExportArchive(records []CaptureExportRecord) error {
	if len(records) == 0 {
		return nil
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	for _, record := range records {
		if err := encoder.Encode(record); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(s.dataDir, 0o750); err != nil {
		return err
	}
	path := filepath.Join(s.dataDir, captureExportArchiveName)
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("capture export archive is not a regular file")
		}
		if info.Size()+int64(buffer.Len()) > maxCaptureExportArchiveBytes {
			if err := os.Rename(path, path+".1"); err != nil {
				return fmt.Errorf("rotate capture export archive: %w", err)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	descriptor, err := unix.Open(path, unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("open capture export archive: %w", err)
	}
	file := os.NewFile(uintptr(descriptor), path)
	if _, err := file.Write(buffer.Bytes()); err != nil {
		file.Close()
		return fmt.Errorf("append capture export archive: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}
