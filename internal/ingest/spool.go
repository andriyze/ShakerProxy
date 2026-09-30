package ingest

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Spool struct {
	Root                      string
	MaxBytes                  int64
	ReserveBytes              uint64
	Now                       func() time.Time
	mu                        sync.Mutex
	selectionTombstones       map[string]EventSelectionTombstone
	selectionTombstoneOrder   []string
	selectionTombstonesLoaded bool
	usage                     spoolUsage
}

// spoolUsage caches record counts and byte totals so the hot Accept path does
// not re-read and re-verify every pending record on each event. It is updated
// by this process's own writes and removals, invalidated by bulk purges, and
// periodically refreshed from a cheap directory scan to heal any drift.
type spoolUsage struct {
	loaded             bool
	loadedAt           time.Time
	pendingRecords     int
	pendingBytes       int64
	quarantinedRecords int
	quarantinedBytes   int64
}

const (
	MaxDrainBatchRecords  = 1000
	spoolUsageRefreshTime = 30 * time.Second
)

func (s *Spool) Accept(raw []byte) (AcceptResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensure(); err != nil {
		return AcceptResult{}, err
	}
	now := s.now()
	envelope, decodeErr := DecodeEnvelope(raw)
	if decodeErr != nil {
		return s.quarantine(raw, decodeErr.Error(), now)
	}
	if tombstoned, err := s.captureTombstonedLocked(envelope.CaptureSessionID); err != nil {
		return AcceptResult{}, err
	} else if tombstoned {
		return AcceptResult{}, fmt.Errorf("%w: %s", ErrCaptureTombstoned, envelope.CaptureSessionID)
	}
	if tombstone, tombstoned, err := s.eventSelectionTombstonedLocked(envelope); err != nil {
		return AcceptResult{}, err
	} else if tombstoned {
		return AcceptResult{}, fmt.Errorf("%w: %s", ErrEventSelectionTombstoned, tombstone.OperationID)
	}
	canonical, err := json.Marshal(envelope)
	if err != nil {
		return AcceptResult{}, err
	}
	eventDigest := sha256.Sum256(canonical)
	recordID := envelopeRecordID(envelope)
	path := filepath.Join(s.Root, "pending", recordID+".json")
	if existing, readErr := readBoundedRecord(path); readErr == nil {
		if envelopeRecordID(existing.Envelope) != recordID {
			return AcceptResult{}, errors.New("ingestion spool identity binding is invalid")
		}
		if existing.EventSHA256 == hex.EncodeToString(eventDigest[:]) {
			return AcceptResult{Accepted: true, Duplicate: true, RecordID: recordID}, nil
		}
		return s.quarantine(raw, "event ID conflicts with different content", now)
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return AcceptResult{}, readErr
	}
	usage, err := s.usageLocked(now)
	if err != nil {
		return AcceptResult{}, err
	}
	record := Record{Schema: SchemaVersion, ReceivedAt: now, EventSHA256: hex.EncodeToString(eventDigest[:]), Envelope: envelope}
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return AcceptResult{}, err
	}
	encoded = append(encoded, '\n')
	if usage.pendingRecords >= MaxPendingRecords || usage.pendingBytes+int64(len(encoded)) > s.maxBytes() {
		return AcceptResult{}, errors.New("ingestion spool backpressure limit reached")
	}
	available, err := s.availableBytes()
	if err != nil || available <= s.reserveBytes()+uint64(len(encoded)) {
		return AcceptResult{}, errors.New("ingestion spool emergency reserve reached")
	}
	if err := writeAtomic(filepath.Join(s.Root, "pending"), recordID+".json", encoded); err != nil {
		s.usage.loaded = false
		return AcceptResult{}, err
	}
	s.usage.pendingRecords++
	s.usage.pendingBytes += int64(len(encoded))
	return AcceptResult{Accepted: true, RecordID: recordID}, nil
}

func (s *Spool) PendingBatch(limit int) ([]PendingRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit < 1 || limit > MaxDrainBatchRecords {
		return nil, errors.New("ingestion drain batch limit is invalid")
	}
	if err := s.ensure(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(s.Root, "pending"))
	if err != nil {
		return nil, err
	}
	batch := make([]PendingRecord, 0, min(limit, len(entries)))
	purgePaths := make([]string, 0)
	for _, entry := range entries {
		if len(batch) == limit {
			break
		}
		recordID, valid := pendingRecordID(entry.Name())
		if entry.IsDir() || !valid {
			return nil, errors.New("ingestion spool contains an invalid pending entry")
		}
		record, err := readBoundedRecord(filepath.Join(s.Root, "pending", entry.Name()))
		if err != nil {
			return nil, err
		}
		if envelopeRecordID(record.Envelope) != recordID {
			return nil, errors.New("ingestion spool record identity does not match its filename")
		}
		if tombstoned, err := s.captureTombstonedLocked(record.Envelope.CaptureSessionID); err != nil {
			return nil, err
		} else if tombstoned {
			purgePaths = append(purgePaths, filepath.Join(s.Root, "pending", entry.Name()))
			continue
		}
		if _, tombstoned, err := s.eventSelectionTombstonedLocked(record.Envelope); err != nil {
			return nil, err
		} else if tombstoned {
			purgePaths = append(purgePaths, filepath.Join(s.Root, "pending", entry.Name()))
			continue
		}
		batch = append(batch, PendingRecord{RecordID: recordID, Record: record})
	}
	if len(purgePaths) > 0 {
		s.usage.loaded = false
	}
	for _, path := range purgePaths {
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("purge tombstoned pending record: %w", err)
		}
	}
	if len(purgePaths) > 0 {
		if err := syncDirectory(filepath.Join(s.Root, "pending")); err != nil {
			return nil, err
		}
	}
	return batch, nil
}

func (s *Spool) Acknowledge(recordIDs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(recordIDs) == 0 || len(recordIDs) > MaxDrainBatchRecords {
		return errors.New("ingestion acknowledgement batch is invalid")
	}
	if err := s.ensure(); err != nil {
		return err
	}
	directory := filepath.Join(s.Root, "pending")
	seen := make(map[string]struct{}, len(recordIDs))
	for _, recordID := range recordIDs {
		if !validRecordID(recordID) {
			return errors.New("ingestion acknowledgement identity is invalid")
		}
		if _, exists := seen[recordID]; exists {
			return errors.New("ingestion acknowledgement contains a duplicate identity")
		}
		seen[recordID] = struct{}{}
		path := filepath.Join(directory, recordID+".json")
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("ingestion acknowledgement target is unsafe")
		}
		record, err := readBoundedRecord(path)
		if err != nil || envelopeRecordID(record.Envelope) != recordID {
			return errors.New("ingestion acknowledgement target does not match its identity")
		}
		if err := os.Remove(path); err != nil {
			s.usage.loaded = false
			return err
		}
		s.usage.pendingRecords--
		s.usage.pendingBytes -= info.Size()
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// Stats verifies every pending record and reports the oldest pending receive
// time. It is intended for status endpoints, not per-event paths.
func (s *Spool) Stats() (Stats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensure(); err != nil {
		return Stats{}, err
	}
	return s.statsLocked(s.now())
}

// QuickStats reports counts, bytes, and storage pressure from the cached usage
// without reading record contents, so health checks stay cheap even with a
// large backlog. OldestPendingAt and IngestLagSeconds are not populated.
func (s *Spool) QuickStats() (Stats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensure(); err != nil {
		return Stats{}, err
	}
	now := s.now()
	usage, err := s.usageLocked(now)
	if err != nil {
		return Stats{}, err
	}
	stats := Stats{Schema: SchemaVersion, GeneratedAt: now, PendingRecords: usage.pendingRecords, PendingBytes: usage.pendingBytes, QuarantinedRecords: usage.quarantinedRecords, QuarantinedBytes: usage.quarantinedBytes}
	available, availableErr := s.availableBytes()
	stats.StoragePressure = stats.PendingBytes >= s.maxBytes() || availableErr != nil || available <= s.reserveBytes()
	return stats, nil
}

// SetAside removes pending records that can never be written. Rejected records
// are moved intact into the rejected directory for operator inspection or
// replay; purged records belong to deleted captures or selections and are
// discarded. Unknown or already-removed identities are ignored.
func (s *Spool) SetAside(recordIDs []string, purge bool) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(recordIDs) == 0 || len(recordIDs) > MaxDrainBatchRecords {
		return 0, errors.New("ingestion set-aside batch is invalid")
	}
	if err := s.ensure(); err != nil {
		return 0, err
	}
	pending := filepath.Join(s.Root, "pending")
	rejected := filepath.Join(s.Root, "rejected")
	s.usage.loaded = false
	moved := 0
	for _, recordID := range recordIDs {
		if !validRecordID(recordID) {
			return moved, errors.New("ingestion set-aside identity is invalid")
		}
		path := filepath.Join(pending, recordID+".json")
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return moved, errors.New("ingestion set-aside target is unsafe")
		}
		if purge {
			err = os.Remove(path)
		} else {
			err = os.Rename(path, filepath.Join(rejected, recordID+".json"))
		}
		if err != nil {
			return moved, err
		}
		moved++
	}
	if moved == 0 {
		return 0, nil
	}
	if !purge {
		if err := syncDirectory(rejected); err != nil {
			return moved, err
		}
	}
	return moved, syncDirectory(pending)
}

// usageLocked returns cached counts, rebuilding them from a stat-only scan
// when they are missing or stale.
func (s *Spool) usageLocked(now time.Time) (spoolUsage, error) {
	if s.usage.loaded && !now.Before(s.usage.loadedAt) && now.Sub(s.usage.loadedAt) < spoolUsageRefreshTime && s.usage.pendingRecords >= 0 && s.usage.pendingBytes >= 0 {
		return s.usage, nil
	}
	usage := spoolUsage{loaded: true, loadedAt: now}
	var err error
	usage.pendingRecords, usage.pendingBytes, _, err = directoryUsage(filepath.Join(s.Root, "pending"), false)
	if err != nil {
		return spoolUsage{}, err
	}
	for _, directory := range []string{"quarantine", "rejected"} {
		count, bytes, _, err := directoryUsage(filepath.Join(s.Root, directory), false)
		if err != nil {
			return spoolUsage{}, err
		}
		usage.quarantinedRecords += count
		usage.quarantinedBytes += bytes
	}
	s.usage = usage
	return usage, nil
}

func (s *Spool) Quarantine(raw []byte, reason string) (AcceptResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensure(); err != nil {
		return AcceptResult{}, err
	}
	if !validText(reason, 1, MaxTextBytes) {
		reason = "adapter input is invalid"
	}
	return s.quarantine(raw, reason, s.now())
}

func (s *Spool) quarantine(raw []byte, reason string, now time.Time) (AcceptResult, error) {
	digest := sha256.Sum256(raw)
	recordID := hex.EncodeToString(digest[:])
	path := filepath.Join(s.Root, "quarantine", recordID+".json")
	if _, err := os.Lstat(path); err == nil {
		return AcceptResult{Quarantined: true, RecordID: recordID, Reason: reason}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return AcceptResult{}, err
	}
	prefix := raw
	if len(prefix) > MaxQuarantineBytes {
		prefix = prefix[:MaxQuarantineBytes]
	}
	record := QuarantineRecord{Schema: SchemaVersion, ReceivedAt: now, InputSHA256: recordID, Reason: reason, PrefixBase64: base64.StdEncoding.EncodeToString(prefix)}
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return AcceptResult{}, err
	}
	encoded = append(encoded, '\n')
	usage, err := s.usageLocked(now)
	if err != nil {
		return AcceptResult{}, err
	}
	if usage.quarantinedRecords >= MaxPendingRecords || usage.quarantinedBytes+int64(len(encoded)) > s.maxBytes()/4 {
		return AcceptResult{}, errors.New("ingestion quarantine backpressure limit reached")
	}
	if err := writeAtomic(filepath.Join(s.Root, "quarantine"), recordID+".json", encoded); err != nil {
		s.usage.loaded = false
		return AcceptResult{}, err
	}
	s.usage.quarantinedRecords++
	s.usage.quarantinedBytes += int64(len(encoded))
	return AcceptResult{Quarantined: true, RecordID: recordID, Reason: reason}, nil
}

func (s *Spool) statsLocked(now time.Time) (Stats, error) {
	stats := Stats{Schema: SchemaVersion, GeneratedAt: now}
	var err error
	stats.PendingRecords, stats.PendingBytes, stats.OldestPendingAt, err = directoryUsage(filepath.Join(s.Root, "pending"), true)
	if err != nil {
		return Stats{}, err
	}
	for _, directory := range []string{"quarantine", "rejected"} {
		count, bytes, _, err := directoryUsage(filepath.Join(s.Root, directory), false)
		if err != nil {
			return Stats{}, err
		}
		stats.QuarantinedRecords += count
		stats.QuarantinedBytes += bytes
	}
	s.usage = spoolUsage{loaded: true, loadedAt: now, pendingRecords: stats.PendingRecords, pendingBytes: stats.PendingBytes, quarantinedRecords: stats.QuarantinedRecords, quarantinedBytes: stats.QuarantinedBytes}
	if !stats.OldestPendingAt.IsZero() && now.After(stats.OldestPendingAt) {
		stats.IngestLagSeconds = now.Sub(stats.OldestPendingAt).Seconds()
	}
	available, availableErr := s.availableBytes()
	stats.StoragePressure = stats.PendingBytes >= s.maxBytes() || availableErr != nil || available <= s.reserveBytes()
	return stats, nil
}

func directoryUsage(directory string, useRecordTime bool) (int, int64, time.Time, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return 0, 0, time.Time{}, err
	}
	count := 0
	var total int64
	var oldest time.Time
	for _, entry := range entries {
		recordID, validName := pendingRecordID(entry.Name())
		if entry.IsDir() || !validName {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > MaxEventBytes+8192 {
			return 0, 0, time.Time{}, errors.New("ingestion spool contains an unsafe record")
		}
		count++
		total += info.Size()
		recordTime := info.ModTime().UTC()
		if useRecordTime {
			record, err := readBoundedRecord(filepath.Join(directory, entry.Name()))
			if err != nil {
				return 0, 0, time.Time{}, err
			}
			if envelopeRecordID(record.Envelope) != recordID {
				return 0, 0, time.Time{}, errors.New("ingestion spool record identity does not match its filename")
			}
			recordTime = record.ReceivedAt
		}
		if oldest.IsZero() || recordTime.Before(oldest) {
			oldest = recordTime
		}
	}
	return count, total, oldest, nil
}

func envelopeRecordID(envelope Envelope) string {
	digest := sha256.Sum256([]byte(string(envelope.Source) + "\x00" + envelope.EventID))
	return hex.EncodeToString(digest[:])
}

func pendingRecordID(name string) (string, bool) {
	if !strings.HasSuffix(name, ".json") || len(name) != 69 {
		return "", false
	}
	recordID := strings.TrimSuffix(name, ".json")
	return recordID, validRecordID(recordID)
}

func validRecordID(recordID string) bool {
	if len(recordID) != sha256.Size*2 || recordID != strings.ToLower(recordID) {
		return false
	}
	_, err := hex.DecodeString(recordID)
	return err == nil
}

func readBoundedRecord(path string) (Record, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Record{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > MaxEventBytes+8192 {
		return Record{}, errors.New("ingestion spool record is unsafe")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Record{}, err
	}
	var record Record
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil || decoder.Decode(&struct{}{}) != io.EOF || record.Schema != SchemaVersion || record.ReceivedAt.IsZero() || len(record.EventSHA256) != 64 || record.Envelope.Validate() != nil {
		return Record{}, errors.New("ingestion spool record is invalid")
	}
	if _, err := hex.DecodeString(record.EventSHA256); err != nil {
		return Record{}, errors.New("ingestion spool record digest is invalid")
	}
	canonical, err := json.Marshal(record.Envelope)
	if err != nil {
		return Record{}, err
	}
	digest := sha256.Sum256(canonical)
	if record.EventSHA256 != hex.EncodeToString(digest[:]) {
		return Record{}, errors.New("ingestion spool record digest does not match")
	}
	return record, nil
}

func (s *Spool) ensure() error {
	if s.Root == "" || !filepath.IsAbs(s.Root) || filepath.Clean(s.Root) == "/" {
		return errors.New("ingestion spool root must be an absolute non-root path")
	}
	for _, path := range []string{s.Root, filepath.Join(s.Root, "pending"), filepath.Join(s.Root, "quarantine"), filepath.Join(s.Root, "rejected"), filepath.Join(s.Root, "tombstones"), filepath.Join(s.Root, "selection-tombstones")} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("ingestion spool directory is unsafe")
		}
	}
	return nil
}

func writeAtomic(directory, name string, data []byte) error {
	if strings.Contains(name, "/") || !strings.HasSuffix(name, ".json") {
		return errors.New("ingestion spool filename is invalid")
	}
	temporary, err := os.CreateTemp(directory, ".event-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, filepath.Join(directory, name)); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func syncDirectory(directory string) error {
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (s *Spool) availableBytes() (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(s.Root, &stat); err != nil {
		return 0, err
	}
	return stat.Bavail * uint64(stat.Bsize), nil
}

func (s *Spool) maxBytes() int64 {
	if s.MaxBytes > 0 {
		return s.MaxBytes
	}
	return DefaultSpoolBytes
}

func (s *Spool) reserveBytes() uint64 {
	if s.ReserveBytes > 0 {
		return s.ReserveBytes
	}
	return DefaultReserve
}

func (s *Spool) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func FormatStats(stats Stats) string {
	return fmt.Sprintf("%d pending (%d bytes), %d quarantined", stats.PendingRecords, stats.PendingBytes, stats.QuarantinedRecords)
}
