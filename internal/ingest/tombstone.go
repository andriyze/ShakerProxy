package ingest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
)

const CaptureTombstoneSchemaVersion = 1

var ErrCaptureTombstoned = errors.New("capture session has been permanently tombstoned")

type CaptureTombstone struct {
	Schema           int       `json:"schema"`
	CaptureSessionID string    `json:"capture_session_id"`
	OperationID      string    `json:"operation_id"`
	Actor            string    `json:"actor"`
	CreatedAt        time.Time `json:"created_at"`
}

type SpoolTombstoneResult struct {
	Tombstone     CaptureTombstone `json:"tombstone"`
	Existing      bool             `json:"existing"`
	PurgedRecords int              `json:"purged_records"`
	PurgedBytes   int64            `json:"purged_bytes"`
}

func (t CaptureTombstone) Validate() error {
	if t.Schema != CaptureTombstoneSchemaVersion || !capture.ValidSessionID(t.CaptureSessionID) {
		return errors.New("capture tombstone schema or session ID is invalid")
	}
	if !opaqueIDPattern.MatchString(t.OperationID) {
		return errors.New("capture tombstone operation ID is invalid")
	}
	if !validText(t.Actor, 1, 96) {
		return errors.New("capture tombstone actor is invalid")
	}
	if t.CreatedAt.IsZero() || t.CreatedAt.Year() < 2000 || t.CreatedAt.Year() > 3000 {
		return errors.New("capture tombstone timestamp is invalid")
	}
	return nil
}

func (s *Spool) PutCaptureTombstone(tombstone CaptureTombstone) (SpoolTombstoneResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := tombstone.Validate(); err != nil {
		return SpoolTombstoneResult{}, err
	}
	tombstone.CreatedAt = tombstone.CreatedAt.UTC().Truncate(time.Microsecond)
	if err := s.ensure(); err != nil {
		return SpoolTombstoneResult{}, err
	}
	existing, exists, err := s.readCaptureTombstoneLocked(tombstone.CaptureSessionID)
	if err != nil {
		return SpoolTombstoneResult{}, err
	}
	if exists {
		tombstone = existing
	} else {
		encoded, err := json.MarshalIndent(tombstone, "", "  ")
		if err != nil {
			return SpoolTombstoneResult{}, err
		}
		encoded = append(encoded, '\n')
		if err := writeAtomic(filepath.Join(s.Root, "tombstones"), tombstone.CaptureSessionID+".json", encoded); err != nil {
			return SpoolTombstoneResult{}, fmt.Errorf("persist capture tombstone: %w", err)
		}
	}
	purgedRecords, purgedBytes, err := s.purgeCapturePendingLocked(tombstone.CaptureSessionID)
	if err != nil {
		return SpoolTombstoneResult{Tombstone: tombstone, Existing: exists, PurgedRecords: purgedRecords, PurgedBytes: purgedBytes}, err
	}
	return SpoolTombstoneResult{Tombstone: tombstone, Existing: exists, PurgedRecords: purgedRecords, PurgedBytes: purgedBytes}, nil
}

func (s *Spool) PutCaptureTombstoneForPreview(tombstone CaptureTombstone, expected CaptureEventSpoolFootprint) (SpoolTombstoneResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := tombstone.Validate(); err != nil {
		return SpoolTombstoneResult{}, err
	}
	if err := expected.Validate(); err != nil {
		return SpoolTombstoneResult{}, err
	}
	tombstone.CreatedAt = tombstone.CreatedAt.UTC().Truncate(time.Microsecond)
	if err := s.ensure(); err != nil {
		return SpoolTombstoneResult{}, err
	}
	existing, exists, err := s.readCaptureTombstoneLocked(tombstone.CaptureSessionID)
	if err != nil {
		return SpoolTombstoneResult{}, err
	}
	if exists {
		purgedRecords, purgedBytes, err := s.purgeCapturePendingLocked(existing.CaptureSessionID)
		return SpoolTombstoneResult{Tombstone: existing, Existing: true, PurgedRecords: purgedRecords, PurgedBytes: purgedBytes}, err
	}
	actual, err := s.readCaptureEventFootprintLocked(tombstone.CaptureSessionID)
	if err != nil {
		return SpoolTombstoneResult{}, err
	}
	if actual != expected {
		return SpoolTombstoneResult{}, ErrCaptureEventDeletionPreviewStale
	}
	encoded, err := json.MarshalIndent(tombstone, "", "  ")
	if err != nil {
		return SpoolTombstoneResult{}, err
	}
	encoded = append(encoded, '\n')
	if err := writeAtomic(filepath.Join(s.Root, "tombstones"), tombstone.CaptureSessionID+".json", encoded); err != nil {
		return SpoolTombstoneResult{}, fmt.Errorf("persist capture tombstone: %w", err)
	}
	purgedRecords, purgedBytes, err := s.purgeCapturePendingLocked(tombstone.CaptureSessionID)
	return SpoolTombstoneResult{Tombstone: tombstone, PurgedRecords: purgedRecords, PurgedBytes: purgedBytes}, err
}

func (s *Spool) ReadCaptureEventFootprint(captureSessionID string) (CaptureEventSpoolFootprint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !capture.ValidSessionID(captureSessionID) {
		return CaptureEventSpoolFootprint{}, errors.New("capture session ID is invalid")
	}
	if err := s.ensure(); err != nil {
		return CaptureEventSpoolFootprint{}, err
	}
	return s.readCaptureEventFootprintLocked(captureSessionID)
}

func (s *Spool) readCaptureEventFootprintLocked(captureSessionID string) (CaptureEventSpoolFootprint, error) {
	_, tombstoned, err := s.readCaptureTombstoneLocked(captureSessionID)
	if err != nil {
		return CaptureEventSpoolFootprint{}, err
	}
	entries, err := os.ReadDir(filepath.Join(s.Root, "pending"))
	if err != nil {
		return CaptureEventSpoolFootprint{}, err
	}
	footprint := CaptureEventSpoolFootprint{TombstonePresent: tombstoned}
	for _, entry := range entries {
		recordID, valid := pendingRecordID(entry.Name())
		if entry.IsDir() || !valid {
			return CaptureEventSpoolFootprint{}, errors.New("ingestion spool contains an invalid pending entry")
		}
		record, err := readBoundedRecord(filepath.Join(s.Root, "pending", entry.Name()))
		if err != nil || envelopeRecordID(record.Envelope) != recordID {
			return CaptureEventSpoolFootprint{}, errors.New("ingestion spool record identity does not match its filename")
		}
		if record.Envelope.CaptureSessionID != captureSessionID {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return CaptureEventSpoolFootprint{}, errors.New("ingestion spool preview target is unsafe")
		}
		footprint.PendingRecords++
		footprint.PendingFileBytes += info.Size()
	}
	return footprint, footprint.Validate()
}

func (s *Spool) readCaptureTombstoneLocked(captureSessionID string) (CaptureTombstone, bool, error) {
	path := filepath.Join(s.Root, "tombstones", captureSessionID+".json")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return CaptureTombstone{}, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 2 || info.Size() > 4096 {
		return CaptureTombstone{}, false, errors.New("capture tombstone is unavailable or unsafe")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return CaptureTombstone{}, false, err
	}
	var tombstone CaptureTombstone
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&tombstone); err != nil || decoder.Decode(&struct{}{}) != io.EOF || tombstone.Validate() != nil || tombstone.CaptureSessionID != captureSessionID {
		return CaptureTombstone{}, false, errors.New("capture tombstone is invalid")
	}
	tombstone.CreatedAt = tombstone.CreatedAt.UTC()
	return tombstone, true, nil
}

func (s *Spool) captureTombstonedLocked(captureSessionID string) (bool, error) {
	if captureSessionID == "" {
		return false, nil
	}
	_, exists, err := s.readCaptureTombstoneLocked(captureSessionID)
	return exists, err
}

func (s *Spool) purgeCapturePendingLocked(captureSessionID string) (int, int64, error) {
	s.usage.loaded = false
	if err := s.purgeRejectedLocked(func(envelope Envelope) bool { return envelope.CaptureSessionID == captureSessionID }); err != nil {
		return 0, 0, err
	}
	directory := filepath.Join(s.Root, "pending")
	entries, err := os.ReadDir(directory)
	if err != nil {
		return 0, 0, err
	}
	type purgeTarget struct {
		path string
		size int64
	}
	targets := make([]purgeTarget, 0)
	for _, entry := range entries {
		recordID, valid := pendingRecordID(entry.Name())
		if entry.IsDir() || !valid {
			return 0, 0, errors.New("ingestion spool contains an invalid pending entry")
		}
		path := filepath.Join(directory, entry.Name())
		record, err := readBoundedRecord(path)
		if err != nil || envelopeRecordID(record.Envelope) != recordID {
			return 0, 0, errors.New("ingestion spool record identity does not match its filename")
		}
		if record.Envelope.CaptureSessionID != captureSessionID {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return 0, 0, errors.New("ingestion spool purge target is unsafe")
		}
		targets = append(targets, purgeTarget{path: path, size: info.Size()})
	}
	var purgedBytes int64
	for index, target := range targets {
		if err := os.Remove(target.path); err != nil {
			return index, purgedBytes, fmt.Errorf("purge tombstoned capture record: %w", err)
		}
		purgedBytes += target.size
	}
	if len(targets) > 0 {
		if err := syncDirectory(directory); err != nil {
			return len(targets), purgedBytes, err
		}
	}
	return len(targets), purgedBytes, nil
}

// purgeRejectedLocked deletes set-aside records that belong to deleted data.
// Rejected records are full events retained for operator inspection, so a
// capture or device/time deletion must remove them as well. An unverifiable
// rejected record fails the deletion closed rather than being skipped.
func (s *Spool) purgeRejectedLocked(match func(Envelope) bool) error {
	directory := filepath.Join(s.Root, "rejected")
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	removed := 0
	for _, entry := range entries {
		recordID, valid := pendingRecordID(entry.Name())
		if entry.IsDir() || !valid {
			return errors.New("ingestion spool contains an invalid rejected entry")
		}
		path := filepath.Join(directory, entry.Name())
		record, err := readBoundedRecord(path)
		if err != nil || envelopeRecordID(record.Envelope) != recordID {
			return errors.New("ingestion spool rejected record identity does not match its filename")
		}
		if !match(record.Envelope) {
			continue
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("purge rejected record: %w", err)
		}
		removed++
	}
	if removed > 0 {
		s.usage.loaded = false
		return syncDirectory(directory)
	}
	return nil
}
