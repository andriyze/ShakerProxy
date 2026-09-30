package ingest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"time"
)

const (
	EventSelectionSchemaVersion = 1
	MaxEventSelectionAddresses  = 256
	MaxEventSelectionTombstones = 1024
	maxSelectionTombstoneBytes  = 64 << 10
)

var (
	ErrEventSelectionTombstoned = errors.New("event matches a permanent device/time deletion tombstone")
	ErrEventSelectionConflict   = errors.New("event selection tombstone identity is already bound to different evidence")
)

type EventSelectionAddress struct {
	Address string    `json:"address"`
	StartAt time.Time `json:"start_at"`
	EndAt   time.Time `json:"end_at"`
}

type EventSelection struct {
	Schema    int                     `json:"schema"`
	DeviceID  string                  `json:"device_id"`
	StartAt   time.Time               `json:"start_at"`
	EndAt     time.Time               `json:"end_at"`
	Addresses []EventSelectionAddress `json:"addresses"`
}

type EventSelectionTombstone struct {
	Schema                int            `json:"schema"`
	OperationID           string         `json:"operation_id"`
	Actor                 string         `json:"actor"`
	Selection             EventSelection `json:"selection"`
	SelectionSHA256       string         `json:"selection_sha256"`
	QuerySnapshotID       string         `json:"query_snapshot_id"`
	QuerySnapshotSHA256   string         `json:"query_snapshot_sha256"`
	DeletionPreviewSHA256 string         `json:"deletion_preview_sha256,omitempty"`
	CreatedAt             time.Time      `json:"created_at"`
}

type EventSelectionSpoolFootprint struct {
	PendingRecords   int   `json:"pending_records"`
	PendingFileBytes int64 `json:"pending_file_bytes"`
}

type EventSelectionTombstoneResult struct {
	Tombstone     EventSelectionTombstone `json:"tombstone"`
	Existing      bool                    `json:"existing"`
	PurgedRecords int                     `json:"purged_records"`
	PurgedBytes   int64                   `json:"purged_bytes"`
}

func CanonicalEventSelection(deviceID string, startAt, endAt time.Time, addresses []EventSelectionAddress) (EventSelection, error) {
	canonical := make([]EventSelectionAddress, len(addresses))
	for index, address := range addresses {
		canonical[index] = EventSelectionAddress{Address: address.Address, StartAt: address.StartAt.UTC().Round(0), EndAt: address.EndAt.UTC().Round(0)}
	}
	sort.Slice(canonical, func(i, j int) bool { return compareEventSelectionAddress(canonical[i], canonical[j]) < 0 })
	merged := make([]EventSelectionAddress, 0, len(canonical))
	for _, address := range canonical {
		if len(merged) == 0 || merged[len(merged)-1].Address != address.Address || address.StartAt.After(merged[len(merged)-1].EndAt) {
			merged = append(merged, address)
			continue
		}
		if address.EndAt.After(merged[len(merged)-1].EndAt) {
			merged[len(merged)-1].EndAt = address.EndAt
		}
	}
	selection := EventSelection{Schema: EventSelectionSchemaVersion, DeviceID: deviceID, StartAt: startAt.UTC().Round(0), EndAt: endAt.UTC().Round(0), Addresses: merged}
	return selection, selection.Validate()
}

func (s EventSelection) Validate() error {
	if s.Schema != EventSelectionSchemaVersion || !deviceIDPattern.MatchString(s.DeviceID) || s.StartAt.Location() != time.UTC || s.EndAt.Location() != time.UTC || !s.StartAt.Before(s.EndAt) || s.EndAt.Sub(s.StartAt) > 30*24*time.Hour || len(s.Addresses) > MaxEventSelectionAddresses {
		return errors.New("event selection identity or range is invalid")
	}
	for index, address := range s.Addresses {
		parsed, err := netip.ParseAddr(address.Address)
		if err != nil || parsed.String() != address.Address || parsed.IsUnspecified() || parsed.IsMulticast() || address.StartAt.Location() != time.UTC || address.EndAt.Location() != time.UTC || address.StartAt.Before(s.StartAt) || address.EndAt.After(s.EndAt) || !address.StartAt.Before(address.EndAt) {
			return errors.New("event selection address evidence is invalid")
		}
		if index > 0 && compareEventSelectionAddress(s.Addresses[index-1], address) >= 0 || index > 0 && s.Addresses[index-1].Address == address.Address && !address.StartAt.After(s.Addresses[index-1].EndAt) {
			return errors.New("event selection addresses are not canonical")
		}
	}
	return nil
}

func (s EventSelection) SHA256() (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (s EventSelection) Matches(envelope Envelope) bool {
	if s.Validate() != nil || envelope.Validate() != nil || envelope.OccurredAt.Before(s.StartAt) || !envelope.OccurredAt.Before(s.EndAt) {
		return false
	}
	return s.matchesValidatedEnvelope(envelope, ProjectNetworkFields(envelope))
}

func (s EventSelection) matchesValidatedEnvelope(envelope Envelope, projection NetworkProjection) bool {
	if envelope.DeviceID != "" {
		return envelope.DeviceID == s.DeviceID
	}
	for _, observed := range []string{projection.SourceIP, projection.DestinationIP} {
		if observed == "" {
			continue
		}
		for _, address := range s.Addresses {
			if address.Address == observed && !envelope.OccurredAt.Before(address.StartAt) && envelope.OccurredAt.Before(address.EndAt) {
				return true
			}
		}
	}
	return false
}

func (t EventSelectionTombstone) Validate() error {
	selectionSHA, err := t.Selection.SHA256()
	if t.Schema != EventSelectionSchemaVersion || !opaqueIDPattern.MatchString(t.OperationID) || !validText(t.Actor, 1, 96) || err != nil || t.SelectionSHA256 != selectionSHA || !ValidQuerySnapshotID(t.QuerySnapshotID) || !querySnapshotSHA256.MatchString(t.QuerySnapshotSHA256) || t.DeletionPreviewSHA256 != "" && !querySnapshotSHA256.MatchString(t.DeletionPreviewSHA256) || t.CreatedAt.IsZero() || t.CreatedAt.Year() < 2000 || t.CreatedAt.Year() > 3000 {
		return errors.New("event selection tombstone is invalid")
	}
	return nil
}

func (f EventSelectionSpoolFootprint) Validate() error {
	if f.PendingRecords < 0 || f.PendingRecords > MaxPendingRecords || f.PendingFileBytes < 0 || f.PendingRecords == 0 && f.PendingFileBytes != 0 || f.PendingRecords > 0 && f.PendingFileBytes == 0 {
		return errors.New("event selection spool footprint is invalid")
	}
	return nil
}

func (s *Spool) ReadEventSelectionSpoolFootprint(selection EventSelection) (EventSelectionSpoolFootprint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if selection.Validate() != nil {
		return EventSelectionSpoolFootprint{}, errors.New("event selection is invalid")
	}
	if err := s.ensure(); err != nil {
		return EventSelectionSpoolFootprint{}, err
	}
	footprint, _, err := s.eventSelectionPendingTargetsLocked(selection)
	return footprint, err
}

func (s *Spool) PutEventSelectionTombstoneForPreview(tombstone EventSelectionTombstone, expected EventSelectionSpoolFootprint) (EventSelectionTombstoneResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if tombstone.Validate() != nil || expected.Validate() != nil {
		return EventSelectionTombstoneResult{}, errors.New("event selection tombstone request is invalid")
	}
	tombstone.CreatedAt = tombstone.CreatedAt.UTC().Truncate(time.Microsecond)
	if err := s.ensure(); err != nil {
		return EventSelectionTombstoneResult{}, err
	}
	if err := s.loadEventSelectionTombstonesLocked(); err != nil {
		return EventSelectionTombstoneResult{}, err
	}
	if existing, found := s.selectionTombstones[tombstone.OperationID]; found {
		if !reflect.DeepEqual(existing, tombstone) {
			return EventSelectionTombstoneResult{}, ErrEventSelectionConflict
		}
		footprint, targets, err := s.eventSelectionPendingTargetsLocked(existing.Selection)
		if err != nil {
			return EventSelectionTombstoneResult{}, err
		}
		s.usage.loaded = false
		if err := s.purgeRejectedLocked(existing.Selection.Matches); err != nil {
			return EventSelectionTombstoneResult{}, err
		}
		purgedRecords, purgedBytes, err := purgeEventSelectionTargets(targets)
		return EventSelectionTombstoneResult{Tombstone: existing, Existing: true, PurgedRecords: purgedRecords, PurgedBytes: purgedBytes}, errors.Join(err, syncIfTargets(filepath.Join(s.Root, "pending"), footprint.PendingRecords))
	}
	if len(s.selectionTombstones) >= MaxEventSelectionTombstones {
		return EventSelectionTombstoneResult{}, errors.New("event selection tombstone limit reached")
	}
	actual, targets, err := s.eventSelectionPendingTargetsLocked(tombstone.Selection)
	if err != nil {
		return EventSelectionTombstoneResult{}, err
	}
	if actual != expected {
		return EventSelectionTombstoneResult{}, ErrCaptureEventDeletionPreviewStale
	}
	encoded, err := json.MarshalIndent(tombstone, "", "  ")
	if err != nil || len(encoded) > maxSelectionTombstoneBytes {
		return EventSelectionTombstoneResult{}, errors.New("event selection tombstone encoding is invalid")
	}
	encoded = append(encoded, '\n')
	if err := writeAtomic(filepath.Join(s.Root, "selection-tombstones"), tombstone.OperationID+".json", encoded); err != nil {
		return EventSelectionTombstoneResult{}, fmt.Errorf("persist event selection tombstone: %w", err)
	}
	s.selectionTombstones[tombstone.OperationID] = tombstone
	s.selectionTombstoneOrder = append(s.selectionTombstoneOrder, tombstone.OperationID)
	sort.Strings(s.selectionTombstoneOrder)
	s.usage.loaded = false
	if err := s.purgeRejectedLocked(tombstone.Selection.Matches); err != nil {
		return EventSelectionTombstoneResult{}, err
	}
	purgedRecords, purgedBytes, purgeErr := purgeEventSelectionTargets(targets)
	return EventSelectionTombstoneResult{Tombstone: tombstone, PurgedRecords: purgedRecords, PurgedBytes: purgedBytes}, errors.Join(purgeErr, syncIfTargets(filepath.Join(s.Root, "pending"), purgedRecords))
}

type eventSelectionPurgeTarget struct {
	path string
	size int64
}

func (s *Spool) eventSelectionPendingTargetsLocked(selection EventSelection) (EventSelectionSpoolFootprint, []eventSelectionPurgeTarget, error) {
	entries, err := os.ReadDir(filepath.Join(s.Root, "pending"))
	if err != nil {
		return EventSelectionSpoolFootprint{}, nil, err
	}
	footprint := EventSelectionSpoolFootprint{}
	targets := make([]eventSelectionPurgeTarget, 0)
	for _, entry := range entries {
		recordID, valid := pendingRecordID(entry.Name())
		if entry.IsDir() || !valid {
			return EventSelectionSpoolFootprint{}, nil, errors.New("ingestion spool contains an invalid pending entry")
		}
		path := filepath.Join(s.Root, "pending", entry.Name())
		record, err := readBoundedRecord(path)
		if err != nil || envelopeRecordID(record.Envelope) != recordID {
			return EventSelectionSpoolFootprint{}, nil, errors.New("ingestion spool record identity does not match its filename")
		}
		if !selection.Matches(record.Envelope) {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return EventSelectionSpoolFootprint{}, nil, errors.New("ingestion spool selection target is unsafe")
		}
		footprint.PendingRecords++
		footprint.PendingFileBytes += info.Size()
		targets = append(targets, eventSelectionPurgeTarget{path: path, size: info.Size()})
	}
	return footprint, targets, footprint.Validate()
}

func (s *Spool) eventSelectionTombstonedLocked(envelope Envelope) (EventSelectionTombstone, bool, error) {
	if err := s.loadEventSelectionTombstonesLocked(); err != nil {
		return EventSelectionTombstone{}, false, err
	}
	projection := NetworkProjection{}
	if envelope.DeviceID == "" {
		projection = ProjectNetworkFields(envelope)
	}
	for _, key := range s.selectionTombstoneOrder {
		tombstone := s.selectionTombstones[key]
		if !envelope.OccurredAt.Before(tombstone.Selection.StartAt) && envelope.OccurredAt.Before(tombstone.Selection.EndAt) && tombstone.Selection.matchesValidatedEnvelope(envelope, projection) {
			return tombstone, true, nil
		}
	}
	return EventSelectionTombstone{}, false, nil
}

func (s *Spool) loadEventSelectionTombstonesLocked() error {
	if s.selectionTombstonesLoaded {
		return nil
	}
	entries, err := os.ReadDir(filepath.Join(s.Root, "selection-tombstones"))
	if err != nil {
		return err
	}
	if len(entries) > MaxEventSelectionTombstones {
		return errors.New("event selection tombstone limit exceeded")
	}
	loaded := make(map[string]EventSelectionTombstone, len(entries))
	order := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return errors.New("event selection tombstone directory contains an invalid entry")
		}
		operationID := entry.Name()[:len(entry.Name())-len(".json")]
		if !opaqueIDPattern.MatchString(operationID) {
			return errors.New("event selection tombstone filename is invalid")
		}
		path := filepath.Join(s.Root, "selection-tombstones", entry.Name())
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 2 || info.Size() > maxSelectionTombstoneBytes {
			return errors.New("event selection tombstone is unavailable or unsafe")
		}
		encoded, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var tombstone EventSelectionTombstone
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&tombstone) != nil || decoder.Decode(&struct{}{}) != io.EOF || tombstone.Validate() != nil || tombstone.OperationID != operationID {
			return errors.New("event selection tombstone is invalid")
		}
		tombstone.CreatedAt = tombstone.CreatedAt.UTC()
		loaded[operationID] = tombstone
		order = append(order, operationID)
	}
	sort.Strings(order)
	s.selectionTombstones = loaded
	s.selectionTombstoneOrder = order
	s.selectionTombstonesLoaded = true
	return nil
}

func purgeEventSelectionTargets(targets []eventSelectionPurgeTarget) (int, int64, error) {
	var bytesPurged int64
	for index, target := range targets {
		if err := os.Remove(target.path); err != nil {
			return index, bytesPurged, fmt.Errorf("purge event selection record: %w", err)
		}
		bytesPurged += target.size
	}
	return len(targets), bytesPurged, nil
}

func syncIfTargets(directory string, count int) error {
	if count == 0 {
		return nil
	}
	return syncDirectory(directory)
}

func compareEventSelectionAddress(left, right EventSelectionAddress) int {
	if left.Address < right.Address {
		return -1
	}
	if left.Address > right.Address {
		return 1
	}
	if left.StartAt.Before(right.StartAt) {
		return -1
	}
	if left.StartAt.After(right.StartAt) {
		return 1
	}
	if left.EndAt.Before(right.EndAt) {
		return -1
	}
	if left.EndAt.After(right.EndAt) {
		return 1
	}
	return 0
}
