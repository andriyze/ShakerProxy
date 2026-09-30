package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
)

const (
	legacyCoordinatedCaptureRetentionPreviewSchema = 1
	coordinatedCaptureRetentionPreviewSchema       = 2
	coordinatedCaptureRetentionLedgerSchema        = 1
	maxCoordinatedCaptureRetentionPreviews         = 1024
	maxCaptureRetentionPreviewLedgerBytes          = 256 << 20
)

type coordinatedCaptureRetentionPreview struct {
	Schema                                  int                                 `json:"schema"`
	PreviewSHA256                           string                              `json:"preview_sha256"`
	GeneratedAt                             time.Time                           `json:"generated_at"`
	ExpiresAt                               time.Time                           `json:"expires_at"`
	HostRetention                           capture.RetentionPreview            `json:"host_retention"`
	Selected                                []coordinatedCaptureDeletionPreview `json:"selected"`
	NormalizedEventRows                     int64                               `json:"normalized_event_rows"`
	ExclusiveIdentityRows                   int64                               `json:"exclusive_identity_rows"`
	PendingSpoolRecords                     int                                 `json:"pending_spool_records"`
	PendingSpoolBytes                       int64                               `json:"pending_spool_bytes"`
	ExistingExportRecords                   int                                 `json:"existing_export_records"`
	ImmediatelyRecoverableBytes             int64                               `json:"immediately_recoverable_bytes"`
	LogicalBytesReclaimableAfterMaintenance int64                               `json:"logical_bytes_reclaimable_after_maintenance"`
	DeletedDataClasses                      []string                            `json:"deleted_data_classes"`
	RetainedDataClasses                     []string                            `json:"retained_data_classes"`
}

type coordinatedCaptureRetentionPreviewRecord struct {
	Schema        int                                `json:"schema"`
	Preview       coordinatedCaptureRetentionPreview `json:"preview"`
	Administrator string                             `json:"administrator"`
	RecordedAt    time.Time                          `json:"recorded_at"`
}

type coordinatedCaptureRetentionPreviewLedger struct {
	Schema  int                                        `json:"schema"`
	Records []coordinatedCaptureRetentionPreviewRecord `json:"records"`
}

func (s *Server) buildCoordinatedCaptureRetentionPreview(ctx context.Context, host capture.RetentionPreview) (coordinatedCaptureRetentionPreview, error) {
	if s.captureEventDeletions == nil || s.zeekCheckpointDeletions == nil || s.suricataCheckpointDeletions == nil {
		return coordinatedCaptureRetentionPreview{}, errors.New("capture deletion services are not configured")
	}
	if err := validateHostCaptureRetentionPreview(host); err != nil {
		return coordinatedCaptureRetentionPreview{}, err
	}
	preview := coordinatedCaptureRetentionPreview{
		Schema: coordinatedCaptureRetentionPreviewSchema, HostRetention: host,
		GeneratedAt: host.GeneratedAt.UTC(), ExpiresAt: host.ExpiresAt.UTC(),
		Selected:            []coordinatedCaptureDeletionPreview{},
		DeletedDataClasses:  append([]string(nil), coordinatedCaptureDeletedDataClasses...),
		RetainedDataClasses: append([]string(nil), coordinatedCaptureRetainedDataClasses...),
	}
	for _, candidate := range host.Selected {
		if err := ctx.Err(); err != nil {
			return coordinatedCaptureRetentionPreview{}, err
		}
		var hostDeletion capture.DeletionPreview
		if err := s.gateway.Call(ctx, "PreviewCaptureDeletionUntil", gatewayprotocol.PreviewCaptureDeletionUntilParams{SessionID: candidate.SessionID, ExpiresAt: host.ExpiresAt}, &hostDeletion); err != nil {
			return coordinatedCaptureRetentionPreview{}, err
		}
		if hostDeletion.Footprint != candidate.Footprint {
			return coordinatedCaptureRetentionPreview{}, errors.New("capture retention host deletion preview drifted from the selected footprint")
		}
		events, err := s.captureEventDeletions.Preview(ctx, candidate.SessionID)
		if err != nil {
			return coordinatedCaptureRetentionPreview{}, err
		}
		zeek, err := s.zeekCheckpointDeletions.Preview(ctx, candidate.SessionID)
		if err != nil {
			return coordinatedCaptureRetentionPreview{}, err
		}
		suricata, err := s.suricataCheckpointDeletions.Preview(ctx, candidate.SessionID)
		if err != nil {
			return coordinatedCaptureRetentionPreview{}, err
		}
		exports, err := s.store.ListCaptureExports(candidate.SessionID)
		if err != nil {
			return coordinatedCaptureRetentionPreview{}, err
		}
		item, err := newCoordinatedCaptureDeletionPreview(hostDeletion, events, zeek, suricata, len(exports))
		if err != nil {
			return coordinatedCaptureRetentionPreview{}, err
		}
		preview.Selected = append(preview.Selected, item)
		if item.GeneratedAt.After(preview.GeneratedAt) {
			preview.GeneratedAt = item.GeneratedAt
		}
		if item.ExpiresAt.Before(preview.ExpiresAt) {
			preview.ExpiresAt = item.ExpiresAt
		}
		if err := addCaptureRetentionItemTotals(&preview, item); err != nil {
			return coordinatedCaptureRetentionPreview{}, err
		}
	}
	digest, err := coordinatedCaptureRetentionPreviewHash(preview)
	if err != nil {
		return coordinatedCaptureRetentionPreview{}, err
	}
	preview.PreviewSHA256 = digest
	return preview, preview.validate()
}

func (p coordinatedCaptureRetentionPreview) validate() error {
	if p.Schema != legacyCoordinatedCaptureRetentionPreviewSchema && p.Schema != coordinatedCaptureRetentionPreviewSchema || !validSHA256(p.PreviewSHA256) || p.GeneratedAt.IsZero() || !p.ExpiresAt.After(p.GeneratedAt) || validateHostCaptureRetentionPreview(p.HostRetention) != nil || len(p.Selected) != len(p.HostRetention.Selected) {
		return errors.New("coordinated capture retention preview is invalid")
	}
	expectedDeletionSchema := coordinatedCaptureDeletionSchema
	expectedDeletedClasses, expectedRetainedClasses := coordinatedCaptureDeletedDataClasses, coordinatedCaptureRetainedDataClasses
	if p.Schema == legacyCoordinatedCaptureRetentionPreviewSchema {
		expectedDeletionSchema = legacyCoordinatedCaptureDeletionSchema
		expectedDeletedClasses, expectedRetainedClasses = legacyCoordinatedCaptureDeletedDataClasses, legacyCoordinatedCaptureRetainedDataClasses
	}
	if !equalStringSlices(p.DeletedDataClasses, expectedDeletedClasses) || !equalStringSlices(p.RetainedDataClasses, expectedRetainedClasses) {
		return errors.New("coordinated capture retention data classes are invalid")
	}
	generatedAt, expiresAt := p.HostRetention.GeneratedAt.UTC(), p.HostRetention.ExpiresAt.UTC()
	var eventRows, identities, spoolRecords, exports int64
	var spoolBytes, immediateBytes, deferredBytes int64
	for index, item := range p.Selected {
		candidate := p.HostRetention.Selected[index]
		if item.Schema != expectedDeletionSchema || item.validate() != nil || item.SessionID != candidate.SessionID || item.HostArtifacts.Footprint != candidate.Footprint || item.HostArtifacts.ExpiresAt.After(p.HostRetention.ExpiresAt) {
			return errors.New("coordinated capture retention preview contains inconsistent selected evidence")
		}
		if item.GeneratedAt.After(generatedAt) {
			generatedAt = item.GeneratedAt
		}
		if item.ExpiresAt.Before(expiresAt) {
			expiresAt = item.ExpiresAt
		}
		var err error
		if eventRows, err = addNonnegativeInt64(eventRows, item.NormalizedEvents.Database.EventRows); err != nil {
			return err
		}
		if identities, err = addNonnegativeInt64(identities, item.NormalizedEvents.Database.ExclusiveIdentityRows); err != nil {
			return err
		}
		if spoolRecords, err = addNonnegativeInt64(spoolRecords, int64(item.NormalizedEvents.Spool.PendingRecords)); err != nil {
			return err
		}
		if spoolBytes, err = addNonnegativeInt64(spoolBytes, item.NormalizedEvents.Spool.PendingFileBytes); err != nil {
			return err
		}
		if exports, err = addNonnegativeInt64(exports, int64(item.ExistingExportRecords)); err != nil {
			return err
		}
		itemImmediate, err := addNonnegativeInt64(item.HostArtifacts.EstimatedRecoverableBytes, item.NormalizedEvents.EstimatedImmediatelyReclaimableBytes)
		if err != nil {
			return err
		}
		if p.Schema == coordinatedCaptureRetentionPreviewSchema {
			itemImmediate, err = addNonnegativeInt64(itemImmediate, item.ZeekCheckpoint.CheckpointBytes)
			if err == nil {
				itemImmediate, err = addNonnegativeInt64(itemImmediate, item.ZeekCheckpoint.ActiveProgressBytes)
			}
			if err == nil {
				itemImmediate, err = addNonnegativeInt64(itemImmediate, item.SuricataCheckpoint.CheckpointBytes)
			}
			if err == nil {
				itemImmediate, err = addNonnegativeInt64(itemImmediate, item.SuricataCheckpoint.ActiveProgressBytes)
			}
			if err != nil {
				return err
			}
		}
		if immediateBytes, err = addNonnegativeInt64(immediateBytes, itemImmediate); err != nil {
			return err
		}
		if deferredBytes, err = addNonnegativeInt64(deferredBytes, item.NormalizedEvents.LogicalBytesReclaimableAfterMaintenance); err != nil {
			return err
		}
	}
	if !p.GeneratedAt.Equal(generatedAt) || !p.ExpiresAt.Equal(expiresAt) || p.NormalizedEventRows != eventRows || p.ExclusiveIdentityRows != identities || int64(p.PendingSpoolRecords) != spoolRecords || p.PendingSpoolBytes != spoolBytes || int64(p.ExistingExportRecords) != exports || p.ImmediatelyRecoverableBytes != immediateBytes || p.LogicalBytesReclaimableAfterMaintenance != deferredBytes {
		return errors.New("coordinated capture retention preview totals do not match selected evidence")
	}
	expected, err := coordinatedCaptureRetentionPreviewHash(p)
	if err != nil || expected != p.PreviewSHA256 {
		return errors.New("coordinated capture retention preview digest does not match")
	}
	return nil
}

func coordinatedCaptureRetentionPreviewHash(preview coordinatedCaptureRetentionPreview) (string, error) {
	evidence := preview
	evidence.PreviewSHA256 = ""
	return coordinatorHashJSON(evidence)
}

func (s *Store) recordCoordinatedCaptureRetentionPreview(preview coordinatedCaptureRetentionPreview, administrator string) (coordinatedCaptureRetentionPreviewRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if preview.Schema != coordinatedCaptureRetentionPreviewSchema || preview.validate() != nil || !validCoordinatorText(administrator, 1, 96) || !preview.ExpiresAt.After(time.Now().UTC()) {
		return coordinatedCaptureRetentionPreviewRecord{}, errors.New("capture retention preview record is invalid or expired")
	}
	ledger, err := s.readCoordinatedCaptureRetentionPreviewsLocked()
	if err != nil {
		return coordinatedCaptureRetentionPreviewRecord{}, err
	}
	for _, record := range ledger.Records {
		if record.Preview.PreviewSHA256 != preview.PreviewSHA256 {
			continue
		}
		if record.Administrator != administrator {
			return coordinatedCaptureRetentionPreviewRecord{}, errors.New("capture retention preview belongs to a different administrator")
		}
		return record, nil
	}
	if err := pruneCoordinatedCaptureRetentionPreviewsLocked(&ledger, time.Now().UTC()); err != nil {
		return coordinatedCaptureRetentionPreviewRecord{}, err
	}
	record := coordinatedCaptureRetentionPreviewRecord{Schema: coordinatedCaptureRetentionPreviewSchema, Preview: preview, Administrator: administrator, RecordedAt: time.Now().UTC().Truncate(time.Microsecond)}
	ledger.Records = append(ledger.Records, record)
	if err := s.writeCoordinatedCaptureRetentionPreviewsLocked(ledger); err != nil {
		return coordinatedCaptureRetentionPreviewRecord{}, err
	}
	return record, nil
}

func (s *Store) getCoordinatedCaptureRetentionPreview(previewSHA256, administrator string) (coordinatedCaptureRetentionPreviewRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validSHA256(previewSHA256) || !validCoordinatorText(administrator, 1, 96) {
		return coordinatedCaptureRetentionPreviewRecord{}, errors.New("capture retention preview lookup is invalid")
	}
	ledger, err := s.readCoordinatedCaptureRetentionPreviewsLocked()
	if err != nil {
		return coordinatedCaptureRetentionPreviewRecord{}, err
	}
	for _, record := range ledger.Records {
		if record.Preview.PreviewSHA256 == previewSHA256 && record.Administrator == administrator {
			return record, nil
		}
	}
	return coordinatedCaptureRetentionPreviewRecord{}, os.ErrNotExist
}

func (s *Store) getCoordinatedCaptureRetentionPreviewByHostDigest(hostSHA256, administrator string) (coordinatedCaptureRetentionPreviewRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validSHA256(hostSHA256) || !validCoordinatorText(administrator, 1, 96) {
		return coordinatedCaptureRetentionPreviewRecord{}, errors.New("capture retention host preview lookup is invalid")
	}
	ledger, err := s.readCoordinatedCaptureRetentionPreviewsLocked()
	if err != nil {
		return coordinatedCaptureRetentionPreviewRecord{}, err
	}
	var found *coordinatedCaptureRetentionPreviewRecord
	for index := range ledger.Records {
		record := &ledger.Records[index]
		if record.Preview.HostRetention.PreviewSHA256 != hostSHA256 || record.Administrator != administrator {
			continue
		}
		if found != nil {
			return coordinatedCaptureRetentionPreviewRecord{}, errors.New("capture retention host preview digest is ambiguous")
		}
		copy := *record
		found = &copy
	}
	if found == nil {
		return coordinatedCaptureRetentionPreviewRecord{}, os.ErrNotExist
	}
	return *found, nil
}

func (s *Store) readCoordinatedCaptureRetentionPreviewsLocked() (coordinatedCaptureRetentionPreviewLedger, error) {
	path := filepath.Join(s.dataDir, "capture-retention-previews.json")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return coordinatedCaptureRetentionPreviewLedger{Schema: coordinatedCaptureRetentionLedgerSchema, Records: []coordinatedCaptureRetentionPreviewRecord{}}, nil
	}
	if err != nil {
		return coordinatedCaptureRetentionPreviewLedger{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxCaptureRetentionPreviewLedgerBytes {
		return coordinatedCaptureRetentionPreviewLedger{}, errors.New("capture retention preview ledger is not a bounded regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return coordinatedCaptureRetentionPreviewLedger{}, err
	}
	var ledger coordinatedCaptureRetentionPreviewLedger
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&ledger) != nil || ledger.Schema != coordinatedCaptureRetentionLedgerSchema || len(ledger.Records) > maxCoordinatedCaptureRetentionPreviews {
		return coordinatedCaptureRetentionPreviewLedger{}, errors.New("capture retention preview ledger is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return coordinatedCaptureRetentionPreviewLedger{}, errors.New("capture retention preview ledger has trailing data")
	}
	if err := validateCoordinatedCaptureRetentionPreviewLedger(ledger); err != nil {
		return coordinatedCaptureRetentionPreviewLedger{}, err
	}
	return ledger, nil
}

func (s *Store) writeCoordinatedCaptureRetentionPreviewsLocked(ledger coordinatedCaptureRetentionPreviewLedger) error {
	if err := validateCoordinatedCaptureRetentionPreviewLedger(ledger); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil || len(encoded)+1 > maxCaptureRetentionPreviewLedgerBytes {
		return errors.New("capture retention preview ledger is oversized or invalid")
	}
	if err := os.MkdirAll(s.dataDir, 0o750); err != nil {
		return err
	}
	path := filepath.Join(s.dataDir, "capture-retention-previews.json")
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return errors.New("capture retention preview ledger is not a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return atomicWrite(path, append(encoded, '\n'), 0o600)
}

func validateCoordinatedCaptureRetentionPreviewLedger(ledger coordinatedCaptureRetentionPreviewLedger) error {
	if ledger.Schema != coordinatedCaptureRetentionLedgerSchema || len(ledger.Records) > maxCoordinatedCaptureRetentionPreviews {
		return errors.New("capture retention preview ledger is invalid")
	}
	seen := make(map[string]struct{}, len(ledger.Records))
	for _, record := range ledger.Records {
		if record.Schema != legacyCoordinatedCaptureRetentionPreviewSchema && record.Schema != coordinatedCaptureRetentionPreviewSchema || record.Preview.Schema != record.Schema || record.Preview.validate() != nil || !validCoordinatorText(record.Administrator, 1, 96) || record.RecordedAt.Before(record.Preview.GeneratedAt) || record.RecordedAt.After(record.Preview.ExpiresAt) {
			return errors.New("capture retention preview ledger contains an invalid record")
		}
		if _, exists := seen[record.Preview.PreviewSHA256]; exists {
			return errors.New("capture retention preview ledger contains duplicate previews")
		}
		seen[record.Preview.PreviewSHA256] = struct{}{}
	}
	return nil
}

func retentionSelectedPreview(preview coordinatedCaptureRetentionPreview, sessionID string) (coordinatedCaptureDeletionPreview, error) {
	for _, selected := range preview.Selected {
		if selected.SessionID == sessionID {
			return selected, nil
		}
	}
	return coordinatedCaptureDeletionPreview{}, os.ErrNotExist
}

func validateHostCaptureRetentionPreview(preview capture.RetentionPreview) error {
	if preview.Schema != 1 || !validSHA256(preview.PreviewSHA256) || preview.GeneratedAt.IsZero() || !preview.ExpiresAt.After(preview.GeneratedAt) || preview.ExpiresAt.Sub(preview.GeneratedAt) > capture.RetentionPreviewLifetime || preview.Policy.Validate() != nil || preview.EvaluatedSessions < 0 || preview.EvaluatedSessions > capture.MaxRetentionEvaluatedSessions || preview.ExcludedSessions < 0 || preview.ExcludedSessions > capture.MaxRetentionEvaluatedSessions || preview.EvaluatedSessions+preview.ExcludedSessions > capture.MaxRetentionEvaluatedSessions || len(preview.Selected) > capture.MaxRetentionCandidates || len(preview.BlockedByRetentionLock) > capture.MaxRetentionCandidates || preview.EvaluatedPCAPBytes < 0 || preview.ExcludedPCAPBytes < 0 || preview.DeleteFiles < 0 || preview.ImmediatelyRecoverableBytes < 0 || preview.ProjectedPCAPBytes < 0 || len(preview.Selected)+len(preview.BlockedByRetentionLock) > preview.EvaluatedSessions || preview.SharedPCAPCollateralKnown || !containsString(preview.DeletedDataClasses, "capture_session_metadata") || !containsString(preview.DeletedDataClasses, "pcap_artifacts") {
		return errors.New("host capture retention preview is invalid")
	}
	seen := make(map[string]struct{}, len(preview.Selected)+len(preview.BlockedByRetentionLock))
	var deleteFiles int
	var immediateBytes, selectedPCAPBytes int64
	for _, group := range []struct {
		candidates []capture.RetentionCandidate
		locked     bool
	}{{preview.Selected, false}, {preview.BlockedByRetentionLock, true}} {
		for _, candidate := range group.candidates {
			if !capture.ValidSessionID(candidate.SessionID) || !validCoordinatorText(candidate.Name, 1, 96) || candidate.FinalizedAt.IsZero() || candidate.FinalizedAt.After(preview.GeneratedAt) || candidate.RetentionLock != group.locked || candidate.Footprint.CaptureFiles < 0 || candidate.Footprint.CaptureBytes < 0 || candidate.Footprint.MetadataFiles < 0 || candidate.Footprint.MetadataBytes < 0 || len(candidate.Reasons) < 1 || len(candidate.Reasons) > 2 {
				return errors.New("host capture retention preview contains an invalid candidate")
			}
			for _, reason := range candidate.Reasons {
				if reason != "MAX_AGE" && reason != "MAX_PCAP_BYTES" {
					return errors.New("host capture retention preview contains an invalid selection reason")
				}
			}
			if _, exists := seen[candidate.SessionID]; exists {
				return errors.New("host capture retention preview contains a duplicate session")
			}
			seen[candidate.SessionID] = struct{}{}
			if group.locked {
				continue
			}
			if candidate.Footprint.MetadataFiles > math.MaxInt-candidate.Footprint.CaptureFiles {
				return errors.New("capture retention preview count overflow")
			}
			candidateFiles := candidate.Footprint.CaptureFiles + candidate.Footprint.MetadataFiles
			if candidateFiles > math.MaxInt-deleteFiles {
				return errors.New("capture retention preview count overflow")
			}
			deleteFiles += candidateFiles
			var err error
			candidateBytes, err := addNonnegativeInt64(candidate.Footprint.CaptureBytes, candidate.Footprint.MetadataBytes)
			if err != nil {
				return err
			}
			if immediateBytes, err = addNonnegativeInt64(immediateBytes, candidateBytes); err != nil {
				return err
			}
			if selectedPCAPBytes, err = addNonnegativeInt64(selectedPCAPBytes, candidate.Footprint.CaptureBytes); err != nil {
				return err
			}
		}
	}
	if deleteFiles != preview.DeleteFiles || immediateBytes != preview.ImmediatelyRecoverableBytes || selectedPCAPBytes > preview.EvaluatedPCAPBytes || preview.ProjectedPCAPBytes != preview.EvaluatedPCAPBytes-selectedPCAPBytes || preview.PCAPByteTargetMet != (preview.Policy.MaxPCAPBytes == 0 || preview.ProjectedPCAPBytes <= preview.Policy.MaxPCAPBytes) {
		return errors.New("host capture retention preview totals are inconsistent")
	}
	return nil
}

func addCaptureRetentionItemTotals(preview *coordinatedCaptureRetentionPreview, item coordinatedCaptureDeletionPreview) error {
	var err error
	if preview.NormalizedEventRows, err = addNonnegativeInt64(preview.NormalizedEventRows, item.NormalizedEvents.Database.EventRows); err != nil {
		return err
	}
	if preview.ExclusiveIdentityRows, err = addNonnegativeInt64(preview.ExclusiveIdentityRows, item.NormalizedEvents.Database.ExclusiveIdentityRows); err != nil {
		return err
	}
	if item.NormalizedEvents.Spool.PendingRecords > math.MaxInt-preview.PendingSpoolRecords || item.ExistingExportRecords > math.MaxInt-preview.ExistingExportRecords {
		return errors.New("capture retention preview count overflow")
	}
	preview.PendingSpoolRecords += item.NormalizedEvents.Spool.PendingRecords
	preview.ExistingExportRecords += item.ExistingExportRecords
	if preview.PendingSpoolBytes, err = addNonnegativeInt64(preview.PendingSpoolBytes, item.NormalizedEvents.Spool.PendingFileBytes); err != nil {
		return err
	}
	itemImmediate, err := addNonnegativeInt64(item.HostArtifacts.EstimatedRecoverableBytes, item.NormalizedEvents.EstimatedImmediatelyReclaimableBytes)
	if err != nil {
		return err
	}
	if item.Schema == coordinatedCaptureDeletionSchema {
		itemImmediate, err = addNonnegativeInt64(itemImmediate, item.ZeekCheckpoint.CheckpointBytes)
		if err == nil {
			itemImmediate, err = addNonnegativeInt64(itemImmediate, item.ZeekCheckpoint.ActiveProgressBytes)
		}
		if err == nil {
			itemImmediate, err = addNonnegativeInt64(itemImmediate, item.SuricataCheckpoint.CheckpointBytes)
		}
		if err == nil {
			itemImmediate, err = addNonnegativeInt64(itemImmediate, item.SuricataCheckpoint.ActiveProgressBytes)
		}
		if err != nil {
			return err
		}
	}
	if preview.ImmediatelyRecoverableBytes, err = addNonnegativeInt64(preview.ImmediatelyRecoverableBytes, itemImmediate); err != nil {
		return err
	}
	if preview.LogicalBytesReclaimableAfterMaintenance, err = addNonnegativeInt64(preview.LogicalBytesReclaimableAfterMaintenance, item.NormalizedEvents.LogicalBytesReclaimableAfterMaintenance); err != nil {
		return err
	}
	return nil
}

func addNonnegativeInt64(left, right int64) (int64, error) {
	if left < 0 || right < 0 || right > math.MaxInt64-left {
		return 0, errors.New("capture retention preview total overflow")
	}
	return left + right, nil
}
