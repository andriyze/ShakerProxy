package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"shakerproxy.dev/shakerproxy/internal/analyzer"
	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/ingest"
)

const (
	legacyCoordinatedCaptureDeletionSchema = 1
	coordinatedCaptureDeletionSchema       = 2
	coordinatedCaptureDeletionLedgerSchema = 1
	maxCoordinatedCaptureDeletions         = 1024
	maxCaptureDeletionRetries              = 32
	maxCaptureDeletionSupersessions        = 16
	maxCaptureDeletionLedgerBytes          = 16 << 20
)

type coordinatedCaptureDeletionState string

const (
	coordinatedDeletionPending   coordinatedCaptureDeletionState = "PENDING"
	coordinatedDeletionRunning   coordinatedCaptureDeletionState = "RUNNING"
	coordinatedDeletionCompleted coordinatedCaptureDeletionState = "COMPLETED"
	coordinatedDeletionPartial   coordinatedCaptureDeletionState = "PARTIAL"
	coordinatedDeletionFailed    coordinatedCaptureDeletionState = "FAILED"
	coordinatedDeletionCancelled coordinatedCaptureDeletionState = "CANCELLED"
)

type captureDeletionBackendState string

const (
	deletionBackendNotStarted captureDeletionBackendState = "NOT_STARTED"
	deletionBackendRunning    captureDeletionBackendState = "RUNNING"
	deletionBackendCompleted  captureDeletionBackendState = "COMPLETED"
	deletionBackendFailed     captureDeletionBackendState = "FAILED"
)

type coordinatedCaptureDeletionPreview struct {
	Schema                int                                 `json:"schema"`
	SessionID             string                              `json:"session_id"`
	PreviewSHA256         string                              `json:"preview_sha256"`
	GeneratedAt           time.Time                           `json:"generated_at"`
	ExpiresAt             time.Time                           `json:"expires_at"`
	HostArtifacts         capture.DeletionPreview             `json:"host_artifacts"`
	NormalizedEvents      ingest.CaptureEventDeletionPreview  `json:"normalized_events"`
	ZeekCheckpoint        *analyzer.CheckpointDeletionPreview `json:"zeek_checkpoint,omitempty"`
	SuricataCheckpoint    *analyzer.CheckpointDeletionPreview `json:"suricata_checkpoint,omitempty"`
	DeletedDataClasses    []string                            `json:"deleted_data_classes"`
	RetainedDataClasses   []string                            `json:"retained_data_classes"`
	ExistingExportRecords int                                 `json:"existing_export_records"`
	CopyBoundaries        []deletionCopyBoundary              `json:"copy_boundaries,omitempty"`
	Confirmation          string                              `json:"confirmation"`
}

type captureDeletionBackendResult struct {
	Backend            string                              `json:"backend"`
	State              captureDeletionBackendState         `json:"state"`
	UpdatedAt          time.Time                           `json:"updated_at"`
	Failure            string                              `json:"failure,omitempty"`
	HostArtifacts      *capture.DeletionJob                `json:"host_artifacts,omitempty"`
	NormalizedEvents   *ingest.CaptureEventDeletionOutcome `json:"normalized_events,omitempty"`
	AnalyzerCheckpoint *analyzer.CheckpointDeletionOutcome `json:"analyzer_checkpoint,omitempty"`
}

type coordinatedCaptureDeletionJob struct {
	Schema              int                             `json:"schema"`
	ID                  string                          `json:"id"`
	SessionID           string                          `json:"session_id"`
	State               coordinatedCaptureDeletionState `json:"state"`
	Phase               string                          `json:"phase"`
	ProgressPercent     int                             `json:"progress_percent"`
	Administrator       string                          `json:"administrator"`
	PreviewSHA256       string                          `json:"preview_sha256"`
	Backends            []captureDeletionBackendResult  `json:"backends"`
	RetainedDataClasses []string                        `json:"retained_data_classes"`
	CreatedAt           time.Time                       `json:"created_at"`
	UpdatedAt           time.Time                       `json:"updated_at"`
	CompletedAt         *time.Time                      `json:"completed_at,omitempty"`
	Failure             string                          `json:"failure,omitempty"`
}

type coordinatedCaptureDeletionRecord struct {
	Schema         int                               `json:"schema"`
	Job            coordinatedCaptureDeletionJob     `json:"job"`
	Preview        coordinatedCaptureDeletionPreview `json:"preview"`
	IdempotencyKey string                            `json:"idempotency_key"`
	RequestSHA256  string                            `json:"request_sha256"`
	Retries        []captureDeletionRetryRecord      `json:"retries,omitempty"`
	Supersessions  []captureDeletionSupersession     `json:"supersessions,omitempty"`
	CancelKey      string                            `json:"cancel_key,omitempty"`
	CancelledBy    string                            `json:"cancelled_by,omitempty"`
}

type captureDeletionRetryRecord struct {
	IdempotencyKey string                          `json:"idempotency_key"`
	Administrator  string                          `json:"administrator"`
	StartedAt      time.Time                       `json:"started_at"`
	CompletedAt    *time.Time                      `json:"completed_at,omitempty"`
	ResultState    coordinatedCaptureDeletionState `json:"result_state,omitempty"`
}

type captureDeletionSupersession struct {
	IdempotencyKey           string                            `json:"idempotency_key"`
	Administrator            string                            `json:"administrator"`
	Previous                 coordinatedCaptureDeletionPreview `json:"previous_preview"`
	ReplacementPreviewSHA256 string                            `json:"replacement_preview_sha256"`
	SupersededAt             time.Time                         `json:"superseded_at"`
}

type coordinatedCaptureDeletionLedger struct {
	Schema  int                                `json:"schema"`
	Records []coordinatedCaptureDeletionRecord `json:"records"`
}

var coordinatedCaptureDeletionIDPattern = regexp.MustCompile(`^capture-delete-operation-[a-f0-9]{32}$`)
var hostCaptureDeletionIDPattern = regexp.MustCompile(`^capture-delete-[a-f0-9]{32}$`)

var (
	errCoordinatedCaptureDeletionInvalid  = errors.New("coordinated capture deletion request is invalid")
	errCoordinatedCaptureDeletionConflict = errors.New("capture deletion idempotency key conflicts with an existing request")
	errCoordinatedCaptureDeletionExpired  = errors.New("capture deletion preview has expired")
	errCaptureDeletionRetryInvalid        = errors.New("capture deletion retry request is invalid")
	errCaptureDeletionRetryConflict       = errors.New("capture deletion retry idempotency key conflicts with an existing request")
	errCaptureDeletionRetryLimit          = errors.New("capture deletion retry limit exceeded")
	errCaptureDeletionCancelInvalid       = errors.New("capture deletion can no longer be cancelled safely")
	errCaptureDeletionCancelConflict      = errors.New("capture deletion cancellation idempotency key conflicts with existing evidence")
	errCaptureDeletionSupersedeInvalid    = errors.New("capture deletion supersession is invalid")
	errCaptureDeletionSupersedeConflict   = errors.New("capture deletion supersession idempotency key conflicts with existing evidence")
	errCaptureDeletionSupersedeLimit      = errors.New("capture deletion supersession limit exceeded")
)

var legacyCoordinatedCaptureDeletedDataClasses = []string{
	"capture_session_metadata",
	"pcap_artifacts",
	"normalized_event_metadata",
	"normalized_event_exclusive_identities",
	"pending_ingest_spool_records",
}

var legacyCoordinatedCaptureRetainedDataClasses = []string{
	"analyzer_checkpoints",
	"capture_export_audit",
	"external_exported_copies",
	"existing_backups",
}

var coordinatedCaptureDeletedDataClasses = []string{
	"capture_session_metadata",
	"pcap_artifacts",
	"normalized_event_metadata",
	"normalized_event_exclusive_identities",
	"pending_ingest_spool_records",
	"analyzer_checkpoints",
}

var coordinatedCaptureRetainedDataClasses = []string{
	"capture_export_audit",
	"external_exported_copies",
	"existing_backups",
}

type captureEventDeletionService interface {
	Preview(context.Context, string) (ingest.CaptureEventDeletionPreview, error)
	Delete(context.Context, ingest.CaptureEventDeletionRequest) (ingest.CaptureEventDeletionOutcome, error)
}

type analyzerCheckpointDeletionService interface {
	Preview(context.Context, string) (analyzer.CheckpointDeletionPreview, error)
	Delete(context.Context, analyzer.CheckpointDeletionRequest) (analyzer.CheckpointDeletionOutcome, error)
	AuthorizeReindex(context.Context, analyzer.CheckpointReindexRequest) (analyzer.CheckpointReindexOutcome, error)
}

func newCoordinatedCaptureDeletionPreview(host capture.DeletionPreview, events ingest.CaptureEventDeletionPreview, zeek, suricata analyzer.CheckpointDeletionPreview, existingExportRecords int) (coordinatedCaptureDeletionPreview, error) {
	if !validHostCaptureDeletionPreview(host) || events.Validate() != nil || zeek.Validate() != nil || suricata.Validate() != nil || host.SessionID != events.CaptureSessionID || host.SessionID != zeek.CaptureSessionID || host.SessionID != suricata.CaptureSessionID || zeek.Engine != analyzer.EngineZeek || suricata.Engine != analyzer.EngineSuricata || existingExportRecords < 0 || existingExportRecords > maxCaptureExportRecords {
		return coordinatedCaptureDeletionPreview{}, errors.New("capture deletion backend previews are invalid or inconsistent")
	}
	generatedAt := host.GeneratedAt.UTC()
	if events.GeneratedAt.After(generatedAt) {
		generatedAt = events.GeneratedAt.UTC()
	}
	if zeek.GeneratedAt.After(generatedAt) {
		generatedAt = zeek.GeneratedAt.UTC()
	}
	if suricata.GeneratedAt.After(generatedAt) {
		generatedAt = suricata.GeneratedAt.UTC()
	}
	expiresAt := host.ExpiresAt.UTC()
	if events.ExpiresAt.Before(expiresAt) {
		expiresAt = events.ExpiresAt.UTC()
	}
	if zeek.ExpiresAt.Before(expiresAt) {
		expiresAt = zeek.ExpiresAt.UTC()
	}
	if suricata.ExpiresAt.Before(expiresAt) {
		expiresAt = suricata.ExpiresAt.UTC()
	}
	if !expiresAt.After(generatedAt) {
		return coordinatedCaptureDeletionPreview{}, errors.New("capture deletion backend previews do not share a usable validity window")
	}
	preview := coordinatedCaptureDeletionPreview{
		Schema: coordinatedCaptureDeletionSchema, SessionID: host.SessionID,
		GeneratedAt: generatedAt, ExpiresAt: expiresAt, HostArtifacts: host, NormalizedEvents: events, ZeekCheckpoint: &zeek, SuricataCheckpoint: &suricata,
		DeletedDataClasses: append([]string(nil), coordinatedCaptureDeletedDataClasses...), RetainedDataClasses: append([]string(nil), coordinatedCaptureRetainedDataClasses...),
		ExistingExportRecords: existingExportRecords, CopyBoundaries: deletionCopyBoundaries(existingExportRecords), Confirmation: host.SessionID,
	}
	digest, err := coordinatedCaptureDeletionPreviewHash(preview)
	if err != nil {
		return coordinatedCaptureDeletionPreview{}, err
	}
	preview.PreviewSHA256 = digest
	return preview, preview.validate()
}

func (p coordinatedCaptureDeletionPreview) validate() error {
	if p.Schema != legacyCoordinatedCaptureDeletionSchema && p.Schema != coordinatedCaptureDeletionSchema || !capture.ValidSessionID(p.SessionID) || !validSHA256(p.PreviewSHA256) || !validHostCaptureDeletionPreview(p.HostArtifacts) || p.NormalizedEvents.Validate() != nil || p.HostArtifacts.SessionID != p.SessionID || p.NormalizedEvents.CaptureSessionID != p.SessionID || p.GeneratedAt.IsZero() || !p.ExpiresAt.After(p.GeneratedAt) || p.ExpiresAt.After(p.HostArtifacts.ExpiresAt) || p.ExpiresAt.After(p.NormalizedEvents.ExpiresAt) || p.ExistingExportRecords < 0 || p.ExistingExportRecords > maxCaptureExportRecords || validateDeletionCopyBoundaries(p.CopyBoundaries, p.ExistingExportRecords) != nil || p.Confirmation != p.SessionID {
		return errors.New("coordinated capture deletion preview is invalid")
	}
	if p.Schema == legacyCoordinatedCaptureDeletionSchema {
		if p.ZeekCheckpoint != nil || p.SuricataCheckpoint != nil || len(p.CopyBoundaries) != 0 || !equalStringSlices(p.DeletedDataClasses, legacyCoordinatedCaptureDeletedDataClasses) || !equalStringSlices(p.RetainedDataClasses, legacyCoordinatedCaptureRetainedDataClasses) {
			return errors.New("legacy coordinated capture deletion preview is invalid")
		}
	} else if p.ZeekCheckpoint == nil || p.SuricataCheckpoint == nil || p.ZeekCheckpoint.Validate() != nil || p.SuricataCheckpoint.Validate() != nil || p.ZeekCheckpoint.Engine != analyzer.EngineZeek || p.SuricataCheckpoint.Engine != analyzer.EngineSuricata || p.ZeekCheckpoint.CaptureSessionID != p.SessionID || p.SuricataCheckpoint.CaptureSessionID != p.SessionID || p.ExpiresAt.After(p.ZeekCheckpoint.ExpiresAt) || p.ExpiresAt.After(p.SuricataCheckpoint.ExpiresAt) || !equalStringSlices(p.DeletedDataClasses, coordinatedCaptureDeletedDataClasses) || !equalStringSlices(p.RetainedDataClasses, coordinatedCaptureRetainedDataClasses) {
		return errors.New("coordinated capture deletion analyzer previews are invalid")
	}
	expectedGeneratedAt, expectedExpiresAt := p.HostArtifacts.GeneratedAt.UTC(), p.HostArtifacts.ExpiresAt.UTC()
	for _, validity := range [][2]time.Time{{p.NormalizedEvents.GeneratedAt, p.NormalizedEvents.ExpiresAt}} {
		if validity[0].After(expectedGeneratedAt) {
			expectedGeneratedAt = validity[0].UTC()
		}
		if validity[1].Before(expectedExpiresAt) {
			expectedExpiresAt = validity[1].UTC()
		}
	}
	if p.Schema == coordinatedCaptureDeletionSchema {
		for _, validity := range [][2]time.Time{{p.ZeekCheckpoint.GeneratedAt, p.ZeekCheckpoint.ExpiresAt}, {p.SuricataCheckpoint.GeneratedAt, p.SuricataCheckpoint.ExpiresAt}} {
			if validity[0].After(expectedGeneratedAt) {
				expectedGeneratedAt = validity[0].UTC()
			}
			if validity[1].Before(expectedExpiresAt) {
				expectedExpiresAt = validity[1].UTC()
			}
		}
	}
	if !p.GeneratedAt.Equal(expectedGeneratedAt) || !p.ExpiresAt.Equal(expectedExpiresAt) {
		return errors.New("coordinated capture deletion validity window does not match its backends")
	}
	expected, err := coordinatedCaptureDeletionPreviewHash(p)
	if err != nil || expected != p.PreviewSHA256 {
		return errors.New("coordinated capture deletion preview digest does not match")
	}
	return nil
}

func coordinatedCaptureDeletionPreviewHash(preview coordinatedCaptureDeletionPreview) (string, error) {
	if preview.Schema == legacyCoordinatedCaptureDeletionSchema {
		evidence := struct {
			Schema                int                                `json:"schema"`
			SessionID             string                             `json:"session_id"`
			GeneratedAt           time.Time                          `json:"generated_at"`
			ExpiresAt             time.Time                          `json:"expires_at"`
			HostArtifacts         capture.DeletionPreview            `json:"host_artifacts"`
			NormalizedEvents      ingest.CaptureEventDeletionPreview `json:"normalized_events"`
			DeletedDataClasses    []string                           `json:"deleted_data_classes"`
			RetainedDataClasses   []string                           `json:"retained_data_classes"`
			ExistingExportRecords int                                `json:"existing_export_records"`
			Confirmation          string                             `json:"confirmation"`
		}{preview.Schema, preview.SessionID, preview.GeneratedAt.UTC(), preview.ExpiresAt.UTC(), preview.HostArtifacts, preview.NormalizedEvents, preview.DeletedDataClasses, preview.RetainedDataClasses, preview.ExistingExportRecords, preview.Confirmation}
		return coordinatorHashJSON(evidence)
	}
	evidence := struct {
		Schema                int                                 `json:"schema"`
		SessionID             string                              `json:"session_id"`
		GeneratedAt           time.Time                           `json:"generated_at"`
		ExpiresAt             time.Time                           `json:"expires_at"`
		HostArtifacts         capture.DeletionPreview             `json:"host_artifacts"`
		NormalizedEvents      ingest.CaptureEventDeletionPreview  `json:"normalized_events"`
		ZeekCheckpoint        *analyzer.CheckpointDeletionPreview `json:"zeek_checkpoint"`
		SuricataCheckpoint    *analyzer.CheckpointDeletionPreview `json:"suricata_checkpoint"`
		DeletedDataClasses    []string                            `json:"deleted_data_classes"`
		RetainedDataClasses   []string                            `json:"retained_data_classes"`
		ExistingExportRecords int                                 `json:"existing_export_records"`
		CopyBoundaries        []deletionCopyBoundary              `json:"copy_boundaries,omitempty"`
		Confirmation          string                              `json:"confirmation"`
	}{preview.Schema, preview.SessionID, preview.GeneratedAt.UTC(), preview.ExpiresAt.UTC(), preview.HostArtifacts, preview.NormalizedEvents, preview.ZeekCheckpoint, preview.SuricataCheckpoint, preview.DeletedDataClasses, preview.RetainedDataClasses, preview.ExistingExportRecords, preview.CopyBoundaries, preview.Confirmation}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func validHostCaptureDeletionPreview(preview capture.DeletionPreview) bool {
	if preview.Schema != 1 || !capture.ValidSessionID(preview.SessionID) || !validSHA256(preview.PreviewSHA256) || preview.GeneratedAt.IsZero() || !preview.ExpiresAt.After(preview.GeneratedAt) || preview.ExpiresAt.Sub(preview.GeneratedAt) > capture.DeletionPreviewLifetime || preview.RetentionLock || preview.Footprint.CaptureFiles < 0 || preview.Footprint.CaptureBytes < 0 || preview.Footprint.MetadataFiles < 0 || preview.Footprint.MetadataBytes < 0 || preview.EstimatedRecoverableBytes != preview.Footprint.TotalBytes() || preview.Confirmation != preview.SessionID {
		return false
	}
	switch preview.State {
	case capture.StateCompleted, capture.StateStopped, capture.StateStoragePressure, capture.StateFailed:
	default:
		return false
	}
	return containsString(preview.DeletedDataClasses, "capture_session_metadata") && containsString(preview.DeletedDataClasses, "pcap_artifacts")
}

func (s *Store) beginCoordinatedCaptureDeletion(preview coordinatedCaptureDeletionPreview, administrator, idempotencyKey string) (coordinatedCaptureDeletionRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if preview.validate() != nil || !validCoordinatorText(administrator, 1, 96) || !validCoordinatorOpaqueKey(idempotencyKey) {
		return coordinatedCaptureDeletionRecord{}, false, errCoordinatedCaptureDeletionInvalid
	}
	requestSHA256, err := coordinatedCaptureDeletionRequestSHA(preview, administrator, idempotencyKey)
	if err != nil {
		return coordinatedCaptureDeletionRecord{}, false, err
	}
	ledger, err := s.readCoordinatedCaptureDeletionsLocked()
	if err != nil {
		return coordinatedCaptureDeletionRecord{}, false, err
	}
	for _, existing := range ledger.Records {
		if existing.IdempotencyKey == idempotencyKey {
			if existing.RequestSHA256 != requestSHA256 {
				return coordinatedCaptureDeletionRecord{}, false, errCoordinatedCaptureDeletionConflict
			}
			return existing, true, nil
		}
		for _, retry := range existing.Retries {
			if retry.IdempotencyKey == idempotencyKey {
				return coordinatedCaptureDeletionRecord{}, false, errCoordinatedCaptureDeletionConflict
			}
		}
		for _, supersession := range existing.Supersessions {
			if supersession.IdempotencyKey == idempotencyKey {
				return coordinatedCaptureDeletionRecord{}, false, errCoordinatedCaptureDeletionConflict
			}
		}
		if existing.CancelKey == idempotencyKey {
			return coordinatedCaptureDeletionRecord{}, false, errCoordinatedCaptureDeletionConflict
		}
	}
	if err := pruneCoordinatedCaptureDeletionsLocked(&ledger, time.Now().UTC()); err != nil {
		return coordinatedCaptureDeletionRecord{}, false, err
	}
	if !preview.ExpiresAt.After(time.Now().UTC()) {
		return coordinatedCaptureDeletionRecord{}, false, errCoordinatedCaptureDeletionExpired
	}
	id, err := newCoordinatedCaptureDeletionID(ledger.Records)
	if err != nil {
		return coordinatedCaptureDeletionRecord{}, false, err
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	backends := []captureDeletionBackendResult{
		{Backend: "normalized_events", State: deletionBackendNotStarted, UpdatedAt: now},
		{Backend: "host_capture_artifacts", State: deletionBackendNotStarted, UpdatedAt: now},
	}
	if preview.Schema == coordinatedCaptureDeletionSchema {
		backends = []captureDeletionBackendResult{
			{Backend: "normalized_events", State: deletionBackendNotStarted, UpdatedAt: now},
			{Backend: "zeek_checkpoint", State: deletionBackendNotStarted, UpdatedAt: now},
			{Backend: "suricata_checkpoint", State: deletionBackendNotStarted, UpdatedAt: now},
			{Backend: "host_capture_artifacts", State: deletionBackendNotStarted, UpdatedAt: now},
		}
	}
	record := coordinatedCaptureDeletionRecord{
		Schema: preview.Schema, Preview: preview, IdempotencyKey: idempotencyKey, RequestSHA256: requestSHA256,
		Job: coordinatedCaptureDeletionJob{
			Schema: preview.Schema, ID: id, SessionID: preview.SessionID, State: coordinatedDeletionPending, Phase: "AWAITING_BACKENDS", ProgressPercent: 5,
			Administrator: administrator, PreviewSHA256: preview.PreviewSHA256,
			Backends:            backends,
			RetainedDataClasses: append([]string(nil), preview.RetainedDataClasses...), CreatedAt: now, UpdatedAt: now,
		},
	}
	ledger.Records = append(ledger.Records, record)
	if err := s.writeCoordinatedCaptureDeletionsLocked(ledger); err != nil {
		return coordinatedCaptureDeletionRecord{}, false, err
	}
	return record, false, nil
}

func coordinatedCaptureDeletionRequestSHA(preview coordinatedCaptureDeletionPreview, administrator, idempotencyKey string) (string, error) {
	return coordinatorHashJSON(struct {
		SessionID      string `json:"session_id"`
		PreviewSHA256  string `json:"preview_sha256"`
		Confirmation   string `json:"confirmation"`
		Administrator  string `json:"administrator"`
		IdempotencyKey string `json:"idempotency_key"`
	}{preview.SessionID, preview.PreviewSHA256, preview.Confirmation, administrator, idempotencyKey})
}

func (s *Store) updateCoordinatedCaptureDeletion(id string, update func(*coordinatedCaptureDeletionRecord) error) (coordinatedCaptureDeletionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !coordinatedCaptureDeletionIDPattern.MatchString(id) || update == nil {
		return coordinatedCaptureDeletionRecord{}, errors.New("capture deletion operation update is invalid")
	}
	ledger, err := s.readCoordinatedCaptureDeletionsLocked()
	if err != nil {
		return coordinatedCaptureDeletionRecord{}, err
	}
	for index := range ledger.Records {
		if ledger.Records[index].Job.ID != id {
			continue
		}
		original := ledger.Records[index]
		completedBackendDigests := make(map[int]string)
		for backendIndex, backend := range original.Job.Backends {
			if backend.State == deletionBackendCompleted {
				digest, err := coordinatorHashJSON(backend)
				if err != nil {
					return coordinatedCaptureDeletionRecord{}, err
				}
				completedBackendDigests[backendIndex] = digest
			}
		}
		completedRetryDigests := make(map[int]string)
		for retryIndex, retry := range original.Retries {
			if retry.CompletedAt == nil {
				continue
			}
			digest, err := coordinatorHashJSON(retry)
			if err != nil {
				return coordinatedCaptureDeletionRecord{}, err
			}
			completedRetryDigests[retryIndex] = digest
		}
		if err := update(&ledger.Records[index]); err != nil {
			return coordinatedCaptureDeletionRecord{}, err
		}
		updated := ledger.Records[index]
		if len(updated.Retries) != len(original.Retries) || !reflect.DeepEqual(updated.Supersessions, original.Supersessions) {
			return coordinatedCaptureDeletionRecord{}, errors.New("capture deletion operation changed immutable retry or supersession history")
		}
		for retryIndex, originalRetry := range original.Retries {
			updatedRetry := updated.Retries[retryIndex]
			if originalRetry.IdempotencyKey != updatedRetry.IdempotencyKey || originalRetry.Administrator != updatedRetry.Administrator || !originalRetry.StartedAt.Equal(updatedRetry.StartedAt) {
				return coordinatedCaptureDeletionRecord{}, errors.New("capture deletion operation changed immutable retry evidence")
			}
			if originalDigest, exists := completedRetryDigests[retryIndex]; exists {
				updatedDigest, digestErr := coordinatorHashJSON(updatedRetry)
				if digestErr != nil || originalDigest != updatedDigest {
					return coordinatedCaptureDeletionRecord{}, errors.New("capture deletion operation changed immutable retry evidence")
				}
			}
		}
		if len(updated.Job.Backends) == len(original.Job.Backends) {
			for backendIndex, originalDigest := range completedBackendDigests {
				updatedDigest, digestErr := coordinatorHashJSON(updated.Job.Backends[backendIndex])
				if digestErr != nil || originalDigest != updatedDigest {
					return coordinatedCaptureDeletionRecord{}, errors.New("capture deletion operation changed a completed backend acknowledgement")
				}
			}
		}
		if updated.Schema != original.Schema || updated.Preview.PreviewSHA256 != original.Preview.PreviewSHA256 || updated.IdempotencyKey != original.IdempotencyKey || updated.RequestSHA256 != original.RequestSHA256 || updated.Job.ID != original.Job.ID || updated.Job.SessionID != original.Job.SessionID || updated.Job.Administrator != original.Job.Administrator || updated.Job.PreviewSHA256 != original.Job.PreviewSHA256 || !updated.Job.CreatedAt.Equal(original.Job.CreatedAt) || updated.validate() != nil {
			return coordinatedCaptureDeletionRecord{}, errors.New("capture deletion operation update changed immutable or invalid evidence")
		}
		if err := s.writeCoordinatedCaptureDeletionsLocked(ledger); err != nil {
			return coordinatedCaptureDeletionRecord{}, err
		}
		return updated, nil
	}
	return coordinatedCaptureDeletionRecord{}, os.ErrNotExist
}

func (s *Store) listCoordinatedCaptureDeletionJobs() ([]coordinatedCaptureDeletionJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ledger, err := s.readCoordinatedCaptureDeletionsLocked()
	if err != nil {
		return nil, err
	}
	jobs := make([]coordinatedCaptureDeletionJob, 0, len(ledger.Records))
	for _, record := range ledger.Records {
		jobs = append(jobs, record.Job)
	}
	return jobs, nil
}

func (s *Store) getCoordinatedCaptureDeletionJob(id string) (coordinatedCaptureDeletionJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !coordinatedCaptureDeletionIDPattern.MatchString(id) {
		return coordinatedCaptureDeletionJob{}, errors.New("capture deletion operation ID is invalid")
	}
	ledger, err := s.readCoordinatedCaptureDeletionsLocked()
	if err != nil {
		return coordinatedCaptureDeletionJob{}, err
	}
	for _, record := range ledger.Records {
		if record.Job.ID == id {
			return record.Job, nil
		}
	}
	return coordinatedCaptureDeletionJob{}, os.ErrNotExist
}

func (s *Store) getCoordinatedCaptureDeletionRecord(id string) (coordinatedCaptureDeletionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !coordinatedCaptureDeletionIDPattern.MatchString(id) {
		return coordinatedCaptureDeletionRecord{}, errors.New("capture deletion operation ID is invalid")
	}
	ledger, err := s.readCoordinatedCaptureDeletionsLocked()
	if err != nil {
		return coordinatedCaptureDeletionRecord{}, err
	}
	for _, record := range ledger.Records {
		if record.Job.ID == id {
			return record, nil
		}
	}
	return coordinatedCaptureDeletionRecord{}, os.ErrNotExist
}

func (s *Store) getCoordinatedCaptureDeletionByIdempotencyKey(idempotencyKey string) (coordinatedCaptureDeletionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validCoordinatorOpaqueKey(idempotencyKey) {
		return coordinatedCaptureDeletionRecord{}, errors.New("capture deletion idempotency key is invalid")
	}
	ledger, err := s.readCoordinatedCaptureDeletionsLocked()
	if err != nil {
		return coordinatedCaptureDeletionRecord{}, err
	}
	for _, record := range ledger.Records {
		if record.IdempotencyKey == idempotencyKey {
			return record, nil
		}
	}
	return coordinatedCaptureDeletionRecord{}, os.ErrNotExist
}

func (s *Store) beginCoordinatedCaptureDeletionRetry(id, idempotencyKey, administrator string) (coordinatedCaptureDeletionRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !coordinatedCaptureDeletionIDPattern.MatchString(id) || !validCoordinatorOpaqueKey(idempotencyKey) || !validCoordinatorText(administrator, 1, 96) {
		return coordinatedCaptureDeletionRecord{}, false, errCaptureDeletionRetryInvalid
	}
	ledger, err := s.readCoordinatedCaptureDeletionsLocked()
	if err != nil {
		return coordinatedCaptureDeletionRecord{}, false, err
	}
	for _, existing := range ledger.Records {
		if existing.IdempotencyKey == idempotencyKey || existing.CancelKey == idempotencyKey {
			return coordinatedCaptureDeletionRecord{}, false, errCaptureDeletionRetryConflict
		}
		for _, retry := range existing.Retries {
			if retry.IdempotencyKey != idempotencyKey {
				continue
			}
			if existing.Job.ID != id || retry.Administrator != administrator {
				return coordinatedCaptureDeletionRecord{}, false, errCaptureDeletionRetryConflict
			}
			return existing, retry.CompletedAt != nil, nil
		}
		for _, supersession := range existing.Supersessions {
			if supersession.IdempotencyKey == idempotencyKey {
				return coordinatedCaptureDeletionRecord{}, false, errCaptureDeletionRetryConflict
			}
		}
	}
	for index := range ledger.Records {
		if ledger.Records[index].Job.ID != id {
			continue
		}
		if hasUnfinishedCaptureDeletionRetry(ledger.Records[index].Retries) {
			return coordinatedCaptureDeletionRecord{}, false, errCaptureDeletionRetryConflict
		}
		if ledger.Records[index].Job.State == coordinatedDeletionCancelled {
			return coordinatedCaptureDeletionRecord{}, false, errCaptureDeletionRetryInvalid
		}
		if len(ledger.Records[index].Retries) >= maxCaptureDeletionRetries {
			return coordinatedCaptureDeletionRecord{}, false, errCaptureDeletionRetryLimit
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		retry := captureDeletionRetryRecord{IdempotencyKey: idempotencyKey, Administrator: administrator, StartedAt: now}
		replayed := false
		if ledger.Records[index].Job.State == coordinatedDeletionCompleted {
			retry.CompletedAt = &now
			retry.ResultState = coordinatedDeletionCompleted
			replayed = true
		}
		ledger.Records[index].Retries = append(ledger.Records[index].Retries, retry)
		if ledger.Records[index].validate() != nil {
			return coordinatedCaptureDeletionRecord{}, false, errors.New("capture deletion retry intent is invalid")
		}
		if err := s.writeCoordinatedCaptureDeletionsLocked(ledger); err != nil {
			return coordinatedCaptureDeletionRecord{}, false, err
		}
		return ledger.Records[index], replayed, nil
	}
	return coordinatedCaptureDeletionRecord{}, false, os.ErrNotExist
}

func (s *Store) cancelCoordinatedCaptureDeletion(id, idempotencyKey, administrator string) (coordinatedCaptureDeletionRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !coordinatedCaptureDeletionIDPattern.MatchString(id) || !validCoordinatorOpaqueKey(idempotencyKey) || !validCoordinatorText(administrator, 1, 96) {
		return coordinatedCaptureDeletionRecord{}, false, errCaptureDeletionCancelInvalid
	}
	ledger, err := s.readCoordinatedCaptureDeletionsLocked()
	if err != nil {
		return coordinatedCaptureDeletionRecord{}, false, err
	}
	for _, existing := range ledger.Records {
		if existing.CancelKey == idempotencyKey {
			if existing.Job.ID != id || existing.CancelledBy != administrator {
				return coordinatedCaptureDeletionRecord{}, false, errCaptureDeletionCancelConflict
			}
			return existing, true, nil
		}
		if existing.IdempotencyKey == idempotencyKey {
			return coordinatedCaptureDeletionRecord{}, false, errCaptureDeletionCancelConflict
		}
		for _, retry := range existing.Retries {
			if retry.IdempotencyKey == idempotencyKey {
				return coordinatedCaptureDeletionRecord{}, false, errCaptureDeletionCancelConflict
			}
		}
		for _, supersession := range existing.Supersessions {
			if supersession.IdempotencyKey == idempotencyKey {
				return coordinatedCaptureDeletionRecord{}, false, errCaptureDeletionCancelConflict
			}
		}
	}
	for index := range ledger.Records {
		record := &ledger.Records[index]
		if record.Job.ID != id {
			continue
		}
		if record.Job.Administrator != administrator || record.Job.State != coordinatedDeletionPending || !allBackendsState(record.Job.Backends, deletionBackendNotStarted) || hasUnfinishedCaptureDeletionRetry(record.Retries) {
			return coordinatedCaptureDeletionRecord{}, false, errCaptureDeletionCancelInvalid
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		record.Job.State, record.Job.Phase, record.Job.ProgressPercent = coordinatedDeletionCancelled, "CANCELLED_BEFORE_BARRIER", 0
		record.Job.UpdatedAt, record.Job.CompletedAt, record.Job.Failure = now, &now, ""
		record.CancelKey, record.CancelledBy = idempotencyKey, administrator
		if record.validate() != nil {
			return coordinatedCaptureDeletionRecord{}, false, errors.New("capture deletion cancellation evidence is invalid")
		}
		if err := s.writeCoordinatedCaptureDeletionsLocked(ledger); err != nil {
			return coordinatedCaptureDeletionRecord{}, false, err
		}
		return *record, false, nil
	}
	return coordinatedCaptureDeletionRecord{}, false, os.ErrNotExist
}

func (s *Store) supersedeCoordinatedCaptureDeletion(id string, preview coordinatedCaptureDeletionPreview, idempotencyKey, administrator string) (coordinatedCaptureDeletionRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !coordinatedCaptureDeletionIDPattern.MatchString(id) || preview.Schema != coordinatedCaptureDeletionSchema || preview.validate() != nil || !validCoordinatorOpaqueKey(idempotencyKey) || !validCoordinatorText(administrator, 1, 96) {
		return coordinatedCaptureDeletionRecord{}, false, errCaptureDeletionSupersedeInvalid
	}
	ledger, err := s.readCoordinatedCaptureDeletionsLocked()
	if err != nil {
		return coordinatedCaptureDeletionRecord{}, false, err
	}
	for _, existing := range ledger.Records {
		if existing.IdempotencyKey == idempotencyKey || existing.CancelKey == idempotencyKey {
			return coordinatedCaptureDeletionRecord{}, false, errCaptureDeletionSupersedeConflict
		}
		for _, retry := range existing.Retries {
			if retry.IdempotencyKey == idempotencyKey {
				return coordinatedCaptureDeletionRecord{}, false, errCaptureDeletionSupersedeConflict
			}
		}
		for _, supersession := range existing.Supersessions {
			if supersession.IdempotencyKey != idempotencyKey {
				continue
			}
			if existing.Job.ID != id || supersession.Administrator != administrator || supersession.ReplacementPreviewSHA256 != preview.PreviewSHA256 {
				return coordinatedCaptureDeletionRecord{}, false, errCaptureDeletionSupersedeConflict
			}
			return existing, true, nil
		}
	}
	for index := range ledger.Records {
		record := &ledger.Records[index]
		if record.Job.ID != id {
			continue
		}
		if record.Job.Administrator != administrator || preview.SessionID != record.Job.SessionID || !preview.ExpiresAt.After(time.Now().UTC()) || !preview.GeneratedAt.After(record.Preview.GeneratedAt) || record.Job.State != coordinatedDeletionPartial && record.Job.State != coordinatedDeletionFailed || hasUnfinishedCaptureDeletionRetry(record.Retries) {
			return coordinatedCaptureDeletionRecord{}, false, errCaptureDeletionSupersedeInvalid
		}
		if len(record.Supersessions) >= maxCaptureDeletionSupersessions {
			return coordinatedCaptureDeletionRecord{}, false, errCaptureDeletionSupersedeLimit
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		for _, backend := range record.Job.Backends {
			if backend.UpdatedAt.After(now) {
				now = backend.UpdatedAt
			}
		}
		record.Supersessions = append(record.Supersessions, captureDeletionSupersession{IdempotencyKey: idempotencyKey, Administrator: administrator, Previous: record.Preview, ReplacementPreviewSHA256: preview.PreviewSHA256, SupersededAt: now})
		record.Preview = preview
		record.Job.PreviewSHA256 = preview.PreviewSHA256
		for backendIndex := range record.Job.Backends {
			if record.Job.Backends[backendIndex].State == deletionBackendCompleted {
				continue
			}
			record.Job.Backends[backendIndex] = captureDeletionBackendResult{Backend: record.Job.Backends[backendIndex].Backend, State: deletionBackendNotStarted, UpdatedAt: now}
		}
		record.Job.State, record.Job.Phase, record.Job.ProgressPercent = coordinatedDeletionPending, "SUPERSEDED_AWAITING_BACKENDS", 5
		record.Job.UpdatedAt, record.Job.CompletedAt, record.Job.Failure = now, nil, ""
		if validationErr := record.Preview.validate(); validationErr != nil {
			return coordinatedCaptureDeletionRecord{}, false, validationErr
		}
		if validationErr := record.Job.validate(); validationErr != nil {
			return coordinatedCaptureDeletionRecord{}, false, validationErr
		}
		if validationErr := record.validate(); validationErr != nil {
			return coordinatedCaptureDeletionRecord{}, false, validationErr
		}
		if err := s.writeCoordinatedCaptureDeletionsLocked(ledger); err != nil {
			return coordinatedCaptureDeletionRecord{}, false, err
		}
		return *record, false, nil
	}
	return coordinatedCaptureDeletionRecord{}, false, os.ErrNotExist
}

func (s *Store) finishCoordinatedCaptureDeletionRetry(id, idempotencyKey string) (coordinatedCaptureDeletionRecord, error) {
	return s.updateCoordinatedCaptureDeletion(id, func(candidate *coordinatedCaptureDeletionRecord) error {
		for index := range candidate.Retries {
			if candidate.Retries[index].IdempotencyKey != idempotencyKey {
				continue
			}
			if candidate.Retries[index].CompletedAt != nil {
				return nil
			}
			now := time.Now().UTC().Truncate(time.Microsecond)
			candidate.Retries[index].CompletedAt = &now
			candidate.Retries[index].ResultState = candidate.Job.State
			return nil
		}
		return errors.New("capture deletion retry intent is missing")
	})
}

func (s *Store) listRecoverableCoordinatedCaptureDeletions() ([]coordinatedCaptureDeletionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ledger, err := s.readCoordinatedCaptureDeletionsLocked()
	if err != nil {
		return nil, err
	}
	records := make([]coordinatedCaptureDeletionRecord, 0)
	for _, record := range ledger.Records {
		if record.Job.State == coordinatedDeletionPending || record.Job.State == coordinatedDeletionRunning || hasUnfinishedCaptureDeletionRetry(record.Retries) {
			records = append(records, record)
		}
	}
	return records, nil
}

func (s *Server) executeCoordinatedCaptureDeletion(ctx context.Context, record coordinatedCaptureDeletionRecord) (coordinatedCaptureDeletionJob, error) {
	if record.Job.State == coordinatedDeletionCompleted || record.Job.State == coordinatedDeletionCancelled {
		return record.Job, nil
	}
	if s.captureEventDeletions == nil {
		return coordinatedCaptureDeletionJob{}, errors.New("normalized-event deletion service is not configured")
	}
	if record.Schema == coordinatedCaptureDeletionSchema && (s.zeekCheckpointDeletions == nil || s.suricataCheckpointDeletions == nil) {
		return coordinatedCaptureDeletionJob{}, errors.New("analyzer checkpoint deletion services are not configured")
	}
	var err error
	if record.Job.Backends[0].State != deletionBackendCompleted {
		record, err = s.store.updateCoordinatedCaptureDeletion(record.Job.ID, func(candidate *coordinatedCaptureDeletionRecord) error {
			now := time.Now().UTC().Truncate(time.Microsecond)
			candidate.Job.State, candidate.Job.Phase, candidate.Job.ProgressPercent = coordinatedDeletionRunning, "TOMBSTONES_WRITING", 15
			candidate.Job.UpdatedAt, candidate.Job.CompletedAt, candidate.Job.Failure = now, nil, ""
			candidate.Job.Backends[0] = captureDeletionBackendResult{Backend: "normalized_events", State: deletionBackendRunning, UpdatedAt: now}
			return nil
		})
		if err != nil {
			return coordinatedCaptureDeletionJob{}, err
		}
		outcome, deleteErr := s.captureEventDeletions.Delete(ctx, ingest.CaptureEventDeletionRequest{
			Schema: ingest.CaptureEventDeletionOperationSchema, Preview: record.Preview.NormalizedEvents,
			OperationID: record.Job.ID, Actor: record.Job.Administrator,
		})
		if deleteErr == nil && !validNormalizedEventDeletionAcknowledgement(outcome, record) {
			deleteErr = errors.New("normalized-event deletion service returned inconsistent acknowledgement evidence")
		}
		if deleteErr != nil {
			if ctx.Err() != nil {
				return coordinatedCaptureDeletionJob{}, ctx.Err()
			}
			failed, persistErr := s.failCoordinatedCaptureDeletion(record.Job.ID, 0, "NORMALIZED_EVENTS_FAILED", deleteErr)
			if persistErr != nil {
				return coordinatedCaptureDeletionJob{}, persistErr
			}
			return failed.Job, nil
		}
		record, err = s.store.updateCoordinatedCaptureDeletion(record.Job.ID, func(candidate *coordinatedCaptureDeletionRecord) error {
			now := time.Now().UTC().Truncate(time.Microsecond)
			candidate.Job.State, candidate.Job.Phase, candidate.Job.ProgressPercent = coordinatedDeletionRunning, "INGESTION_BARRIER_SET", 55
			candidate.Job.UpdatedAt = now
			candidate.Job.Backends[0] = captureDeletionBackendResult{Backend: "normalized_events", State: deletionBackendCompleted, UpdatedAt: now, NormalizedEvents: &outcome}
			return nil
		})
		if err != nil {
			return coordinatedCaptureDeletionJob{}, err
		}
	}

	if record.Schema == coordinatedCaptureDeletionSchema {
		analyzerBackends := []struct {
			index    int
			name     string
			phase    string
			failed   string
			preview  *analyzer.CheckpointDeletionPreview
			service  analyzerCheckpointDeletionService
			progress int
		}{
			{1, "zeek_checkpoint", "ZEEK_CHECKPOINT_DELETING", "ZEEK_CHECKPOINT_FAILED", record.Preview.ZeekCheckpoint, s.zeekCheckpointDeletions, 65},
			{2, "suricata_checkpoint", "SURICATA_CHECKPOINT_DELETING", "SURICATA_CHECKPOINT_FAILED", record.Preview.SuricataCheckpoint, s.suricataCheckpointDeletions, 75},
		}
		for _, backend := range analyzerBackends {
			if record.Job.Backends[backend.index].State == deletionBackendCompleted {
				continue
			}
			record, err = s.store.updateCoordinatedCaptureDeletion(record.Job.ID, func(candidate *coordinatedCaptureDeletionRecord) error {
				now := time.Now().UTC().Truncate(time.Microsecond)
				candidate.Job.State, candidate.Job.Phase, candidate.Job.ProgressPercent = coordinatedDeletionRunning, backend.phase, backend.progress
				candidate.Job.UpdatedAt, candidate.Job.CompletedAt, candidate.Job.Failure = now, nil, ""
				candidate.Job.Backends[backend.index] = captureDeletionBackendResult{Backend: backend.name, State: deletionBackendRunning, UpdatedAt: now}
				return nil
			})
			if err != nil {
				return coordinatedCaptureDeletionJob{}, err
			}
			outcome, deleteErr := backend.service.Delete(ctx, analyzer.CheckpointDeletionRequest{
				Schema: analyzer.CheckpointDeletionSchema, OperationID: record.Job.ID, Actor: record.Job.Administrator, Preview: *backend.preview,
			})
			if deleteErr == nil && !validAnalyzerCheckpointDeletionAcknowledgement(outcome, *backend.preview, record) {
				deleteErr = errors.New("analyzer checkpoint deletion service returned inconsistent acknowledgement evidence")
			}
			if deleteErr != nil {
				if ctx.Err() != nil {
					return coordinatedCaptureDeletionJob{}, ctx.Err()
				}
				failed, persistErr := s.failCoordinatedCaptureDeletion(record.Job.ID, backend.index, backend.failed, deleteErr)
				if persistErr != nil {
					return coordinatedCaptureDeletionJob{}, persistErr
				}
				return failed.Job, nil
			}
			record, err = s.store.updateCoordinatedCaptureDeletion(record.Job.ID, func(candidate *coordinatedCaptureDeletionRecord) error {
				now := time.Now().UTC().Truncate(time.Microsecond)
				candidate.Job.State, candidate.Job.Phase, candidate.Job.ProgressPercent = coordinatedDeletionRunning, backend.phase+"_VERIFIED", backend.progress+5
				candidate.Job.UpdatedAt = now
				candidate.Job.Backends[backend.index] = captureDeletionBackendResult{Backend: backend.name, State: deletionBackendCompleted, UpdatedAt: now, AnalyzerCheckpoint: &outcome}
				return nil
			})
			if err != nil {
				return coordinatedCaptureDeletionJob{}, err
			}
		}
	}

	hostBackendIndex := len(record.Job.Backends) - 1
	if record.Job.Backends[hostBackendIndex].State != deletionBackendCompleted {
		record, err = s.store.updateCoordinatedCaptureDeletion(record.Job.ID, func(candidate *coordinatedCaptureDeletionRecord) error {
			now := time.Now().UTC().Truncate(time.Microsecond)
			candidate.Job.State, candidate.Job.Phase, candidate.Job.ProgressPercent = coordinatedDeletionRunning, "PCAP_DELETING", 85
			candidate.Job.UpdatedAt, candidate.Job.CompletedAt, candidate.Job.Failure = now, nil, ""
			candidate.Job.Backends[hostBackendIndex] = captureDeletionBackendResult{Backend: "host_capture_artifacts", State: deletionBackendRunning, UpdatedAt: now}
			return nil
		})
		if err != nil {
			return coordinatedCaptureDeletionJob{}, err
		}
		params := gatewayprotocol.DeleteCaptureParams{Request: capture.DeleteRequest{
			SessionID: record.Job.SessionID, PreviewSHA256: record.Preview.HostArtifacts.PreviewSHA256,
			PreviewExpiresAt: record.Preview.HostArtifacts.ExpiresAt, Confirmation: record.Preview.HostArtifacts.Confirmation,
			Administrator: record.Job.Administrator, IdempotencyKey: record.Job.ID + "-host",
		}}
		var hostJob capture.DeletionJob
		deleteErr := s.gateway.Call(ctx, "DeleteCapture", params, &hostJob)
		if deleteErr == nil && !validHostCaptureDeletionAcknowledgement(hostJob, record) {
			deleteErr = errors.New("host capture deletion returned inconsistent or incomplete acknowledgement evidence")
		}
		if deleteErr != nil {
			if ctx.Err() != nil {
				return coordinatedCaptureDeletionJob{}, ctx.Err()
			}
			failed, persistErr := s.failCoordinatedCaptureDeletion(record.Job.ID, hostBackendIndex, "HOST_CAPTURE_ARTIFACTS_FAILED", deleteErr)
			if persistErr != nil {
				return coordinatedCaptureDeletionJob{}, persistErr
			}
			return failed.Job, nil
		}
		record, err = s.store.updateCoordinatedCaptureDeletion(record.Job.ID, func(candidate *coordinatedCaptureDeletionRecord) error {
			now := time.Now().UTC().Truncate(time.Microsecond)
			candidate.Job.State, candidate.Job.Phase, candidate.Job.ProgressPercent = coordinatedDeletionRunning, "VERIFYING", 95
			candidate.Job.UpdatedAt = now
			candidate.Job.Backends[hostBackendIndex] = captureDeletionBackendResult{Backend: "host_capture_artifacts", State: deletionBackendCompleted, UpdatedAt: now, HostArtifacts: &hostJob}
			return nil
		})
		if err != nil {
			return coordinatedCaptureDeletionJob{}, err
		}
	}

	record, err = s.store.updateCoordinatedCaptureDeletion(record.Job.ID, func(candidate *coordinatedCaptureDeletionRecord) error {
		now := time.Now().UTC().Truncate(time.Microsecond)
		candidate.Job.State, candidate.Job.Phase, candidate.Job.ProgressPercent = coordinatedDeletionCompleted, "COMPLETED", 100
		candidate.Job.UpdatedAt, candidate.Job.CompletedAt, candidate.Job.Failure = now, &now, ""
		return nil
	})
	if err != nil {
		return coordinatedCaptureDeletionJob{}, err
	}
	return record.Job, nil
}

// RunCaptureDeletionRecovery resumes durable capture deletions at startup and
// then periodically, so a job left RUNNING by an interrupted request (client
// disconnect, timeout, backend outage) is carried to a final state without a
// restart.
func (s *Server) RunCaptureDeletionRecovery(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	s.ResumeCaptureDeletions(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.ResumeCaptureDeletions(ctx)
		}
	}
}

// ResumeCaptureDeletions continues durable backend work after a control API restart.
// User-triggered retries are reauthenticated before their intent reaches this path;
// startup recovery only resumes already-authorized, persisted operations.
func (s *Server) ResumeCaptureDeletions(ctx context.Context) {
	records, err := s.store.listRecoverableCoordinatedCaptureDeletions()
	if err != nil {
		s.logger.Error("capture deletion recovery ledger unavailable", "error", err)
		return
	}
	for _, candidate := range records {
		if ctx.Err() != nil {
			return
		}
		s.captureDeletionMu.Lock()
		record, recoveryErr := s.store.getCoordinatedCaptureDeletionRecord(candidate.Job.ID)
		if recoveryErr == nil && (record.Job.State == coordinatedDeletionPending || record.Job.State == coordinatedDeletionRunning) {
			record.Job, recoveryErr = s.executeCoordinatedCaptureDeletion(ctx, record)
		}
		if recoveryErr == nil {
			record, recoveryErr = s.store.getCoordinatedCaptureDeletionRecord(candidate.Job.ID)
		}
		if recoveryErr == nil {
			for _, retry := range record.Retries {
				if retry.CompletedAt != nil {
					continue
				}
				record, recoveryErr = s.store.finishCoordinatedCaptureDeletionRetry(record.Job.ID, retry.IdempotencyKey)
				if recoveryErr != nil {
					break
				}
			}
		}
		s.captureDeletionMu.Unlock()
		if recoveryErr != nil {
			s.logger.Error("capture deletion recovery failed", "job_id", candidate.Job.ID, "error", recoveryErr)
			continue
		}
		s.logger.Info("capture deletion recovery acknowledged", "job_id", record.Job.ID, "state", record.Job.State)
	}
}

func (s *Server) failCoordinatedCaptureDeletion(id string, backendIndex int, phase string, cause error) (coordinatedCaptureDeletionRecord, error) {
	return s.store.updateCoordinatedCaptureDeletion(id, func(candidate *coordinatedCaptureDeletionRecord) error {
		if backendIndex < 0 || backendIndex >= len(candidate.Job.Backends) {
			return errors.New("capture deletion failure backend is invalid")
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		failure := boundedCoordinatorFailure(cause)
		candidate.Job.Backends[backendIndex] = captureDeletionBackendResult{Backend: candidate.Job.Backends[backendIndex].Backend, State: deletionBackendFailed, UpdatedAt: now, Failure: failure}
		candidate.Job.State = coordinatedDeletionFailed
		if hasBackendState(candidate.Job.Backends, deletionBackendCompleted) {
			candidate.Job.State = coordinatedDeletionPartial
		}
		candidate.Job.Phase, candidate.Job.UpdatedAt, candidate.Job.CompletedAt, candidate.Job.Failure = phase, now, &now, failure
		if candidate.Job.ProgressPercent >= 100 {
			candidate.Job.ProgressPercent = 99
		}
		return nil
	})
}

func validHostCaptureDeletionAcknowledgement(job capture.DeletionJob, record coordinatedCaptureDeletionRecord) bool {
	for _, preview := range coordinatedCaptureDeletionRecordPreviews(record) {
		if job.Schema == 1 && hostCaptureDeletionIDPattern.MatchString(job.ID) && job.SessionID == record.Job.SessionID && job.State == capture.DeletionCompleted && job.Phase == "VERIFIED" && job.ProgressPercent == 100 && job.Administrator == record.Job.Administrator && job.PreviewSHA256 == preview.HostArtifacts.PreviewSHA256 && job.Footprint == preview.HostArtifacts.Footprint && job.SharedPCAPCollateralKnown == preview.HostArtifacts.SharedPCAPCollateralKnown && job.CompletedAt != nil && !job.CompletedAt.Before(job.CreatedAt) && job.RemainingFiles == 0 && job.RemainingBytes == 0 {
			return true
		}
	}
	return false
}

func validNormalizedEventDeletionAcknowledgement(outcome ingest.CaptureEventDeletionOutcome, record coordinatedCaptureDeletionRecord) bool {
	for _, combined := range coordinatedCaptureDeletionRecordPreviews(record) {
		preview := combined.NormalizedEvents
		if outcome.Validate() != nil || outcome.CaptureSessionID != record.Job.SessionID || outcome.PreviewSHA256 != preview.PreviewSHA256 || outcome.Tombstone.OperationID != record.Job.ID || outcome.Tombstone.Actor != record.Job.Administrator || outcome.Database.DeletedEventRows != preview.Database.EventRows || outcome.Database.DeletedIdentityRows != preview.Database.ExclusiveIdentityRows || outcome.Database.DeletedEventLogicalBytes != preview.Database.EventLogicalBytes || outcome.Database.DeletedIdentityLogicalBytes != preview.Database.IdentityLogicalBytes {
			continue
		}
		if !preview.Spool.TombstonePresent && !outcome.Spool.Existing && (outcome.Spool.PurgedRecords != preview.Spool.PendingRecords || outcome.Spool.PurgedBytes != preview.Spool.PendingFileBytes) {
			continue
		}
		return true
	}
	return false
}

func validAnalyzerCheckpointDeletionAcknowledgement(outcome analyzer.CheckpointDeletionOutcome, preview analyzer.CheckpointDeletionPreview, record coordinatedCaptureDeletionRecord) bool {
	return outcome.Validate() == nil && outcome.Engine == preview.Engine && outcome.CaptureSessionID == record.Job.SessionID && outcome.OperationID == record.Job.ID && outcome.Actor == record.Job.Administrator && outcome.PreviewSHA256 == preview.PreviewSHA256 && outcome.CheckpointWasPresent == preview.CheckpointPresent && outcome.DeletedCheckpointBytes == preview.CheckpointBytes && outcome.ActiveProgressWasPresent == preview.ActiveProgressPresent && outcome.DeletedActiveProgressBytes == preview.ActiveProgressBytes && outcome.VerifiedAbsent
}

func validStoredAnalyzerCheckpointDeletionAcknowledgement(outcome analyzer.CheckpointDeletionOutcome, engine analyzer.Engine, record coordinatedCaptureDeletionRecord) bool {
	for _, preview := range coordinatedCaptureDeletionRecordPreviews(record) {
		candidate := preview.ZeekCheckpoint
		if engine == analyzer.EngineSuricata {
			candidate = preview.SuricataCheckpoint
		}
		if candidate != nil && validAnalyzerCheckpointDeletionAcknowledgement(outcome, *candidate, record) {
			return true
		}
	}
	return false
}

func coordinatedCaptureDeletionRecordPreviews(record coordinatedCaptureDeletionRecord) []coordinatedCaptureDeletionPreview {
	previews := make([]coordinatedCaptureDeletionPreview, 0, len(record.Supersessions)+1)
	for _, supersession := range record.Supersessions {
		previews = append(previews, supersession.Previous)
	}
	return append(previews, record.Preview)
}

func (s *Store) readCoordinatedCaptureDeletionsLocked() (coordinatedCaptureDeletionLedger, error) {
	path := filepath.Join(s.dataDir, "capture-deletion-operations.json")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return coordinatedCaptureDeletionLedger{Schema: coordinatedCaptureDeletionLedgerSchema, Records: []coordinatedCaptureDeletionRecord{}}, nil
	}
	if err != nil {
		return coordinatedCaptureDeletionLedger{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxCaptureDeletionLedgerBytes {
		return coordinatedCaptureDeletionLedger{}, errors.New("capture deletion operation ledger is not a bounded regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return coordinatedCaptureDeletionLedger{}, err
	}
	var ledger coordinatedCaptureDeletionLedger
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&ledger) != nil || ledger.Schema != coordinatedCaptureDeletionLedgerSchema || len(ledger.Records) > maxCoordinatedCaptureDeletions {
		return coordinatedCaptureDeletionLedger{}, errors.New("capture deletion operation ledger is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return coordinatedCaptureDeletionLedger{}, errors.New("capture deletion operation ledger has trailing data")
	}
	if err := validateCoordinatedCaptureDeletionLedger(ledger); err != nil {
		return coordinatedCaptureDeletionLedger{}, err
	}
	return ledger, nil
}

func (s *Store) writeCoordinatedCaptureDeletionsLocked(ledger coordinatedCaptureDeletionLedger) error {
	if err := validateCoordinatedCaptureDeletionLedger(ledger); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil || len(encoded)+1 > maxCaptureDeletionLedgerBytes {
		return errors.New("capture deletion operation ledger is oversized or invalid")
	}
	if err := os.MkdirAll(s.dataDir, 0o750); err != nil {
		return err
	}
	path := filepath.Join(s.dataDir, "capture-deletion-operations.json")
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return errors.New("capture deletion operation ledger is not a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return atomicWrite(path, append(encoded, '\n'), 0o600)
}

func validateCoordinatedCaptureDeletionLedger(ledger coordinatedCaptureDeletionLedger) error {
	if ledger.Schema != coordinatedCaptureDeletionLedgerSchema || len(ledger.Records) > maxCoordinatedCaptureDeletions {
		return errors.New("capture deletion operation ledger is invalid")
	}
	seenIDs := make(map[string]struct{}, len(ledger.Records))
	seenKeys := make(map[string]struct{}, len(ledger.Records))
	for _, record := range ledger.Records {
		if record.validate() != nil {
			return errors.New("capture deletion operation ledger contains an invalid record")
		}
		if _, exists := seenIDs[record.Job.ID]; exists {
			return errors.New("capture deletion operation ledger contains duplicate operation IDs")
		}
		if _, exists := seenKeys[record.IdempotencyKey]; exists {
			return errors.New("capture deletion operation ledger contains duplicate idempotency keys")
		}
		seenIDs[record.Job.ID] = struct{}{}
		seenKeys[record.IdempotencyKey] = struct{}{}
		for _, retry := range record.Retries {
			if _, exists := seenKeys[retry.IdempotencyKey]; exists {
				return errors.New("capture deletion operation ledger contains duplicate retry idempotency keys")
			}
			seenKeys[retry.IdempotencyKey] = struct{}{}
		}
		for _, supersession := range record.Supersessions {
			if _, exists := seenKeys[supersession.IdempotencyKey]; exists {
				return errors.New("capture deletion operation ledger contains duplicate supersession idempotency keys")
			}
			seenKeys[supersession.IdempotencyKey] = struct{}{}
		}
		if record.CancelKey != "" {
			if _, exists := seenKeys[record.CancelKey]; exists {
				return errors.New("capture deletion operation ledger contains duplicate cancellation idempotency keys")
			}
			seenKeys[record.CancelKey] = struct{}{}
		}
	}
	return nil
}

func (r coordinatedCaptureDeletionRecord) validate() error {
	previews := coordinatedCaptureDeletionRecordPreviews(r)
	originalPreview := previews[0]
	expectedRequestSHA, requestErr := coordinatedCaptureDeletionRequestSHA(originalPreview, r.Job.Administrator, r.IdempotencyKey)
	if r.Schema != legacyCoordinatedCaptureDeletionSchema && r.Schema != coordinatedCaptureDeletionSchema || r.Preview.Schema != r.Schema || r.Job.Schema != r.Schema || r.Preview.validate() != nil || !validCoordinatorOpaqueKey(r.IdempotencyKey) || requestErr != nil || r.RequestSHA256 != expectedRequestSHA || r.Job.validate() != nil || r.Job.SessionID != r.Preview.SessionID || r.Job.PreviewSHA256 != r.Preview.PreviewSHA256 || !equalStringSlices(r.Job.RetainedDataClasses, r.Preview.RetainedDataClasses) || len(r.Retries) > maxCaptureDeletionRetries || len(r.Supersessions) > maxCaptureDeletionSupersessions {
		return errors.New("coordinated capture deletion record is invalid")
	}
	for index, supersession := range r.Supersessions {
		replacement := r.Preview
		if index+1 < len(r.Supersessions) {
			replacement = r.Supersessions[index+1].Previous
		}
		if r.Schema != coordinatedCaptureDeletionSchema || supersession.Previous.validate() != nil || supersession.Previous.SessionID != r.Job.SessionID || replacement.PreviewSHA256 != supersession.ReplacementPreviewSHA256 || !replacement.GeneratedAt.After(supersession.Previous.GeneratedAt) || !validCoordinatorOpaqueKey(supersession.IdempotencyKey) || supersession.Administrator != r.Job.Administrator || !validSHA256(supersession.ReplacementPreviewSHA256) || supersession.SupersededAt.Before(r.Job.CreatedAt) || index > 0 && (supersession.Previous.PreviewSHA256 != r.Supersessions[index-1].ReplacementPreviewSHA256 || supersession.SupersededAt.Before(r.Supersessions[index-1].SupersededAt)) {
			return errors.New("coordinated capture deletion supersession record is invalid")
		}
	}
	for index, backend := range r.Job.Backends {
		if backend.State != deletionBackendCompleted {
			continue
		}
		switch backend.Backend {
		case "normalized_events":
			if index != 0 || !validNormalizedEventDeletionAcknowledgement(*backend.NormalizedEvents, r) {
				return errors.New("stored normalized-event deletion acknowledgement does not match its operation")
			}
		case "zeek_checkpoint":
			if r.Schema != coordinatedCaptureDeletionSchema || index != 1 || !validStoredAnalyzerCheckpointDeletionAcknowledgement(*backend.AnalyzerCheckpoint, analyzer.EngineZeek, r) {
				return errors.New("stored Zeek checkpoint deletion acknowledgement does not match its operation")
			}
		case "suricata_checkpoint":
			if r.Schema != coordinatedCaptureDeletionSchema || index != 2 || !validStoredAnalyzerCheckpointDeletionAcknowledgement(*backend.AnalyzerCheckpoint, analyzer.EngineSuricata, r) {
				return errors.New("stored Suricata checkpoint deletion acknowledgement does not match its operation")
			}
		case "host_capture_artifacts":
			if index != len(r.Job.Backends)-1 || !validHostCaptureDeletionAcknowledgement(*backend.HostArtifacts, r) {
				return errors.New("stored host capture deletion acknowledgement does not match its operation")
			}
		}
	}
	seenRetries := make(map[string]struct{}, len(r.Retries)+len(r.Supersessions))
	for _, retry := range r.Retries {
		if !validCoordinatorOpaqueKey(retry.IdempotencyKey) || retry.IdempotencyKey == r.IdempotencyKey || !validCoordinatorText(retry.Administrator, 1, 96) || retry.Administrator != r.Job.Administrator || retry.StartedAt.Before(r.Job.CreatedAt) {
			return errors.New("coordinated capture deletion retry record is invalid")
		}
		if _, exists := seenRetries[retry.IdempotencyKey]; exists {
			return errors.New("coordinated capture deletion retry key is duplicated")
		}
		seenRetries[retry.IdempotencyKey] = struct{}{}
		if retry.CompletedAt == nil {
			if retry.ResultState != "" {
				return errors.New("unfinished capture deletion retry contains a result")
			}
		} else if retry.CompletedAt.Before(retry.StartedAt) || retry.ResultState != coordinatedDeletionCompleted && retry.ResultState != coordinatedDeletionPartial && retry.ResultState != coordinatedDeletionFailed {
			return errors.New("completed capture deletion retry result is invalid")
		}
	}
	for _, supersession := range r.Supersessions {
		if _, exists := seenRetries[supersession.IdempotencyKey]; exists || supersession.IdempotencyKey == r.IdempotencyKey || supersession.IdempotencyKey == r.CancelKey {
			return errors.New("coordinated capture deletion supersession key is duplicated")
		}
		seenRetries[supersession.IdempotencyKey] = struct{}{}
	}
	if r.Job.State == coordinatedDeletionCancelled {
		if !validCoordinatorOpaqueKey(r.CancelKey) || r.CancelledBy != r.Job.Administrator {
			return errors.New("cancelled capture deletion lacks cancellation evidence")
		}
	} else if r.CancelKey != "" || r.CancelledBy != "" {
		return errors.New("active capture deletion contains cancellation evidence")
	}
	return nil
}

func (j coordinatedCaptureDeletionJob) validate() error {
	if j.Schema != legacyCoordinatedCaptureDeletionSchema && j.Schema != coordinatedCaptureDeletionSchema || !coordinatedCaptureDeletionIDPattern.MatchString(j.ID) || !capture.ValidSessionID(j.SessionID) || !validCoordinatorText(j.Administrator, 1, 96) || !validSHA256(j.PreviewSHA256) || !validCoordinatorText(j.Phase, 1, 64) || j.ProgressPercent < 0 || j.ProgressPercent > 100 || j.CreatedAt.IsZero() || j.UpdatedAt.Before(j.CreatedAt) || j.Failure != "" && !validCoordinatorText(j.Failure, 1, 512) {
		return errors.New("coordinated capture deletion job is invalid")
	}
	expectedBackends := []string{"normalized_events", "host_capture_artifacts"}
	expectedRetained := legacyCoordinatedCaptureRetainedDataClasses
	if j.Schema == coordinatedCaptureDeletionSchema {
		expectedBackends = []string{"normalized_events", "zeek_checkpoint", "suricata_checkpoint", "host_capture_artifacts"}
		expectedRetained = coordinatedCaptureRetainedDataClasses
	}
	if len(j.Backends) != len(expectedBackends) || !equalStringSlices(j.RetainedDataClasses, expectedRetained) {
		return errors.New("coordinated capture deletion backends are invalid")
	}
	for index, backend := range j.Backends {
		if backend.Backend != expectedBackends[index] {
			return errors.New("coordinated capture deletion backend order is invalid")
		}
		backendErr := backend.validate()
		if backend.UpdatedAt.Before(j.CreatedAt) || backend.UpdatedAt.After(j.UpdatedAt) || backend.Failure != "" && !validCoordinatorText(backend.Failure, 1, 512) || backendErr != nil {
			if backendErr != nil {
				return errors.New("coordinated capture deletion backend result is invalid: " + backend.Backend + ": " + backendErr.Error())
			}
			return errors.New("coordinated capture deletion backend result timestamp is invalid: " + backend.Backend)
		}
	}
	switch j.State {
	case coordinatedDeletionPending, coordinatedDeletionRunning:
		if j.CompletedAt != nil || j.ProgressPercent == 100 {
			return errors.New("unfinished coordinated capture deletion has completion evidence")
		}
	case coordinatedDeletionCompleted:
		if j.CompletedAt == nil || j.CompletedAt.Before(j.CreatedAt) || j.ProgressPercent != 100 || !allBackendsState(j.Backends, deletionBackendCompleted) {
			return errors.New("completed coordinated capture deletion lacks backend acknowledgements")
		}
	case coordinatedDeletionPartial:
		if j.CompletedAt == nil || j.CompletedAt.Before(j.CreatedAt) || !hasBackendState(j.Backends, deletionBackendCompleted) || !hasBackendState(j.Backends, deletionBackendFailed) {
			return errors.New("partial coordinated capture deletion lacks mixed backend outcomes")
		}
	case coordinatedDeletionFailed:
		if j.CompletedAt == nil || j.CompletedAt.Before(j.CreatedAt) || !hasBackendState(j.Backends, deletionBackendFailed) || hasBackendState(j.Backends, deletionBackendCompleted) {
			return errors.New("failed coordinated capture deletion has inconsistent backend outcomes")
		}
	case coordinatedDeletionCancelled:
		if j.Phase != "CANCELLED_BEFORE_BARRIER" || j.CompletedAt == nil || j.CompletedAt.Before(j.CreatedAt) || j.ProgressPercent != 0 || j.Failure != "" || !allBackendsState(j.Backends, deletionBackendNotStarted) {
			return errors.New("cancelled coordinated capture deletion crossed a backend barrier")
		}
	default:
		return errors.New("coordinated capture deletion state is invalid")
	}
	return nil
}

func (r captureDeletionBackendResult) validate() error {
	switch r.State {
	case deletionBackendNotStarted, deletionBackendRunning:
		if r.Failure != "" || r.HostArtifacts != nil || r.NormalizedEvents != nil || r.AnalyzerCheckpoint != nil {
			return errors.New("unfinished backend contains terminal evidence")
		}
	case deletionBackendFailed:
		if r.Failure == "" || r.HostArtifacts != nil || r.NormalizedEvents != nil || r.AnalyzerCheckpoint != nil {
			return errors.New("failed backend lacks bounded failure evidence")
		}
	case deletionBackendCompleted:
		if r.Failure != "" {
			return errors.New("completed backend contains a failure")
		}
		if r.Backend == "normalized_events" {
			if r.NormalizedEvents == nil || r.NormalizedEvents.Validate() != nil || r.HostArtifacts != nil || r.AnalyzerCheckpoint != nil {
				return errors.New("normalized-event backend lacks a valid acknowledgement")
			}
		} else if r.Backend == "zeek_checkpoint" || r.Backend == "suricata_checkpoint" {
			if r.AnalyzerCheckpoint == nil || r.AnalyzerCheckpoint.Validate() != nil || r.HostArtifacts != nil || r.NormalizedEvents != nil {
				return errors.New("analyzer-checkpoint backend lacks a valid acknowledgement")
			}
		} else if r.Backend == "host_capture_artifacts" {
			if r.HostArtifacts == nil || r.HostArtifacts.State != capture.DeletionCompleted || r.HostArtifacts.CompletedAt == nil || r.NormalizedEvents != nil || r.AnalyzerCheckpoint != nil {
				return errors.New("host-artifact backend lacks a valid acknowledgement")
			}
		} else {
			return errors.New("capture deletion backend name is invalid")
		}
	default:
		return errors.New("capture deletion backend state is invalid")
	}
	return nil
}

func newCoordinatedCaptureDeletionID(records []coordinatedCaptureDeletionRecord) (string, error) {
	existing := make(map[string]struct{}, len(records))
	for _, record := range records {
		existing[record.Job.ID] = struct{}{}
	}
	for attempts := 0; attempts < 8; attempts++ {
		value := make([]byte, 16)
		if _, err := rand.Read(value); err != nil {
			return "", err
		}
		id := "capture-delete-operation-" + hex.EncodeToString(value)
		if _, exists := existing[id]; !exists {
			return id, nil
		}
	}
	return "", errors.New("could not allocate a unique capture deletion operation ID")
}

func coordinatorHashJSON(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func validCoordinatorOpaqueKey(value string) bool {
	if len(value) < 16 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

func validCoordinatorText(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum || value != strings.TrimSpace(value) || !utf8.ValidString(value) {
		return false
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func equalStringSlices(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func hasBackendState(backends []captureDeletionBackendResult, state captureDeletionBackendState) bool {
	for _, backend := range backends {
		if backend.State == state {
			return true
		}
	}
	return false
}

func allBackendsState(backends []captureDeletionBackendResult, state captureDeletionBackendState) bool {
	if len(backends) == 0 {
		return false
	}
	for _, backend := range backends {
		if backend.State != state {
			return false
		}
	}
	return true
}

func hasUnfinishedCaptureDeletionRetry(retries []captureDeletionRetryRecord) bool {
	for _, retry := range retries {
		if retry.CompletedAt == nil {
			return true
		}
	}
	return false
}

func boundedCoordinatorFailure(err error) string {
	if err == nil {
		return ""
	}
	message := strings.TrimSpace(err.Error())
	message = strings.ToValidUTF8(message, "?")
	message = strings.Map(func(char rune) rune {
		if char < 0x20 || char == 0x7f {
			return ' '
		}
		return char
	}, message)
	message = strings.TrimSpace(message)
	if len(message) > 512 {
		message = message[:512]
		for !utf8.ValidString(message) {
			message = message[:len(message)-1]
		}
		message = strings.TrimSpace(message)
	}
	if message == "" {
		return "unspecified failure"
	}
	return message
}
