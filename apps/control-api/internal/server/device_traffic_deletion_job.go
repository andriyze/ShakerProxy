package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/analyzer"
	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/ingest"
	deviceinventory "shakerproxy.dev/shakerproxy/internal/inventory"
)

const (
	deviceTrafficDeletionJobSchema      = 1
	maxDeviceTrafficDeletionJobs        = 1024
	maxDeviceTrafficDeletionRetries     = 32
	maxDeviceTrafficDeletionLedgerBytes = 32 << 20
)

type deviceTrafficDeletionJobState string

const (
	deviceTrafficDeletionPending   deviceTrafficDeletionJobState = "PENDING"
	deviceTrafficDeletionRunning   deviceTrafficDeletionJobState = "RUNNING"
	deviceTrafficDeletionCompleted deviceTrafficDeletionJobState = "COMPLETED"
	deviceTrafficDeletionPartial   deviceTrafficDeletionJobState = "PARTIAL"
	deviceTrafficDeletionCancelled deviceTrafficDeletionJobState = "CANCELLED"
)

type deviceTrafficDeletionRetry struct {
	IdempotencyKey string                        `json:"idempotency_key"`
	Administrator  string                        `json:"administrator"`
	StartedAt      time.Time                     `json:"started_at"`
	CompletedAt    *time.Time                    `json:"completed_at,omitempty"`
	ResultState    deviceTrafficDeletionJobState `json:"result_state,omitempty"`
}

type deviceTrafficDeletionJob struct {
	Schema              int                                   `json:"schema"`
	ID                  string                                `json:"id"`
	DeviceID            string                                `json:"device_id"`
	Choice              capture.SharedPCAPDisposition         `json:"choice"`
	State               deviceTrafficDeletionJobState         `json:"state"`
	Phase               string                                `json:"phase"`
	ProgressPercent     int                                   `json:"progress_percent"`
	Administrator       string                                `json:"administrator"`
	PreviewSHA256       string                                `json:"preview_sha256"`
	DeletedDataClasses  []string                              `json:"deleted_data_classes"`
	RetainedDataClasses []string                              `json:"retained_data_classes"`
	NormalizedEvents    *ingest.EventSelectionDeletionOutcome `json:"normalized_events,omitempty"`
	CaptureEvents       []ingest.CaptureEventDeletionOutcome  `json:"capture_events,omitempty"`
	AnalyzerCheckpoints []deviceTrafficAnalyzerCheckpoint     `json:"analyzer_checkpoints,omitempty"`
	PCAPRewrites        []capture.PCAPRewriteRecord           `json:"pcap_rewrites,omitempty"`
	PCAPDeletions       []capture.PCAPArtifactDeletionRecord  `json:"pcap_deletions,omitempty"`
	AnalyzerReindexes   []analyzer.CheckpointReindexOutcome   `json:"analyzer_reindexes,omitempty"`
	Failure             string                                `json:"failure,omitempty"`
	CreatedAt           time.Time                             `json:"created_at"`
	UpdatedAt           time.Time                             `json:"updated_at"`
	CompletedAt         *time.Time                            `json:"completed_at,omitempty"`
}

type deviceTrafficAnalyzerCheckpoint struct {
	SessionID string                             `json:"session_id"`
	Engine    analyzer.Engine                    `json:"engine"`
	Outcome   analyzer.CheckpointDeletionOutcome `json:"outcome"`
}

type deviceTrafficDeletionRecord struct {
	Schema         int                          `json:"schema"`
	Job            deviceTrafficDeletionJob     `json:"job"`
	Preview        deviceTrafficDeletionPreview `json:"preview"`
	IdempotencyKey string                       `json:"idempotency_key"`
	RequestSHA256  string                       `json:"request_sha256"`
	Retries        []deviceTrafficDeletionRetry `json:"retries"`
	CancelKey      string                       `json:"cancel_key,omitempty"`
	CancelledBy    string                       `json:"cancelled_by,omitempty"`
}

type deviceTrafficDeletionLedger struct {
	Schema  int                           `json:"schema"`
	Records []deviceTrafficDeletionRecord `json:"records"`
}

type createDeviceTrafficDeletionRequest struct {
	Password     string                        `json:"password"`
	Preview      deviceTrafficDeletionPreview  `json:"preview"`
	Choice       capture.SharedPCAPDisposition `json:"choice"`
	Confirmation string                        `json:"confirmation"`
}

type deviceTrafficDeletionActionRequest struct {
	Password string `json:"password"`
}

var deviceTrafficDeletionJobIDPattern = regexp.MustCompile(`^device-traffic-delete-[a-f0-9]{32}$`)

var (
	errDeviceTrafficDeletionInvalid  = errors.New("device traffic deletion request is invalid")
	errDeviceTrafficDeletionConflict = errors.New("device traffic deletion idempotency key conflicts with existing evidence")
	errDeviceTrafficDeletionExpired  = errors.New("device traffic deletion preview has expired")
	errDeviceTrafficDeletionRetry    = errors.New("device traffic deletion retry is invalid")
	errDeviceTrafficDeletionCancel   = errors.New("device traffic deletion can no longer be cancelled safely")
)

var deviceTrafficMetadataDeletedClasses = []string{
	"normalized_event_metadata",
	"normalized_event_exclusive_identities",
	"pending_ingest_spool_records",
}

var deviceTrafficMetadataRetainedClasses = []string{
	"raw_pcap_packet_bytes",
	"analyzer_raw_logs",
	"analyzer_checkpoints",
	"body_artifacts_and_tls_key_logs",
	"search_indexes_not_configured",
	"existing_exports",
	"existing_backups",
}

var deviceTrafficDerivedDeletedClasses = []string{
	"normalized_event_metadata",
	"normalized_event_exclusive_identities",
	"pending_ingest_spool_records",
	"affected_analyzer_checkpoints",
	"affected_analyzer_replay_generations",
}

var deviceTrafficDerivedRetainedClasses = []string{
	"raw_pcap_packet_bytes",
	"normalized_events_outside_selection",
	"body_and_tls_key_log_stores_not_configured",
	"external_search_indexes_not_configured",
	"existing_exports",
	"existing_backups",
}

var deviceTrafficSanitizeDeletedClasses = []string{
	"normalized_event_metadata",
	"normalized_event_exclusive_identities",
	"pending_ingest_spool_records",
	"selected_raw_pcap_packets",
	"stale_analyzer_checkpoints",
}

var deviceTrafficSanitizeRetainedClasses = []string{
	"unmatched_raw_pcap_packets",
	"rebuilt_analyzer_metadata_for_retained_packets",
	"body_and_tls_key_log_stores_not_configured",
	"external_search_indexes_not_configured",
	"existing_exports",
	"existing_backups",
}

var deviceTrafficWholeFileDeletedClasses = []string{
	"affected_capture_session_normalized_events",
	"affected_capture_session_exclusive_identities",
	"affected_capture_session_pending_spool_records",
	"selected_whole_pcap_files",
	"affected_capture_session_analyzer_checkpoints",
}

var deviceTrafficWholeFileRetainedClasses = []string{
	"unselected_pcap_files_without_searchable_metadata",
	"body_and_tls_key_log_stores_not_configured",
	"external_search_indexes_not_configured",
	"existing_exports",
	"existing_backups",
}

func deviceTrafficDeletionClasses(choice capture.SharedPCAPDisposition) ([]string, []string, bool) {
	switch choice {
	case capture.DeleteMetadataOnly:
		return deviceTrafficMetadataDeletedClasses, deviceTrafficMetadataRetainedClasses, true
	case capture.DeleteDerivedContentOnly:
		return deviceTrafficDerivedDeletedClasses, deviceTrafficDerivedRetainedClasses, true
	case capture.SanitizeAndRewritePCAP:
		return deviceTrafficSanitizeDeletedClasses, deviceTrafficSanitizeRetainedClasses, true
	case capture.DeleteWholeCaptureFiles:
		return deviceTrafficWholeFileDeletedClasses, deviceTrafficWholeFileRetainedClasses, true
	default:
		return nil, nil, false
	}
}

func (s *Store) beginDeviceTrafficDeletion(preview deviceTrafficDeletionPreview, choice capture.SharedPCAPDisposition, administrator, idempotencyKey string) (deviceTrafficDeletionRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	deletedClasses, retainedClasses, supportedChoice := deviceTrafficDeletionClasses(choice)
	if preview.validate() != nil || !supportedChoice || !deviceTrafficChoiceExecutable(preview, choice) || !validCoordinatorText(administrator, 1, 96) || preview.NormalizedEventDeletion.Actor != administrator || !validCoordinatorOpaqueKey(idempotencyKey) {
		return deviceTrafficDeletionRecord{}, false, errDeviceTrafficDeletionInvalid
	}
	requestSHA, err := deviceTrafficDeletionRequestSHA(preview, choice, administrator, idempotencyKey)
	if err != nil {
		return deviceTrafficDeletionRecord{}, false, err
	}
	ledger, err := s.readDeviceTrafficDeletionsLocked()
	if err != nil {
		return deviceTrafficDeletionRecord{}, false, err
	}
	for _, record := range ledger.Records {
		if record.IdempotencyKey == idempotencyKey {
			if record.RequestSHA256 != requestSHA {
				return deviceTrafficDeletionRecord{}, false, errDeviceTrafficDeletionConflict
			}
			return record, true, nil
		}
		if record.CancelKey == idempotencyKey {
			return deviceTrafficDeletionRecord{}, false, errDeviceTrafficDeletionConflict
		}
		for _, retry := range record.Retries {
			if retry.IdempotencyKey == idempotencyKey {
				return deviceTrafficDeletionRecord{}, false, errDeviceTrafficDeletionConflict
			}
		}
	}
	if err := pruneDeviceTrafficDeletionsLocked(&ledger, time.Now().UTC()); err != nil {
		return deviceTrafficDeletionRecord{}, false, err
	}
	if !preview.ExpiresAt.After(time.Now().UTC()) {
		return deviceTrafficDeletionRecord{}, false, errDeviceTrafficDeletionExpired
	}
	id := newDeviceTrafficDeletionJobID(requestSHA, ledger.Records)
	now := time.Now().UTC().Truncate(time.Microsecond)
	record := deviceTrafficDeletionRecord{
		Schema: deviceTrafficDeletionJobSchema, Preview: preview, IdempotencyKey: idempotencyKey, RequestSHA256: requestSHA, Retries: []deviceTrafficDeletionRetry{},
		Job: deviceTrafficDeletionJob{
			Schema: deviceTrafficDeletionJobSchema, ID: id, DeviceID: preview.DeviceID, Choice: choice,
			State: deviceTrafficDeletionPending, Phase: "AWAITING_EXECUTION", ProgressPercent: 5,
			Administrator: administrator, PreviewSHA256: preview.PreviewSHA256,
			DeletedDataClasses: append([]string(nil), deletedClasses...), RetainedDataClasses: append([]string(nil), retainedClasses...),
			CaptureEvents: []ingest.CaptureEventDeletionOutcome{}, AnalyzerCheckpoints: []deviceTrafficAnalyzerCheckpoint{},
			PCAPRewrites: []capture.PCAPRewriteRecord{}, PCAPDeletions: []capture.PCAPArtifactDeletionRecord{}, AnalyzerReindexes: []analyzer.CheckpointReindexOutcome{},
			CreatedAt: now, UpdatedAt: now,
		},
	}
	if record.validate() != nil {
		return deviceTrafficDeletionRecord{}, false, errDeviceTrafficDeletionInvalid
	}
	ledger.Records = append(ledger.Records, record)
	if err := s.writeDeviceTrafficDeletionsLocked(ledger); err != nil {
		return deviceTrafficDeletionRecord{}, false, err
	}
	return record, false, nil
}

func deviceTrafficDeletionRequestSHA(preview deviceTrafficDeletionPreview, choice capture.SharedPCAPDisposition, administrator, idempotencyKey string) (string, error) {
	return coordinatorHashJSON(struct {
		DeviceID       string                        `json:"device_id"`
		Choice         capture.SharedPCAPDisposition `json:"choice"`
		PreviewSHA256  string                        `json:"preview_sha256"`
		Administrator  string                        `json:"administrator"`
		IdempotencyKey string                        `json:"idempotency_key"`
	}{preview.DeviceID, choice, preview.PreviewSHA256, administrator, idempotencyKey})
}

func (s *Store) updateDeviceTrafficDeletion(id string, update func(*deviceTrafficDeletionRecord) error) (deviceTrafficDeletionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !deviceTrafficDeletionJobIDPattern.MatchString(id) || update == nil {
		return deviceTrafficDeletionRecord{}, errDeviceTrafficDeletionInvalid
	}
	ledger, err := s.readDeviceTrafficDeletionsLocked()
	if err != nil {
		return deviceTrafficDeletionRecord{}, err
	}
	for index := range ledger.Records {
		if ledger.Records[index].Job.ID != id {
			continue
		}
		original := ledger.Records[index]
		if err := update(&ledger.Records[index]); err != nil {
			return deviceTrafficDeletionRecord{}, err
		}
		updated := ledger.Records[index]
		if updated.Schema != original.Schema || updated.Preview.PreviewSHA256 != original.Preview.PreviewSHA256 || updated.IdempotencyKey != original.IdempotencyKey || updated.RequestSHA256 != original.RequestSHA256 || updated.Job.ID != original.Job.ID || updated.Job.DeviceID != original.Job.DeviceID || updated.Job.Choice != original.Job.Choice || updated.Job.Administrator != original.Job.Administrator || updated.Job.PreviewSHA256 != original.Job.PreviewSHA256 || !updated.Job.CreatedAt.Equal(original.Job.CreatedAt) || updated.validate() != nil {
			return deviceTrafficDeletionRecord{}, errors.New("device traffic deletion update changed immutable evidence")
		}
		if err := s.writeDeviceTrafficDeletionsLocked(ledger); err != nil {
			return deviceTrafficDeletionRecord{}, err
		}
		return updated, nil
	}
	return deviceTrafficDeletionRecord{}, os.ErrNotExist
}

func (s *Store) beginDeviceTrafficDeletionRetry(id, idempotencyKey, administrator string) (deviceTrafficDeletionRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !deviceTrafficDeletionJobIDPattern.MatchString(id) || !validCoordinatorOpaqueKey(idempotencyKey) || !validCoordinatorText(administrator, 1, 96) {
		return deviceTrafficDeletionRecord{}, false, errDeviceTrafficDeletionRetry
	}
	ledger, err := s.readDeviceTrafficDeletionsLocked()
	if err != nil {
		return deviceTrafficDeletionRecord{}, false, err
	}
	for recordIndex := range ledger.Records {
		record := &ledger.Records[recordIndex]
		if record.IdempotencyKey == idempotencyKey || record.CancelKey == idempotencyKey {
			return deviceTrafficDeletionRecord{}, false, errDeviceTrafficDeletionConflict
		}
		for _, retry := range record.Retries {
			if retry.IdempotencyKey != idempotencyKey {
				continue
			}
			if record.Job.ID != id || retry.Administrator != administrator {
				return deviceTrafficDeletionRecord{}, false, errDeviceTrafficDeletionConflict
			}
			return *record, true, nil
		}
		if record.Job.ID != id {
			continue
		}
		if record.Job.State != deviceTrafficDeletionPartial || len(record.Retries) >= maxDeviceTrafficDeletionRetries {
			return deviceTrafficDeletionRecord{}, false, errDeviceTrafficDeletionRetry
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		record.Retries = append(record.Retries, deviceTrafficDeletionRetry{IdempotencyKey: idempotencyKey, Administrator: administrator, StartedAt: now})
		record.Job.State, record.Job.Phase, record.Job.ProgressPercent = deviceTrafficDeletionPending, "RETRY_REQUESTED", 10
		record.Job.UpdatedAt, record.Job.CompletedAt, record.Job.Failure = now, nil, ""
		if record.validate() != nil {
			return deviceTrafficDeletionRecord{}, false, errDeviceTrafficDeletionRetry
		}
		if err := s.writeDeviceTrafficDeletionsLocked(ledger); err != nil {
			return deviceTrafficDeletionRecord{}, false, err
		}
		return *record, false, nil
	}
	return deviceTrafficDeletionRecord{}, false, os.ErrNotExist
}

func (s *Store) finishDeviceTrafficDeletionRetry(id, key string) (deviceTrafficDeletionRecord, error) {
	return s.updateDeviceTrafficDeletion(id, func(record *deviceTrafficDeletionRecord) error {
		for index := range record.Retries {
			if record.Retries[index].IdempotencyKey != key {
				continue
			}
			if record.Retries[index].CompletedAt != nil {
				return nil
			}
			now := time.Now().UTC().Truncate(time.Microsecond)
			record.Retries[index].CompletedAt = &now
			record.Retries[index].ResultState = record.Job.State
			return nil
		}
		return errDeviceTrafficDeletionRetry
	})
}

func (s *Store) cancelDeviceTrafficDeletion(id, key, administrator string) (deviceTrafficDeletionRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !deviceTrafficDeletionJobIDPattern.MatchString(id) || !validCoordinatorOpaqueKey(key) || !validCoordinatorText(administrator, 1, 96) {
		return deviceTrafficDeletionRecord{}, false, errDeviceTrafficDeletionCancel
	}
	ledger, err := s.readDeviceTrafficDeletionsLocked()
	if err != nil {
		return deviceTrafficDeletionRecord{}, false, err
	}
	for index := range ledger.Records {
		record := &ledger.Records[index]
		if record.CancelKey == key {
			if record.Job.ID != id || record.CancelledBy != administrator {
				return deviceTrafficDeletionRecord{}, false, errDeviceTrafficDeletionConflict
			}
			return *record, true, nil
		}
		if record.IdempotencyKey == key {
			return deviceTrafficDeletionRecord{}, false, errDeviceTrafficDeletionConflict
		}
		for _, retry := range record.Retries {
			if retry.IdempotencyKey == key {
				return deviceTrafficDeletionRecord{}, false, errDeviceTrafficDeletionConflict
			}
		}
		if record.Job.ID != id {
			continue
		}
		if record.Job.State != deviceTrafficDeletionPending || record.Job.Phase != "AWAITING_EXECUTION" {
			return deviceTrafficDeletionRecord{}, false, errDeviceTrafficDeletionCancel
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		record.CancelKey, record.CancelledBy = key, administrator
		record.Job.State, record.Job.Phase, record.Job.ProgressPercent = deviceTrafficDeletionCancelled, "CANCELLED_BEFORE_BARRIER", 0
		record.Job.UpdatedAt, record.Job.CompletedAt = now, &now
		if record.validate() != nil {
			return deviceTrafficDeletionRecord{}, false, errDeviceTrafficDeletionCancel
		}
		if err := s.writeDeviceTrafficDeletionsLocked(ledger); err != nil {
			return deviceTrafficDeletionRecord{}, false, err
		}
		return *record, false, nil
	}
	return deviceTrafficDeletionRecord{}, false, os.ErrNotExist
}

func (s *Store) listDeviceTrafficDeletionJobs() ([]deviceTrafficDeletionJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ledger, err := s.readDeviceTrafficDeletionsLocked()
	if err != nil {
		return nil, err
	}
	jobs := make([]deviceTrafficDeletionJob, 0, len(ledger.Records))
	for _, record := range ledger.Records {
		jobs = append(jobs, record.Job)
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].CreatedAt.After(jobs[j].CreatedAt) })
	return jobs, nil
}

func (s *Store) getDeviceTrafficDeletionRecord(id string) (deviceTrafficDeletionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !deviceTrafficDeletionJobIDPattern.MatchString(id) {
		return deviceTrafficDeletionRecord{}, errDeviceTrafficDeletionInvalid
	}
	ledger, err := s.readDeviceTrafficDeletionsLocked()
	if err != nil {
		return deviceTrafficDeletionRecord{}, err
	}
	for _, record := range ledger.Records {
		if record.Job.ID == id {
			return record, nil
		}
	}
	return deviceTrafficDeletionRecord{}, os.ErrNotExist
}

func (s *Store) readDeviceTrafficDeletionsLocked() (deviceTrafficDeletionLedger, error) {
	path := filepath.Join(s.dataDir, "device-traffic-deletions.json")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return deviceTrafficDeletionLedger{Schema: deviceTrafficDeletionJobSchema, Records: []deviceTrafficDeletionRecord{}}, nil
	}
	if err != nil {
		return deviceTrafficDeletionLedger{}, err
	}
	if len(data) > maxDeviceTrafficDeletionLedgerBytes {
		return deviceTrafficDeletionLedger{}, errors.New("device traffic deletion ledger is too large")
	}
	var ledger deviceTrafficDeletionLedger
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&ledger) != nil || decoder.Decode(&struct{}{}) != io.EOF || ledger.Schema != deviceTrafficDeletionJobSchema || len(ledger.Records) > maxDeviceTrafficDeletionJobs {
		return deviceTrafficDeletionLedger{}, errors.New("device traffic deletion ledger is invalid")
	}
	seenIDs, seenKeys := map[string]struct{}{}, map[string]struct{}{}
	for _, record := range ledger.Records {
		if record.validate() != nil {
			return deviceTrafficDeletionLedger{}, errors.New("device traffic deletion ledger contains an invalid record")
		}
		if _, duplicate := seenIDs[record.Job.ID]; duplicate {
			return deviceTrafficDeletionLedger{}, errors.New("device traffic deletion ledger contains duplicate jobs")
		}
		seenIDs[record.Job.ID] = struct{}{}
		for _, key := range append([]string{record.IdempotencyKey, record.CancelKey}, retryKeys(record.Retries)...) {
			if key == "" {
				continue
			}
			if _, duplicate := seenKeys[key]; duplicate {
				return deviceTrafficDeletionLedger{}, errors.New("device traffic deletion ledger contains duplicate operation keys")
			}
			seenKeys[key] = struct{}{}
		}
	}
	return ledger, nil
}

func (s *Store) writeDeviceTrafficDeletionsLocked(ledger deviceTrafficDeletionLedger) error {
	encoded, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil || len(encoded) > maxDeviceTrafficDeletionLedgerBytes {
		return errors.New("device traffic deletion ledger cannot be encoded safely")
	}
	if err := os.MkdirAll(s.dataDir, 0o750); err != nil {
		return err
	}
	return atomicWrite(filepath.Join(s.dataDir, "device-traffic-deletions.json"), append(encoded, '\n'), 0o600)
}

func (r deviceTrafficDeletionRecord) validate() error {
	job := r.Job
	deletedClasses, retainedClasses, supportedChoice := deviceTrafficDeletionClasses(job.Choice)
	expectedRequestSHA, requestHashErr := deviceTrafficDeletionRequestSHA(r.Preview, job.Choice, job.Administrator, r.IdempotencyKey)
	if r.Schema != deviceTrafficDeletionJobSchema || r.Preview.validate() != nil || !supportedChoice || !validCoordinatorOpaqueKey(r.IdempotencyKey) || requestHashErr != nil || r.RequestSHA256 != expectedRequestSHA || job.Schema != deviceTrafficDeletionJobSchema || !deviceTrafficDeletionJobIDPattern.MatchString(job.ID) || job.DeviceID != r.Preview.DeviceID || !validCoordinatorText(job.Administrator, 1, 96) || r.Preview.NormalizedEventDeletion.Actor != job.Administrator || job.PreviewSHA256 != r.Preview.PreviewSHA256 || !reflect.DeepEqual(job.DeletedDataClasses, deletedClasses) || !reflect.DeepEqual(job.RetainedDataClasses, retainedClasses) || job.ProgressPercent < 0 || job.ProgressPercent > 100 || job.CreatedAt.IsZero() || job.UpdatedAt.Before(job.CreatedAt) || len(r.Retries) > maxDeviceTrafficDeletionRetries || validateDeviceTrafficBackendEvidence(job, r.Preview) != nil {
		return errors.New("device traffic deletion record is invalid")
	}
	for _, retry := range r.Retries {
		if !validCoordinatorOpaqueKey(retry.IdempotencyKey) || retry.Administrator != job.Administrator || retry.StartedAt.Before(job.CreatedAt) || retry.CompletedAt != nil && retry.CompletedAt.Before(retry.StartedAt) || retry.CompletedAt == nil && retry.ResultState != "" || retry.CompletedAt != nil && retry.ResultState != deviceTrafficDeletionCompleted && retry.ResultState != deviceTrafficDeletionPartial {
			return errors.New("device traffic deletion retry is invalid")
		}
	}
	switch job.State {
	case deviceTrafficDeletionPending:
		if job.CompletedAt != nil || job.Failure != "" || job.Phase == "AWAITING_EXECUTION" && job.ProgressPercent != 5 || job.Phase == "RETRY_REQUESTED" && job.ProgressPercent != 10 || job.Phase != "AWAITING_EXECUTION" && job.Phase != "RETRY_REQUESTED" || job.Phase == "AWAITING_EXECUTION" && hasDeviceTrafficBackendEvidence(job) {
			return errors.New("pending device traffic deletion contains terminal evidence")
		}
	case deviceTrafficDeletionRunning:
		validPhase := job.Phase == "INGESTION_BARRIER_SET" && job.ProgressPercent == 25 || job.Choice == capture.SanitizeAndRewritePCAP && (job.Phase == "ANALYZER_BARRIERS_SET" && job.ProgressPercent == 45 || job.Phase == "PCAP_REWRITTEN" && job.ProgressPercent == 75 || job.Phase == "ANALYZER_REINDEXING" && job.ProgressPercent == 90) || job.Choice == capture.DeleteWholeCaptureFiles && (job.Phase == "CAPTURE_EVENTS_DELETED" && job.ProgressPercent == 40 || job.Phase == "ANALYZER_BARRIERS_SET" && job.ProgressPercent == 60 || job.Phase == "PCAP_FILES_DELETED" && job.ProgressPercent == 90)
		if !validPhase || job.CompletedAt != nil || job.Failure != "" {
			return errors.New("running device traffic deletion is invalid")
		}
	case deviceTrafficDeletionCompleted:
		metadataComplete := job.Choice != capture.DeleteWholeCaptureFiles && job.NormalizedEvents != nil && job.NormalizedEvents.Validate() == nil && job.NormalizedEvents.PreviewSHA256 == r.Preview.NormalizedEventDeletion.PreviewSHA256
		wholeComplete := job.Choice == capture.DeleteWholeCaptureFiles && job.NormalizedEvents == nil && deviceTrafficWholeFileEvidenceComplete(job, r.Preview)
		derivedComplete := job.Choice != capture.DeleteDerivedContentOnly || deviceTrafficDerivedEvidenceComplete(job, r.Preview)
		sanitizeComplete := job.Choice != capture.SanitizeAndRewritePCAP || deviceTrafficSanitizeEvidenceComplete(job, r.Preview)
		if job.Phase != "COMPLETED" || job.ProgressPercent != 100 || job.CompletedAt == nil || job.Failure != "" || (!metadataComplete && !wholeComplete) || !derivedComplete || !sanitizeComplete {
			return errors.New("completed device traffic deletion is invalid")
		}
	case deviceTrafficDeletionPartial:
		if job.Phase != "RETRY_REQUIRED" || job.ProgressPercent < 25 || job.ProgressPercent > 90 || job.CompletedAt == nil || job.Failure != "device traffic deletion backend did not complete" {
			return errors.New("partial device traffic deletion is invalid")
		}
	case deviceTrafficDeletionCancelled:
		if job.Phase != "CANCELLED_BEFORE_BARRIER" || job.ProgressPercent != 0 || job.CompletedAt == nil || hasDeviceTrafficBackendEvidence(job) || job.Failure != "" || !validCoordinatorOpaqueKey(r.CancelKey) || r.CancelledBy != job.Administrator {
			return errors.New("cancelled device traffic deletion is invalid")
		}
	default:
		return errors.New("device traffic deletion state is invalid")
	}
	if job.State != deviceTrafficDeletionCancelled && (r.CancelKey != "" || r.CancelledBy != "") {
		return errors.New("non-cancelled device traffic deletion contains cancellation evidence")
	}
	return nil
}

func retryKeys(retries []deviceTrafficDeletionRetry) []string {
	result := make([]string, 0, len(retries))
	for _, retry := range retries {
		result = append(result, retry.IdempotencyKey)
	}
	return result
}

func hasDeviceTrafficBackendEvidence(job deviceTrafficDeletionJob) bool {
	return job.NormalizedEvents != nil || len(job.CaptureEvents) != 0 || len(job.AnalyzerCheckpoints) != 0 || len(job.PCAPRewrites) != 0 || len(job.PCAPDeletions) != 0 || len(job.AnalyzerReindexes) != 0
}

func validateDeviceTrafficBackendEvidence(job deviceTrafficDeletionJob, preview deviceTrafficDeletionPreview) error {
	if job.NormalizedEvents != nil && (job.NormalizedEvents.Validate() != nil || job.NormalizedEvents.PreviewSHA256 != preview.NormalizedEventDeletion.PreviewSHA256 || job.NormalizedEvents.OperationID != job.ID || job.NormalizedEvents.Actor != job.Administrator) {
		return errors.New("device traffic deletion event outcome is invalid")
	}
	if job.Choice == capture.DeleteMetadataOnly {
		if len(job.CaptureEvents) != 0 || len(job.AnalyzerCheckpoints) != 0 || len(job.PCAPRewrites) != 0 || len(job.PCAPDeletions) != 0 || len(job.AnalyzerReindexes) != 0 {
			return errors.New("metadata-only deletion contains packet backend evidence")
		}
		return nil
	}
	if len(job.CaptureEvents) > len(preview.WholeCaptureEvents) || len(job.AnalyzerCheckpoints) > len(preview.AnalyzerReindex)*2 || len(job.PCAPRewrites) > len(preview.PCAP.ImpactedFiles) || len(job.PCAPDeletions) > len(preview.PCAP.ImpactedFiles) || len(job.AnalyzerReindexes) > len(preview.AnalyzerReindex)*2 {
		return errors.New("device traffic deletion backend evidence exceeds its preview")
	}
	if job.Choice == capture.DeleteDerivedContentOnly && (len(job.CaptureEvents) != 0 || len(job.PCAPRewrites) != 0 || len(job.PCAPDeletions) != 0 || len(job.AnalyzerReindexes) != 0) || job.Choice == capture.SanitizeAndRewritePCAP && (len(job.CaptureEvents) != 0 || len(job.PCAPDeletions) != 0) || job.Choice == capture.DeleteWholeCaptureFiles && (job.NormalizedEvents != nil || len(job.PCAPRewrites) != 0 || len(job.AnalyzerReindexes) != 0) {
		return errors.New("device traffic deletion contains evidence for another disposition")
	}
	captureEventKeys := map[string]struct{}{}
	for _, outcome := range job.CaptureEvents {
		previewItem, ok := deviceTrafficWholeEventPreview(preview, outcome.CaptureSessionID)
		if _, duplicate := captureEventKeys[outcome.CaptureSessionID]; duplicate || !ok || outcome.Validate() != nil || outcome.PreviewSHA256 != previewItem.PreviewSHA256 || outcome.Tombstone.OperationID != deviceTrafficCaptureEventOperationID(job.ID, outcome.CaptureSessionID) || outcome.Tombstone.Actor != job.Administrator {
			return errors.New("device traffic deletion capture event outcome is invalid")
		}
		captureEventKeys[outcome.CaptureSessionID] = struct{}{}
	}
	checkpointKeys := map[string]struct{}{}
	for _, checkpoint := range job.AnalyzerCheckpoints {
		key := checkpoint.SessionID + "\x00" + string(checkpoint.Engine)
		if _, duplicate := checkpointKeys[key]; duplicate || checkpoint.Outcome.Validate() != nil || checkpoint.Outcome.CaptureSessionID != checkpoint.SessionID || checkpoint.Outcome.Engine != checkpoint.Engine || checkpoint.Outcome.Actor != job.Administrator {
			return errors.New("device traffic deletion checkpoint outcome is invalid")
		}
		expected, ok := deviceTrafficAnalyzerPreview(preview, checkpoint.SessionID, checkpoint.Engine)
		if !ok || checkpoint.Outcome.PreviewSHA256 != expected.PreviewSHA256 || checkpoint.Outcome.CheckpointWasPresent != expected.CheckpointPresent || checkpoint.Outcome.DeletedCheckpointBytes != expected.CheckpointBytes || checkpoint.Outcome.ActiveProgressWasPresent != expected.ActiveProgressPresent || checkpoint.Outcome.DeletedActiveProgressBytes != expected.ActiveProgressBytes || checkpoint.Outcome.OperationID != deviceTrafficAnalyzerOperationID(job.ID, checkpoint.SessionID, checkpoint.Engine, "delete") {
			return errors.New("device traffic deletion checkpoint outcome does not match its preview")
		}
		checkpointKeys[key] = struct{}{}
	}
	rewriteKeys := map[string]struct{}{}
	for _, rewrite := range job.PCAPRewrites {
		key := rewrite.SessionID + "\x00" + rewrite.FileName
		impact, ok := deviceTrafficPCAPImpact(preview, rewrite.SessionID, rewrite.FileName)
		if _, duplicate := rewriteKeys[key]; duplicate || !ok || rewrite.Validate() != nil || rewrite.State != capture.PCAPRewriteCompleted || rewrite.ID != deviceTrafficPCAPRewriteID(job.ID, rewrite.SessionID, rewrite.FileName) || rewrite.OriginalSHA256 != impact.OriginalSHA256 || rewrite.SelectionSHA256 != preview.PCAP.SelectionSHA256 || rewrite.PacketsRead != impact.PacketsRead || rewrite.PacketsRemoved != impact.MatchedPackets || !rewrite.ReindexRequired || !rewrite.ArtifactReplaced || !validSHA256(rewrite.OutputManifestFileSHA256) {
			return errors.New("device traffic deletion PCAP rewrite outcome is invalid")
		}
		rewriteKeys[key] = struct{}{}
	}
	deletionKeys := map[string]struct{}{}
	for _, deletion := range job.PCAPDeletions {
		key := deletion.SessionID + "\x00" + deletion.FileName
		impact, ok := deviceTrafficPCAPImpact(preview, deletion.SessionID, deletion.FileName)
		if _, duplicate := deletionKeys[key]; duplicate || !ok || deletion.Validate() != nil || deletion.State != capture.PCAPArtifactDeletionCompleted || deletion.ID != deviceTrafficPCAPDeletionID(job.ID, deletion.SessionID, deletion.FileName) || deletion.OriginalSHA256 != impact.OriginalSHA256 || deletion.SelectionSHA256 != preview.PCAP.SelectionSHA256 || deletion.PacketsRead != impact.PacketsRead || deletion.MatchedPacketsRemoved != impact.MatchedPackets || deletion.CollateralPacketsRemoved != impact.CollateralPacketsInWholeDelete || !deletion.ReindexRequired || !deletion.ArtifactRemoved || !validSHA256(deletion.OutputManifestFileSHA256) {
			return errors.New("device traffic deletion PCAP removal outcome is invalid")
		}
		deletionKeys[key] = struct{}{}
	}
	reindexKeys := map[string]struct{}{}
	for _, reindex := range job.AnalyzerReindexes {
		key := reindex.CaptureSessionID + "\x00" + string(reindex.Engine)
		if _, duplicate := reindexKeys[key]; duplicate || reindex.Validate() != nil || reindex.Actor != job.Administrator || reindex.OperationID != deviceTrafficAnalyzerOperationID(job.ID, reindex.CaptureSessionID, reindex.Engine, "reindex") {
			return errors.New("device traffic deletion analyzer reindex outcome is invalid")
		}
		checkpoint, ok := deviceTrafficAnalyzerCheckpointOutcome(job, reindex.CaptureSessionID, reindex.Engine)
		if !ok || reindex.DeletionOperationID != checkpoint.OperationID || reindex.DeletionPreviewSHA256 != checkpoint.PreviewSHA256 || reindex.TargetManifestSHA256 != deviceTrafficSessionManifestSHA(job, reindex.CaptureSessionID) {
			return errors.New("device traffic deletion analyzer reindex outcome does not match its mutation")
		}
		reindexKeys[key] = struct{}{}
	}
	return nil
}

func deviceTrafficSanitizeEvidenceComplete(job deviceTrafficDeletionJob, preview deviceTrafficDeletionPreview) bool {
	if len(job.AnalyzerCheckpoints) != len(preview.AnalyzerReindex)*2 || len(job.PCAPRewrites) != len(preview.PCAP.ImpactedFiles) || len(job.AnalyzerReindexes) != len(preview.AnalyzerReindex)*2 {
		return false
	}
	for _, outcome := range job.AnalyzerReindexes {
		if outcome.State != "COMPLETED" || outcome.CompletedAt == nil {
			return false
		}
	}
	return true
}

func deviceTrafficDerivedEvidenceComplete(job deviceTrafficDeletionJob, preview deviceTrafficDeletionPreview) bool {
	return job.NormalizedEvents != nil && len(job.AnalyzerCheckpoints) == len(preview.AnalyzerReindex)*2
}

func deviceTrafficWholeFileEvidenceComplete(job deviceTrafficDeletionJob, preview deviceTrafficDeletionPreview) bool {
	return len(job.CaptureEvents) == len(preview.WholeCaptureEvents) && len(job.AnalyzerCheckpoints) == len(preview.AnalyzerReindex)*2 && len(job.PCAPDeletions) == len(preview.PCAP.ImpactedFiles)
}

func deviceTrafficWholeEventPreview(preview deviceTrafficDeletionPreview, sessionID string) (ingest.CaptureEventDeletionPreview, bool) {
	for _, item := range preview.WholeCaptureEvents {
		if item.CaptureSessionID == sessionID {
			return item, true
		}
	}
	return ingest.CaptureEventDeletionPreview{}, false
}

func deviceTrafficAnalyzerPreview(preview deviceTrafficDeletionPreview, sessionID string, engine analyzer.Engine) (analyzer.CheckpointDeletionPreview, bool) {
	for _, impact := range preview.AnalyzerReindex {
		if impact.SessionID != sessionID {
			continue
		}
		if engine == analyzer.EngineZeek {
			return impact.Zeek, true
		}
		if engine == analyzer.EngineSuricata {
			return impact.Suricata, true
		}
	}
	return analyzer.CheckpointDeletionPreview{}, false
}

func deviceTrafficPCAPImpact(preview deviceTrafficDeletionPreview, sessionID, fileName string) (capture.PCAPSelectionFileImpact, bool) {
	for _, impact := range preview.PCAP.ImpactedFiles {
		if impact.SessionID == sessionID && impact.FileName == fileName {
			return impact, true
		}
	}
	return capture.PCAPSelectionFileImpact{}, false
}

func deviceTrafficAnalyzerCheckpointOutcome(job deviceTrafficDeletionJob, sessionID string, engine analyzer.Engine) (analyzer.CheckpointDeletionOutcome, bool) {
	for _, checkpoint := range job.AnalyzerCheckpoints {
		if checkpoint.SessionID == sessionID && checkpoint.Engine == engine {
			return checkpoint.Outcome, true
		}
	}
	return analyzer.CheckpointDeletionOutcome{}, false
}

func deviceTrafficSessionManifestSHA(job deviceTrafficDeletionJob, sessionID string) string {
	result := ""
	for _, rewrite := range job.PCAPRewrites {
		if rewrite.SessionID == sessionID {
			result = rewrite.OutputManifestFileSHA256
		}
	}
	return result
}

func deviceTrafficAnalyzerOperationID(jobID, sessionID string, engine analyzer.Engine, action string) string {
	return jobID + "-" + strings.ToLower(string(engine)) + "-" + action + "-" + strings.TrimPrefix(sessionID, "capture-")
}

func deviceTrafficPCAPRewriteID(jobID, sessionID, fileName string) string {
	digest := sha256.Sum256([]byte(jobID + "\x00" + sessionID + "\x00" + fileName))
	return "pcap-rewrite-" + hex.EncodeToString(digest[:16])
}

func deviceTrafficPCAPDeletionID(jobID, sessionID, fileName string) string {
	digest := sha256.Sum256([]byte(jobID + "\x00" + sessionID + "\x00" + fileName))
	return "pcap-delete-" + hex.EncodeToString(digest[:16])
}

func deviceTrafficCaptureEventOperationID(jobID, sessionID string) string {
	return jobID + "-events-" + strings.TrimPrefix(sessionID, "capture-")
}

func newDeviceTrafficDeletionJobID(requestSHA string, records []deviceTrafficDeletionRecord) string {
	for salt := 0; ; salt++ {
		digest := sha256.Sum256([]byte(requestSHA + ":" + strconv.Itoa(salt)))
		candidate := "device-traffic-delete-" + hex.EncodeToString(digest[:16])
		used := false
		for _, record := range records {
			used = used || record.Job.ID == candidate
		}
		if !used {
			return candidate
		}
	}
}

func deviceTrafficChoiceExecutable(preview deviceTrafficDeletionPreview, selected capture.SharedPCAPDisposition) bool {
	for _, choice := range preview.Choices {
		if choice.Choice == selected {
			return choice.Eligible && choice.ExecutionAvailable
		}
	}
	return false
}

func (s *Server) executeDeviceTrafficDeletion(ctx context.Context, record deviceTrafficDeletionRecord) (deviceTrafficDeletionJob, error) {
	if record.Job.Choice == capture.DeleteDerivedContentOnly {
		return s.executeDerivedDeviceTrafficDeletion(ctx, record)
	}
	if record.Job.Choice == capture.SanitizeAndRewritePCAP {
		return s.executeSanitizedDeviceTrafficDeletion(ctx, record)
	}
	if record.Job.Choice == capture.DeleteWholeCaptureFiles {
		return s.executeWholeFileDeviceTrafficDeletion(ctx, record)
	}
	return s.executeMetadataDeviceTrafficDeletion(ctx, record)
}

func (s *Server) executeDerivedDeviceTrafficDeletion(ctx context.Context, record deviceTrafficDeletionRecord) (deviceTrafficDeletionJob, error) {
	if record.Job.State == deviceTrafficDeletionCompleted || record.Job.State == deviceTrafficDeletionCancelled {
		return record.Job, nil
	}
	current, err := s.store.updateDeviceTrafficDeletion(record.Job.ID, func(value *deviceTrafficDeletionRecord) error {
		now := time.Now().UTC().Truncate(time.Microsecond)
		value.Job.State, value.Job.Phase, value.Job.ProgressPercent = deviceTrafficDeletionRunning, "INGESTION_BARRIER_SET", 25
		value.Job.UpdatedAt, value.Job.CompletedAt, value.Job.Failure = now, nil, ""
		return nil
	})
	if err != nil {
		return deviceTrafficDeletionJob{}, err
	}
	if current.Job.NormalizedEvents == nil {
		outcome, deleteErr := s.eventSelectionDeletions.DeleteEventSelection(ctx, ingest.EventSelectionDeletionRequest{
			Schema: ingest.EventSelectionDeletionOperationSchema, Preview: current.Preview.NormalizedEventDeletion,
			OperationID: current.Job.ID, Actor: current.Job.Administrator,
		})
		if deleteErr != nil || outcome.Validate() != nil || outcome.PreviewSHA256 != current.Preview.NormalizedEventDeletion.PreviewSHA256 || outcome.OperationID != current.Job.ID || outcome.Actor != current.Job.Administrator {
			return s.markDeviceTrafficDeletionPartial(current.Job.ID, 25)
		}
		current, err = s.store.updateDeviceTrafficDeletion(current.Job.ID, func(value *deviceTrafficDeletionRecord) error {
			value.Job.NormalizedEvents = &outcome
			value.Job.UpdatedAt = time.Now().UTC().Truncate(time.Microsecond)
			return nil
		})
		if err != nil {
			return deviceTrafficDeletionJob{}, err
		}
	}
	for _, impact := range current.Preview.AnalyzerReindex {
		for _, item := range []struct {
			engine  analyzer.Engine
			preview analyzer.CheckpointDeletionPreview
			service analyzerCheckpointDeletionService
		}{{analyzer.EngineZeek, impact.Zeek, s.zeekCheckpointDeletions}, {analyzer.EngineSuricata, impact.Suricata, s.suricataCheckpointDeletions}} {
			if _, exists := deviceTrafficAnalyzerCheckpointOutcome(current.Job, impact.SessionID, item.engine); exists {
				continue
			}
			if item.service == nil {
				return s.markDeviceTrafficDeletionPartial(current.Job.ID, 50)
			}
			outcome, deleteErr := item.service.Delete(ctx, analyzer.CheckpointDeletionRequest{
				Schema: analyzer.CheckpointDeletionSchema, OperationID: deviceTrafficAnalyzerOperationID(current.Job.ID, impact.SessionID, item.engine, "delete"),
				Actor: current.Job.Administrator, Preview: item.preview,
			})
			if deleteErr != nil || outcome.Validate() != nil {
				return s.markDeviceTrafficDeletionPartial(current.Job.ID, 50)
			}
			current, err = s.store.updateDeviceTrafficDeletion(current.Job.ID, func(value *deviceTrafficDeletionRecord) error {
				value.Job.AnalyzerCheckpoints = append(value.Job.AnalyzerCheckpoints, deviceTrafficAnalyzerCheckpoint{SessionID: impact.SessionID, Engine: item.engine, Outcome: outcome})
				value.Job.UpdatedAt = time.Now().UTC().Truncate(time.Microsecond)
				return nil
			})
			if err != nil {
				return deviceTrafficDeletionJob{}, err
			}
		}
	}
	if !deviceTrafficDerivedEvidenceComplete(current.Job, current.Preview) {
		return s.markDeviceTrafficDeletionPartial(current.Job.ID, 75)
	}
	current, err = s.store.updateDeviceTrafficDeletion(current.Job.ID, func(value *deviceTrafficDeletionRecord) error {
		now := time.Now().UTC().Truncate(time.Microsecond)
		value.Job.State, value.Job.Phase, value.Job.ProgressPercent = deviceTrafficDeletionCompleted, "COMPLETED", 100
		value.Job.UpdatedAt, value.Job.CompletedAt, value.Job.Failure = now, &now, ""
		return nil
	})
	if err != nil {
		return deviceTrafficDeletionJob{}, err
	}
	return current.Job, nil
}

func (s *Server) executeMetadataDeviceTrafficDeletion(ctx context.Context, record deviceTrafficDeletionRecord) (deviceTrafficDeletionJob, error) {
	if record.Job.State == deviceTrafficDeletionCompleted || record.Job.State == deviceTrafficDeletionCancelled {
		return record.Job, nil
	}
	updated, err := s.store.updateDeviceTrafficDeletion(record.Job.ID, func(current *deviceTrafficDeletionRecord) error {
		now := time.Now().UTC().Truncate(time.Microsecond)
		current.Job.State, current.Job.Phase, current.Job.ProgressPercent = deviceTrafficDeletionRunning, "INGESTION_BARRIER_SET", 25
		current.Job.UpdatedAt, current.Job.CompletedAt, current.Job.Failure = now, nil, ""
		current.Job.NormalizedEvents = nil
		return nil
	})
	if err != nil {
		return deviceTrafficDeletionJob{}, err
	}
	outcome, deleteErr := s.eventSelectionDeletions.DeleteEventSelection(ctx, ingest.EventSelectionDeletionRequest{
		Schema: ingest.EventSelectionDeletionOperationSchema, Preview: updated.Preview.NormalizedEventDeletion,
		OperationID: updated.Job.ID, Actor: updated.Job.Administrator,
	})
	updated, persistErr := s.store.updateDeviceTrafficDeletion(record.Job.ID, func(current *deviceTrafficDeletionRecord) error {
		now := time.Now().UTC().Truncate(time.Microsecond)
		current.Job.UpdatedAt, current.Job.CompletedAt = now, &now
		if deleteErr != nil || outcome.Validate() != nil || outcome.PreviewSHA256 != current.Preview.NormalizedEventDeletion.PreviewSHA256 {
			current.Job.State, current.Job.Phase, current.Job.ProgressPercent = deviceTrafficDeletionPartial, "RETRY_REQUIRED", 50
			current.Job.Failure, current.Job.NormalizedEvents = "device traffic deletion backend did not complete", nil
			return nil
		}
		current.Job.State, current.Job.Phase, current.Job.ProgressPercent = deviceTrafficDeletionCompleted, "COMPLETED", 100
		current.Job.Failure, current.Job.NormalizedEvents = "", &outcome
		return nil
	})
	if persistErr != nil {
		return deviceTrafficDeletionJob{}, persistErr
	}
	return updated.Job, nil
}

func (s *Server) executeSanitizedDeviceTrafficDeletion(ctx context.Context, record deviceTrafficDeletionRecord) (deviceTrafficDeletionJob, error) {
	if record.Job.State == deviceTrafficDeletionCompleted || record.Job.State == deviceTrafficDeletionCancelled {
		return record.Job, nil
	}
	current, err := s.store.updateDeviceTrafficDeletion(record.Job.ID, func(value *deviceTrafficDeletionRecord) error {
		now := time.Now().UTC().Truncate(time.Microsecond)
		value.Job.State, value.Job.Phase, value.Job.ProgressPercent = deviceTrafficDeletionRunning, "INGESTION_BARRIER_SET", 25
		value.Job.UpdatedAt, value.Job.CompletedAt, value.Job.Failure = now, nil, ""
		return nil
	})
	if err != nil {
		return deviceTrafficDeletionJob{}, err
	}
	if current.Job.NormalizedEvents == nil {
		outcome, deleteErr := s.eventSelectionDeletions.DeleteEventSelection(ctx, ingest.EventSelectionDeletionRequest{
			Schema: ingest.EventSelectionDeletionOperationSchema, Preview: current.Preview.NormalizedEventDeletion,
			OperationID: current.Job.ID, Actor: current.Job.Administrator,
		})
		if deleteErr != nil || outcome.Validate() != nil || outcome.PreviewSHA256 != current.Preview.NormalizedEventDeletion.PreviewSHA256 {
			return s.markDeviceTrafficDeletionPartial(current.Job.ID, 25)
		}
		current, err = s.store.updateDeviceTrafficDeletion(current.Job.ID, func(value *deviceTrafficDeletionRecord) error {
			value.Job.NormalizedEvents = &outcome
			value.Job.UpdatedAt = time.Now().UTC().Truncate(time.Microsecond)
			return nil
		})
		if err != nil {
			return deviceTrafficDeletionJob{}, err
		}
	}
	current, err = s.store.updateDeviceTrafficDeletion(current.Job.ID, func(value *deviceTrafficDeletionRecord) error {
		value.Job.Phase, value.Job.ProgressPercent, value.Job.UpdatedAt = "ANALYZER_BARRIERS_SET", 45, time.Now().UTC().Truncate(time.Microsecond)
		return nil
	})
	if err != nil {
		return deviceTrafficDeletionJob{}, err
	}
	for _, impact := range current.Preview.AnalyzerReindex {
		for _, item := range []struct {
			engine  analyzer.Engine
			preview analyzer.CheckpointDeletionPreview
			service analyzerCheckpointDeletionService
		}{{analyzer.EngineZeek, impact.Zeek, s.zeekCheckpointDeletions}, {analyzer.EngineSuricata, impact.Suricata, s.suricataCheckpointDeletions}} {
			if _, exists := deviceTrafficAnalyzerCheckpointOutcome(current.Job, impact.SessionID, item.engine); exists {
				continue
			}
			if item.service == nil {
				return s.markDeviceTrafficDeletionPartial(current.Job.ID, 45)
			}
			outcome, deleteErr := item.service.Delete(ctx, analyzer.CheckpointDeletionRequest{
				Schema: analyzer.CheckpointDeletionSchema, OperationID: deviceTrafficAnalyzerOperationID(current.Job.ID, impact.SessionID, item.engine, "delete"),
				Actor: current.Job.Administrator, Preview: item.preview,
			})
			if deleteErr != nil || outcome.Validate() != nil {
				return s.markDeviceTrafficDeletionPartial(current.Job.ID, 45)
			}
			current, err = s.store.updateDeviceTrafficDeletion(current.Job.ID, func(value *deviceTrafficDeletionRecord) error {
				value.Job.AnalyzerCheckpoints = append(value.Job.AnalyzerCheckpoints, deviceTrafficAnalyzerCheckpoint{SessionID: impact.SessionID, Engine: item.engine, Outcome: outcome})
				value.Job.UpdatedAt = time.Now().UTC().Truncate(time.Microsecond)
				return nil
			})
			if err != nil {
				return deviceTrafficDeletionJob{}, err
			}
		}
	}
	for _, impact := range current.Preview.PCAP.ImpactedFiles {
		if _, exists := deviceTrafficRewriteOutcome(current.Job, impact.SessionID, impact.FileName); exists {
			continue
		}
		request := capture.PCAPRewriteRequest{
			Schema: capture.PCAPRewriteSchema, ID: deviceTrafficPCAPRewriteID(current.Job.ID, impact.SessionID, impact.FileName),
			SessionID: impact.SessionID, FileName: impact.FileName, OriginalSHA256: impact.OriginalSHA256,
			Selection: current.Preview.PCAP.Selection, ToolVersion: "shakerproxy-control-api-v1",
		}
		var rewrite capture.PCAPRewriteRecord
		callErr := s.gateway.CallWithTimeout(ctx, "RewritePCAP", gatewayprotocol.RewritePCAPParams{Request: request}, &rewrite, 2*time.Minute)
		if callErr != nil || rewrite.Validate() != nil || rewrite.State != capture.PCAPRewriteCompleted || rewrite.ID != request.ID {
			return s.markDeviceTrafficDeletionPartial(current.Job.ID, 60)
		}
		current, err = s.store.updateDeviceTrafficDeletion(current.Job.ID, func(value *deviceTrafficDeletionRecord) error {
			value.Job.PCAPRewrites = append(value.Job.PCAPRewrites, rewrite)
			value.Job.UpdatedAt = time.Now().UTC().Truncate(time.Microsecond)
			return nil
		})
		if err != nil {
			return deviceTrafficDeletionJob{}, err
		}
	}
	current, err = s.store.updateDeviceTrafficDeletion(current.Job.ID, func(value *deviceTrafficDeletionRecord) error {
		value.Job.Phase, value.Job.ProgressPercent, value.Job.UpdatedAt = "PCAP_REWRITTEN", 75, time.Now().UTC().Truncate(time.Microsecond)
		return nil
	})
	if err != nil {
		return deviceTrafficDeletionJob{}, err
	}
	for _, impact := range current.Preview.AnalyzerReindex {
		targetManifestSHA := deviceTrafficSessionManifestSHA(current.Job, impact.SessionID)
		for _, item := range []struct {
			engine  analyzer.Engine
			service analyzerCheckpointDeletionService
		}{{analyzer.EngineZeek, s.zeekCheckpointDeletions}, {analyzer.EngineSuricata, s.suricataCheckpointDeletions}} {
			checkpoint, exists := deviceTrafficAnalyzerCheckpointOutcome(current.Job, impact.SessionID, item.engine)
			if !exists || item.service == nil || !validSHA256(targetManifestSHA) {
				return s.markDeviceTrafficDeletionPartial(current.Job.ID, 75)
			}
			request := analyzer.CheckpointReindexRequest{
				Schema: analyzer.CheckpointReindexSchema, OperationID: deviceTrafficAnalyzerOperationID(current.Job.ID, impact.SessionID, item.engine, "reindex"),
				Actor: current.Job.Administrator, Engine: item.engine, CaptureSessionID: impact.SessionID,
				DeletionOperationID: checkpoint.OperationID, DeletionPreviewSHA256: checkpoint.PreviewSHA256, TargetManifestSHA256: targetManifestSHA,
			}
			outcome, reindexErr := item.service.AuthorizeReindex(ctx, request)
			if reindexErr != nil || outcome.Validate() != nil {
				return s.markDeviceTrafficDeletionPartial(current.Job.ID, 75)
			}
			current, err = s.store.updateDeviceTrafficDeletion(current.Job.ID, func(value *deviceTrafficDeletionRecord) error {
				upsertDeviceTrafficReindex(&value.Job, outcome)
				value.Job.UpdatedAt = time.Now().UTC().Truncate(time.Microsecond)
				return nil
			})
			if err != nil {
				return deviceTrafficDeletionJob{}, err
			}
		}
	}
	completed := deviceTrafficSanitizeEvidenceComplete(current.Job, current.Preview)
	current, err = s.store.updateDeviceTrafficDeletion(current.Job.ID, func(value *deviceTrafficDeletionRecord) error {
		now := time.Now().UTC().Truncate(time.Microsecond)
		value.Job.UpdatedAt, value.Job.Failure = now, ""
		if completed {
			value.Job.State, value.Job.Phase, value.Job.ProgressPercent, value.Job.CompletedAt = deviceTrafficDeletionCompleted, "COMPLETED", 100, &now
		} else {
			value.Job.State, value.Job.Phase, value.Job.ProgressPercent, value.Job.CompletedAt = deviceTrafficDeletionRunning, "ANALYZER_REINDEXING", 90, nil
		}
		return nil
	})
	if err != nil {
		return deviceTrafficDeletionJob{}, err
	}
	return current.Job, nil
}

func (s *Server) executeWholeFileDeviceTrafficDeletion(ctx context.Context, record deviceTrafficDeletionRecord) (deviceTrafficDeletionJob, error) {
	if record.Job.State == deviceTrafficDeletionCompleted || record.Job.State == deviceTrafficDeletionCancelled {
		return record.Job, nil
	}
	current, err := s.store.updateDeviceTrafficDeletion(record.Job.ID, func(value *deviceTrafficDeletionRecord) error {
		now := time.Now().UTC().Truncate(time.Microsecond)
		value.Job.State, value.Job.Phase, value.Job.ProgressPercent = deviceTrafficDeletionRunning, "INGESTION_BARRIER_SET", 25
		value.Job.UpdatedAt, value.Job.CompletedAt, value.Job.Failure = now, nil, ""
		return nil
	})
	if err != nil {
		return deviceTrafficDeletionJob{}, err
	}
	for _, preview := range current.Preview.WholeCaptureEvents {
		if _, exists := deviceTrafficCaptureEventOutcome(current.Job, preview.CaptureSessionID); exists {
			continue
		}
		if s.captureEventDeletions == nil {
			return s.markDeviceTrafficDeletionPartial(current.Job.ID, 25)
		}
		operationID := deviceTrafficCaptureEventOperationID(current.Job.ID, preview.CaptureSessionID)
		outcome, deleteErr := s.captureEventDeletions.Delete(ctx, ingest.CaptureEventDeletionRequest{
			Schema: ingest.CaptureEventDeletionOperationSchema, Preview: preview,
			OperationID: operationID, Actor: current.Job.Administrator,
		})
		if deleteErr != nil || outcome.Validate() != nil || outcome.PreviewSHA256 != preview.PreviewSHA256 || outcome.Tombstone.OperationID != operationID || outcome.Tombstone.Actor != current.Job.Administrator {
			return s.markDeviceTrafficDeletionPartial(current.Job.ID, 25)
		}
		current, err = s.store.updateDeviceTrafficDeletion(current.Job.ID, func(value *deviceTrafficDeletionRecord) error {
			value.Job.CaptureEvents = append(value.Job.CaptureEvents, outcome)
			value.Job.UpdatedAt = time.Now().UTC().Truncate(time.Microsecond)
			return nil
		})
		if err != nil {
			return deviceTrafficDeletionJob{}, err
		}
	}
	current, err = s.store.updateDeviceTrafficDeletion(current.Job.ID, func(value *deviceTrafficDeletionRecord) error {
		value.Job.Phase, value.Job.ProgressPercent, value.Job.UpdatedAt = "CAPTURE_EVENTS_DELETED", 40, time.Now().UTC().Truncate(time.Microsecond)
		return nil
	})
	if err != nil {
		return deviceTrafficDeletionJob{}, err
	}
	for _, impact := range current.Preview.AnalyzerReindex {
		for _, item := range []struct {
			engine  analyzer.Engine
			preview analyzer.CheckpointDeletionPreview
			service analyzerCheckpointDeletionService
		}{{analyzer.EngineZeek, impact.Zeek, s.zeekCheckpointDeletions}, {analyzer.EngineSuricata, impact.Suricata, s.suricataCheckpointDeletions}} {
			if _, exists := deviceTrafficAnalyzerCheckpointOutcome(current.Job, impact.SessionID, item.engine); exists {
				continue
			}
			if item.service == nil {
				return s.markDeviceTrafficDeletionPartial(current.Job.ID, 40)
			}
			outcome, deleteErr := item.service.Delete(ctx, analyzer.CheckpointDeletionRequest{
				Schema: analyzer.CheckpointDeletionSchema, OperationID: deviceTrafficAnalyzerOperationID(current.Job.ID, impact.SessionID, item.engine, "delete"),
				Actor: current.Job.Administrator, Preview: item.preview,
			})
			if deleteErr != nil || outcome.Validate() != nil {
				return s.markDeviceTrafficDeletionPartial(current.Job.ID, 40)
			}
			current, err = s.store.updateDeviceTrafficDeletion(current.Job.ID, func(value *deviceTrafficDeletionRecord) error {
				value.Job.AnalyzerCheckpoints = append(value.Job.AnalyzerCheckpoints, deviceTrafficAnalyzerCheckpoint{SessionID: impact.SessionID, Engine: item.engine, Outcome: outcome})
				value.Job.UpdatedAt = time.Now().UTC().Truncate(time.Microsecond)
				return nil
			})
			if err != nil {
				return deviceTrafficDeletionJob{}, err
			}
		}
	}
	current, err = s.store.updateDeviceTrafficDeletion(current.Job.ID, func(value *deviceTrafficDeletionRecord) error {
		value.Job.Phase, value.Job.ProgressPercent, value.Job.UpdatedAt = "ANALYZER_BARRIERS_SET", 60, time.Now().UTC().Truncate(time.Microsecond)
		return nil
	})
	if err != nil {
		return deviceTrafficDeletionJob{}, err
	}
	for _, impact := range current.Preview.PCAP.ImpactedFiles {
		if _, exists := deviceTrafficPCAPDeletionOutcome(current.Job, impact.SessionID, impact.FileName); exists {
			continue
		}
		request := capture.PCAPArtifactDeletionRequest{
			Schema: capture.PCAPArtifactDeletionSchema, ID: deviceTrafficPCAPDeletionID(current.Job.ID, impact.SessionID, impact.FileName),
			SessionID: impact.SessionID, FileName: impact.FileName, OriginalSHA256: impact.OriginalSHA256,
			Selection: current.Preview.PCAP.Selection, ExpectedPackets: impact.PacketsRead,
			ExpectedMatchedPackets: impact.MatchedPackets, ExpectedCollateralPackets: impact.CollateralPacketsInWholeDelete,
		}
		var deletion capture.PCAPArtifactDeletionRecord
		callErr := s.gateway.CallWithTimeout(ctx, "DeletePCAPArtifact", gatewayprotocol.DeletePCAPArtifactParams{Request: request}, &deletion, 2*time.Minute)
		if callErr != nil || deletion.Validate() != nil || deletion.State != capture.PCAPArtifactDeletionCompleted || deletion.ID != request.ID {
			return s.markDeviceTrafficDeletionPartial(current.Job.ID, 60)
		}
		current, err = s.store.updateDeviceTrafficDeletion(current.Job.ID, func(value *deviceTrafficDeletionRecord) error {
			value.Job.PCAPDeletions = append(value.Job.PCAPDeletions, deletion)
			value.Job.UpdatedAt = time.Now().UTC().Truncate(time.Microsecond)
			return nil
		})
		if err != nil {
			return deviceTrafficDeletionJob{}, err
		}
	}
	current, err = s.store.updateDeviceTrafficDeletion(current.Job.ID, func(value *deviceTrafficDeletionRecord) error {
		value.Job.Phase, value.Job.ProgressPercent, value.Job.UpdatedAt = "PCAP_FILES_DELETED", 90, time.Now().UTC().Truncate(time.Microsecond)
		return nil
	})
	if err != nil {
		return deviceTrafficDeletionJob{}, err
	}
	if !deviceTrafficWholeFileEvidenceComplete(current.Job, current.Preview) {
		return s.markDeviceTrafficDeletionPartial(current.Job.ID, 90)
	}
	current, err = s.store.updateDeviceTrafficDeletion(current.Job.ID, func(value *deviceTrafficDeletionRecord) error {
		now := time.Now().UTC().Truncate(time.Microsecond)
		value.Job.State, value.Job.Phase, value.Job.ProgressPercent = deviceTrafficDeletionCompleted, "COMPLETED", 100
		value.Job.UpdatedAt, value.Job.CompletedAt, value.Job.Failure = now, &now, ""
		return nil
	})
	if err != nil {
		return deviceTrafficDeletionJob{}, err
	}
	return current.Job, nil
}

func (s *Server) markDeviceTrafficDeletionPartial(id string, progress int) (deviceTrafficDeletionJob, error) {
	record, err := s.store.updateDeviceTrafficDeletion(id, func(value *deviceTrafficDeletionRecord) error {
		now := time.Now().UTC().Truncate(time.Microsecond)
		value.Job.State, value.Job.Phase = deviceTrafficDeletionPartial, "RETRY_REQUIRED"
		value.Job.ProgressPercent, value.Job.Failure = progress, "device traffic deletion backend did not complete"
		value.Job.UpdatedAt, value.Job.CompletedAt = now, &now
		return nil
	})
	return record.Job, err
}

func deviceTrafficRewriteOutcome(job deviceTrafficDeletionJob, sessionID, fileName string) (capture.PCAPRewriteRecord, bool) {
	for _, rewrite := range job.PCAPRewrites {
		if rewrite.SessionID == sessionID && rewrite.FileName == fileName {
			return rewrite, true
		}
	}
	return capture.PCAPRewriteRecord{}, false
}

func deviceTrafficCaptureEventOutcome(job deviceTrafficDeletionJob, sessionID string) (ingest.CaptureEventDeletionOutcome, bool) {
	for _, outcome := range job.CaptureEvents {
		if outcome.CaptureSessionID == sessionID {
			return outcome, true
		}
	}
	return ingest.CaptureEventDeletionOutcome{}, false
}

func deviceTrafficPCAPDeletionOutcome(job deviceTrafficDeletionJob, sessionID, fileName string) (capture.PCAPArtifactDeletionRecord, bool) {
	for _, deletion := range job.PCAPDeletions {
		if deletion.SessionID == sessionID && deletion.FileName == fileName {
			return deletion, true
		}
	}
	return capture.PCAPArtifactDeletionRecord{}, false
}

func upsertDeviceTrafficReindex(job *deviceTrafficDeletionJob, outcome analyzer.CheckpointReindexOutcome) {
	for index := range job.AnalyzerReindexes {
		if job.AnalyzerReindexes[index].CaptureSessionID == outcome.CaptureSessionID && job.AnalyzerReindexes[index].Engine == outcome.Engine {
			job.AnalyzerReindexes[index] = outcome
			return
		}
	}
	job.AnalyzerReindexes = append(job.AnalyzerReindexes, outcome)
}

func (s *Server) createDeviceTrafficDeletionJob(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	deviceID := r.PathValue("deviceID")
	var request createDeviceTrafficDeletionRequest
	if !deviceinventory.ValidDeviceID(deviceID) || decodeJSONBounded(r, &request, 4<<20) != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request does not match an executable device deletion choice")
		return
	}
	_, _, supportedChoice := deviceTrafficDeletionClasses(request.Choice)
	if request.Preview.validate() != nil || request.Preview.DeviceID != deviceID || request.Confirmation != deviceID || request.Preview.Confirmation != deviceID || !supportedChoice || !deviceTrafficChoiceExecutable(request.Preview, request.Choice) {
		writeError(w, http.StatusBadRequest, "invalid_request", "request does not match an executable device deletion choice")
		return
	}
	if s.eventSelectionDeletions == nil || request.Choice == capture.DeleteWholeCaptureFiles && s.captureEventDeletions == nil || (request.Choice == capture.DeleteDerivedContentOnly || request.Choice == capture.SanitizeAndRewritePCAP || request.Choice == capture.DeleteWholeCaptureFiles) && (s.zeekCheckpointDeletions == nil || s.suricataCheckpointDeletions == nil) {
		writeError(w, http.StatusServiceUnavailable, "device_deletion_backend_unavailable", "device deletion backend is not configured")
		return
	}
	username := sessionUsername(r.Context())
	if !s.confirmAdministrator(w, r, request.Password, passwordAlways) {
		return
	}
	if request.Preview.NormalizedEventDeletion.Actor != username {
		writeError(w, http.StatusForbidden, "deletion_preview_actor_mismatch", "device deletion preview belongs to a different administrator")
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		writeError(w, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key header is required")
		return
	}
	s.deviceTrafficDeletionMu.Lock()
	defer s.deviceTrafficDeletionMu.Unlock()
	record, _, err := s.store.beginDeviceTrafficDeletion(request.Preview, request.Choice, username, key)
	if err != nil {
		s.writeDeviceTrafficDeletionStoreError(w, err)
		return
	}
	if record.Job.State == deviceTrafficDeletionPending || record.Job.State == deviceTrafficDeletionRunning {
		ctx, cancel := durableOperationContext(r)
		defer cancel()
		job, executeErr := s.executeDeviceTrafficDeletion(ctx, record)
		if executeErr != nil {
			writeError(w, http.StatusServiceUnavailable, "device_deletion_store_unavailable", "device deletion progress could not be persisted")
			return
		}
		record.Job = job
	}
	writeJSON(w, http.StatusAccepted, record.Job)
}

func (s *Server) listDeviceTrafficDeletionJobs(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	jobs, err := s.store.listDeviceTrafficDeletionJobs()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "device_deletion_jobs_unavailable", "device deletion jobs are temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": jobs})
}

func (s *Server) getDeviceTrafficDeletionJob(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	record, err := s.store.getDeviceTrafficDeletionRecord(r.PathValue("jobID"))
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "device_deletion_job_not_found", "device deletion job was not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_device_deletion_job", "device deletion job ID is invalid")
		return
	}
	writeJSON(w, http.StatusOK, record.Job)
}

func (s *Server) retryDeviceTrafficDeletionJob(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var request deviceTrafficDeletionActionRequest
	if decodeJSON(r, &request) != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "device deletion retry request is invalid")
		return
	}
	username := sessionUsername(r.Context())
	if !s.confirmAdministrator(w, r, request.Password, passwordAlways) {
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		writeError(w, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key header is required")
		return
	}
	s.deviceTrafficDeletionMu.Lock()
	defer s.deviceTrafficDeletionMu.Unlock()
	record, _, err := s.store.beginDeviceTrafficDeletionRetry(r.PathValue("jobID"), key, username)
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "device_deletion_job_not_found", "device deletion job was not found")
		return
	}
	if err != nil {
		s.writeDeviceTrafficDeletionStoreError(w, err)
		return
	}
	if record.Job.State == deviceTrafficDeletionPending || record.Job.State == deviceTrafficDeletionRunning {
		ctx, cancel := durableOperationContext(r)
		defer cancel()
		job, executeErr := s.executeDeviceTrafficDeletion(ctx, record)
		if executeErr != nil {
			writeError(w, http.StatusServiceUnavailable, "device_deletion_store_unavailable", "device deletion retry progress could not be persisted")
			return
		}
		record.Job = job
	}
	finished, err := s.store.finishDeviceTrafficDeletionRetry(record.Job.ID, key)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "device_deletion_store_unavailable", "device deletion retry result could not be persisted")
		return
	}
	writeJSON(w, http.StatusAccepted, finished.Job)
}

func (s *Server) cancelDeviceTrafficDeletionJob(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var request deviceTrafficDeletionActionRequest
	if err := decodeOptionalJSON(r, &request, 4<<10); err != nil {
		writeDecodeError(w, err, "device deletion cancellation")
		return
	}
	username := sessionUsername(r.Context())
	if !s.confirmAdministrator(w, r, request.Password, passwordRecent) {
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		writeError(w, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key header is required")
		return
	}
	s.deviceTrafficDeletionMu.Lock()
	defer s.deviceTrafficDeletionMu.Unlock()
	record, _, err := s.store.cancelDeviceTrafficDeletion(r.PathValue("jobID"), key, username)
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "device_deletion_job_not_found", "device deletion job was not found")
		return
	}
	if err != nil {
		s.writeDeviceTrafficDeletionStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, record.Job)
}

func (s *Server) writeDeviceTrafficDeletionStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errDeviceTrafficDeletionInvalid), errors.Is(err, errDeviceTrafficDeletionRetry):
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
	case errors.Is(err, errDeviceTrafficDeletionConflict):
		writeError(w, http.StatusConflict, "device_deletion_idempotency_conflict", err.Error())
	case errors.Is(err, errDeviceTrafficDeletionExpired):
		writeError(w, http.StatusGone, "device_deletion_preview_expired", err.Error())
	case errors.Is(err, errDeviceTrafficDeletionCancel):
		writeError(w, http.StatusConflict, "device_deletion_cancel_unsafe", err.Error())
	case errors.Is(err, errDeviceTrafficDeletionLedgerFull):
		writeError(w, http.StatusInsufficientStorage, "device_deletion_history_full", "Device deletion history is full: "+err.Error()+".")
	default:
		writeError(w, http.StatusServiceUnavailable, "device_deletion_store_unavailable", "device deletion intent could not be persisted")
	}
}

func (s *Server) ResumeDeviceTrafficDeletions(ctx context.Context) {
	if s.eventSelectionDeletions == nil {
		return
	}
	s.deviceTrafficDeletionMu.Lock()
	defer s.deviceTrafficDeletionMu.Unlock()
	jobs, err := s.store.listDeviceTrafficDeletionJobs()
	if err != nil {
		s.logger.Error("device deletion recovery scan failed", "error", err)
		return
	}
	for _, job := range jobs {
		if job.State != deviceTrafficDeletionPending && job.State != deviceTrafficDeletionRunning {
			continue
		}
		record, err := s.store.getDeviceTrafficDeletionRecord(job.ID)
		if err != nil {
			continue
		}
		if _, err := s.executeDeviceTrafficDeletion(ctx, record); err != nil {
			s.logger.Error("device deletion recovery failed", "job_id", job.ID, "error", err)
		}
	}
}

func (s *Server) RunDeviceTrafficDeletionRecovery(ctx context.Context) {
	s.ResumeDeviceTrafficDeletions(ctx)
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.ResumeDeviceTrafficDeletions(ctx)
		}
	}
}
