package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/ingest"
)

const captureTestID = "capture-0123456789abcdef0123456789abcdef"

type captureDeletionEventStub struct {
	preview        ingest.CaptureEventDeletionPreview
	previewErr     error
	deleteErr      error
	deleteRequests []ingest.CaptureEventDeletionRequest
}

func (s *captureDeletionEventStub) Preview(_ context.Context, captureSessionID string) (ingest.CaptureEventDeletionPreview, error) {
	if s.previewErr != nil {
		return ingest.CaptureEventDeletionPreview{}, s.previewErr
	}
	if s.preview.CaptureSessionID != captureSessionID {
		return ingest.CaptureEventDeletionPreview{}, errors.New("unexpected capture scope")
	}
	return s.preview, nil
}

func (s *captureDeletionEventStub) Delete(_ context.Context, request ingest.CaptureEventDeletionRequest) (ingest.CaptureEventDeletionOutcome, error) {
	s.deleteRequests = append(s.deleteRequests, request)
	if s.deleteErr != nil {
		return ingest.CaptureEventDeletionOutcome{}, s.deleteErr
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	tombstone := ingest.CaptureTombstone{Schema: ingest.CaptureTombstoneSchemaVersion, CaptureSessionID: request.Preview.CaptureSessionID, OperationID: request.OperationID, Actor: request.Actor, CreatedAt: now}
	receipt := ingest.CaptureEventDeletionReceipt{Schema: ingest.CaptureEventDeletionPreviewSchema, CaptureSessionID: request.Preview.CaptureSessionID, OperationID: request.OperationID, PreviewSHA256: request.Preview.PreviewSHA256, DeletedEventRows: request.Preview.Database.EventRows, DeletedIdentityRows: request.Preview.Database.ExclusiveIdentityRows, DeletedEventLogicalBytes: request.Preview.Database.EventLogicalBytes, DeletedIdentityLogicalBytes: request.Preview.Database.IdentityLogicalBytes, DatabaseReclaimMode: ingest.DatabaseReclaimDeferred, VerifiedAbsent: true, CompletedAt: now}
	spool := ingest.SpoolTombstoneResult{Tombstone: tombstone, PurgedRecords: request.Preview.Spool.PendingRecords, PurgedBytes: request.Preview.Spool.PendingFileBytes}
	return ingest.CaptureEventDeletionOutcome{Schema: ingest.CaptureEventDeletionOperationSchema, CaptureSessionID: request.Preview.CaptureSessionID, PreviewSHA256: request.Preview.PreviewSHA256, Tombstone: tombstone, Spool: spool, Database: receipt, CompletedAt: now}, nil
}

func TestCaptureStartBindsAdministratorAndIdempotencyAtAPI(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	result := capture.View{Session: capture.Session{ID: captureTestID}, State: capture.StateStarting, Active: true}
	requests := startGatewayStub(t, socketPath, result)
	server, session := configuredAPIServer(t, socketPath)
	body := `{"name":"case window","mode":"HEADERS_ONLY","segment_size_mib":4,"segment_seconds":60,"max_files":4,"stop_after_seconds":600,"retention_lock":true,"case_id":"CASE-1","start_reason":"triage"}`
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/captures", body, session, "http-capture-request-0001")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("unexpected response %d: %s", recorder.Code, recorder.Body.String())
	}
	rpcRequest := <-requests
	if rpcRequest.Method != "StartCapture" {
		t.Fatalf("unexpected RPC method: %s", rpcRequest.Method)
	}
	var params gatewayprotocol.StartCaptureParams
	if err := gatewayprotocol.DecodeParams(rpcRequest.Params, &params); err != nil {
		t.Fatal(err)
	}
	if params.Request.Administrator != "admin" || params.Request.IdempotencyKey != "http-capture-request-0001" || params.Request.Name != "case window" {
		t.Fatalf("unexpected capture params: %#v", params)
	}
}

func TestCaptureStartRejectsCallerSuppliedAdministrator(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/captures", `{"name":"bad","mode":"HEADERS_ONLY","administrator":"root"}`, session, "http-capture-request-0002")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unexpected response %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestCaptureStopRequiresIdempotencyAndUsesOnlySessionID(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	result := capture.View{Session: capture.Session{ID: captureTestID, StartedAt: time.Now()}, State: capture.StateRunning, Active: true}
	requests := startGatewayStub(t, socketPath, result)
	server, session := configuredAPIServer(t, socketPath)
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/captures/"+captureTestID+"/stop", `{}`, session, "http-capture-stop-0001")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("unexpected response %d: %s", recorder.Code, recorder.Body.String())
	}
	rpcRequest := <-requests
	var params gatewayprotocol.StopCaptureParams
	if rpcRequest.Method != "StopCapture" || gatewayprotocol.DecodeParams(rpcRequest.Params, &params) != nil || params.SessionID != captureTestID {
		t.Fatalf("unexpected stop request: %s %s", rpcRequest.Method, rpcRequest.Params)
	}
}

func TestCaptureDeletionPreviewUsesOnlyValidatedSessionID(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	preview := coordinatorDeletionPreview(t, 0)
	requests := startGatewayStub(t, socketPath, preview.HostArtifacts)
	events := &captureDeletionEventStub{preview: preview.NormalizedEvents}
	server, session := configuredAPIServerWithConfig(t, socketPath, func(config *Config) {
		config.CaptureEventDeletions = events
		configureAnalyzerDeletionPreviews(config, preview)
	})
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/captures/"+captureTestID+"/deletion-preview", `{}`, session, "")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || !strings.Contains(recorder.Body.String(), preview.PreviewSHA256) || !strings.Contains(recorder.Body.String(), "normalized_events") || !strings.Contains(recorder.Body.String(), "existing_backups") {
		t.Fatalf("unexpected response %d: %s", recorder.Code, recorder.Body.String())
	}
	rpcRequest := <-requests
	var params gatewayprotocol.PreviewCaptureDeletionParams
	if rpcRequest.Method != "PreviewCaptureDeletion" || gatewayprotocol.DecodeParams(rpcRequest.Params, &params) != nil || params.SessionID != captureTestID {
		t.Fatalf("unexpected preview request: %s %s", rpcRequest.Method, rpcRequest.Params)
	}
}

func TestCaptureDeletionCancelIsDurableAndSafeOnlyBeforeBarrier(t *testing.T) {
	preview := coordinatorDeletionPreview(t, 0)
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	record, _, err := server.store.beginCoordinatedCaptureDeletion(preview, "admin", "capture-delete-cancel-create-0001")
	if err != nil {
		t.Fatal(err)
	}
	cancel := authenticatedJSONRequest(http.MethodPost, "/api/v1/capture-deletion-jobs/"+record.Job.ID+"/cancel", `{"password":"`+activationTestPassword+`"}`, session, "capture-delete-cancel-0001")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, cancel)
	var cancelled coordinatedCaptureDeletionJob
	_ = json.Unmarshal(recorder.Body.Bytes(), &cancelled)
	if recorder.Code != http.StatusOK || cancelled.State != coordinatedDeletionCancelled || cancelled.Phase != "CANCELLED_BEFORE_BARRIER" || cancelled.ProgressPercent != 0 || cancelled.CompletedAt == nil || !allBackendsState(cancelled.Backends, deletionBackendNotStarted) {
		t.Fatalf("capture deletion was not cancelled before its barrier: %d %#v", recorder.Code, cancelled)
	}
	replay := authenticatedJSONRequest(http.MethodPost, "/api/v1/capture-deletion-jobs/"+record.Job.ID+"/cancel", `{"password":"`+activationTestPassword+`"}`, session, "capture-delete-cancel-0001")
	replayRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(replayRecorder, replay)
	if replayRecorder.Code != http.StatusOK {
		t.Fatalf("capture deletion cancellation did not replay: %d %s", replayRecorder.Code, replayRecorder.Body.String())
	}
	retry := authenticatedJSONRequest(http.MethodPost, "/api/v1/capture-deletion-jobs/"+record.Job.ID+"/retry", `{"password":"`+activationTestPassword+`"}`, session, "capture-delete-cancel-retry-0001")
	retryRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(retryRecorder, retry)
	if retryRecorder.Code != http.StatusBadRequest {
		t.Fatalf("cancelled deletion accepted retry: %d %s", retryRecorder.Code, retryRecorder.Body.String())
	}
}

func TestCaptureDeletionCancelRejectsBackendProgress(t *testing.T) {
	preview := coordinatorDeletionPreview(t, 0)
	store := NewStore(t.TempDir(), filepath.Join(t.TempDir(), "setup-token"))
	record, _, err := store.beginCoordinatedCaptureDeletion(preview, "admin", "capture-delete-cancel-create-0002")
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.updateCoordinatedCaptureDeletion(record.Job.ID, func(candidate *coordinatedCaptureDeletionRecord) error {
		now := time.Now().UTC().Truncate(time.Microsecond)
		candidate.Job.State, candidate.Job.Phase, candidate.Job.ProgressPercent = coordinatedDeletionRunning, "TOMBSTONES_WRITING", 15
		candidate.Job.UpdatedAt = now
		candidate.Job.Backends[0] = captureDeletionBackendResult{Backend: "normalized_events", State: deletionBackendRunning, UpdatedAt: now}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.cancelCoordinatedCaptureDeletion(record.Job.ID, "capture-delete-cancel-unsafe-0001", "admin"); !errors.Is(err, errCaptureDeletionCancelInvalid) {
		t.Fatalf("capture deletion cancellation crossed its barrier: %v", err)
	}
}

func TestCaptureDeletionReauthenticatesAndBindsActor(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	preview := coordinatorDeletionPreview(t, 0)
	completedAt := time.Now().UTC().Truncate(time.Microsecond)
	hostJob := capture.DeletionJob{Schema: 1, ID: "capture-delete-0123456789abcdef0123456789abcdef", SessionID: captureTestID, State: capture.DeletionCompleted, Phase: "VERIFIED", ProgressPercent: 100, Administrator: "admin", PreviewSHA256: preview.HostArtifacts.PreviewSHA256, Footprint: preview.HostArtifacts.Footprint, RetainedDataClasses: []string{"normalized_event_metadata"}, CreatedAt: completedAt, UpdatedAt: completedAt, CompletedAt: &completedAt}
	requests := startGatewayStub(t, socketPath, hostJob)
	events := &captureDeletionEventStub{preview: preview.NormalizedEvents}
	var zeek, suricata *captureDeletionAnalyzerStub
	server, session := configuredAPIServerWithConfig(t, socketPath, func(config *Config) {
		config.CaptureEventDeletions = events
		zeek, suricata = configureAnalyzerDeletionPreviews(config, preview)
	})
	body, err := json.Marshal(deleteCaptureRequest{Password: activationTestPassword, Preview: preview, Confirmation: captureTestID})
	if err != nil {
		t.Fatal(err)
	}
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/captures/"+captureTestID+"/deletion-jobs", string(body), session, "capture-delete-api-0001")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted || recorder.Header().Get("Cache-Control") != "no-store" || strings.Contains(recorder.Body.String(), activationTestPassword) {
		t.Fatalf("unexpected response %d: %s", recorder.Code, recorder.Body.String())
	}
	var coordinatedJob coordinatedCaptureDeletionJob
	if err := json.Unmarshal(recorder.Body.Bytes(), &coordinatedJob); err != nil || coordinatedJob.State != coordinatedDeletionCompleted || !allBackendsState(coordinatedJob.Backends, deletionBackendCompleted) {
		t.Fatalf("unexpected coordinated deletion job: %#v err=%v", coordinatedJob, err)
	}
	rpcRequest := <-requests
	var params gatewayprotocol.DeleteCaptureParams
	if rpcRequest.Method != "DeleteCapture" || gatewayprotocol.DecodeParams(rpcRequest.Params, &params) != nil || params.Request.SessionID != captureTestID || params.Request.Administrator != "admin" || params.Request.IdempotencyKey != coordinatedJob.ID+"-host" || params.Request.PreviewSHA256 != preview.HostArtifacts.PreviewSHA256 || strings.Contains(string(rpcRequest.Params), activationTestPassword) {
		t.Fatalf("unexpected deletion request: %s %s", rpcRequest.Method, rpcRequest.Params)
	}
	if len(events.deleteRequests) != 1 || events.deleteRequests[0].Actor != "admin" || events.deleteRequests[0].OperationID != coordinatedJob.ID || events.deleteRequests[0].Preview.PreviewSHA256 != preview.NormalizedEvents.PreviewSHA256 {
		t.Fatalf("unexpected normalized-event deletion request: %#v", events.deleteRequests)
	}
	if len(zeek.deleteRequests) != 1 || len(suricata.deleteRequests) != 1 || zeek.deleteRequests[0].OperationID != coordinatedJob.ID || suricata.deleteRequests[0].OperationID != coordinatedJob.ID || zeek.deleteRequests[0].Actor != "admin" || suricata.deleteRequests[0].Actor != "admin" {
		t.Fatalf("unexpected analyzer checkpoint deletion requests: zeek=%#v suricata=%#v", zeek.deleteRequests, suricata.deleteRequests)
	}
	if _, err := server.store.updateCoordinatedCaptureDeletion(coordinatedJob.ID, func(candidate *coordinatedCaptureDeletionRecord) error {
		changed := candidate.Job.Backends[0].NormalizedEvents.CompletedAt.Add(time.Second)
		candidate.Job.Backends[0].NormalizedEvents.CompletedAt = changed
		candidate.Job.Backends[0].NormalizedEvents.Database.CompletedAt = changed
		return nil
	}); err == nil || !strings.Contains(err.Error(), "completed backend") {
		t.Fatalf("completed normalized-event acknowledgement was mutable: %v", err)
	}
	replay := authenticatedJSONRequest(http.MethodPost, "/api/v1/captures/"+captureTestID+"/deletion-jobs", string(body), session, "capture-delete-api-0001")
	replayRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(replayRecorder, replay)
	if replayRecorder.Code != http.StatusAccepted || len(events.deleteRequests) != 1 || len(zeek.deleteRequests) != 1 || len(suricata.deleteRequests) != 1 || !strings.Contains(replayRecorder.Body.String(), coordinatedJob.ID) {
		t.Fatalf("completed deletion did not replay without repeating a backend: %d %s", replayRecorder.Code, replayRecorder.Body.String())
	}
}

func TestCaptureDeletionStopsBeforeHostWhenAnalyzerCheckpointFails(t *testing.T) {
	preview := coordinatorDeletionPreview(t, 0)
	events := &captureDeletionEventStub{preview: preview.NormalizedEvents}
	var zeek, suricata *captureDeletionAnalyzerStub
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) {
		config.CaptureEventDeletions = events
		zeek, suricata = configureAnalyzerDeletionPreviews(config, preview)
		suricata.deleteErr = errors.New("injected Suricata checkpoint failure")
	})
	body, err := json.Marshal(deleteCaptureRequest{Password: activationTestPassword, Preview: preview, Confirmation: captureTestID})
	if err != nil {
		t.Fatal(err)
	}
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/captures/"+captureTestID+"/deletion-jobs", string(body), session, "capture-delete-analyzer-failed-0001")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	var job coordinatedCaptureDeletionJob
	if recorder.Code != http.StatusAccepted || json.Unmarshal(recorder.Body.Bytes(), &job) != nil || job.State != coordinatedDeletionPartial || job.Phase != "SURICATA_CHECKPOINT_FAILED" || job.Backends[0].State != deletionBackendCompleted || job.Backends[1].State != deletionBackendCompleted || job.Backends[2].State != deletionBackendFailed || job.Backends[3].State != deletionBackendNotStarted || len(events.deleteRequests) != 1 || len(zeek.deleteRequests) != 1 || len(suricata.deleteRequests) != 1 {
		t.Fatalf("analyzer failure did not stop before host deletion: %d %#v body=%s", recorder.Code, job, recorder.Body.String())
	}
}

func TestCaptureDeletionRejectsWrongPasswordAndUnknownFields(t *testing.T) {
	preview := coordinatorDeletionPreview(t, 0)
	events := &captureDeletionEventStub{preview: preview.NormalizedEvents}
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) { config.CaptureEventDeletions = events })
	body, err := json.Marshal(deleteCaptureRequest{Password: "wrong", Preview: preview, Confirmation: captureTestID})
	if err != nil {
		t.Fatal(err)
	}
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/captures/"+captureTestID+"/deletion-jobs", string(body), session, "capture-delete-api-0002")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password returned %d: %s", recorder.Code, recorder.Body.String())
	}
	body, err = json.Marshal(map[string]any{"password": activationTestPassword, "preview": preview, "confirmation": captureTestID, "administrator": "root"})
	if err != nil {
		t.Fatal(err)
	}
	request = authenticatedJSONRequest(http.MethodPost, "/api/v1/captures/"+captureTestID+"/deletion-jobs", string(body), session, "capture-delete-api-0003")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("caller-supplied actor returned %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestCaptureDeletionRejectsNewLegacySchemaRequest(t *testing.T) {
	preview := coordinatorDeletionPreview(t, 0)
	preview.Schema = legacyCoordinatedCaptureDeletionSchema
	preview.ZeekCheckpoint = nil
	preview.SuricataCheckpoint = nil
	preview.CopyBoundaries = nil
	preview.DeletedDataClasses = append([]string(nil), legacyCoordinatedCaptureDeletedDataClasses...)
	preview.RetainedDataClasses = append([]string(nil), legacyCoordinatedCaptureRetainedDataClasses...)
	digest, err := coordinatedCaptureDeletionPreviewHash(preview)
	if err != nil {
		t.Fatal(err)
	}
	preview.PreviewSHA256 = digest
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	body, err := json.Marshal(deleteCaptureRequest{Password: activationTestPassword, Preview: preview, Confirmation: captureTestID})
	if err != nil {
		t.Fatal(err)
	}
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/captures/"+captureTestID+"/deletion-jobs", string(body), session, "capture-delete-legacy-rejected-0001")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("new legacy deletion request was accepted: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestCaptureDeletionJobsListIsBoundedEnvelope(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	request := httptest.NewRequest(http.MethodGet, "/api/v1/capture-deletion-jobs", nil)
	request.Host = "shakerproxy.test"
	request.Header.Set("Authorization", "Bearer "+session)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || recorder.Body.String() != "{\"jobs\":[]}\n" {
		t.Fatalf("unexpected jobs response %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestCaptureDeletionPersistsPartialWhenHostBackendFails(t *testing.T) {
	preview := coordinatorDeletionPreview(t, 0)
	events := &captureDeletionEventStub{preview: preview.NormalizedEvents}
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) { config.CaptureEventDeletions = events })
	body, err := json.Marshal(deleteCaptureRequest{Password: activationTestPassword, Preview: preview, Confirmation: captureTestID})
	if err != nil {
		t.Fatal(err)
	}
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/captures/"+captureTestID+"/deletion-jobs", string(body), session, "capture-delete-partial-0001")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	var job coordinatedCaptureDeletionJob
	if recorder.Code != http.StatusAccepted || json.Unmarshal(recorder.Body.Bytes(), &job) != nil || job.State != coordinatedDeletionPartial || job.Backends[0].State != deletionBackendCompleted || job.Backends[3].State != deletionBackendFailed || job.CompletedAt == nil {
		t.Fatalf("host failure was not retained as PARTIAL: %d %#v body=%s", recorder.Code, job, recorder.Body.String())
	}
	getRequest := httptest.NewRequest(http.MethodGet, "/api/v1/capture-deletion-jobs/"+job.ID, nil)
	getRequest.Host = "shakerproxy.test"
	getRequest.Header.Set("Authorization", "Bearer "+session)
	getRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(getRecorder, getRequest)
	if getRecorder.Code != http.StatusOK || !strings.Contains(getRecorder.Body.String(), `"state":"PARTIAL"`) || !strings.Contains(getRecorder.Body.String(), `"state":"COMPLETED"`) || !strings.Contains(getRecorder.Body.String(), `"state":"FAILED"`) {
		t.Fatalf("durable partial job was not queryable: %d %s", getRecorder.Code, getRecorder.Body.String())
	}
}

func TestCaptureDeletionStopsBeforeHostWhenEventBarrierFails(t *testing.T) {
	preview := coordinatorDeletionPreview(t, 0)
	events := &captureDeletionEventStub{preview: preview.NormalizedEvents, deleteErr: errors.New("injected normalized-event backend failure")}
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) { config.CaptureEventDeletions = events })
	body, err := json.Marshal(deleteCaptureRequest{Password: activationTestPassword, Preview: preview, Confirmation: captureTestID})
	if err != nil {
		t.Fatal(err)
	}
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/captures/"+captureTestID+"/deletion-jobs", string(body), session, "capture-delete-failed-0001")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	var job coordinatedCaptureDeletionJob
	if recorder.Code != http.StatusAccepted || json.Unmarshal(recorder.Body.Bytes(), &job) != nil || job.State != coordinatedDeletionFailed || job.Phase != "NORMALIZED_EVENTS_FAILED" || job.Backends[0].State != deletionBackendFailed || job.Backends[1].State != deletionBackendNotStarted || job.Backends[2].State != deletionBackendNotStarted || job.Backends[3].State != deletionBackendNotStarted || job.CompletedAt == nil {
		t.Fatalf("event barrier failure did not stop before host deletion: %d %#v body=%s", recorder.Code, job, recorder.Body.String())
	}
}

func TestCaptureDeletionRetryCompletesPartialWithoutRepeatingCompletedBackend(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	preview := coordinatorDeletionPreview(t, 0)
	events := &captureDeletionEventStub{preview: preview.NormalizedEvents}
	server, session := configuredAPIServerWithConfig(t, socketPath, func(config *Config) {
		config.CaptureEventDeletions = events
		configureAnalyzerDeletionPreviews(config, preview)
	})
	body, err := json.Marshal(deleteCaptureRequest{Password: activationTestPassword, Preview: preview, Confirmation: captureTestID})
	if err != nil {
		t.Fatal(err)
	}
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/captures/"+captureTestID+"/deletion-jobs", string(body), session, "capture-delete-partial-retry-0001")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	var partial coordinatedCaptureDeletionJob
	if recorder.Code != http.StatusAccepted || json.Unmarshal(recorder.Body.Bytes(), &partial) != nil || partial.State != coordinatedDeletionPartial {
		t.Fatalf("failed to create partial operation: %d %s", recorder.Code, recorder.Body.String())
	}

	completedAt := time.Now().UTC().Truncate(time.Microsecond)
	hostJob := capture.DeletionJob{Schema: 1, ID: "capture-delete-1123456789abcdef0123456789abcdef", SessionID: captureTestID, State: capture.DeletionCompleted, Phase: "VERIFIED", ProgressPercent: 100, Administrator: "admin", PreviewSHA256: preview.HostArtifacts.PreviewSHA256, Footprint: preview.HostArtifacts.Footprint, RetainedDataClasses: []string{"normalized_event_metadata"}, CreatedAt: completedAt, UpdatedAt: completedAt, CompletedAt: &completedAt}
	requests := startGatewayStub(t, socketPath, hostJob)
	retry := authenticatedJSONRequest(http.MethodPost, "/api/v1/capture-deletion-jobs/"+partial.ID+"/retry", `{"password":"`+activationTestPassword+`"}`, session, "capture-delete-retry-api-0001")
	retryRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(retryRecorder, retry)
	var completed coordinatedCaptureDeletionJob
	if retryRecorder.Code != http.StatusAccepted || json.Unmarshal(retryRecorder.Body.Bytes(), &completed) != nil || completed.State != coordinatedDeletionCompleted || len(events.deleteRequests) != 1 {
		t.Fatalf("partial retry did not complete safely: %d %#v events=%d body=%s", retryRecorder.Code, completed, len(events.deleteRequests), retryRecorder.Body.String())
	}
	rpcRequest := <-requests
	var params gatewayprotocol.DeleteCaptureParams
	if rpcRequest.Method != "DeleteCapture" || gatewayprotocol.DecodeParams(rpcRequest.Params, &params) != nil || params.Request.IdempotencyKey != partial.ID+"-host" {
		t.Fatalf("unexpected retry host request: %s %s", rpcRequest.Method, rpcRequest.Params)
	}

	replay := authenticatedJSONRequest(http.MethodPost, "/api/v1/capture-deletion-jobs/"+partial.ID+"/retry", `{"password":"`+activationTestPassword+`"}`, session, "capture-delete-retry-api-0001")
	replayRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(replayRecorder, replay)
	if replayRecorder.Code != http.StatusAccepted || !strings.Contains(replayRecorder.Body.String(), `"state":"COMPLETED"`) || len(events.deleteRequests) != 1 {
		t.Fatalf("retry replay repeated work or changed result: %d %s events=%d", replayRecorder.Code, replayRecorder.Body.String(), len(events.deleteRequests))
	}
}

func TestCaptureDeletionRetryRestartsFailedEventBarrier(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	preview := coordinatorDeletionPreview(t, 0)
	events := &captureDeletionEventStub{preview: preview.NormalizedEvents, deleteErr: errors.New("injected normalized-event backend failure")}
	server, session := configuredAPIServerWithConfig(t, socketPath, func(config *Config) {
		config.CaptureEventDeletions = events
		configureAnalyzerDeletionPreviews(config, preview)
	})
	body, err := json.Marshal(deleteCaptureRequest{Password: activationTestPassword, Preview: preview, Confirmation: captureTestID})
	if err != nil {
		t.Fatal(err)
	}
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/captures/"+captureTestID+"/deletion-jobs", string(body), session, "capture-delete-event-retry-0001")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	var failed coordinatedCaptureDeletionJob
	if recorder.Code != http.StatusAccepted || json.Unmarshal(recorder.Body.Bytes(), &failed) != nil || failed.State != coordinatedDeletionFailed {
		t.Fatalf("failed to create failed operation: %d %s", recorder.Code, recorder.Body.String())
	}

	events.deleteErr = nil
	completedAt := time.Now().UTC().Truncate(time.Microsecond)
	hostJob := capture.DeletionJob{Schema: 1, ID: "capture-delete-2123456789abcdef0123456789abcdef", SessionID: captureTestID, State: capture.DeletionCompleted, Phase: "VERIFIED", ProgressPercent: 100, Administrator: "admin", PreviewSHA256: preview.HostArtifacts.PreviewSHA256, Footprint: preview.HostArtifacts.Footprint, RetainedDataClasses: []string{"normalized_event_metadata"}, CreatedAt: completedAt, UpdatedAt: completedAt, CompletedAt: &completedAt}
	requests := startGatewayStub(t, socketPath, hostJob)
	retry := authenticatedJSONRequest(http.MethodPost, "/api/v1/capture-deletion-jobs/"+failed.ID+"/retry", `{"password":"`+activationTestPassword+`"}`, session, "capture-delete-event-retry-api-0001")
	retryRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(retryRecorder, retry)
	if retryRecorder.Code != http.StatusAccepted || !strings.Contains(retryRecorder.Body.String(), `"state":"COMPLETED"`) || len(events.deleteRequests) != 2 {
		t.Fatalf("event retry did not complete: %d %s events=%d", retryRecorder.Code, retryRecorder.Body.String(), len(events.deleteRequests))
	}
	if rpcRequest := <-requests; rpcRequest.Method != "DeleteCapture" {
		t.Fatalf("unexpected retry RPC: %s", rpcRequest.Method)
	}
}

func TestCaptureDeletionRetryRequiresReauthenticationAndIdempotency(t *testing.T) {
	preview := coordinatorDeletionPreview(t, 0)
	events := &captureDeletionEventStub{preview: preview.NormalizedEvents, deleteErr: errors.New("injected normalized-event backend failure")}
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) { config.CaptureEventDeletions = events })
	body, err := json.Marshal(deleteCaptureRequest{Password: activationTestPassword, Preview: preview, Confirmation: captureTestID})
	if err != nil {
		t.Fatal(err)
	}
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/captures/"+captureTestID+"/deletion-jobs", string(body), session, "capture-delete-retry-auth-0001")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	var failed coordinatedCaptureDeletionJob
	if json.Unmarshal(recorder.Body.Bytes(), &failed) != nil {
		t.Fatalf("failed to decode setup operation: %s", recorder.Body.String())
	}
	for name, testCase := range map[string]struct {
		password string
		key      string
		expected int
	}{
		"wrong password": {password: "wrong", key: "capture-delete-retry-auth-0002", expected: http.StatusUnauthorized},
		"missing key":    {password: activationTestPassword, expected: http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			retry := authenticatedJSONRequest(http.MethodPost, "/api/v1/capture-deletion-jobs/"+failed.ID+"/retry", `{"password":"`+testCase.password+`"}`, session, testCase.key)
			retryRecorder := httptest.NewRecorder()
			server.Handler().ServeHTTP(retryRecorder, retry)
			if retryRecorder.Code != testCase.expected {
				t.Fatalf("unexpected response %d: %s", retryRecorder.Code, retryRecorder.Body.String())
			}
		})
	}
}

func TestCaptureDeletionStartupRecoveryCompletesOperationAndRetryEvidence(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	preview := coordinatorDeletionPreview(t, 0)
	events := &captureDeletionEventStub{preview: preview.NormalizedEvents}
	completedAt := time.Now().UTC().Truncate(time.Microsecond)
	hostJob := capture.DeletionJob{Schema: 1, ID: "capture-delete-3123456789abcdef0123456789abcdef", SessionID: captureTestID, State: capture.DeletionCompleted, Phase: "VERIFIED", ProgressPercent: 100, Administrator: "admin", PreviewSHA256: preview.HostArtifacts.PreviewSHA256, Footprint: preview.HostArtifacts.Footprint, RetainedDataClasses: []string{"normalized_event_metadata"}, CreatedAt: completedAt, UpdatedAt: completedAt, CompletedAt: &completedAt}
	requests := startGatewayStub(t, socketPath, hostJob)
	server, _ := configuredAPIServerWithConfig(t, socketPath, func(config *Config) {
		config.CaptureEventDeletions = events
		configureAnalyzerDeletionPreviews(config, preview)
	})
	record, _, err := server.store.beginCoordinatedCaptureDeletion(preview, "admin", "capture-delete-recovery-0001")
	if err != nil {
		t.Fatal(err)
	}
	record, replayed, err := server.store.beginCoordinatedCaptureDeletionRetry(record.Job.ID, "capture-delete-recovery-retry-0001", "admin")
	if err != nil || replayed {
		t.Fatalf("failed to persist interrupted retry: replayed=%t err=%v", replayed, err)
	}
	record.Job, err = server.executeCoordinatedCaptureDeletion(t.Context(), record)
	if err != nil || record.Job.State != coordinatedDeletionCompleted {
		t.Fatalf("failed to simulate terminal result before retry receipt: %#v err=%v", record.Job, err)
	}
	if rpcRequest := <-requests; rpcRequest.Method != "DeleteCapture" {
		t.Fatalf("unexpected recovery setup RPC: %s", rpcRequest.Method)
	}

	server.ResumeCaptureDeletions(t.Context())
	recovered, err := server.store.getCoordinatedCaptureDeletionRecord(record.Job.ID)
	if err != nil || recovered.Job.State != coordinatedDeletionCompleted || len(recovered.Retries) != 1 || recovered.Retries[0].CompletedAt == nil || recovered.Retries[0].ResultState != coordinatedDeletionCompleted || len(events.deleteRequests) != 1 {
		t.Fatalf("startup recovery did not close retry evidence without repeating backends: %#v err=%v events=%d", recovered, err, len(events.deleteRequests))
	}
}

func TestCaptureDeletionStartupRecoveryResumesPendingBackends(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	preview := coordinatorDeletionPreview(t, 0)
	events := &captureDeletionEventStub{preview: preview.NormalizedEvents}
	completedAt := time.Now().UTC().Truncate(time.Microsecond)
	hostJob := capture.DeletionJob{Schema: 1, ID: "capture-delete-4123456789abcdef0123456789abcdef", SessionID: captureTestID, State: capture.DeletionCompleted, Phase: "VERIFIED", ProgressPercent: 100, Administrator: "admin", PreviewSHA256: preview.HostArtifacts.PreviewSHA256, Footprint: preview.HostArtifacts.Footprint, RetainedDataClasses: []string{"normalized_event_metadata"}, CreatedAt: completedAt, UpdatedAt: completedAt, CompletedAt: &completedAt}
	requests := startGatewayStub(t, socketPath, hostJob)
	server, _ := configuredAPIServerWithConfig(t, socketPath, func(config *Config) {
		config.CaptureEventDeletions = events
		configureAnalyzerDeletionPreviews(config, preview)
	})
	record, _, err := server.store.beginCoordinatedCaptureDeletion(preview, "admin", "capture-delete-pending-recovery-0001")
	if err != nil {
		t.Fatal(err)
	}

	server.ResumeCaptureDeletions(t.Context())
	if rpcRequest := <-requests; rpcRequest.Method != "DeleteCapture" {
		t.Fatalf("unexpected startup recovery RPC: %s", rpcRequest.Method)
	}
	recovered, err := server.store.getCoordinatedCaptureDeletionRecord(record.Job.ID)
	if err != nil || recovered.Job.State != coordinatedDeletionCompleted || len(events.deleteRequests) != 1 {
		t.Fatalf("startup did not resume pending backends: %#v err=%v events=%d", recovered.Job, err, len(events.deleteRequests))
	}
}

func TestCaptureRetentionPreviewUsesValidatedBoundedPolicy(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	preview := coordinatorRetentionPreview(t, 0)
	preview.HostRetention.Policy = capture.RetentionPolicyInput{MaxAgeSeconds: 86400, MaxPCAPBytes: 1048576}
	requests := startGatewaySequenceStub(t, socketPath, preview.HostRetention, preview.Selected[0].HostArtifacts)
	events := &captureDeletionEventStub{preview: preview.Selected[0].NormalizedEvents}
	server, session := configuredAPIServerWithConfig(t, socketPath, func(config *Config) {
		config.CaptureEventDeletions = events
		configureAnalyzerDeletionPreviews(config, preview.Selected[0])
	})
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/capture-retention/preview", `{"max_age_seconds":86400,"max_pcap_bytes":1048576}`, session, "")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || !strings.Contains(recorder.Body.String(), `"normalized_event_rows":3`) || !strings.Contains(recorder.Body.String(), `"host_retention"`) {
		t.Fatalf("unexpected retention response %d: %s", recorder.Code, recorder.Body.String())
	}
	rpcRequest := <-requests
	var params gatewayprotocol.PreviewCaptureRetentionParams
	if rpcRequest.Method != "PreviewCaptureRetention" || gatewayprotocol.DecodeParams(rpcRequest.Params, &params) != nil || params.Policy != preview.HostRetention.Policy {
		t.Fatalf("unexpected retention RPC: %s %s", rpcRequest.Method, rpcRequest.Params)
	}
	if rpcRequest = <-requests; rpcRequest.Method != "PreviewCaptureDeletionUntil" {
		t.Fatalf("retention did not freeze selected host deletion evidence: %s", rpcRequest.Method)
	}
	if info, err := os.Stat(filepath.Join(server.store.dataDir, "capture-retention-previews.json")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("retention preview was not persisted privately: %v err=%v", info, err)
	}
}

func TestCaptureRetentionPreviewRejectsUnboundedAndUnknownFields(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	for _, body := range []string{`{"max_age_seconds":0,"max_pcap_bytes":0}`, `{"max_age_seconds":3600,"max_pcap_bytes":0,"device":"all"}`} {
		request := authenticatedJSONRequest(http.MethodPost, "/api/v1/capture-retention/preview", body, session, "")
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("invalid retention policy returned %d: %s", recorder.Code, recorder.Body.String())
		}
	}
}

func TestCaptureRetentionPolicyGetIsNoStore(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	policy := capture.DefaultRetentionPolicy()
	requests := startGatewayStub(t, socketPath, policy)
	server, session := configuredAPIServer(t, socketPath)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/capture-retention/policy", nil)
	request.Host = "shakerproxy.test"
	request.Header.Set("Authorization", "Bearer "+session)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || !strings.Contains(recorder.Body.String(), `"revision":0`) {
		t.Fatalf("unexpected policy response %d: %s", recorder.Code, recorder.Body.String())
	}
	if rpcRequest := <-requests; rpcRequest.Method != "GetCaptureRetentionPolicy" {
		t.Fatalf("unexpected policy RPC: %s", rpcRequest.Method)
	}
}

func TestCaptureRetentionPolicyApplyReauthenticatesAndBindsActor(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	now := time.Now().UTC()
	policy := capture.RetentionPolicy{Schema: 1, Revision: 1, Enabled: true, Rules: capture.RetentionPolicyInput{MaxAgeSeconds: 86400, MaxPCAPBytes: 1048576}, RunEverySeconds: 1800, PreviewSHA256: strings.Repeat("e", 64), UpdatedBy: "admin", UpdatedAt: now}
	requests := startGatewayStub(t, socketPath, policy)
	server, session := configuredAPIServer(t, socketPath)
	body := `{"password":"` + activationTestPassword + `","expected_revision":0,"enabled":true,"rules":{"max_age_seconds":86400,"max_pcap_bytes":1048576},"run_every_seconds":1800,"preview_sha256":"` + policy.PreviewSHA256 + `","preview_expires_at":"` + now.Add(10*time.Minute).Format(time.RFC3339Nano) + `"}`
	request := authenticatedJSONRequest(http.MethodPut, "/api/v1/capture-retention/policy", body, session, "capture-retention-policy-api-0001")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || strings.Contains(recorder.Body.String(), activationTestPassword) {
		t.Fatalf("unexpected apply response %d: %s", recorder.Code, recorder.Body.String())
	}
	rpcRequest := <-requests
	var params gatewayprotocol.ApplyCaptureRetentionPolicyParams
	if rpcRequest.Method != "ApplyCaptureRetentionPolicy" || gatewayprotocol.DecodeParams(rpcRequest.Params, &params) != nil || params.Request.Administrator != "admin" || params.Request.IdempotencyKey != "capture-retention-policy-api-0001" || params.Request.Rules != policy.Rules || strings.Contains(string(rpcRequest.Params), activationTestPassword) {
		t.Fatalf("unexpected apply RPC: %s %s", rpcRequest.Method, rpcRequest.Params)
	}
}

func TestCaptureRetentionPolicyApplyRejectsWrongPassword(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	base := `,"expected_revision":0,"enabled":false,"rules":{"max_age_seconds":86400,"max_pcap_bytes":1048576},"run_every_seconds":1800,"preview_sha256":"` + strings.Repeat("f", 64) + `","preview_expires_at":"2026-09-01T12:10:00Z"}`
	request := authenticatedJSONRequest(http.MethodPut, "/api/v1/capture-retention/policy", `{"password":"wrong"`+base, session, "capture-retention-policy-api-0002")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password returned %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestCaptureRetentionRunReauthenticatesAndBindsActor(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	now := time.Now().UTC()
	preview := coordinatorRetentionPreview(t, 0)
	run := capture.RetentionRun{Schema: 1, ID: "retention-run-0123456789abcdef0123456789abcdef", State: capture.RetentionRunCompleted, Phase: "VERIFIED", PolicyRevision: 1, Policy: capture.RetentionPolicyInput{MaxAgeSeconds: 86400}, PreviewSHA256: preview.HostRetention.PreviewSHA256, Administrator: "admin", Trigger: capture.RetentionTriggerManual, Items: []capture.RetentionRunItem{}, CreatedAt: now, UpdatedAt: now, CompletedAt: &now}
	requests := startGatewayStub(t, socketPath, run)
	server, session := configuredAPIServer(t, socketPath)
	if _, err := server.store.recordCoordinatedCaptureRetentionPreview(preview, "admin"); err != nil {
		t.Fatal(err)
	}
	bodyBytes, _ := json.Marshal(startCaptureRetentionRunRequest{Password: activationTestPassword, PolicyRevision: 1, Preview: preview})
	body := string(bodyBytes)
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/capture-retention/runs", body, session, "capture-retention-run-api-0001")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted || recorder.Header().Get("Cache-Control") != "no-store" || strings.Contains(recorder.Body.String(), activationTestPassword) {
		t.Fatalf("unexpected run response %d: %s", recorder.Code, recorder.Body.String())
	}
	rpcRequest := <-requests
	var params gatewayprotocol.StartCaptureRetentionRunParams
	if rpcRequest.Method != "StartCaptureRetentionRun" || gatewayprotocol.DecodeParams(rpcRequest.Params, &params) != nil || params.Request.Administrator != "admin" || params.Request.IdempotencyKey != "capture-retention-run-api-0001" || params.Request.Trigger != capture.RetentionTriggerManual || params.Request.ScheduledFor != nil || strings.Contains(string(rpcRequest.Params), activationTestPassword) {
		t.Fatalf("unexpected run RPC: %s %s", rpcRequest.Method, rpcRequest.Params)
	}
}

func TestCaptureRetentionRunCoordinatesEventsBeforeHostDeletion(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	reviewed := coordinatorRetentionPreview(t, 0)
	preview := reviewed.Selected[0]
	now := time.Now().UTC().Truncate(time.Microsecond)
	run := capture.RetentionRun{Schema: 1, ID: "retention-run-1123456789abcdef0123456789abcdef", State: capture.RetentionRunPending, Phase: "RECORDING_INTENT", PolicyRevision: 1, Policy: capture.RetentionPolicyInput{MaxPCAPBytes: 1}, PreviewSHA256: reviewed.HostRetention.PreviewSHA256, Administrator: "admin", Trigger: capture.RetentionTriggerManual, SelectedSessions: 1, RemainingFiles: preview.HostArtifacts.Footprint.TotalFiles(), RemainingBytes: preview.HostArtifacts.Footprint.TotalBytes(), CreatedAt: now, UpdatedAt: now, Items: []capture.RetentionRunItem{{SessionID: captureTestID, Name: "retention fixture", Reasons: []string{"MAX_PCAP_BYTES"}, Footprint: preview.HostArtifacts.Footprint, State: capture.RetentionItemPending, DeletionPreviewSHA256: preview.HostArtifacts.PreviewSHA256, DeletionPreviewExpiresAt: preview.HostArtifacts.ExpiresAt, DeletionIdempotencyKey: "retention-delete-coordinated-0001", UpdatedAt: now}}}
	completedAt := now.Add(time.Second)
	hostJob := capture.DeletionJob{Schema: 1, ID: "capture-delete-5123456789abcdef0123456789abcdef", SessionID: captureTestID, State: capture.DeletionCompleted, Phase: "VERIFIED", ProgressPercent: 100, Administrator: "admin", PreviewSHA256: preview.HostArtifacts.PreviewSHA256, Footprint: preview.HostArtifacts.Footprint, RetainedDataClasses: []string{"normalized_event_metadata"}, CreatedAt: now, UpdatedAt: completedAt, CompletedAt: &completedAt}
	completed := run
	completed.State, completed.Phase, completed.DeletedSessions, completed.RemainingFiles, completed.RemainingBytes = capture.RetentionRunCompleted, "VERIFIED", 1, 0, 0
	completed.UpdatedAt, completed.CompletedAt = completedAt, &completedAt
	completed.Items = append([]capture.RetentionRunItem(nil), run.Items...)
	completed.Items[0].State, completed.Items[0].DeletionJobID, completed.Items[0].UpdatedAt = capture.RetentionItemDeleted, hostJob.ID, completedAt
	outcomeResponse := func(request gatewayprotocol.Request) any {
		var params gatewayprotocol.RecordCaptureRetentionItemOutcomeParams
		if gatewayprotocol.DecodeParams(request.Params, &params) != nil {
			return completed
		}
		result := completed
		result.Items = append([]capture.RetentionRunItem(nil), completed.Items...)
		result.Items[0].CoordinatedDeletionJobID = params.Request.CoordinatedDeletionJobID
		return result
	}
	requests := startGatewaySequenceStub(t, socketPath, run, hostJob, outcomeResponse)
	events := &captureDeletionEventStub{preview: preview.NormalizedEvents}
	server, session := configuredAPIServerWithConfig(t, socketPath, func(config *Config) { config.CaptureEventDeletions = events })
	if _, err := server.store.recordCoordinatedCaptureRetentionPreview(reviewed, "admin"); err != nil {
		t.Fatal(err)
	}
	bodyBytes, _ := json.Marshal(startCaptureRetentionRunRequest{Password: activationTestPassword, PolicyRevision: 1, Preview: reviewed})
	body := string(bodyBytes)
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/capture-retention/runs", body, session, "capture-retention-coordinated-api-0001")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted || !strings.Contains(recorder.Body.String(), `"state":"COMPLETED"`) || len(events.deleteRequests) != 1 {
		t.Fatalf("retention did not coordinate both backends: %d %s events=%d", recorder.Code, recorder.Body.String(), len(events.deleteRequests))
	}
	received := make([]gatewayprotocol.Request, 0, 3)
	for rpcRequest := range requests {
		received = append(received, rpcRequest)
	}
	if len(received) != 3 || received[0].Method != "StartCaptureRetentionRun" || received[1].Method != "DeleteCapture" || received[2].Method != "RecordCaptureRetentionItemOutcome" {
		t.Fatalf("unexpected coordinated retention RPC sequence: %#v", received)
	}
	var deleteParams gatewayprotocol.DeleteCaptureParams
	if gatewayprotocol.DecodeParams(received[1].Params, &deleteParams) != nil || deleteParams.Request.Administrator != "admin" {
		t.Fatalf("host deletion actor was not bound: %s", received[1].Params)
	}
	var outcomeParams gatewayprotocol.RecordCaptureRetentionItemOutcomeParams
	if gatewayprotocol.DecodeParams(received[2].Params, &outcomeParams) != nil || outcomeParams.Request.State != capture.RetentionItemDeleted || outcomeParams.Request.DeletionJobID != hostJob.ID || !coordinatedCaptureDeletionIDPattern.MatchString(outcomeParams.Request.CoordinatedDeletionJobID) {
		t.Fatalf("retention outcome lacked coordinated evidence: %s", received[2].Params)
	}
	if events.deleteRequests[0].Actor != "admin" || events.deleteRequests[0].OperationID != outcomeParams.Request.CoordinatedDeletionJobID {
		t.Fatalf("normalized-event deletion was not bound to retention operation: %#v", events.deleteRequests[0])
	}
}

func TestAutomaticCaptureRetentionCoordinatesEventsBeforeHostDeletion(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	preview := coordinatorDeletionPreview(t, 0)
	now := time.Now().UTC().Truncate(time.Microsecond)
	scheduledFor := now
	run := capture.RetentionRun{Schema: 1, ID: "retention-run-2123456789abcdef0123456789abcdef", State: capture.RetentionRunPending, Phase: "RECORDING_INTENT", PolicyRevision: 2, Policy: capture.RetentionPolicyInput{MaxPCAPBytes: 1}, PreviewSHA256: strings.Repeat("8", 64), Administrator: "system:retention", Trigger: capture.RetentionTriggerAutomatic, ScheduledFor: &scheduledFor, SelectedSessions: 1, RemainingFiles: preview.HostArtifacts.Footprint.TotalFiles(), RemainingBytes: preview.HostArtifacts.Footprint.TotalBytes(), CreatedAt: now, UpdatedAt: now, Items: []capture.RetentionRunItem{{SessionID: captureTestID, Name: "automatic retention fixture", Reasons: []string{"MAX_PCAP_BYTES"}, Footprint: preview.HostArtifacts.Footprint, State: capture.RetentionItemPending, DeletionPreviewSHA256: preview.HostArtifacts.PreviewSHA256, DeletionPreviewExpiresAt: preview.HostArtifacts.ExpiresAt, DeletionIdempotencyKey: "retention-delete-automatic-0001", UpdatedAt: now}}}
	completedAt := now.Add(time.Second)
	hostJob := capture.DeletionJob{Schema: 1, ID: "capture-delete-6123456789abcdef0123456789abcdef", SessionID: captureTestID, State: capture.DeletionCompleted, Phase: "VERIFIED", ProgressPercent: 100, Administrator: "system:retention", PreviewSHA256: preview.HostArtifacts.PreviewSHA256, Footprint: preview.HostArtifacts.Footprint, RetainedDataClasses: []string{"normalized_event_metadata"}, CreatedAt: now, UpdatedAt: completedAt, CompletedAt: &completedAt}
	completed := run
	completed.State, completed.Phase, completed.DeletedSessions, completed.RemainingFiles, completed.RemainingBytes = capture.RetentionRunCompleted, "VERIFIED", 1, 0, 0
	completed.UpdatedAt, completed.CompletedAt = completedAt, &completedAt
	completed.Items = append([]capture.RetentionRunItem(nil), run.Items...)
	completed.Items[0].State, completed.Items[0].DeletionJobID, completed.Items[0].UpdatedAt = capture.RetentionItemDeleted, hostJob.ID, completedAt
	outcomeResponse := func(request gatewayprotocol.Request) any {
		var params gatewayprotocol.RecordCaptureRetentionItemOutcomeParams
		_ = gatewayprotocol.DecodeParams(request.Params, &params)
		result := completed
		result.Items = append([]capture.RetentionRunItem(nil), completed.Items...)
		result.Items[0].CoordinatedDeletionJobID = params.Request.CoordinatedDeletionJobID
		return result
	}
	tick := capture.RetentionSchedulerTick{Status: capture.RetentionSchedulerStatus{Schema: 1, Enabled: true, PolicyRevision: 2, CheckedAt: now}, Run: &run}
	requests := startGatewaySequenceStub(t, socketPath, []capture.RetentionRun{}, tick, preview.HostArtifacts, hostJob, outcomeResponse)
	events := &captureDeletionEventStub{preview: preview.NormalizedEvents}
	server, _ := configuredAPIServerWithConfig(t, socketPath, func(config *Config) {
		config.CaptureEventDeletions = events
		configureAnalyzerDeletionPreviews(config, preview)
	})
	if err := server.RunCaptureRetentionSchedulerOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	received := make([]gatewayprotocol.Request, 0, 5)
	for rpcRequest := range requests {
		received = append(received, rpcRequest)
	}
	if len(received) != 5 || received[0].Method != "ListCaptureRetentionRuns" || received[1].Method != "RunCaptureRetentionSchedulerOnce" || received[2].Method != "PreviewCaptureDeletionUntil" || received[3].Method != "DeleteCapture" || received[4].Method != "RecordCaptureRetentionItemOutcome" {
		t.Fatalf("unexpected automatic retention RPC sequence: %#v", received)
	}
	if len(events.deleteRequests) != 1 || events.deleteRequests[0].Actor != "system:retention" {
		t.Fatalf("automatic retention did not bind system actor to event deletion: %#v", events.deleteRequests)
	}
}

func TestCaptureRetentionStopsBeforeHostWhenEventDeletionFails(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	reviewed := coordinatorRetentionPreview(t, 0)
	preview := reviewed.Selected[0]
	now := time.Now().UTC().Truncate(time.Microsecond)
	run := capture.RetentionRun{Schema: 1, ID: "retention-run-3123456789abcdef0123456789abcdef", State: capture.RetentionRunPending, Phase: "RECORDING_INTENT", PolicyRevision: 1, Policy: capture.RetentionPolicyInput{MaxPCAPBytes: 1}, PreviewSHA256: reviewed.HostRetention.PreviewSHA256, Administrator: "admin", Trigger: capture.RetentionTriggerManual, SelectedSessions: 1, RemainingFiles: preview.HostArtifacts.Footprint.TotalFiles(), RemainingBytes: preview.HostArtifacts.Footprint.TotalBytes(), CreatedAt: now, UpdatedAt: now, Items: []capture.RetentionRunItem{{SessionID: captureTestID, Name: "failed retention fixture", Reasons: []string{"MAX_PCAP_BYTES"}, Footprint: preview.HostArtifacts.Footprint, State: capture.RetentionItemPending, DeletionPreviewSHA256: preview.HostArtifacts.PreviewSHA256, DeletionPreviewExpiresAt: preview.HostArtifacts.ExpiresAt, DeletionIdempotencyKey: "retention-delete-event-failure-0001", UpdatedAt: now}}}
	failedResponse := func(request gatewayprotocol.Request) any {
		var params gatewayprotocol.RecordCaptureRetentionItemOutcomeParams
		_ = gatewayprotocol.DecodeParams(request.Params, &params)
		result := run
		result.State, result.Phase, result.FailedSessions = capture.RetentionRunFailed, "VERIFIED", 1
		result.CompletedAt = &now
		result.Items = append([]capture.RetentionRunItem(nil), run.Items...)
		result.Items[0].State, result.Items[0].CoordinatedDeletionJobID, result.Items[0].Failure = capture.RetentionItemFailed, params.Request.CoordinatedDeletionJobID, params.Request.Failure
		return result
	}
	requests := startGatewaySequenceStub(t, socketPath, run, failedResponse)
	events := &captureDeletionEventStub{preview: preview.NormalizedEvents, deleteErr: errors.New("injected retention event deletion failure")}
	server, session := configuredAPIServerWithConfig(t, socketPath, func(config *Config) { config.CaptureEventDeletions = events })
	if _, err := server.store.recordCoordinatedCaptureRetentionPreview(reviewed, "admin"); err != nil {
		t.Fatal(err)
	}
	bodyBytes, _ := json.Marshal(startCaptureRetentionRunRequest{Password: activationTestPassword, PolicyRevision: 1, Preview: reviewed})
	body := string(bodyBytes)
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/capture-retention/runs", body, session, "capture-retention-event-failure-api-0001")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted || !strings.Contains(recorder.Body.String(), `"state":"FAILED"`) || len(events.deleteRequests) != 1 {
		t.Fatalf("retention event failure was not authoritative: %d %s events=%d", recorder.Code, recorder.Body.String(), len(events.deleteRequests))
	}
	received := make([]gatewayprotocol.Request, 0, 2)
	for rpcRequest := range requests {
		received = append(received, rpcRequest)
	}
	if len(received) != 2 || received[0].Method != "StartCaptureRetentionRun" || received[1].Method != "RecordCaptureRetentionItemOutcome" {
		t.Fatalf("host deletion ran after retention event failure: %#v", received)
	}
}

func TestCaptureRetentionSchedulerStatusIsNoStore(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	now := time.Now().UTC()
	next := now.Add(time.Hour)
	status := capture.RetentionSchedulerStatus{Schema: 1, Enabled: true, PolicyRevision: 2, CheckedAt: now, NextRunAt: &next}
	requests := startGatewayStub(t, socketPath, status)
	server, session := configuredAPIServer(t, socketPath)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/capture-retention/scheduler", nil)
	request.Host = "shakerproxy.test"
	request.Header.Set("Authorization", "Bearer "+session)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || !strings.Contains(recorder.Body.String(), next.Format(time.RFC3339Nano)) {
		t.Fatalf("unexpected scheduler response %d: %s", recorder.Code, recorder.Body.String())
	}
	if rpcRequest := <-requests; rpcRequest.Method != "GetCaptureRetentionSchedulerStatus" {
		t.Fatalf("unexpected scheduler RPC: %s", rpcRequest.Method)
	}
}

func TestCaptureRetentionRunsListUsesBoundedEnvelope(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	requests := startGatewayStub(t, socketPath, []capture.RetentionRun{})
	server, session := configuredAPIServer(t, socketPath)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/capture-retention/runs", nil)
	request.Host = "shakerproxy.test"
	request.Header.Set("Authorization", "Bearer "+session)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || recorder.Body.String() != "{\"runs\":[]}\n" {
		t.Fatalf("unexpected runs response %d: %s", recorder.Code, recorder.Body.String())
	}
	if rpcRequest := <-requests; rpcRequest.Method != "ListCaptureRetentionRuns" {
		t.Fatalf("unexpected runs RPC: %s", rpcRequest.Method)
	}
}

func TestCaptureEndpointsRequireAuthentication(t *testing.T) {
	server, _ := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	for _, endpoint := range []struct{ method, target, body string }{
		{http.MethodGet, "/api/v1/captures", ""},
		{http.MethodPost, "/api/v1/captures/" + captureTestID + "/deletion-preview", `{}`},
		{http.MethodPost, "/api/v1/captures/" + captureTestID + "/deletion-jobs", `{}`},
		{http.MethodGet, "/api/v1/capture-deletion-jobs", ""},
		{http.MethodGet, "/api/v1/capture-deletion-jobs/capture-delete-operation-0123456789abcdef0123456789abcdef", ""},
		{http.MethodPost, "/api/v1/capture-deletion-jobs/capture-delete-operation-0123456789abcdef0123456789abcdef/retry", `{}`},
		{http.MethodPost, "/api/v1/devices/device-0123456789abcdef0123456789abcdef/traffic-deletion-jobs", `{}`},
		{http.MethodGet, "/api/v1/device-traffic-deletion-jobs", ""},
		{http.MethodGet, "/api/v1/device-traffic-deletion-jobs/device-traffic-delete-0123456789abcdef0123456789abcdef", ""},
		{http.MethodPost, "/api/v1/device-traffic-deletion-jobs/device-traffic-delete-0123456789abcdef0123456789abcdef/retry", `{}`},
		{http.MethodPost, "/api/v1/device-traffic-deletion-jobs/device-traffic-delete-0123456789abcdef0123456789abcdef/cancel", `{}`},
		{http.MethodPost, "/api/v1/capture-retention/preview", `{}`},
		{http.MethodGet, "/api/v1/capture-retention/policy", ""},
		{http.MethodPut, "/api/v1/capture-retention/policy", `{}`},
		{http.MethodPost, "/api/v1/capture-retention/runs", `{}`},
		{http.MethodGet, "/api/v1/capture-retention/runs", ""},
		{http.MethodGet, "/api/v1/capture-retention/scheduler", ""},
	} {
		request := httptest.NewRequest(endpoint.method, endpoint.target, strings.NewReader(endpoint.body))
		request.Host = "shakerproxy.test"
		if endpoint.body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s returned %d: %s", endpoint.method, endpoint.target, recorder.Code, recorder.Body.String())
		}
	}
}

func TestCaptureExportRequiresReauthentication(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/captures/"+captureTestID+"/files/capture_00001.pcapng/export", `{"password":"wrong"}`, session, "")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected response %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestCaptureExportStreamsManifestBoundRangeAndRecordsHistory(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	content := []byte("0123456789abcdef")
	hash := "9f9f5111f7b27a781f1f1ddde5ebc2dd2b796bfc7365c9c28b548e564176929f"
	manifest := &capture.Manifest{Schema: 1, SessionID: captureTestID, Files: []capture.CaptureFile{{Name: "capture_00001.pcapng", SizeBytes: int64(len(content)), SHA256: hash}}}
	requests := startCaptureExportGatewayStub(t, socketPath, capture.View{Session: capture.Session{ID: captureTestID}, State: capture.StateCompleted, Manifest: manifest}, content, hash)
	server, session := configuredAPIServer(t, socketPath)
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/captures/"+captureTestID+"/files/capture_00001.pcapng/export", `{"password":"`+activationTestPassword+`"}`, session, "")
	request.Header.Set("Range", "bytes=4-9")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusPartialContent || recorder.Body.String() != "456789" {
		t.Fatalf("unexpected response %d: %q", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Content-Range") != "bytes 4-9/16" || recorder.Header().Get("X-ShakerProxy-SHA256") != hash || recorder.Header().Get("Accept-Ranges") != "bytes" {
		t.Fatalf("missing export integrity headers: %#v", recorder.Header())
	}
	first, second := <-requests, <-requests
	if first.Method != "GetCaptureStats" || second.Method != "ReadCaptureArtifact" {
		t.Fatalf("unexpected RPC sequence: %s, %s", first.Method, second.Method)
	}
	var params gatewayprotocol.ReadCaptureArtifactParams
	if gatewayprotocol.DecodeParams(second.Params, &params) != nil || params.FileName != "capture_00001.pcapng" || params.Offset != 4 || params.Length != 6 {
		t.Fatalf("unexpected artifact read parameters: %#v", params)
	}
	records, err := server.store.ListCaptureExports(captureTestID)
	if err != nil || len(records) != 1 || !records[0].Complete || records[0].BytesSent != 6 || records[0].Username != "admin" {
		t.Fatalf("unexpected export history: %#v, %v", records, err)
	}
}

func TestCaptureExportRejectsTraversalAndInvalidRanges(t *testing.T) {
	if validCaptureArtifactName("../session.json") || validCaptureArtifactName("nested/capture.pcapng") || validCaptureArtifactName("capture.pcapng\nX: injected") {
		t.Fatal("accepted unsafe capture artifact name")
	}
	if _, _, _, err := parseByteRange("bytes=-5", 16); err == nil {
		t.Fatal("accepted suffix range")
	}
	if _, _, _, err := parseByteRange("bytes=0-1,4-5", 16); err == nil {
		t.Fatal("accepted multiple ranges")
	}
	start, end, partial, err := parseByteRange("bytes=10-", 16)
	if err != nil || start != 10 || end != 15 || !partial {
		t.Fatalf("open-ended range failed: %d %d %v %v", start, end, partial, err)
	}
}

func startCaptureExportGatewayStub(t *testing.T, socketPath string, view capture.View, content []byte, hash string) <-chan gatewayprotocol.Request {
	t.Helper()
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan gatewayprotocol.Request, 4)
	go func() {
		defer listener.Close()
		for index := 0; index < 2; index++ {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			var request gatewayprotocol.Request
			if json.NewDecoder(connection).Decode(&request) != nil {
				connection.Close()
				return
			}
			requests <- request
			result := any(view)
			if request.Method == "ReadCaptureArtifact" {
				var params gatewayprotocol.ReadCaptureArtifactParams
				if gatewayprotocol.DecodeParams(request.Params, &params) != nil {
					connection.Close()
					return
				}
				end := min(int64(len(content)), params.Offset+int64(params.Length))
				result = capture.ArtifactChunk{SessionID: captureTestID, FileName: params.FileName, FileSHA256: hash, Offset: params.Offset, TotalBytes: int64(len(content)), Data: content[params.Offset:end], EOF: end == int64(len(content))}
			}
			_ = json.NewEncoder(connection).Encode(gatewayprotocol.Response{JSONRPC: gatewayprotocol.JSONRPCVersion, ID: request.ID, Result: result})
			connection.Close()
		}
	}()
	return requests
}
