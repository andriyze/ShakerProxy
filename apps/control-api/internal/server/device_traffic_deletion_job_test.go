package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/analyzer"
	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/ingest"
	"shakerproxy.dev/shakerproxy/internal/pcapng"
)

func deviceTrafficDeletionJobPreview(t *testing.T) deviceTrafficDeletionPreview {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	start, end := now.Add(-2*time.Hour), now.Add(-time.Hour)
	identityStart, identityEnd := start, end
	rule, err := pcapng.CanonicalWindowedSelectionRule([]pcapng.SelectionIdentity{{Kind: pcapng.SelectionIdentityIP, Value: "10.77.0.111", StartAt: &identityStart, EndAt: &identityEnd}})
	if err != nil {
		t.Fatal(err)
	}
	selection, err := eventSelectionFromPCAP("device-0123456789abcdef0123456789abcdef", start, end, rule)
	if err != nil {
		t.Fatal(err)
	}
	canonical := "device.id:" + selection.DeviceID + " AND time>=" + start.Format(time.RFC3339Nano) + " AND time<" + end.Format(time.RFC3339Nano)
	snapshot := ingest.EventQuerySnapshot{
		Schema: 1, ID: "qsnap-0123456789abcdef0123456789abcdef", CanonicalQuery: canonical, Sort: ingest.DefaultEventQuerySort(),
		MatchedCount: 0, CountRelation: "eq", CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute),
		DatasetWatermark: ingest.EventDatasetWatermark{ReceivedAt: now, RecordID: strings.Repeat("a", 64)}, SnapshotSHA256: strings.Repeat("b", 64), PolicyVersion: ingest.QuerySnapshotPolicyVersion,
	}
	selectionSHA, _ := selection.SHA256()
	database := ingest.EventSelectionDeletionPreview{
		Schema: 1, Actor: "admin", Selection: selection, SelectionSHA256: selectionSHA, QuerySnapshot: snapshot,
		Database: ingest.EventSelectionDatabaseFootprint{}, DatabaseReclaimMode: ingest.DatabaseReclaimDeferred,
		GeneratedAt: now.Add(time.Microsecond), ExpiresAt: snapshot.ExpiresAt,
	}
	database.PreviewSHA256 = deviceDeletionTestDigest(database)
	bundle := ingest.EventSelectionDeletionBundle{
		Schema: 1, Actor: "admin", Selection: selection, SelectionSHA256: selectionSHA, QuerySnapshot: snapshot,
		Spool: ingest.EventSelectionSpoolFootprint{}, Database: database, DatabaseReclaimMode: ingest.DatabaseReclaimDeferred,
		GeneratedAt: database.GeneratedAt, ExpiresAt: database.ExpiresAt,
	}
	bundle.PreviewSHA256 = deviceDeletionTestDigest(bundle)
	pcap := capture.PCAPSelectionImpact{
		Schema: 1, Selection: rule, SelectionSHA256: selectionDigest(rule), GeneratedAt: now.Add(2 * time.Microsecond),
		ImpactedFiles: []capture.PCAPSelectionFileImpact{}, Blockers: []capture.PCAPSelectionBlocker{}, Exact: true,
	}
	choices, exact := buildDeviceTrafficChoices(bundle, nil, nil, pcap)
	preview := deviceTrafficDeletionPreview{
		Schema: deviceTrafficPreviewSchema, GeneratedAt: now.Add(3 * time.Microsecond), ExpiresAt: bundle.ExpiresAt,
		DeviceID: selection.DeviceID, DeviceName: "fixture", StartAt: start, EndAt: end, InventoryEvidenceAsOf: now,
		IdentityEvidenceCoversRange: true, CapabilityLimitations: []string{"time-bounded IPv6 device-address evidence is not yet indexed"},
		NormalizedEvents: snapshot, NormalizedEventDeletion: bundle, PCAP: pcap, Choices: choices, ExactImpact: exact,
		SecureErasureGuaranteed: false, Confirmation: selection.DeviceID,
	}
	preview.PreviewSHA256, err = hashDeviceTrafficPreview(preview)
	if err != nil || preview.validate() != nil {
		t.Fatalf("invalid job preview: %#v err=%v", preview, err)
	}
	return preview
}

func sanitizedDeviceTrafficDeletionJobPreview(t *testing.T) deviceTrafficDeletionPreview {
	t.Helper()
	preview := deviceTrafficDeletionJobPreview(t)
	sessionID := "capture-0123456789abcdef0123456789abcdef"
	now := preview.GeneratedAt
	preview.PCAP.EvaluatedSessions, preview.PCAP.EvaluatedFiles, preview.PCAP.ScannedBytes, preview.PCAP.AvailableBytes = 1, 1, 4096, 8<<30
	preview.PCAP.ImpactedFiles = []capture.PCAPSelectionFileImpact{{
		SessionID: sessionID, FileName: "capture.pcapng", OriginalSHA256: strings.Repeat("c", 64), OriginalBytes: 4096,
		SanitizedBytes: 3072, PacketsRead: 10, MatchedPackets: 4, CollateralPacketsInWholeDelete: 6,
		RetainedIPAddresses: 1, RetainedIdentitySHA256: strings.Repeat("d", 64), RetainedIPSample: []string{"10.77.0.222"},
		TemporaryBytesRequired: 4096, TemporaryCapacityAvailable: true,
	}}
	preview.WholeCaptureEvents = []ingest.CaptureEventDeletionPreview{deviceTrafficCaptureEventPreview(t, sessionID, now, 12)}
	zeek := analyzerDeletionPreviewForSession(t, analyzer.EngineZeek, sessionID, now)
	suricata := analyzerDeletionPreviewForSession(t, analyzer.EngineSuricata, sessionID, now)
	preview.AnalyzerReindex = []deviceTrafficAnalyzerImpact{{SessionID: sessionID, Zeek: zeek, Suricata: suricata}}
	preview.Choices, preview.ExactImpact = buildDeviceTrafficChoices(preview.NormalizedEventDeletion, preview.WholeCaptureEvents, preview.AnalyzerReindex, preview.PCAP)
	preview.PreviewSHA256, _ = hashDeviceTrafficPreview(preview)
	if err := preview.validate(); err != nil {
		t.Fatalf("invalid sanitize preview: %v", err)
	}
	return preview
}

func deviceTrafficCaptureEventPreview(t *testing.T, sessionID string, now time.Time, rows int64) ingest.CaptureEventDeletionPreview {
	t.Helper()
	identities := rows / 2
	preview, err := (ingest.CaptureEventDeletionPlanner{
		Spool: &ingest.Spool{Root: filepath.Join(t.TempDir(), "spool"), MaxBytes: 8 << 20, ReserveBytes: 1},
		Database: coordinatorFootprintReader{footprint: ingest.CaptureEventDatabaseFootprint{
			EventRows: rows, ExclusiveIdentityRows: identities, EventLogicalBytes: rows * 256,
			IdentityLogicalBytes: identities * 128, MaxIngestSequence: rows,
		}},
		Now: func() time.Time { return now },
	}).Preview(t.Context(), sessionID)
	if err != nil {
		t.Fatal(err)
	}
	return preview
}

func createDeviceTrafficDeletionBody(t *testing.T, preview deviceTrafficDeletionPreview) string {
	t.Helper()
	encoded, err := json.Marshal(createDeviceTrafficDeletionRequest{Password: activationTestPassword, Preview: preview, Choice: capture.DeleteMetadataOnly, Confirmation: preview.DeviceID})
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestDeviceTrafficMetadataDeletionJobIsDurableAndIdempotent(t *testing.T) {
	preview := deviceTrafficDeletionJobPreview(t)
	selection := &deviceDeletionSelectionService{}
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "gateway.sock"), func(config *Config) {
		config.EventSelectionDeletions = selection
	})
	body := createDeviceTrafficDeletionBody(t, preview)
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/devices/"+preview.DeviceID+"/traffic-deletion-jobs", body, session, "device-traffic-job-create-0001")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected device deletion response %d: %s", recorder.Code, recorder.Body.String())
	}
	var job deviceTrafficDeletionJob
	if err := json.Unmarshal(recorder.Body.Bytes(), &job); err != nil {
		t.Fatal(err)
	}
	if job.State != deviceTrafficDeletionCompleted || job.Phase != "COMPLETED" || job.NormalizedEvents == nil || selection.deleteCalls != 1 || selection.deleteRequest.OperationID != job.ID {
		t.Fatalf("metadata deletion did not complete durably: %#v calls=%d", job, selection.deleteCalls)
	}
	replay := authenticatedJSONRequest(http.MethodPost, "/api/v1/devices/"+preview.DeviceID+"/traffic-deletion-jobs", body, session, "device-traffic-job-create-0001")
	replayRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(replayRecorder, replay)
	var replayed deviceTrafficDeletionJob
	_ = json.Unmarshal(replayRecorder.Body.Bytes(), &replayed)
	if replayRecorder.Code != http.StatusAccepted || replayed.ID != job.ID || selection.deleteCalls != 1 {
		t.Fatalf("initial request replay repeated mutation: %d %#v calls=%d", replayRecorder.Code, replayed, selection.deleteCalls)
	}
	info, err := os.Stat(filepath.Join(server.store.dataDir, "device-traffic-deletions.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("device deletion ledger mode is unsafe: %v", info.Mode())
	}
	list := authenticatedJSONRequest(http.MethodGet, "/api/v1/device-traffic-deletion-jobs", "", session, "")
	listRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(listRecorder, list)
	if listRecorder.Code != http.StatusOK || !strings.Contains(listRecorder.Body.String(), job.ID) {
		t.Fatalf("job listing failed %d: %s", listRecorder.Code, listRecorder.Body.String())
	}
}

func TestDeviceTrafficDerivedDeletionCoordinatesConfiguredStoresAndRetainsPCAP(t *testing.T) {
	preview := sanitizedDeviceTrafficDeletionJobPreview(t)
	selection := &deviceDeletionSelectionService{}
	zeekPreview, suricataPreview := preview.AnalyzerReindex[0].Zeek, preview.AnalyzerReindex[0].Suricata
	zeek := &captureDeletionAnalyzerStub{engine: analyzer.EngineZeek, preview: &zeekPreview}
	suricata := &captureDeletionAnalyzerStub{engine: analyzer.EngineSuricata, preview: &suricataPreview}
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "gateway.sock"), func(config *Config) {
		config.EventSelectionDeletions = selection
		config.ZeekCheckpointDeletions = zeek
		config.SuricataCheckpointDeletions = suricata
	})
	bodyBytes, err := json.Marshal(createDeviceTrafficDeletionRequest{Password: activationTestPassword, Preview: preview, Choice: capture.DeleteDerivedContentOnly, Confirmation: preview.DeviceID})
	if err != nil {
		t.Fatal(err)
	}
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/devices/"+preview.DeviceID+"/traffic-deletion-jobs", string(bodyBytes), session, "device-traffic-derived-0001")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	var job deviceTrafficDeletionJob
	_ = json.Unmarshal(recorder.Body.Bytes(), &job)
	if recorder.Code != http.StatusAccepted || job.State != deviceTrafficDeletionCompleted || job.Choice != capture.DeleteDerivedContentOnly || job.NormalizedEvents == nil || len(job.AnalyzerCheckpoints) != 2 || len(job.PCAPRewrites) != 0 || len(job.PCAPDeletions) != 0 || len(job.AnalyzerReindexes) != 0 || selection.deleteCalls != 1 || len(zeek.deleteRequests) != 1 || len(suricata.deleteRequests) != 1 {
		t.Fatalf("derived deletion did not coordinate only configured derived stores: status=%d job=%#v", recorder.Code, job)
	}
	replay := authenticatedJSONRequest(http.MethodPost, "/api/v1/devices/"+preview.DeviceID+"/traffic-deletion-jobs", string(bodyBytes), session, "device-traffic-derived-0001")
	replayRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(replayRecorder, replay)
	if replayRecorder.Code != http.StatusAccepted || selection.deleteCalls != 1 || len(zeek.deleteRequests) != 1 || len(suricata.deleteRequests) != 1 {
		t.Fatalf("derived deletion replay repeated a completed backend: %d %s", replayRecorder.Code, replayRecorder.Body.String())
	}
}

func TestDeviceTrafficDerivedDeletionRetryPreservesCompletedBarriers(t *testing.T) {
	preview := sanitizedDeviceTrafficDeletionJobPreview(t)
	selection := &deviceDeletionSelectionService{}
	zeekPreview, suricataPreview := preview.AnalyzerReindex[0].Zeek, preview.AnalyzerReindex[0].Suricata
	zeek := &captureDeletionAnalyzerStub{engine: analyzer.EngineZeek, preview: &zeekPreview}
	suricata := &captureDeletionAnalyzerStub{engine: analyzer.EngineSuricata, preview: &suricataPreview, deleteErr: errors.New("injected analyzer failure")}
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "gateway.sock"), func(config *Config) {
		config.EventSelectionDeletions = selection
		config.ZeekCheckpointDeletions = zeek
		config.SuricataCheckpointDeletions = suricata
	})
	bodyBytes, _ := json.Marshal(createDeviceTrafficDeletionRequest{Password: activationTestPassword, Preview: preview, Choice: capture.DeleteDerivedContentOnly, Confirmation: preview.DeviceID})
	create := authenticatedJSONRequest(http.MethodPost, "/api/v1/devices/"+preview.DeviceID+"/traffic-deletion-jobs", string(bodyBytes), session, "device-traffic-derived-partial-0001")
	createRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(createRecorder, create)
	var partial deviceTrafficDeletionJob
	_ = json.Unmarshal(createRecorder.Body.Bytes(), &partial)
	if createRecorder.Code != http.StatusAccepted || partial.State != deviceTrafficDeletionPartial || partial.ProgressPercent != 50 || partial.NormalizedEvents == nil || len(partial.AnalyzerCheckpoints) != 1 {
		t.Fatalf("derived backend failure did not preserve partial evidence: %d %#v", createRecorder.Code, partial)
	}
	suricata.deleteErr = nil
	retry := authenticatedJSONRequest(http.MethodPost, "/api/v1/device-traffic-deletion-jobs/"+partial.ID+"/retry", `{"password":"`+activationTestPassword+`"}`, session, "device-traffic-derived-retry-0001")
	retryRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(retryRecorder, retry)
	var completed deviceTrafficDeletionJob
	_ = json.Unmarshal(retryRecorder.Body.Bytes(), &completed)
	if retryRecorder.Code != http.StatusAccepted || completed.State != deviceTrafficDeletionCompleted || selection.deleteCalls != 1 || len(zeek.deleteRequests) != 1 || len(suricata.deleteRequests) != 2 {
		t.Fatalf("derived retry repeated completed barriers: %d %#v", retryRecorder.Code, completed)
	}
}

func TestDeviceTrafficLegacyPreviewRemainsValid(t *testing.T) {
	preview := sanitizedDeviceTrafficDeletionJobPreview(t)
	preview.Schema = legacyDeviceTrafficPreviewSchema
	preview.Choices, preview.ExactImpact = buildDeviceTrafficChoicesForSchema(preview.Schema, preview.NormalizedEventDeletion, preview.WholeCaptureEvents, preview.AnalyzerReindex, preview.PCAP)
	preview.PreviewSHA256, _ = hashDeviceTrafficPreview(preview)
	if err := preview.validate(); err != nil || preview.Choices[1].ExecutionAvailable {
		t.Fatalf("legacy preview compatibility was lost: %#v err=%v", preview.Choices[1], err)
	}
}

func TestDeviceTrafficSanitizeJobCoordinatesEveryBoundBackend(t *testing.T) {
	preview := sanitizedDeviceTrafficDeletionJobPreview(t)
	selection := &deviceDeletionSelectionService{}
	zeekPreview, suricataPreview := preview.AnalyzerReindex[0].Zeek, preview.AnalyzerReindex[0].Suricata
	zeek := &captureDeletionAnalyzerStub{engine: analyzer.EngineZeek, preview: &zeekPreview}
	suricata := &captureDeletionAnalyzerStub{engine: analyzer.EngineSuricata, preview: &suricataPreview}
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	requests := startGatewaySequenceStub(t, socketPath, func(rpc gatewayprotocol.Request) any {
		return sanitizedRewriteResponse(t, rpc)
	})
	server, session := configuredAPIServerWithConfig(t, socketPath, func(config *Config) {
		config.EventSelectionDeletions = selection
		config.ZeekCheckpointDeletions = zeek
		config.SuricataCheckpointDeletions = suricata
	})
	bodyBytes, err := json.Marshal(createDeviceTrafficDeletionRequest{Password: activationTestPassword, Preview: preview, Choice: capture.SanitizeAndRewritePCAP, Confirmation: preview.DeviceID})
	if err != nil {
		t.Fatal(err)
	}
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/devices/"+preview.DeviceID+"/traffic-deletion-jobs", string(bodyBytes), session, "device-traffic-sanitize-0001")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	var job deviceTrafficDeletionJob
	_ = json.Unmarshal(recorder.Body.Bytes(), &job)
	rpc := <-requests
	if recorder.Code != http.StatusAccepted || job.State != deviceTrafficDeletionRunning || job.Phase != "ANALYZER_REINDEXING" || job.Choice != capture.SanitizeAndRewritePCAP || job.NormalizedEvents == nil || len(job.AnalyzerCheckpoints) != 2 || len(job.PCAPRewrites) != 1 || len(job.AnalyzerReindexes) != 2 || selection.deleteCalls != 1 || len(zeek.deleteRequests) != 1 || len(suricata.deleteRequests) != 1 || len(zeek.reindexRequests) != 1 || len(suricata.reindexRequests) != 1 {
		t.Fatalf("sanitize coordination did not complete: status=%d rpc=%#v job=%#v", recorder.Code, rpc, job)
	}
	if rpc.Method != "RewritePCAP" {
		t.Fatalf("unexpected host mutation: %#v", rpc)
	}
	zeek.reindexState, suricata.reindexState = "COMPLETED", "COMPLETED"
	server.ResumeDeviceTrafficDeletions(t.Context())
	stored, err := server.store.getDeviceTrafficDeletionRecord(job.ID)
	if err != nil || stored.Job.State != deviceTrafficDeletionCompleted || stored.Job.Phase != "COMPLETED" || len(zeek.reindexRequests) != 2 || len(suricata.reindexRequests) != 2 {
		t.Fatalf("completed analyzer reindex did not finish sanitize job: %#v err=%v", stored.Job, err)
	}
	replay := authenticatedJSONRequest(http.MethodPost, "/api/v1/devices/"+preview.DeviceID+"/traffic-deletion-jobs", string(bodyBytes), session, "device-traffic-sanitize-0001")
	replayRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(replayRecorder, replay)
	if replayRecorder.Code != http.StatusAccepted || selection.deleteCalls != 1 || len(zeek.deleteRequests) != 1 || len(suricata.deleteRequests) != 1 || len(zeek.reindexRequests) != 2 || len(suricata.reindexRequests) != 2 {
		t.Fatalf("sanitize replay repeated backend mutation: %d %s", replayRecorder.Code, replayRecorder.Body.String())
	}
}

func TestDeviceTrafficWholeFileJobDeletesSessionCollateralAndReviewedArtifacts(t *testing.T) {
	preview := sanitizedDeviceTrafficDeletionJobPreview(t)
	selection := &deviceDeletionSelectionService{}
	events := &captureDeletionEventStub{preview: preview.WholeCaptureEvents[0]}
	zeekPreview, suricataPreview := preview.AnalyzerReindex[0].Zeek, preview.AnalyzerReindex[0].Suricata
	zeek := &captureDeletionAnalyzerStub{engine: analyzer.EngineZeek, preview: &zeekPreview}
	suricata := &captureDeletionAnalyzerStub{engine: analyzer.EngineSuricata, preview: &suricataPreview}
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	requests := startGatewaySequenceStub(t, socketPath, func(rpc gatewayprotocol.Request) any {
		return wholeFileDeletionResponse(t, rpc)
	})
	server, session := configuredAPIServerWithConfig(t, socketPath, func(config *Config) {
		config.EventSelectionDeletions = selection
		config.CaptureEventDeletions = events
		config.ZeekCheckpointDeletions = zeek
		config.SuricataCheckpointDeletions = suricata
	})
	bodyBytes, _ := json.Marshal(createDeviceTrafficDeletionRequest{Password: activationTestPassword, Preview: preview, Choice: capture.DeleteWholeCaptureFiles, Confirmation: preview.DeviceID})
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/devices/"+preview.DeviceID+"/traffic-deletion-jobs", string(bodyBytes), session, "device-traffic-whole-file-0001")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	var job deviceTrafficDeletionJob
	_ = json.Unmarshal(recorder.Body.Bytes(), &job)
	rpc := <-requests
	if recorder.Code != http.StatusAccepted || job.State != deviceTrafficDeletionCompleted || job.Choice != capture.DeleteWholeCaptureFiles || job.NormalizedEvents != nil || len(job.CaptureEvents) != 1 || len(job.AnalyzerCheckpoints) != 2 || len(job.PCAPDeletions) != 1 || len(job.PCAPRewrites) != 0 || len(job.AnalyzerReindexes) != 0 || selection.deleteCalls != 0 || len(events.deleteRequests) != 1 || len(zeek.deleteRequests) != 1 || len(suricata.deleteRequests) != 1 || len(zeek.reindexRequests) != 0 || len(suricata.reindexRequests) != 0 {
		t.Fatalf("whole-file coordination did not complete: status=%d rpc=%#v job=%#v", recorder.Code, rpc, job)
	}
	if rpc.Method != "DeletePCAPArtifact" || events.deleteRequests[0].OperationID != deviceTrafficCaptureEventOperationID(job.ID, preview.WholeCaptureEvents[0].CaptureSessionID) {
		t.Fatalf("whole-file mutation lost its stable evidence: rpc=%#v events=%#v", rpc, events.deleteRequests)
	}
	replay := authenticatedJSONRequest(http.MethodPost, "/api/v1/devices/"+preview.DeviceID+"/traffic-deletion-jobs", string(bodyBytes), session, "device-traffic-whole-file-0001")
	replayRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(replayRecorder, replay)
	if replayRecorder.Code != http.StatusAccepted || len(events.deleteRequests) != 1 || len(zeek.deleteRequests) != 1 || len(suricata.deleteRequests) != 1 {
		t.Fatalf("whole-file replay repeated backend mutation: %d %s", replayRecorder.Code, replayRecorder.Body.String())
	}
}

func sanitizedRewriteResponse(t *testing.T, rpc gatewayprotocol.Request) capture.PCAPRewriteRecord {
	t.Helper()
	var params gatewayprotocol.RewritePCAPParams
	if rpc.Method != "RewritePCAP" || gatewayprotocol.DecodeParams(rpc.Params, &params) != nil {
		return capture.PCAPRewriteRecord{}
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	completed := now
	membership := pcapng.Membership{Schema: pcapng.MembershipSchema, State: pcapng.MembershipExact, PacketCount: 6, LinkTypes: []uint16{1}, MACAddresses: []string{}, IPAddresses: []string{"10.77.0.222"}}
	record := capture.PCAPRewriteRecord{
		Schema: capture.PCAPRewriteSchema, ID: params.Request.ID, SessionID: params.Request.SessionID, FileName: params.Request.FileName,
		State: capture.PCAPRewriteCompleted, OriginalSHA256: params.Request.OriginalSHA256, OriginalManifestSHA256: strings.Repeat("e", 64),
		Selection: params.Request.Selection, SelectionSHA256: selectionDigest(params.Request.Selection), Tool: capture.PCAPRewriteTool, ToolVersion: params.Request.ToolVersion,
		OutputSHA256: strings.Repeat("f", 64), OutputManifestSHA256: strings.Repeat("1", 64), OutputManifestFileSHA256: strings.Repeat("2", 64),
		OriginalBytes: 4096, OutputBytes: 3072, PacketsRead: 10, PacketsWritten: 6, PacketsRemoved: 4, OutputMembership: &membership,
		ArtifactReplaced: true, ReindexRequired: true, IndexInvalidationState: "PENDING", Failures: []string{}, StartedAt: now, CompletedAt: &completed,
	}
	if err := record.Validate(); err != nil {
		t.Errorf("invalid rewrite fixture: %v", err)
	}
	return record
}

func wholeFileDeletionResponse(t *testing.T, rpc gatewayprotocol.Request) capture.PCAPArtifactDeletionRecord {
	t.Helper()
	var params gatewayprotocol.DeletePCAPArtifactParams
	if rpc.Method != "DeletePCAPArtifact" || gatewayprotocol.DecodeParams(rpc.Params, &params) != nil {
		return capture.PCAPArtifactDeletionRecord{}
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	completed := now
	record := capture.PCAPArtifactDeletionRecord{
		Schema: capture.PCAPArtifactDeletionSchema, ID: params.Request.ID, SessionID: params.Request.SessionID, FileName: params.Request.FileName,
		State: capture.PCAPArtifactDeletionCompleted, OriginalSHA256: params.Request.OriginalSHA256, OriginalManifestSHA256: strings.Repeat("e", 64),
		OutputManifestSHA256: strings.Repeat("1", 64), OutputManifestFileSHA256: strings.Repeat("2", 64),
		Selection: params.Request.Selection, SelectionSHA256: selectionDigest(params.Request.Selection), OriginalBytes: 4096,
		ExpectedPackets: params.Request.ExpectedPackets, ExpectedMatchedPackets: params.Request.ExpectedMatchedPackets, ExpectedCollateralPackets: params.Request.ExpectedCollateralPackets,
		PacketsRead: params.Request.ExpectedPackets, MatchedPacketsRemoved: params.Request.ExpectedMatchedPackets, CollateralPacketsRemoved: params.Request.ExpectedCollateralPackets,
		ArtifactRemoved: true, ReindexRequired: true, IndexInvalidationState: "PENDING", SecureErasureGuaranteed: false,
		StartedAt: now, CompletedAt: &completed,
	}
	if err := record.Validate(); err != nil {
		t.Errorf("invalid whole-file fixture: %v", err)
	}
	return record
}

func TestDeviceTrafficSanitizeRetryPreservesCompletedBarriers(t *testing.T) {
	preview := sanitizedDeviceTrafficDeletionJobPreview(t)
	selection := &deviceDeletionSelectionService{}
	zeekPreview, suricataPreview := preview.AnalyzerReindex[0].Zeek, preview.AnalyzerReindex[0].Suricata
	zeek := &captureDeletionAnalyzerStub{engine: analyzer.EngineZeek, preview: &zeekPreview, reindexState: "COMPLETED"}
	suricata := &captureDeletionAnalyzerStub{engine: analyzer.EngineSuricata, preview: &suricataPreview, reindexState: "COMPLETED"}
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	requests := startGatewaySequenceStub(t, socketPath, func(gatewayprotocol.Request) any { return capture.PCAPRewriteRecord{} }, func(rpc gatewayprotocol.Request) any { return sanitizedRewriteResponse(t, rpc) })
	server, session := configuredAPIServerWithConfig(t, socketPath, func(config *Config) {
		config.EventSelectionDeletions = selection
		config.ZeekCheckpointDeletions = zeek
		config.SuricataCheckpointDeletions = suricata
	})
	bodyBytes, _ := json.Marshal(createDeviceTrafficDeletionRequest{Password: activationTestPassword, Preview: preview, Choice: capture.SanitizeAndRewritePCAP, Confirmation: preview.DeviceID})
	create := authenticatedJSONRequest(http.MethodPost, "/api/v1/devices/"+preview.DeviceID+"/traffic-deletion-jobs", string(bodyBytes), session, "device-traffic-sanitize-partial-0001")
	createRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(createRecorder, create)
	var partial deviceTrafficDeletionJob
	_ = json.Unmarshal(createRecorder.Body.Bytes(), &partial)
	if createRecorder.Code != http.StatusAccepted || partial.State != deviceTrafficDeletionPartial || partial.ProgressPercent != 60 {
		t.Fatalf("ambiguous host rewrite was not partial: %d %#v", createRecorder.Code, partial)
	}
	retry := authenticatedJSONRequest(http.MethodPost, "/api/v1/device-traffic-deletion-jobs/"+partial.ID+"/retry", `{"password":"`+activationTestPassword+`"}`, session, "device-traffic-sanitize-retry-0001")
	retryRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(retryRecorder, retry)
	var completed deviceTrafficDeletionJob
	_ = json.Unmarshal(retryRecorder.Body.Bytes(), &completed)
	firstRPC, secondRPC := <-requests, <-requests
	var firstParams, secondParams gatewayprotocol.RewritePCAPParams
	_ = gatewayprotocol.DecodeParams(firstRPC.Params, &firstParams)
	_ = gatewayprotocol.DecodeParams(secondRPC.Params, &secondParams)
	if retryRecorder.Code != http.StatusAccepted || completed.State != deviceTrafficDeletionCompleted || selection.deleteCalls != 1 || len(zeek.deleteRequests) != 1 || len(suricata.deleteRequests) != 1 || firstParams.Request.ID == "" || firstParams.Request.ID != secondParams.Request.ID {
		t.Fatalf("sanitize retry did not preserve completed barriers: %d %#v first=%#v second=%#v", retryRecorder.Code, completed, firstParams, secondParams)
	}
}

func TestDeviceTrafficWholeFileRetryPreservesCompletedBarriers(t *testing.T) {
	preview := sanitizedDeviceTrafficDeletionJobPreview(t)
	events := &captureDeletionEventStub{preview: preview.WholeCaptureEvents[0]}
	zeekPreview, suricataPreview := preview.AnalyzerReindex[0].Zeek, preview.AnalyzerReindex[0].Suricata
	zeek := &captureDeletionAnalyzerStub{engine: analyzer.EngineZeek, preview: &zeekPreview}
	suricata := &captureDeletionAnalyzerStub{engine: analyzer.EngineSuricata, preview: &suricataPreview}
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	requests := startGatewaySequenceStub(t, socketPath, func(gatewayprotocol.Request) any { return capture.PCAPArtifactDeletionRecord{} }, func(rpc gatewayprotocol.Request) any { return wholeFileDeletionResponse(t, rpc) })
	server, session := configuredAPIServerWithConfig(t, socketPath, func(config *Config) {
		config.EventSelectionDeletions = &deviceDeletionSelectionService{}
		config.CaptureEventDeletions = events
		config.ZeekCheckpointDeletions = zeek
		config.SuricataCheckpointDeletions = suricata
	})
	bodyBytes, _ := json.Marshal(createDeviceTrafficDeletionRequest{Password: activationTestPassword, Preview: preview, Choice: capture.DeleteWholeCaptureFiles, Confirmation: preview.DeviceID})
	create := authenticatedJSONRequest(http.MethodPost, "/api/v1/devices/"+preview.DeviceID+"/traffic-deletion-jobs", string(bodyBytes), session, "device-traffic-whole-partial-0001")
	createRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(createRecorder, create)
	var partial deviceTrafficDeletionJob
	_ = json.Unmarshal(createRecorder.Body.Bytes(), &partial)
	if createRecorder.Code != http.StatusAccepted || partial.State != deviceTrafficDeletionPartial || partial.ProgressPercent != 60 {
		t.Fatalf("ambiguous whole-file host result was not partial: %d %#v", createRecorder.Code, partial)
	}
	retry := authenticatedJSONRequest(http.MethodPost, "/api/v1/device-traffic-deletion-jobs/"+partial.ID+"/retry", `{"password":"`+activationTestPassword+`"}`, session, "device-traffic-whole-retry-0001")
	retryRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(retryRecorder, retry)
	var completed deviceTrafficDeletionJob
	_ = json.Unmarshal(retryRecorder.Body.Bytes(), &completed)
	firstRPC, secondRPC := <-requests, <-requests
	var firstParams, secondParams gatewayprotocol.DeletePCAPArtifactParams
	_ = gatewayprotocol.DecodeParams(firstRPC.Params, &firstParams)
	_ = gatewayprotocol.DecodeParams(secondRPC.Params, &secondParams)
	if retryRecorder.Code != http.StatusAccepted || completed.State != deviceTrafficDeletionCompleted || len(events.deleteRequests) != 1 || len(zeek.deleteRequests) != 1 || len(suricata.deleteRequests) != 1 || firstParams.Request.ID == "" || firstParams.Request.ID != secondParams.Request.ID {
		t.Fatalf("whole-file retry did not preserve completed barriers: %d %#v first=%#v second=%#v", retryRecorder.Code, completed, firstParams, secondParams)
	}
}

func TestDeviceTrafficMetadataDeletionRetriesPartialBackend(t *testing.T) {
	preview := deviceTrafficDeletionJobPreview(t)
	selection := &deviceDeletionSelectionService{deleteErr: errors.New("injected backend failure")}
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "gateway.sock"), func(config *Config) {
		config.EventSelectionDeletions = selection
	})
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/devices/"+preview.DeviceID+"/traffic-deletion-jobs", createDeviceTrafficDeletionBody(t, preview), session, "device-traffic-job-create-0002")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	var partial deviceTrafficDeletionJob
	_ = json.Unmarshal(recorder.Body.Bytes(), &partial)
	if recorder.Code != http.StatusAccepted || partial.State != deviceTrafficDeletionPartial || partial.Phase != "RETRY_REQUIRED" || partial.Failure == "" || selection.deleteCalls != 1 {
		t.Fatalf("backend failure was not conservatively partial: %d %#v", recorder.Code, partial)
	}
	selection.deleteErr = nil
	retry := authenticatedJSONRequest(http.MethodPost, "/api/v1/device-traffic-deletion-jobs/"+partial.ID+"/retry", `{"password":"`+activationTestPassword+`"}`, session, "device-traffic-job-retry-0001")
	retryRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(retryRecorder, retry)
	var completed deviceTrafficDeletionJob
	_ = json.Unmarshal(retryRecorder.Body.Bytes(), &completed)
	if retryRecorder.Code != http.StatusAccepted || completed.State != deviceTrafficDeletionCompleted || selection.deleteCalls != 2 {
		t.Fatalf("partial job did not retry: %d %#v calls=%d", retryRecorder.Code, completed, selection.deleteCalls)
	}
	replay := authenticatedJSONRequest(http.MethodPost, "/api/v1/device-traffic-deletion-jobs/"+partial.ID+"/retry", `{"password":"`+activationTestPassword+`"}`, session, "device-traffic-job-retry-0001")
	replayRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(replayRecorder, replay)
	if replayRecorder.Code != http.StatusAccepted || selection.deleteCalls != 2 {
		t.Fatalf("retry replay repeated backend mutation: %d calls=%d body=%s", replayRecorder.Code, selection.deleteCalls, replayRecorder.Body.String())
	}
}

func TestDeviceTrafficDeletionCancelIsSafeOnlyBeforeBarrier(t *testing.T) {
	preview := deviceTrafficDeletionJobPreview(t)
	selection := &deviceDeletionSelectionService{}
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "gateway.sock"), func(config *Config) {
		config.EventSelectionDeletions = selection
	})
	record, _, err := server.store.beginDeviceTrafficDeletion(preview, capture.DeleteMetadataOnly, "admin", "device-traffic-job-create-0003")
	if err != nil {
		t.Fatal(err)
	}
	cancel := authenticatedJSONRequest(http.MethodPost, "/api/v1/device-traffic-deletion-jobs/"+record.Job.ID+"/cancel", `{"password":"`+activationTestPassword+`"}`, session, "device-traffic-job-cancel-0001")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, cancel)
	var cancelled deviceTrafficDeletionJob
	_ = json.Unmarshal(recorder.Body.Bytes(), &cancelled)
	if recorder.Code != http.StatusOK || cancelled.State != deviceTrafficDeletionCancelled || cancelled.Phase != "CANCELLED_BEFORE_BARRIER" || selection.deleteCalls != 0 {
		t.Fatalf("pre-barrier cancellation failed: %d %#v", recorder.Code, cancelled)
	}
	secondCancel := authenticatedJSONRequest(http.MethodPost, "/api/v1/device-traffic-deletion-jobs/"+record.Job.ID+"/cancel", `{"password":"`+activationTestPassword+`"}`, session, "device-traffic-job-cancel-0002")
	secondRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(secondRecorder, secondCancel)
	if secondRecorder.Code != http.StatusConflict {
		t.Fatalf("cancel after terminal state returned %d: %s", secondRecorder.Code, secondRecorder.Body.String())
	}
}

func TestResumeDeviceTrafficDeletionUsesPersistedPreview(t *testing.T) {
	preview := deviceTrafficDeletionJobPreview(t)
	selection := &deviceDeletionSelectionService{}
	server, _ := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "gateway.sock"), func(config *Config) {
		config.EventSelectionDeletions = selection
	})
	record, _, err := server.store.beginDeviceTrafficDeletion(preview, capture.DeleteMetadataOnly, "admin", "device-traffic-job-create-0004")
	if err != nil {
		t.Fatal(err)
	}
	server.ResumeDeviceTrafficDeletions(t.Context())
	stored, err := server.store.getDeviceTrafficDeletionRecord(record.Job.ID)
	if err != nil || stored.Job.State != deviceTrafficDeletionCompleted || selection.deleteCalls != 1 || selection.deleteRequest.Preview.PreviewSHA256 != preview.NormalizedEventDeletion.PreviewSHA256 {
		t.Fatalf("restart recovery did not reuse reviewed evidence: %#v calls=%d err=%v", stored.Job, selection.deleteCalls, err)
	}
}

func TestDeviceTrafficDeletionJobRejectsAuthorizationAndIdempotencySubstitution(t *testing.T) {
	preview := deviceTrafficDeletionJobPreview(t)
	selection := &deviceDeletionSelectionService{}
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "gateway.sock"), func(config *Config) {
		config.EventSelectionDeletions = selection
	})
	wrongPasswordBody := createDeviceTrafficDeletionBody(t, preview)
	wrongPasswordBody = strings.Replace(wrongPasswordBody, activationTestPassword, "wrong-password", 1)
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/devices/"+preview.DeviceID+"/traffic-deletion-jobs", wrongPasswordBody, session, "device-traffic-job-auth-0001")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized || selection.deleteCalls != 0 {
		t.Fatalf("bad reauthentication returned %d and %d backend calls", recorder.Code, selection.deleteCalls)
	}
	request = authenticatedJSONRequest(http.MethodPost, "/api/v1/devices/"+preview.DeviceID+"/traffic-deletion-jobs", createDeviceTrafficDeletionBody(t, preview), session, "device-traffic-job-conflict-0001")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("fixture deletion failed: %d %s", recorder.Code, recorder.Body.String())
	}
	changed := preview
	changed.DeviceName = "changed fixture"
	changed.PreviewSHA256, _ = hashDeviceTrafficPreview(changed)
	if err := changed.validate(); err != nil {
		t.Fatal(err)
	}
	request = authenticatedJSONRequest(http.MethodPost, "/api/v1/devices/"+preview.DeviceID+"/traffic-deletion-jobs", createDeviceTrafficDeletionBody(t, changed), session, "device-traffic-job-conflict-0001")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusConflict || selection.deleteCalls != 1 {
		t.Fatalf("idempotency substitution returned %d and %d backend calls: %s", recorder.Code, selection.deleteCalls, recorder.Body.String())
	}
}

func TestDeviceTrafficDeletionLedgerFailsClosedOnTamper(t *testing.T) {
	preview := deviceTrafficDeletionJobPreview(t)
	store := NewStore(t.TempDir(), filepath.Join(t.TempDir(), "setup-token"))
	if _, _, err := store.beginDeviceTrafficDeletion(preview, capture.DeleteMetadataOnly, "admin", "device-traffic-job-tamper-0001"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.dataDir, "device-traffic-deletions.json")
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	encoded = []byte(strings.Replace(string(encoded), preview.PreviewSHA256, strings.Repeat("f", 64), 1))
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.listDeviceTrafficDeletionJobs(); err == nil {
		t.Fatal("tampered device traffic deletion ledger was accepted")
	}
}
