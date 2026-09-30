package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/ingest"
	"shakerproxy.dev/shakerproxy/internal/inventory"
)

type deviceDeletionSnapshotRepository struct {
	query ingest.RecentEventQuery
}

type deviceDeletionSelectionService struct {
	request       ingest.EventSelectionDeletionPreviewRequest
	deleteRequest ingest.EventSelectionDeletionRequest
	deleteErr     error
	deleteCalls   int
}

func (s *deviceDeletionSelectionService) PreviewEventSelection(_ context.Context, request ingest.EventSelectionDeletionPreviewRequest) (ingest.EventSelectionDeletionBundle, error) {
	s.request = request
	selectionSHA, _ := request.Selection.SHA256()
	database := ingest.EventSelectionDeletionPreview{
		Schema: ingest.EventSelectionDeletionSchema, Actor: request.Actor, Selection: request.Selection, SelectionSHA256: selectionSHA, QuerySnapshot: request.QuerySnapshot,
		Database:                                ingest.EventSelectionDatabaseFootprint{EventRows: request.QuerySnapshot.MatchedCount, ExclusiveIdentityRows: 5, EventLogicalBytes: 2048, IdentityLogicalBytes: 512, MaxIngestSequence: request.QuerySnapshot.DatasetWatermark.IngestSequence},
		LogicalBytesReclaimableAfterMaintenance: 2560, DatabaseReclaimMode: ingest.DatabaseReclaimDeferred,
		GeneratedAt: request.QuerySnapshot.CreatedAt.Add(time.Microsecond), ExpiresAt: request.QuerySnapshot.ExpiresAt,
	}
	database.PreviewSHA256 = deviceDeletionTestDigest(database)
	preview := ingest.EventSelectionDeletionBundle{
		Schema: 1, Actor: request.Actor, Selection: request.Selection, SelectionSHA256: selectionSHA, QuerySnapshot: request.QuerySnapshot,
		Spool: ingest.EventSelectionSpoolFootprint{PendingRecords: 2, PendingFileBytes: 1024}, Database: database,
		EstimatedImmediatelyReclaimableBytes: 1024, LogicalBytesReclaimableAfterMaintenance: 2560,
		DatabaseReclaimMode: ingest.DatabaseReclaimDeferred, GeneratedAt: database.GeneratedAt, ExpiresAt: database.ExpiresAt,
	}
	preview.PreviewSHA256 = deviceDeletionTestDigest(preview)
	return preview, preview.Validate()
}

func (s *deviceDeletionSelectionService) DeleteEventSelection(_ context.Context, request ingest.EventSelectionDeletionRequest) (ingest.EventSelectionDeletionOutcome, error) {
	s.deleteRequest, s.deleteCalls = request, s.deleteCalls+1
	if s.deleteErr != nil {
		return ingest.EventSelectionDeletionOutcome{}, s.deleteErr
	}
	tombstone := ingest.EventSelectionTombstone{
		Schema: 1, OperationID: request.OperationID, Actor: request.Actor, Selection: request.Preview.Selection,
		SelectionSHA256: request.Preview.SelectionSHA256, QuerySnapshotID: request.Preview.QuerySnapshot.ID,
		QuerySnapshotSHA256: request.Preview.QuerySnapshot.SnapshotSHA256, DeletionPreviewSHA256: request.Preview.PreviewSHA256,
		CreatedAt: request.Preview.GeneratedAt,
	}
	completedAt := time.Now().UTC().Truncate(time.Microsecond)
	receipt := ingest.EventSelectionDeletionReceipt{
		Schema: 1, OperationID: request.OperationID, PreviewSHA256: request.Preview.Database.PreviewSHA256,
		DeletedEventRows: request.Preview.Database.Database.EventRows, DeletedIdentityRows: request.Preview.Database.Database.ExclusiveIdentityRows,
		DeletedEventLogicalBytes: request.Preview.Database.Database.EventLogicalBytes, DeletedIdentityLogicalBytes: request.Preview.Database.Database.IdentityLogicalBytes,
		DatabaseReclaimMode: ingest.DatabaseReclaimDeferred, VerifiedAbsent: true, CompletedAt: completedAt,
	}
	return ingest.EventSelectionDeletionOutcome{
		Schema: 1, OperationID: request.OperationID, Actor: request.Actor, PreviewSHA256: request.Preview.PreviewSHA256,
		Tombstone: tombstone, Spool: ingest.EventSelectionTombstoneResult{Tombstone: tombstone, PurgedRecords: request.Preview.Spool.PendingRecords, PurgedBytes: request.Preview.Spool.PendingFileBytes},
		Database: receipt, CompletedAt: completedAt,
	}, nil
}

func deviceDeletionTestDigest(value any) string {
	switch typed := value.(type) {
	case ingest.EventSelectionDeletionPreview:
		typed.PreviewSHA256 = ""
		value = typed
	case ingest.EventSelectionDeletionBundle:
		typed.PreviewSHA256 = ""
		value = typed
	}
	encoded, _ := json.Marshal(value)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func (r *deviceDeletionSnapshotRepository) CreateEventQuerySnapshot(_ context.Context, _ string, canonical string, query ingest.RecentEventQuery, lifetime time.Duration) (ingest.EventQuerySnapshot, error) {
	r.query = query
	now := time.Now().UTC()
	return ingest.EventQuerySnapshot{
		Schema: 1, ID: "qsnap-1234567890abcdef1234567890abcdef", CanonicalQuery: canonical, Sort: ingest.DefaultEventQuerySort(),
		MatchedCount: 7, CountRelation: "eq", CreatedAt: now, ExpiresAt: now.Add(lifetime),
		DatasetWatermark: ingest.EventDatasetWatermark{IngestSequence: 12, ReceivedAt: now, RecordID: strings.Repeat("a", 64)},
		SnapshotSHA256:   strings.Repeat("b", 64), PolicyVersion: ingest.QuerySnapshotPolicyVersion,
	}, nil
}

func (r *deviceDeletionSnapshotRepository) GetEventQuerySnapshot(context.Context, string, string) (ingest.EventQuerySnapshot, error) {
	return ingest.EventQuerySnapshot{}, ingest.ErrQuerySnapshotNotFound
}

func TestDeviceTrafficDeletionPreviewExposesExactSharedPCAPChoices(t *testing.T) {
	clock := time.Now().UTC().Add(-time.Minute)
	inventoryStore := &inventory.Store{Path: filepath.Join(t.TempDir(), "inventory.json"), Now: func() time.Time { return clock }, Random: func(value []byte) (int, error) {
		for index := range value {
			value[index] = byte(index + 1)
		}
		return len(value), nil
	}}
	snapshot, err := inventoryStore.ReconcileDHCP4([]inventory.DHCP4Lease{{
		Address: netip.MustParseAddr("10.77.0.111"), HardwareAddr: "52:54:00:ab:cd:01", ClientID: "01:52:54:00:ab:cd:01",
		ValidLifetime: 2 * time.Hour, ExpiresAt: clock.Add(time.Hour), State: 0,
	}})
	if err != nil || len(snapshot.Devices) != 1 {
		t.Fatalf("prepare device evidence: %#v err=%v", snapshot, err)
	}
	deviceID := snapshot.Devices[0].ID
	repository := &deviceDeletionSnapshotRepository{}
	selectionService := &deviceDeletionSelectionService{}
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	requests := startGatewaySequenceStub(t, socketPath, func(request gatewayprotocol.Request) any {
		var params gatewayprotocol.PreviewPCAPSelectionParams
		if gatewayprotocol.DecodeParams(request.Params, &params) != nil {
			return capture.PCAPSelectionImpact{}
		}
		return capture.PCAPSelectionImpact{
			Schema: 1, Selection: params.Selection, SelectionSHA256: selectionDigest(params.Selection), GeneratedAt: time.Now().UTC(),
			EvaluatedSessions: 1, EvaluatedFiles: 1, ScannedBytes: 4096, AvailableBytes: 8 << 30, Exact: true,
			ImpactedFiles: []capture.PCAPSelectionFileImpact{{
				SessionID: "capture-0123456789abcdef0123456789abcdef", FileName: "capture.pcapng", OriginalSHA256: strings.Repeat("c", 64),
				OriginalBytes: 4096, SanitizedBytes: 3072, PacketsRead: 10, MatchedPackets: 4, CollateralPacketsInWholeDelete: 6,
				RetainedMACAddresses: 2, RetainedIPAddresses: 2, RetainedIdentitySHA256: strings.Repeat("d", 64),
				RetainedMACSample: []string{"52:54:00:00:00:02"}, RetainedIPSample: []string{"10.77.0.1"},
				TemporaryBytesRequired: 2<<30 + 4096, TemporaryCapacityAvailable: true,
			}}, Blockers: []capture.PCAPSelectionBlocker{}, SecureErasureGuaranteed: false,
		}
	})
	server, session := configuredAPIServerWithConfig(t, socketPath, func(config *Config) {
		config.Inventory = inventoryStore
		config.EventSnapshots = repository
		config.EventSelectionDeletions = selectionService
		captureID := "capture-0123456789abcdef0123456789abcdef"
		wholeEvents := deviceTrafficCaptureEventPreview(t, captureID, time.Now().UTC(), 12)
		config.CaptureEventDeletions = &captureDeletionEventStub{preview: wholeEvents}
		zeek := analyzerDeletionPreviewForSession(t, "ZEEK", captureID, time.Now().UTC())
		suricata := analyzerDeletionPreviewForSession(t, "SURICATA", captureID, time.Now().UTC())
		config.ZeekCheckpointDeletions = &captureDeletionAnalyzerStub{engine: "ZEEK", preview: &zeek}
		config.SuricataCheckpointDeletions = &captureDeletionAnalyzerStub{engine: "SURICATA", preview: &suricata}
	})
	start, end := clock.Add(-30*time.Minute), clock
	body := `{"start_at":"` + start.Format(time.RFC3339Nano) + `","end_at":"` + end.Format(time.RFC3339Nano) + `"}`
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/devices/"+deviceID+"/traffic-deletion-preview", body, session, "")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected preview response %d: %s", recorder.Code, recorder.Body.String())
	}
	var preview deviceTrafficDeletionPreview
	if err := json.Unmarshal(recorder.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	if preview.DeviceID != deviceID || !preview.ExactImpact || preview.SecureErasureGuaranteed || len(preview.Choices) != 4 || preview.NormalizedEvents.MatchedCount != 7 || preview.NormalizedEventDeletion.Database.Database.EventRows != 7 || preview.NormalizedEventDeletion.Spool.PendingRecords != 2 || !preview.IdentityEvidenceCoversRange || preview.ExistingExportRecords != 0 || len(preview.CopyBoundaries) != 6 || preview.CopyBoundaries[3].Configured || preview.CopyBoundaries[5].CountExact || len(preview.PreviewSHA256) != 64 {
		t.Fatalf("device deletion preview lost bound evidence: %#v", preview)
	}
	derived, whole, sanitize := preview.Choices[1], preview.Choices[2], preview.Choices[3]
	metadata := preview.Choices[0]
	if metadata.Choice != capture.DeleteMetadataOnly || !metadata.Eligible || !metadata.ExecutionAvailable || metadata.NormalizedEventRows != 7 || !metadata.RetainsPacketBytes {
		t.Fatalf("metadata-only execution choice is inaccurate: %#v", metadata)
	}
	if derived.Choice != capture.DeleteDerivedContentOnly || !derived.Eligible || !derived.ExecutionAvailable || derived.NormalizedEventRows != 7 || derived.AnalyzerReplayBarriers != 2 || derived.AnalyzerCheckpointsRemoved != 0 || !derived.RetainsPacketBytes {
		t.Fatalf("derived-content execution choice is inaccurate: %#v", derived)
	}
	if whole.Choice != capture.DeleteWholeCaptureFiles || !whole.Eligible || !whole.ExecutionAvailable || whole.NormalizedEventRows != 12 || whole.CollateralEventRows != 5 || whole.PCAPFilesDeleted != 1 || whole.MatchedPacketsRemoved != 4 || whole.CollateralPacketsRemoved != 6 || whole.PCAPBytesReclaimable != 4096 {
		t.Fatalf("whole-file collateral choice is inaccurate: %#v", whole)
	}
	if sanitize.Choice != capture.SanitizeAndRewritePCAP || !sanitize.Eligible || !sanitize.ExecutionAvailable || sanitize.PCAPFilesRewritten != 1 || sanitize.CollateralPacketsRemoved != 0 || sanitize.PCAPBytesReclaimable != 1024 || sanitize.TemporaryBytesRequired != 2<<30+4096 || len(preview.AnalyzerReindex) != 1 {
		t.Fatalf("sanitize choice is inaccurate: %#v", sanitize)
	}
	if repository.query.Filter.Canonical == "" || !strings.Contains(repository.query.Filter.Canonical, deviceID) {
		t.Fatalf("normalized-event query was not frozen to the device: %#v", repository.query)
	}
	if selectionService.request.Actor != "admin" || selectionService.request.Selection.DeviceID != deviceID || len(selectionService.request.Selection.Addresses) != 1 {
		t.Fatalf("normalized-event deletion preview lost canonical selection: %#v", selectionService.request)
	}
	if rpcRequest := <-requests; rpcRequest.Method != "PreviewPCAPSelection" {
		t.Fatalf("unexpected gateway RPC: %s", rpcRequest.Method)
	}
}

func TestDevicePCAPSelectionRejectsOverlappingIdentityOwnership(t *testing.T) {
	start := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	snapshot := inventory.Snapshot{Schema: 1, EvidenceAsOf: end, Devices: []inventory.Device{
		{Schema: 1, ID: "device-0123456789abcdef0123456789abcdef", Identities: []inventory.Identity{{Kind: inventory.IdentityMAC, Value: "52:54:00:ab:cd:01", Source: inventory.SourceDHCP4Lease, Confidence: 95, FirstSeen: start, LastSeen: end}}},
		{Schema: 1, ID: "device-ffeeddccbbaa99887766554433221100", Identities: []inventory.Identity{{Kind: inventory.IdentityMAC, Value: "52:54:00:ab:cd:01", Source: inventory.SourceDHCP4Lease, Confidence: 95, FirstSeen: start.Add(30 * time.Minute), LastSeen: end}}},
	}}
	_, _, _, conflicts, err := devicePCAPSelection(snapshot, snapshot.Devices[0].ID, start, end)
	if err != nil || len(conflicts) != 1 || conflicts[0] != "MAC:52:54:00:ab:cd:01" {
		t.Fatalf("overlapping device identity was not blocked: conflicts=%#v err=%v", conflicts, err)
	}
}

func TestDeviceTrafficSchemaTwoChoicesRespectHoldsAndAnalyzerEvidence(t *testing.T) {
	preview := sanitizedDeviceTrafficDeletionJobPreview(t)
	withoutAnalyzers, _ := buildDeviceTrafficChoices(preview.NormalizedEventDeletion, preview.WholeCaptureEvents, nil, preview.PCAP)
	if withoutAnalyzers[1].Eligible || withoutAnalyzers[1].ExecutionAvailable || !withoutAnalyzers[0].ExecutionAvailable {
		t.Fatalf("missing analyzer evidence changed the wrong choices: %#v", withoutAnalyzers)
	}
	preview.PCAP.ImpactedFiles[0].RetentionLocked = true
	withHold, _ := buildDeviceTrafficChoices(preview.NormalizedEventDeletion, preview.WholeCaptureEvents, preview.AnalyzerReindex, preview.PCAP)
	for _, choice := range withHold {
		if choice.ExecutionAvailable {
			t.Fatalf("retention-locked traffic exposed executable choice: %#v", choice)
		}
	}
}
