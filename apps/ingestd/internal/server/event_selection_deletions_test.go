package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

type eventSelectionDeletionLifecycleStub struct {
	preview        ingest.EventSelectionDeletionBundle
	previewErr     error
	deleteOutcome  ingest.EventSelectionDeletionOutcome
	deleteErr      error
	previewRequest ingest.EventSelectionDeletionPreviewRequest
	deleteRequest  ingest.EventSelectionDeletionRequest
}

func (s *eventSelectionDeletionLifecycleStub) Preview(_ context.Context, request ingest.EventSelectionDeletionPreviewRequest) (ingest.EventSelectionDeletionBundle, error) {
	s.previewRequest = request
	return s.preview, s.previewErr
}

func (s *eventSelectionDeletionLifecycleStub) Delete(_ context.Context, request ingest.EventSelectionDeletionRequest) (ingest.EventSelectionDeletionOutcome, error) {
	s.deleteRequest = request
	return s.deleteOutcome, s.deleteErr
}

func eventSelectionDeletionRouteFixture(t *testing.T) (ingest.EventSelectionDeletionPreviewRequest, ingest.EventSelectionDeletionBundle, ingest.EventSelectionDeletionRequest, ingest.EventSelectionDeletionOutcome) {
	t.Helper()
	start := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	selection, err := ingest.CanonicalEventSelection("device-0123456789abcdef0123456789abcdef", start, end, nil)
	if err != nil {
		t.Fatal(err)
	}
	created := start.Add(3 * time.Hour)
	snapshot := ingest.EventQuerySnapshot{
		Schema: 1, ID: "qsnap-0123456789abcdef0123456789abcdef",
		CanonicalQuery: "device.id:device-0123456789abcdef0123456789abcdef AND time>=2026-09-01T12:00:00Z AND time<2026-09-01T13:00:00Z",
		Sort:           ingest.DefaultEventQuerySort(), MatchedCount: 0, CountRelation: "eq", CreatedAt: created, ExpiresAt: created.Add(10 * time.Minute),
		DatasetWatermark: ingest.EventDatasetWatermark{ReceivedAt: created, RecordID: strings.Repeat("a", 64)}, SnapshotSHA256: strings.Repeat("b", 64), PolicyVersion: ingest.QuerySnapshotPolicyVersion,
	}
	selectionSHA, _ := selection.SHA256()
	database := ingest.EventSelectionDeletionPreview{
		Schema: ingest.EventSelectionDeletionSchema, Actor: "admin", Selection: selection, SelectionSHA256: selectionSHA, QuerySnapshot: snapshot,
		Database: ingest.EventSelectionDatabaseFootprint{}, DatabaseReclaimMode: ingest.DatabaseReclaimDeferred,
		GeneratedAt: created.Add(time.Minute), ExpiresAt: snapshot.ExpiresAt,
	}
	database.PreviewSHA256 = testJSONDigest(database)
	preview := ingest.EventSelectionDeletionBundle{
		Schema: 1, Actor: "admin", Selection: selection, SelectionSHA256: selectionSHA, QuerySnapshot: snapshot,
		Spool: ingest.EventSelectionSpoolFootprint{}, Database: database, DatabaseReclaimMode: ingest.DatabaseReclaimDeferred,
		GeneratedAt: database.GeneratedAt, ExpiresAt: database.ExpiresAt,
	}
	preview.PreviewSHA256 = testJSONDigest(preview)
	request := ingest.EventSelectionDeletionPreviewRequest{Actor: "admin", Selection: selection, QuerySnapshot: snapshot}
	deletion := ingest.EventSelectionDeletionRequest{Schema: 1, Preview: preview, OperationID: "event-selection-route-0001", Actor: "admin"}
	tombstone := ingest.EventSelectionTombstone{
		Schema: 1, OperationID: deletion.OperationID, Actor: "admin", Selection: selection, SelectionSHA256: selectionSHA,
		QuerySnapshotID: snapshot.ID, QuerySnapshotSHA256: snapshot.SnapshotSHA256, DeletionPreviewSHA256: preview.PreviewSHA256, CreatedAt: preview.GeneratedAt,
	}
	receipt := ingest.EventSelectionDeletionReceipt{Schema: 1, OperationID: deletion.OperationID, PreviewSHA256: database.PreviewSHA256, DatabaseReclaimMode: ingest.DatabaseReclaimDeferred, VerifiedAbsent: true, CompletedAt: created.Add(2 * time.Minute)}
	outcome := ingest.EventSelectionDeletionOutcome{Schema: 1, OperationID: deletion.OperationID, Actor: "admin", PreviewSHA256: preview.PreviewSHA256, Tombstone: tombstone, Spool: ingest.EventSelectionTombstoneResult{Tombstone: tombstone}, Database: receipt, CompletedAt: receipt.CompletedAt}
	for label, validation := range map[string]error{"database": database.Validate(), "preview": preview.Validate(), "request": request.Validate(), "deletion": deletion.Validate(), "outcome": outcome.Validate()} {
		if validation != nil {
			t.Fatalf("invalid %s fixture: %v", label, validation)
		}
	}
	return request, preview, deletion, outcome
}

func testJSONDigest(value any) string {
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

func newEventSelectionDeletionTestServer(t *testing.T, lifecycle EventSelectionDeletionLifecycle) *Server {
	t.Helper()
	server, err := New(Config{
		Spool: &ingest.Spool{Root: filepath.Join(t.TempDir(), "spool"), MaxBytes: 8 << 20, ReserveBytes: 1},
		Token: []byte(testToken), QueryToken: []byte(testQueryToken), DeletionToken: []byte(testDeletionToken),
		SelectionDeletions: lifecycle, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func TestEventSelectionDeletionRoutesRequireDistinctCredentialAndBoundEvidence(t *testing.T) {
	previewRequest, preview, deletion, outcome := eventSelectionDeletionRouteFixture(t)
	lifecycle := &eventSelectionDeletionLifecycleStub{preview: preview, deleteOutcome: outcome}
	server := newEventSelectionDeletionTestServer(t, lifecycle)
	encodedPreview, _ := json.Marshal(previewRequest)
	for name, token := range map[string]string{"missing": "", "ingest": testToken, "query": testQueryToken} {
		request := httptest.NewRequest(http.MethodPost, "/v1/event-selection-deletions/preview", strings.NewReader(string(encodedPreview)))
		request.Header.Set("Content-Type", "application/json")
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("%s credential returned %d", name, recorder.Code)
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/event-selection-deletions/preview", strings.NewReader(string(encodedPreview)))
	request.Header.Set("Authorization", "Bearer "+testDeletionToken)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || lifecycle.previewRequest.Actor != "admin" || !strings.Contains(recorder.Body.String(), preview.PreviewSHA256) {
		t.Fatalf("unexpected selection preview response %d: %s", recorder.Code, recorder.Body.String())
	}
	encodedDeletion, _ := json.Marshal(deletion)
	request = httptest.NewRequest(http.MethodPost, "/v1/event-selection-deletions/execute", strings.NewReader(string(encodedDeletion)))
	request.Header.Set("Authorization", "Bearer "+testDeletionToken)
	request.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || lifecycle.deleteRequest.OperationID != deletion.OperationID || !strings.Contains(recorder.Body.String(), `"verified_absent":true`) {
		t.Fatalf("unexpected selection deletion response %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestEventSelectionDeletionRoutesMapLifecycleErrors(t *testing.T) {
	_, _, deletion, _ := eventSelectionDeletionRouteFixture(t)
	encoded, _ := json.Marshal(deletion)
	for name, testCase := range map[string]struct {
		err    error
		status int
		code   string
	}{
		"expired":  {ingest.ErrEventSelectionDeletionPreviewExpired, http.StatusGone, "deletion_preview_expired"},
		"stale":    {ingest.ErrEventSelectionDeletionPreviewStale, http.StatusConflict, "deletion_preview_stale"},
		"conflict": {ingest.ErrEventSelectionDeletionConflict, http.StatusConflict, "deletion_conflict"},
		"barrier":  {ingest.ErrEventSelectionTombstoneMissing, http.StatusConflict, "deletion_barrier_missing"},
	} {
		t.Run(name, func(t *testing.T) {
			server := newEventSelectionDeletionTestServer(t, &eventSelectionDeletionLifecycleStub{deleteErr: testCase.err})
			request := httptest.NewRequest(http.MethodPost, "/v1/event-selection-deletions/execute", strings.NewReader(string(encoded)))
			request.Header.Set("Authorization", "Bearer "+testDeletionToken)
			request.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			server.Handler().ServeHTTP(recorder, request)
			if recorder.Code != testCase.status || !strings.Contains(recorder.Body.String(), `"code":"`+testCase.code+`"`) {
				t.Fatalf("unexpected mapped error %d: %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestEventSelectionDeletionRouteRejectsUnknownFields(t *testing.T) {
	server := newEventSelectionDeletionTestServer(t, &eventSelectionDeletionLifecycleStub{})
	request := httptest.NewRequest(http.MethodPost, "/v1/event-selection-deletions/preview", strings.NewReader(`{"unknown":true}`))
	request.Header.Set("Authorization", "Bearer "+testDeletionToken)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown selection deletion field returned %d: %s", recorder.Code, recorder.Body.String())
	}
}
