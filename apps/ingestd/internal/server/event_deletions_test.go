package server

import (
	"context"
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

const testDeletionToken = "deletion-test-token-0000000000000001"

type eventDeletionLifecycleStub struct {
	preview       ingest.CaptureEventDeletionPreview
	previewErr    error
	deleteOutcome ingest.CaptureEventDeletionOutcome
	deleteErr     error
	deleteRequest ingest.CaptureEventDeletionRequest
}

func (s *eventDeletionLifecycleStub) Preview(context.Context, string) (ingest.CaptureEventDeletionPreview, error) {
	return s.preview, s.previewErr
}

func (s *eventDeletionLifecycleStub) Delete(_ context.Context, request ingest.CaptureEventDeletionRequest) (ingest.CaptureEventDeletionOutcome, error) {
	s.deleteRequest = request
	return s.deleteOutcome, s.deleteErr
}

type eventDeletionFootprintReader struct {
	footprint ingest.CaptureEventDatabaseFootprint
}

func (r eventDeletionFootprintReader) ReadCaptureEventFootprint(context.Context, string) (ingest.CaptureEventDatabaseFootprint, error) {
	return r.footprint, nil
}

func eventDeletionFixture(t *testing.T) (ingest.CaptureEventDeletionPreview, ingest.CaptureEventDeletionRequest, ingest.CaptureEventDeletionOutcome) {
	t.Helper()
	now := time.Date(2026, 9, 1, 14, 0, 0, 0, time.UTC)
	captureID := "capture-0123456789abcdef0123456789abcdef"
	spool := &ingest.Spool{Root: filepath.Join(t.TempDir(), "spool"), MaxBytes: 8 << 20, ReserveBytes: 1}
	planner := ingest.CaptureEventDeletionPlanner{Spool: spool, Database: eventDeletionFootprintReader{}, Now: func() time.Time { return now }}
	preview, err := planner.Preview(t.Context(), captureID)
	if err != nil {
		t.Fatal(err)
	}
	request := ingest.CaptureEventDeletionRequest{Schema: ingest.CaptureEventDeletionOperationSchema, Preview: preview, OperationID: "capture-delete-operation-0001", Actor: "admin"}
	tombstone := ingest.CaptureTombstone{Schema: ingest.CaptureTombstoneSchemaVersion, CaptureSessionID: captureID, OperationID: request.OperationID, Actor: request.Actor, CreatedAt: now}
	receipt := ingest.CaptureEventDeletionReceipt{Schema: ingest.CaptureEventDeletionPreviewSchema, CaptureSessionID: captureID, OperationID: request.OperationID, PreviewSHA256: preview.PreviewSHA256, DatabaseReclaimMode: ingest.DatabaseReclaimDeferred, VerifiedAbsent: true, CompletedAt: now}
	outcome := ingest.CaptureEventDeletionOutcome{Schema: ingest.CaptureEventDeletionOperationSchema, CaptureSessionID: captureID, PreviewSHA256: preview.PreviewSHA256, Tombstone: tombstone, Spool: ingest.SpoolTombstoneResult{Tombstone: tombstone}, Database: receipt, CompletedAt: now}
	if err := outcome.Validate(); err != nil {
		t.Fatal(err)
	}
	return preview, request, outcome
}

func newEventDeletionTestServer(t *testing.T, lifecycle CaptureEventDeletionLifecycle) *Server {
	t.Helper()
	server, err := New(Config{
		Spool: &ingest.Spool{Root: filepath.Join(t.TempDir(), "server-spool"), MaxBytes: 8 << 20, ReserveBytes: 1},
		Token: []byte(testToken), QueryToken: []byte(testQueryToken), DeletionToken: []byte(testDeletionToken),
		CaptureDeletions: lifecycle, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func TestCaptureEventDeletionRoutesUseDistinctCredentialAndBoundEvidence(t *testing.T) {
	preview, deleteRequest, outcome := eventDeletionFixture(t)
	lifecycle := &eventDeletionLifecycleStub{preview: preview, deleteOutcome: outcome}
	server := newEventDeletionTestServer(t, lifecycle)
	path := "/v1/capture-event-deletions/" + preview.CaptureSessionID + "/preview"
	for name, token := range map[string]string{"missing": "", "ingest": testToken, "query": testQueryToken} {
		request := httptest.NewRequest(http.MethodPost, path, nil)
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("%s credential returned %d", name, recorder.Code)
		}
	}
	request := httptest.NewRequest(http.MethodPost, path, nil)
	request.Header.Set("Authorization", "Bearer "+testDeletionToken)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || !strings.Contains(recorder.Body.String(), preview.PreviewSHA256) {
		t.Fatalf("unexpected deletion preview response %d: %s", recorder.Code, recorder.Body.String())
	}
	request = httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
	request.Header.Set("Authorization", "Bearer "+testDeletionToken)
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("deletion preview body returned %d: %s", recorder.Code, recorder.Body.String())
	}

	body, err := json.Marshal(deleteRequest)
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/capture-event-deletions/"+preview.CaptureSessionID+"/execute", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer "+testDeletionToken)
	request.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || lifecycle.deleteRequest.OperationID != deleteRequest.OperationID || !strings.Contains(recorder.Body.String(), `"verified_absent":true`) {
		t.Fatalf("unexpected deletion execution response %d: %s", recorder.Code, recorder.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, "/v1/capture-event-deletions/"+preview.CaptureSessionID+"/execute", strings.NewReader(`{"unknown":true}`))
	request.Header.Set("Authorization", "Bearer "+testDeletionToken)
	request.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown deletion request field returned %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestCaptureEventDeletionRouteMapsLifecycleConflicts(t *testing.T) {
	preview, requestBody, _ := eventDeletionFixture(t)
	encoded, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatal(err)
	}
	for name, testCase := range map[string]struct {
		err    error
		status int
		code   string
	}{
		"expired":  {ingest.ErrCaptureEventDeletionPreviewExpired, http.StatusGone, "deletion_preview_expired"},
		"stale":    {ingest.ErrCaptureEventDeletionPreviewStale, http.StatusConflict, "deletion_preview_stale"},
		"conflict": {ingest.ErrCaptureEventDeletionConflict, http.StatusConflict, "deletion_conflict"},
	} {
		t.Run(name, func(t *testing.T) {
			server := newEventDeletionTestServer(t, &eventDeletionLifecycleStub{preview: preview, deleteErr: testCase.err})
			request := httptest.NewRequest(http.MethodPost, "/v1/capture-event-deletions/"+preview.CaptureSessionID+"/execute", strings.NewReader(string(encoded)))
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

func TestServerRejectsSharedDeletionCredential(t *testing.T) {
	preview, _, _ := eventDeletionFixture(t)
	_, err := New(Config{Spool: &ingest.Spool{Root: filepath.Join(t.TempDir(), "spool"), MaxBytes: 8 << 20, ReserveBytes: 1}, Token: []byte(testToken), QueryToken: []byte(testQueryToken), DeletionToken: []byte(testToken), CaptureDeletions: &eventDeletionLifecycleStub{preview: preview}})
	if err == nil {
		t.Fatal("shared ingest and deletion credential was accepted")
	}
}
