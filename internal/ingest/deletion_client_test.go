package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const deletionClientTestToken = "deletion-client-token-00000000000001"

type deletionClientFootprintReader struct{}

func (deletionClientFootprintReader) ReadCaptureEventFootprint(context.Context, string) (CaptureEventDatabaseFootprint, error) {
	return CaptureEventDatabaseFootprint{}, nil
}

func deletionClientFixture(t *testing.T) (CaptureEventDeletionPreview, CaptureEventDeletionRequest, CaptureEventDeletionOutcome) {
	t.Helper()
	now := time.Date(2026, 9, 1, 15, 0, 0, 0, time.UTC)
	captureID := "capture-0123456789abcdef0123456789abcdef"
	planner := CaptureEventDeletionPlanner{Spool: &Spool{Root: filepath.Join(t.TempDir(), "spool"), MaxBytes: 8 << 20, ReserveBytes: 1}, Database: deletionClientFootprintReader{}, Now: func() time.Time { return now }}
	preview, err := planner.Preview(t.Context(), captureID)
	if err != nil {
		t.Fatal(err)
	}
	request := CaptureEventDeletionRequest{Schema: CaptureEventDeletionOperationSchema, Preview: preview, OperationID: "capture-delete-operation-0001", Actor: "admin"}
	tombstone := CaptureTombstone{Schema: CaptureTombstoneSchemaVersion, CaptureSessionID: captureID, OperationID: request.OperationID, Actor: request.Actor, CreatedAt: now}
	receipt := CaptureEventDeletionReceipt{Schema: CaptureEventDeletionPreviewSchema, CaptureSessionID: captureID, OperationID: request.OperationID, PreviewSHA256: preview.PreviewSHA256, DatabaseReclaimMode: DatabaseReclaimDeferred, VerifiedAbsent: true, CompletedAt: now}
	outcome := CaptureEventDeletionOutcome{Schema: CaptureEventDeletionOperationSchema, CaptureSessionID: captureID, PreviewSHA256: preview.PreviewSHA256, Tombstone: tombstone, Spool: SpoolTombstoneResult{Tombstone: tombstone}, Database: receipt, CompletedAt: now}
	return preview, request, outcome
}

func TestDeletionClientAuthenticatesAndValidatesLifecycleResponses(t *testing.T) {
	preview, deletionRequest, outcome := deletionClientFixture(t)
	requests := 0
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+deletionClientTestToken || r.Header.Get("Accept") != "application/json" {
			t.Fatalf("unexpected deletion request metadata: %s %s %#v", r.Method, r.URL.Path, r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/capture-event-deletions/" + preview.CaptureSessionID + "/preview":
			if r.Header.Get("Content-Type") != "" {
				t.Fatalf("preview unexpectedly had a content type: %q", r.Header.Get("Content-Type"))
			}
			_ = json.NewEncoder(w).Encode(preview)
		case "/v1/capture-event-deletions/" + preview.CaptureSessionID + "/execute":
			if r.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("execute content type was %q", r.Header.Get("Content-Type"))
			}
			var received CaptureEventDeletionRequest
			if err := json.NewDecoder(r.Body).Decode(&received); err != nil || received.OperationID != deletionRequest.OperationID || received.Preview.PreviewSHA256 != preview.PreviewSHA256 {
				t.Fatalf("unexpected execute request: %#v err=%v", received, err)
			}
			_ = json.NewEncoder(w).Encode(outcome)
		default:
			http.NotFound(w, r)
		}
	}))
	defer service.Close()
	client, err := NewDeletionClient(service.URL, []byte(deletionClientTestToken), service.Client())
	if err != nil {
		t.Fatal(err)
	}
	actualPreview, err := client.Preview(t.Context(), preview.CaptureSessionID)
	if err != nil || actualPreview.PreviewSHA256 != preview.PreviewSHA256 {
		t.Fatalf("client preview failed: %#v err=%v", actualPreview, err)
	}
	actualOutcome, err := client.Delete(t.Context(), deletionRequest)
	if err != nil || actualOutcome.PreviewSHA256 != outcome.PreviewSHA256 || requests != 2 {
		t.Fatalf("client delete failed: %#v requests=%d err=%v", actualOutcome, requests, err)
	}
}

func TestDeletionClientMapsLifecycleErrorsAndRejectsInvalidJSON(t *testing.T) {
	preview, deletionRequest, _ := deletionClientFixture(t)
	for name, testCase := range map[string]struct {
		status int
		code   string
		target error
	}{
		"expired":  {http.StatusGone, "deletion_preview_expired", ErrCaptureEventDeletionPreviewExpired},
		"stale":    {http.StatusConflict, "deletion_preview_stale", ErrCaptureEventDeletionPreviewStale},
		"conflict": {http.StatusConflict, "deletion_conflict", ErrCaptureEventDeletionConflict},
	} {
		t.Run(name, func(t *testing.T) {
			service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(testCase.status)
				_, _ = w.Write([]byte(`{"error":{"code":"` + testCase.code + `"}}`))
			}))
			defer service.Close()
			client, err := NewDeletionClient(service.URL, []byte(deletionClientTestToken), service.Client())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Delete(t.Context(), deletionRequest); err != testCase.target {
				t.Fatalf("unexpected mapped error: %v", err)
			}
		})
	}
	invalid := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"schema":1,"unknown":true}`))
	}))
	defer invalid.Close()
	client, err := NewDeletionClient(invalid.URL, []byte(deletionClientTestToken), invalid.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Preview(t.Context(), preview.CaptureSessionID); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("invalid preview JSON was accepted: %v", err)
	}
}

func TestDeletionClientRejectsUnsafeConfiguration(t *testing.T) {
	for _, endpoint := range []string{"https://ingestd:8081", "http://user@ingestd:8081", "http://ingestd:8081/path", "http://ingestd:8081?query=1"} {
		if _, err := NewDeletionClient(endpoint, []byte(deletionClientTestToken), nil); err == nil {
			t.Fatalf("unsafe deletion endpoint was accepted: %s", endpoint)
		}
	}
	if _, err := NewDeletionClient("http://ingestd:8081", []byte("short"), nil); err == nil {
		t.Fatal("short deletion token was accepted")
	}
	targetCalled := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetCalled = true }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer redirect.Close()
	client, err := NewDeletionClient(redirect.URL, []byte(deletionClientTestToken), redirect.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Preview(t.Context(), "capture-0123456789abcdef0123456789abcdef"); err == nil || targetCalled {
		t.Fatalf("deletion client followed a credential-bearing redirect: err=%v target_called=%v", err, targetCalled)
	}
}

func TestDeletionClientCoordinatesEventSelectionLifecycle(t *testing.T) {
	selectionService, previewRequest := eventSelectionDeletionServiceFixture(t)
	requests := 0
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+deletionClientTestToken || r.Header.Get("Accept") != "application/json" || r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("unexpected selection deletion request metadata: %s %s %#v", r.Method, r.URL.Path, r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/event-selection-deletions/preview":
			var received EventSelectionDeletionPreviewRequest
			if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
				t.Fatal(err)
			}
			preview, err := selectionService.Preview(r.Context(), received)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(preview)
		case "/v1/event-selection-deletions/execute":
			var received EventSelectionDeletionRequest
			if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
				t.Fatal(err)
			}
			outcome, err := selectionService.Delete(r.Context(), received)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(outcome)
		default:
			http.NotFound(w, r)
		}
	}))
	defer service.Close()
	client, err := NewDeletionClient(service.URL, []byte(deletionClientTestToken), service.Client())
	if err != nil {
		t.Fatal(err)
	}
	preview, err := client.PreviewEventSelection(t.Context(), previewRequest)
	if err != nil || preview.Spool.PendingRecords != 1 {
		t.Fatalf("selection preview client failed: %#v err=%v", preview, err)
	}
	deletion := EventSelectionDeletionRequest{Schema: 1, Preview: preview, OperationID: "selection-deletion-client-0001", Actor: previewRequest.Actor}
	outcome, err := client.DeleteEventSelection(t.Context(), deletion)
	if err != nil || outcome.OperationID != deletion.OperationID || outcome.Spool.PurgedRecords != 1 || requests != 2 {
		t.Fatalf("selection deletion client failed: %#v requests=%d err=%v", outcome, requests, err)
	}
}

func TestDeletionClientMapsEventSelectionErrors(t *testing.T) {
	selectionService, previewRequest := eventSelectionDeletionServiceFixture(t)
	preview, err := selectionService.Preview(t.Context(), previewRequest)
	if err != nil {
		t.Fatal(err)
	}
	request := EventSelectionDeletionRequest{Schema: 1, Preview: preview, OperationID: "selection-deletion-client-0002", Actor: previewRequest.Actor}
	for name, testCase := range map[string]struct {
		code   string
		target error
	}{
		"expired":  {"deletion_preview_expired", ErrEventSelectionDeletionPreviewExpired},
		"stale":    {"deletion_preview_stale", ErrEventSelectionDeletionPreviewStale},
		"conflict": {"deletion_conflict", ErrEventSelectionDeletionConflict},
		"barrier":  {"deletion_barrier_missing", ErrEventSelectionTombstoneMissing},
	} {
		t.Run(name, func(t *testing.T) {
			service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":{"code":"` + testCase.code + `"}}`))
			}))
			defer service.Close()
			client, err := NewDeletionClient(service.URL, []byte(deletionClientTestToken), service.Client())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.DeleteEventSelection(t.Context(), request); !errors.Is(err, testCase.target) {
				t.Fatalf("unexpected mapped selection error: %v", err)
			}
		})
	}
}
