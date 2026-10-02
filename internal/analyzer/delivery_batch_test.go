package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/ingest"
)

// batchingSender records the batches it receives; rejectEvery marks every
// n-th event as quarantined, and fail makes every batch fail.
type batchingSender struct {
	mu          sync.Mutex
	batches     [][][]byte
	rejectEvery int
	fail        bool
}

func (s *batchingSender) Send(context.Context, Engine, string, []byte) error {
	return errors.New("a batching sender must not be used one event at a time")
}

func (s *batchingSender) SendBatch(_ context.Context, _ Engine, _ string, events [][]byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return 0, errors.New("ingest unavailable")
	}
	copied := make([][]byte, len(events))
	for index := range events {
		copied[index] = append([]byte(nil), events[index]...)
	}
	s.batches = append(s.batches, copied)
	rejected := 0
	if s.rejectEvery > 0 {
		for index := range events {
			if (index+1)%s.rejectEvery == 0 {
				rejected++
			}
		}
	}
	return rejected, nil
}

func writeZeekLog(t *testing.T, directory string, lines int) EventFile {
	t.Helper()
	var buffer bytes.Buffer
	for index := 0; index < lines; index++ {
		fmt.Fprintf(&buffer, `{"ts":1788278400.%06d,"uid":"Cbatch%05d"}`+"\n", index, index)
	}
	path := filepath.Join(directory, "conn.log")
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return EventFile{Path: path, ZeekPath: "conn"}
}

// One segment's events used to cost one request and one disk sync each; now
// they go in batches of up to MaxDeliveryBatchEvents.
func TestDeliveryBatchesASegmentsEvents(t *testing.T) {
	sender := &batchingSender{rejectEvery: 100}
	files := []EventFile{writeZeekLog(t, t.TempDir(), 600)}
	delivered, _, err := deliverEventFiles(context.Background(), sender, EngineZeek, testSessionID, files, 64<<20, MaxEventsPerCapture)
	if err != nil {
		t.Fatal(err)
	}
	sizes := []int{}
	for _, batch := range sender.batches {
		sizes = append(sizes, len(batch))
	}
	if fmt.Sprint(sizes) != "[256 256 88]" {
		t.Fatalf("batch sizes = %v", sizes)
	}
	// 2 + 2 + 0 quarantined events are skipped, like a rejected single event.
	if delivered != 596 {
		t.Fatalf("delivered = %d, want 596", delivered)
	}
	var first map[string]any
	if err := json.Unmarshal(sender.batches[0][0], &first); err != nil || first["_path"] != "conn" {
		t.Fatalf("batched events lost their Zeek path: %s err=%v", sender.batches[0][0], err)
	}
}

func TestHTTPSenderPostsNDJSONBatchesAndFallsBackForOlderIngest(t *testing.T) {
	var mu sync.Mutex
	single, batchRequests := 0, 0
	supportsBatch := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(request.Body)
		switch request.URL.Path {
		case "/v1/adapters/zeek/batch":
			if !supportsBatch {
				http.NotFound(w, request)
				return
			}
			batchRequests++
			if request.Header.Get("Content-Type") != "application/x-ndjson" || request.Header.Get("X-ShakerProxy-Capture-Session-ID") != testSessionID {
				t.Errorf("batch headers: %v", request.Header)
			}
			lines := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
			results := make([]ingest.AcceptResult, len(lines))
			for index := range lines {
				results[index] = ingest.AcceptResult{Accepted: true, RecordID: strings.Repeat("a", 64)}
			}
			results[len(results)-1] = ingest.AcceptResult{Quarantined: true, RecordID: strings.Repeat("b", 64), Reason: "invalid"}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"schema": 1, "results": results})
		case "/v1/adapters/zeek":
			single++
			if strings.Contains(string(body), "bad") {
				w.WriteHeader(http.StatusUnprocessableEntity)
				return
			}
			w.WriteHeader(http.StatusAccepted)
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()
	config := Config{Engine: EngineZeek, CaptureRoot: "/capture", StateRoot: "/state", WorkRoot: "/work", IngestURL: server.URL, Token: []byte(strings.Repeat("t", 32)), SourceVersion: "8.2.1"}.WithDefaults()
	sender, err := NewHTTPSender(config)
	if err != nil {
		t.Fatal(err)
	}
	events := [][]byte{[]byte(`{"a":1}`), []byte(`{"a":2}`), []byte(`{"bad":3}`)}
	rejected, err := sender.SendBatch(context.Background(), EngineZeek, testSessionID, events)
	if err != nil || rejected != 1 || batchRequests != 1 || single != 0 {
		t.Fatalf("batch: rejected=%d err=%v batches=%d singles=%d", rejected, err, batchRequests, single)
	}
	if _, err := sender.SendBatch(context.Background(), EngineZeek, testSessionID, [][]byte{[]byte("{\"a\":1}\n{\"b\":2}")}); err == nil {
		t.Fatal("an event containing a newline was batched")
	}
	// An ingest service from before batching answers 404: the sender falls
	// back to one request per event and remembers it.
	supportsBatch = false
	rejected, err = sender.SendBatch(context.Background(), EngineZeek, testSessionID, events)
	if err != nil || rejected != 1 || single != 3 {
		t.Fatalf("fallback: rejected=%d err=%v singles=%d", rejected, err, single)
	}
	supportsBatch = true
	if _, err := sender.SendBatch(context.Background(), EngineZeek, testSessionID, events[:2]); err != nil || batchRequests != 1 || single != 5 {
		t.Fatalf("the fallback was not remembered: batches=%d singles=%d err=%v", batchRequests, single, err)
	}
}

func TestRunnerDoesNotAdvanceActiveProgressAfterAFailedBatch(t *testing.T) {
	root, state, work, _ := writeCaptureFixture(t)
	if err := os.Remove(filepath.Join(root, testSessionID, "runtime", "manifest.json")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(root, testSessionID, "artifacts", "capture_00001.pcapng"))
	if err != nil {
		t.Fatal(err)
	}
	closedAt := time.Date(2026, 9, 1, 11, 58, 0, 0, time.UTC)
	writeJSONFixture(t, filepath.Join(root, testSessionID, "runtime", "active-segments.json"), capture.ActiveSegmentFeed{Schema: capture.SchemaVersion, SessionID: testSessionID, Revision: 1, PublishedAt: closedAt, Segments: []capture.ClosedCaptureSegment{{Sequence: 1, Name: info.Name(), SizeBytes: info.Size(), Modified: info.ModTime().UTC(), ClosedAt: closedAt}}})
	sender := &batchingSender{fail: true}
	runner := testRunner(t, root, state, work, EngineZeek, fixtureProcessor{engine: EngineZeek}, sender)
	if result := runner.RunOnce(context.Background()); len(result.Errors) != 1 {
		t.Fatalf("a failed batch was not surfaced: %#v", result)
	}
	if _, exists, err := runner.State.ReadActiveProgress(EngineZeek, testSessionID); err != nil || exists {
		t.Fatalf("a failed batch advanced progress: exists=%v err=%v", exists, err)
	}
	sender.fail = false
	if result := runner.RunOnce(context.Background()); len(result.Errors) != 0 || result.Segments != 1 || len(sender.batches) != 1 {
		t.Fatalf("retry after the failed batch: %#v batches=%d", result, len(sender.batches))
	}
	progress, exists, err := runner.State.ReadActiveProgress(EngineZeek, testSessionID)
	if err != nil || !exists || progress.LastCompletedSequence != 1 || progress.EventsDelivered != 1 {
		t.Fatalf("progress after the retry: %#v exists=%v err=%v", progress, exists, err)
	}
}
