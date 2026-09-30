package analyzer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
)

type flakySender struct {
	events   [][]byte
	failFrom int
	reject   map[int]bool
	calls    int
}

func (s *flakySender) Send(_ context.Context, _ Engine, _ string, event []byte) error {
	s.calls++
	if s.reject[s.calls] {
		return ErrEventRejected
	}
	if s.failFrom > 0 && s.calls >= s.failFrom {
		return errors.New("ingest unavailable")
	}
	s.events = append(s.events, append([]byte(nil), event...))
	return nil
}

func writeTwoArtifactCapture(t *testing.T) (string, string, string) {
	t.Helper()
	root, state, work, _ := writeCaptureFixture(t)
	artifacts := filepath.Join(root, testSessionID, "artifacts")
	contents := []byte("bounded-pcap-fixture")
	if err := os.WriteFile(filepath.Join(artifacts, "capture_00002.pcapng"), contents, 0o640); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	files := make([]capture.CaptureFile, 0, 2)
	var total int64
	for _, name := range []string{"capture_00001.pcapng", "capture_00002.pcapng"} {
		info, err := os.Stat(filepath.Join(artifacts, name))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, capture.CaptureFile{Name: name, SizeBytes: info.Size(), SHA256: hex.EncodeToString(digest[:]), Modified: info.ModTime().UTC()})
		total += info.Size()
	}
	manifest := capture.Manifest{Schema: capture.SchemaVersion, SessionID: testSessionID, CreatedAt: time.Date(2026, 9, 1, 11, 59, 0, 0, time.UTC), SessionSHA256: strings.Repeat("a", 64), Files: files, TotalSizeBytes: total}
	writeJSONFixture(t, filepath.Join(root, testSessionID, "runtime", "manifest.json"), manifest)
	return root, state, work
}

func TestFinalizedCaptureResumesAfterLastCompletedArtifact(t *testing.T) {
	root, state, work := writeTwoArtifactCapture(t)
	sender := &flakySender{failFrom: 2}
	runner := testRunner(t, root, state, work, EngineZeek, fixtureProcessor{engine: EngineZeek}, sender)
	first := runner.RunOnce(context.Background())
	if len(first.Errors) != 1 || len(sender.events) != 1 {
		t.Fatalf("second artifact failure was not surfaced: %#v events=%d", first, len(sender.events))
	}
	progress, exists, err := runner.State.ReadActiveProgress(EngineZeek, testSessionID)
	if err != nil || !exists || len(progress.Recent) != 1 || !progress.Recent[0].Finalized || progress.EventsDelivered != 1 {
		t.Fatalf("completed artifact was not recorded: %#v exists=%v err=%v", progress, exists, err)
	}
	sender.failFrom = 0
	second := runner.RunOnce(context.Background())
	if len(second.Errors) != 0 || second.Completed != 1 || second.Events != 1 || len(sender.events) != 2 {
		t.Fatalf("retry re-delivered a completed artifact: %#v events=%d", second, len(sender.events))
	}
	checkpoint, exists, err := runner.State.ReadCheckpoint(EngineZeek, testSessionID)
	if err != nil || !exists || checkpoint.EventsDelivered != 2 || checkpoint.ActiveSegments != 0 {
		t.Fatalf("checkpoint totals were wrong: %#v exists=%v err=%v", checkpoint, exists, err)
	}
}

func TestRepeatedCaptureFailuresBackOff(t *testing.T) {
	root, state, work, _ := writeCaptureFixture(t)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	runner := testRunner(t, root, state, work, EngineZeek, fixtureProcessor{engine: EngineZeek, failed: true}, &recordingSender{})
	runner.Now = func() time.Time { return now }
	if result := runner.RunOnce(context.Background()); len(result.Errors) != 1 {
		t.Fatalf("first failure was not reported: %#v", result)
	}
	if result := runner.RunOnce(context.Background()); len(result.Errors) != 1 || result.Deferred != 0 {
		t.Fatalf("first failure should retry on the next poll: %#v", result)
	}
	if result := runner.RunOnce(context.Background()); len(result.Errors) != 0 || result.Deferred != 1 {
		t.Fatalf("repeated failure did not back off: %#v", result)
	}
	now = now.Add(MaxCaptureRetryDelay)
	runner.Processor = fixtureProcessor{engine: EngineZeek}
	if result := runner.RunOnce(context.Background()); len(result.Errors) != 0 || result.Completed != 1 || result.Deferred != 0 {
		t.Fatalf("capture was not retried after its backoff: %#v", result)
	}
}

func TestRejectedAnalyzerEventDoesNotFailDelivery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conn.log")
	lines := `{"ts":1788278400.25,"uid":"Cfixture1"}` + "\n" + `{"ts":1788278400.26,"uid":"Cfixture2"}` + "\n"
	if err := os.WriteFile(path, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	sender := &flakySender{reject: map[int]bool{1: true}}
	delivered, _, err := deliverEventFiles(context.Background(), sender, EngineZeek, testSessionID, []EventFile{{Path: path, ZeekPath: "conn"}}, 1<<20, MaxEventsPerCapture)
	if err != nil || delivered != 1 || len(sender.events) != 1 || !strings.Contains(string(sender.events[0]), "Cfixture2") {
		t.Fatalf("a quarantined event aborted delivery: delivered=%d err=%v", delivered, err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
	}))
	defer server.Close()
	config := Config{Engine: EngineZeek, CaptureRoot: "/capture", StateRoot: "/state", WorkRoot: "/work", IngestURL: server.URL, Token: []byte(strings.Repeat("t", 32)), SourceVersion: "8.2.1"}.WithDefaults()
	httpSender, err := NewHTTPSender(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := httpSender.Send(context.Background(), EngineZeek, testSessionID, []byte(`{"ts":1}`)); !errors.Is(err, ErrEventRejected) {
		t.Fatalf("HTTP 422 was not classified as a rejected event: %v", err)
	}
}

func TestSuricataOutputIsNormalizedDeterministically(t *testing.T) {
	run := func(dnsFlow, httpFlow string) []string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "eve.json")
		lines := []string{
			`{"timestamp":"2026-09-21T14:13:20.000000+0000","flow_id":` + dnsFlow + `,"event_type":"dns","src_ip":"10.77.0.23","src_port":40000,"dest_ip":"10.77.0.1","dest_port":53,"proto":"UDP","dns":{"type":"request"}}`,
			`{"timestamp":"2026-09-21T14:13:20.010000+0000","flow_id":` + dnsFlow + `,"event_type":"dns","src_ip":"10.77.0.1","src_port":53,"dest_ip":"10.77.0.23","dest_port":40000,"proto":"UDP","dns":{"type":"response"}}`,
			`{"timestamp":"2026-09-21T14:13:20.090000+0000","flow_id":` + httpFlow + `,"event_type":"http","src_ip":"10.77.0.23","src_port":50000,"dest_ip":"93.184.216.34","dest_port":80,"proto":"TCP","http":{"hostname":"example.com"}}`,
			`{"timestamp":"2026-09-29T08:27:26.942679+0000","event_type":"stats","stats":{"uptime":0}}`,
		}
		if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		sender := &recordingSender{}
		if _, _, err := deliverEventFiles(context.Background(), sender, EngineSuricata, testSessionID, []EventFile{{Path: path}}, 1<<20, MaxEventsPerCapture); err != nil {
			t.Fatal(err)
		}
		out := make([]string, 0, len(sender.events))
		for _, event := range sender.events {
			out = append(out, string(event))
		}
		return out
	}
	first := run("3419338362", "171800015157452")
	second := run("1083396376", "171798697951954")
	if len(first) != 3 || strings.Join(first, "\n") != strings.Join(second, "\n") {
		t.Fatalf("Suricata output differed between runs or kept stats:\n%s\n---\n%s", strings.Join(first, "\n"), strings.Join(second, "\n"))
	}
	var request, response, web struct {
		FlowID uint64 `json:"flow_id"`
	}
	for index, target := range []any{&request, &response, &web} {
		if err := json.Unmarshal([]byte(first[index]), target); err != nil {
			t.Fatal(err)
		}
	}
	if request.FlowID != response.FlowID || request.FlowID == web.FlowID || request.FlowID < 1<<52 || request.FlowID >= 1<<53 {
		t.Fatalf("flow identities were not preserved: %d %d %d", request.FlowID, response.FlowID, web.FlowID)
	}
}

func TestZeekSeedValuesAreDeterministicPerArtifact(t *testing.T) {
	first := zeekSeedValues(withAnalysisSeed(context.Background(), []byte("artifact-a")))
	again := zeekSeedValues(withAnalysisSeed(context.Background(), []byte("artifact-a")))
	other := zeekSeedValues(withAnalysisSeed(context.Background(), []byte("artifact-b")))
	if first == "" || first != again || first == other || len(strings.Fields(first)) != 21 {
		t.Fatalf("unexpected Zeek seeds: %q %q %q", first, again, other)
	}
	if zeekSeedValues(context.Background()) != "" {
		t.Fatal("unseeded analysis produced seed values")
	}
	store := NewStateStore(t.TempDir())
	if err := store.Prepare(); err != nil {
		t.Fatal(err)
	}
	key, err := store.AnalysisSeedKey()
	if err != nil || len(key) != 32 {
		t.Fatalf("seed key was not created: %v", err)
	}
	reloaded, err := store.AnalysisSeedKey()
	if err != nil || string(reloaded) != string(key) {
		t.Fatalf("seed key was not stable: %v", err)
	}
}

func TestZeekBookkeepingLogsAreNotDelivered(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"conn.log", "packet_filter.log", "loaded_scripts.log"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	files, err := discoverEventFiles(EngineZeek, directory)
	if err != nil || len(files) != 1 || files[0].ZeekPath != "conn" {
		t.Fatalf("unexpected Zeek outputs: %#v err=%v", files, err)
	}
}
