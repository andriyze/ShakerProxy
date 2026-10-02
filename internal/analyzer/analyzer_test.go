package analyzer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/pcapng"
)

const testSessionID = "capture-0123456789abcdef0123456789abcdef"

type recordingSender struct {
	events [][]byte
	fail   bool
}

func (s *recordingSender) Send(_ context.Context, _ Engine, _ string, event []byte) error {
	if s.fail {
		return errors.New("ingest unavailable")
	}
	s.events = append(s.events, append([]byte(nil), event...))
	return nil
}

type fixtureProcessor struct {
	engine Engine
	mutate func()
	failed bool
}

func (p fixtureProcessor) Analyze(_ context.Context, file *os.File, directory string) ([]EventFile, error) {
	contents, err := io.ReadAll(file)
	if err != nil || string(contents) != "bounded-pcap-fixture" {
		return nil, errors.New("processor did not receive the verified open capture")
	}
	if p.mutate != nil {
		p.mutate()
	}
	if p.failed {
		return nil, errors.New("parser rejected capture")
	}
	if p.engine == EngineSuricata {
		path := filepath.Join(directory, "eve.json")
		if err := os.WriteFile(path, []byte(`{"timestamp":"2026-09-01T12:00:00Z","event_type":"flow","flow_id":42}`+"\n"), 0o600); err != nil {
			return nil, err
		}
		return []EventFile{{Path: path}}, nil
	}
	path := filepath.Join(directory, "conn.log")
	if err := os.WriteFile(path, []byte(`{"ts":1788278400.25,"uid":"Cfixture"}`+"\n"), 0o600); err != nil {
		return nil, err
	}
	return []EventFile{{Path: path, ZeekPath: "conn"}}, nil
}

func TestConfigRejectsUnsafeEndpointsAndBounds(t *testing.T) {
	base := Config{Engine: EngineZeek, CaptureRoot: "/capture", StateRoot: "/state", WorkRoot: "/work", IngestURL: "http://ingestd:8081", Token: []byte(strings.Repeat("a", 32)), SourceVersion: "8.2.1"}.WithDefaults()
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for index, mutate := range []func(*Config){
		func(value *Config) { value.IngestURL = "https://example.test" },
		func(value *Config) { value.IngestURL = "http://user:pass@ingestd:8081" },
		func(value *Config) { value.CaptureRoot = "relative" },
		func(value *Config) { value.StateRoot = "/capture/state" },
		func(value *Config) { value.Token = []byte("short") },
		func(value *Config) { value.AnalysisLimit = 5 * time.Second },
		func(value *Config) { value.MaxOutputBytes = 2 << 30 },
	} {
		candidate := base
		mutate(&candidate)
		if err := candidate.Validate(); err == nil {
			t.Fatalf("unsafe config case %d was accepted", index)
		}
	}
}

func TestRunnerVerifiesCaptureDeliversAndCheckpoints(t *testing.T) {
	root, state, work, manifest := writeCaptureFixture(t)
	sender := &recordingSender{}
	runner := testRunner(t, root, state, work, EngineZeek, fixtureProcessor{engine: EngineZeek}, sender)
	result := runner.RunOnce(context.Background())
	if len(result.Errors) != 0 || result.Completed != 1 || result.Events != 1 || len(sender.events) != 1 {
		t.Fatalf("unexpected first scan: %#v events=%d", result, len(sender.events))
	}
	var event map[string]any
	if json.Unmarshal(sender.events[0], &event) != nil || event["_path"] != "conn" {
		t.Fatalf("Zeek path was not safely attributed: %s", sender.events[0])
	}
	checkpoint, exists, err := runner.State.ReadCheckpoint(EngineZeek, testSessionID)
	if err != nil || !exists || checkpoint.ManifestSHA256 != manifest || checkpoint.EventsDelivered != 1 {
		t.Fatalf("checkpoint missing or invalid: %#v exists=%v err=%v", checkpoint, exists, err)
	}
	second := runner.RunOnce(context.Background())
	if len(second.Errors) != 0 || second.Skipped != 1 || second.Completed != 0 || len(sender.events) != 1 {
		t.Fatalf("checkpoint did not suppress replay: %#v events=%d", second, len(sender.events))
	}
}

func TestRunnerProcessesClosedRotationsOnceAndCarriesProgressIntoFinalCheckpoint(t *testing.T) {
	root, state, work, _ := writeCaptureFixture(t)
	manifestPath := filepath.Join(root, testSessionID, "runtime", "manifest.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(manifestPath); err != nil {
		t.Fatal(err)
	}
	artifactPath := filepath.Join(root, testSessionID, "artifacts", "capture_00001.pcapng")
	info, err := os.Stat(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	feed := capture.ActiveSegmentFeed{
		Schema: capture.SchemaVersion, SessionID: testSessionID, Revision: 1, PublishedAt: time.Date(2026, 9, 1, 11, 58, 0, 0, time.UTC),
		Segments: []capture.ClosedCaptureSegment{{Sequence: 1, Name: info.Name(), SizeBytes: info.Size(), Modified: info.ModTime().UTC(), ClosedAt: time.Date(2026, 9, 1, 11, 58, 0, 0, time.UTC)}},
	}
	writeJSONFixture(t, filepath.Join(root, testSessionID, "runtime", "active-segments.json"), feed)
	sender := &recordingSender{}
	runner := testRunner(t, root, state, work, EngineZeek, fixtureProcessor{engine: EngineZeek}, sender)
	first := runner.RunOnce(context.Background())
	if len(first.Errors) != 0 || first.Segments != 1 || first.Events != 1 || first.Completed != 0 || len(sender.events) != 1 {
		t.Fatalf("unexpected active scan: %#v events=%d", first, len(sender.events))
	}
	progress, exists, err := runner.State.ReadActiveProgress(EngineZeek, testSessionID)
	if err != nil || !exists || progress.SegmentsProcessed != 1 || progress.EventsDelivered != 1 || len(progress.Recent) != 1 {
		t.Fatalf("active progress missing: %#v exists=%v err=%v", progress, exists, err)
	}
	restarted := testRunner(t, root, state, work, EngineZeek, fixtureProcessor{engine: EngineZeek}, sender)
	second := restarted.RunOnce(context.Background())
	if len(second.Errors) != 0 || second.Segments != 0 || second.Events != 0 || second.Skipped != 1 || len(sender.events) != 1 {
		t.Fatalf("restart replayed an active segment: %#v events=%d", second, len(sender.events))
	}
	if err := os.WriteFile(manifestPath, manifestBytes, 0o640); err != nil {
		t.Fatal(err)
	}
	final := restarted.RunOnce(context.Background())
	if len(final.Errors) != 0 || final.Completed != 1 || final.Events != 0 || len(sender.events) != 1 {
		t.Fatalf("finalization replayed active output: %#v events=%d", final, len(sender.events))
	}
	checkpoint, exists, err := restarted.State.ReadCheckpoint(EngineZeek, testSessionID)
	if err != nil || !exists || checkpoint.ActiveSegments != 1 || checkpoint.EventsDelivered != 1 {
		t.Fatalf("active totals were not carried into checkpoint: %#v exists=%v err=%v", checkpoint, exists, err)
	}
	if _, exists, err := restarted.State.ReadActiveProgress(EngineZeek, testSessionID); err != nil || exists {
		t.Fatalf("finalization retained active progress: exists=%v err=%v", exists, err)
	}
}

func TestRunnerRecordsEvictedActiveRotationGap(t *testing.T) {
	root, state, work, _ := writeCaptureFixture(t)
	if err := os.Remove(filepath.Join(root, testSessionID, "runtime", "manifest.json")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(root, testSessionID, "artifacts", "capture_00001.pcapng"))
	if err != nil {
		t.Fatal(err)
	}
	closedAt := time.Date(2026, 9, 1, 11, 58, 0, 0, time.UTC)
	feed := capture.ActiveSegmentFeed{Schema: capture.SchemaVersion, SessionID: testSessionID, Revision: 3, PublishedAt: closedAt, EvictedSegments: 2, Segments: []capture.ClosedCaptureSegment{{Sequence: 3, Name: info.Name(), SizeBytes: info.Size(), Modified: info.ModTime().UTC(), ClosedAt: closedAt}}}
	writeJSONFixture(t, filepath.Join(root, testSessionID, "runtime", "active-segments.json"), feed)
	runner := testRunner(t, root, state, work, EngineSuricata, fixtureProcessor{engine: EngineSuricata}, &recordingSender{})
	result := runner.RunOnce(context.Background())
	progress, exists, err := runner.State.ReadActiveProgress(EngineSuricata, testSessionID)
	if len(result.Errors) != 0 || result.Segments != 1 || err != nil || !exists || progress.MissedSegments != 2 || progress.LastCompletedSequence != 3 {
		t.Fatalf("evicted rotation gap was not recorded: result=%#v progress=%#v exists=%v err=%v", result, progress, exists, err)
	}
}

func TestRunnerDoesNotAdvanceActiveProgressAfterFailedDelivery(t *testing.T) {
	root, state, work, _ := writeCaptureFixture(t)
	if err := os.Remove(filepath.Join(root, testSessionID, "runtime", "manifest.json")); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(filepath.Join(root, testSessionID, "artifacts", "capture_00001.pcapng"))
	closedAt := time.Date(2026, 9, 1, 11, 58, 0, 0, time.UTC)
	writeJSONFixture(t, filepath.Join(root, testSessionID, "runtime", "active-segments.json"), capture.ActiveSegmentFeed{Schema: capture.SchemaVersion, SessionID: testSessionID, Revision: 1, PublishedAt: closedAt, Segments: []capture.ClosedCaptureSegment{{Sequence: 1, Name: info.Name(), SizeBytes: info.Size(), Modified: info.ModTime().UTC(), ClosedAt: closedAt}}})
	runner := testRunner(t, root, state, work, EngineZeek, fixtureProcessor{engine: EngineZeek}, &recordingSender{fail: true})
	result := runner.RunOnce(context.Background())
	if len(result.Errors) != 1 {
		t.Fatalf("active delivery failure was not surfaced: %#v", result)
	}
	if _, exists, err := runner.State.ReadActiveProgress(EngineZeek, testSessionID); err != nil || exists {
		t.Fatalf("failed active delivery advanced progress: exists=%v err=%v", exists, err)
	}
}

func TestRunnerDoesNotCheckpointFailedDelivery(t *testing.T) {
	root, state, work, _ := writeCaptureFixture(t)
	sender := &recordingSender{fail: true}
	runner := testRunner(t, root, state, work, EngineSuricata, fixtureProcessor{engine: EngineSuricata}, sender)
	result := runner.RunOnce(context.Background())
	if len(result.Errors) != 1 || result.Completed != 0 {
		t.Fatalf("delivery failure was not isolated: %#v", result)
	}
	if _, exists, err := runner.State.ReadCheckpoint(EngineSuricata, testSessionID); err != nil || exists {
		t.Fatalf("failed delivery created a checkpoint: exists=%v err=%v", exists, err)
	}
}

func TestRunnerRejectsArtifactMutationAfterParser(t *testing.T) {
	root, state, work, _ := writeCaptureFixture(t)
	artifactPath := filepath.Join(root, testSessionID, "artifacts", "capture_00001.pcapng")
	info, err := os.Stat(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	processor := fixtureProcessor{engine: EngineZeek, mutate: func() {
		if err := os.WriteFile(artifactPath, []byte(strings.Repeat("x", int(info.Size()))), 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(artifactPath, info.ModTime(), info.ModTime()); err != nil {
			t.Fatal(err)
		}
	}}
	sender := &recordingSender{}
	runner := testRunner(t, root, state, work, EngineZeek, processor, sender)
	result := runner.RunOnce(context.Background())
	if len(result.Errors) != 1 || len(sender.events) != 0 || !strings.Contains(result.Errors[0].Error(), "hash") {
		t.Fatalf("post-parser mutation was not rejected before delivery: %#v events=%d", result, len(sender.events))
	}
}

func TestManifestAndOutputSymlinksAreRejected(t *testing.T) {
	root, _, _, _ := writeCaptureFixture(t)
	job, err := loadCaptureJob(root, testSessionID)
	if err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(root, testSessionID, "artifacts", "capture_00001.pcapng")
	target := filepath.Join(t.TempDir(), "outside.pcapng")
	if err := os.WriteFile(target, []byte("bounded-pcap-fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(artifact); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, artifact); err != nil {
		t.Fatal(err)
	}
	if _, err := openVerifiedArtifact(root, testSessionID, job.Manifest.Files[0]); err == nil {
		t.Fatal("symlinked capture artifact was accepted")
	}
	manifestPath := filepath.Join(root, testSessionID, "runtime", "manifest.json")
	manifestTarget := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(manifestTarget, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(manifestPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(manifestTarget, manifestPath); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCaptureJob(root, testSessionID); err == nil {
		t.Fatal("symlinked capture manifest was accepted")
	}
	outputDirectory := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.log")
	if err := os.WriteFile(outside, []byte(`{"ts":1788278400}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(outputDirectory, "conn.log")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := deliverEventFiles(context.Background(), &recordingSender{}, EngineZeek, testSessionID, []EventFile{{Path: link, ZeekPath: "conn"}}, 1<<20, MaxEventsPerCapture); err == nil {
		t.Fatal("symlinked analyzer output was accepted")
	}
}

func TestManifestRejectsInvalidPacketMembership(t *testing.T) {
	root, _, _, _ := writeCaptureFixture(t)
	job, err := loadCaptureJob(root, testSessionID)
	if err != nil {
		t.Fatal(err)
	}
	job.Manifest.Files[0].PacketMembership = &pcapng.Membership{
		Schema:      pcapng.MembershipSchema,
		State:       pcapng.MembershipExact,
		PacketCount: 1,
		LinkTypes:   []uint16{147},
	}
	if err := validateManifest(job.Manifest, testSessionID); err == nil {
		t.Fatal("manifest with impossible exact packet membership was accepted")
	}
	job.Manifest.Files[0].PacketMembership = nil
	job.Manifest.Files[0].RewriteManifestID = "../rewrite.json"
	if err := validateManifest(job.Manifest, testSessionID); err == nil {
		t.Fatal("manifest with an invalid rewrite lineage ID was accepted")
	}
}

func TestStateStoreRejectsSymlinkRootAndCorruptStatus(t *testing.T) {
	target := t.TempDir()
	root := filepath.Join(t.TempDir(), "state-link")
	if err := os.Symlink(target, root); err != nil {
		t.Fatal(err)
	}
	if err := (StateStore{Root: root}).Prepare(); err == nil {
		t.Fatal("symlinked state root was accepted")
	}
	if _, err := os.Stat(filepath.Join(target, "checkpoints")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("state preparation mutated the symlink target")
	}
	root = filepath.Join(t.TempDir(), "state")
	store := StateStore{Root: root}
	if err := store.Prepare(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "status.json"), []byte(`{"schema":1,"engine":"ZEEK","source_version":"8.2.1","started_at":"2026-09-01T12:00:00Z","updated_at":"2026-09-01T12:00:01Z","unexpected":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadStatus(); err == nil {
		t.Fatal("status with unknown fields was accepted")
	}
}

func TestHTTPSenderUsesBoundAdapterHeadersAndRejectsRedirect(t *testing.T) {
	var captured *http.Request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		captured = request.Clone(request.Context())
		body, _ := io.ReadAll(request.Body)
		if !strings.Contains(string(body), `"event_type":"flow"`) {
			t.Errorf("unexpected body: %s", body)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	config := Config{Engine: EngineSuricata, CaptureRoot: "/capture", StateRoot: "/state", WorkRoot: "/work", IngestURL: server.URL, Token: []byte(strings.Repeat("t", 32)), SourceVersion: "8.0.6"}.WithDefaults()
	sender, err := NewHTTPSender(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.Send(context.Background(), EngineSuricata, testSessionID, []byte(`{"timestamp":"2026-09-01T12:00:00Z","event_type":"flow"}`)); err != nil {
		t.Fatal(err)
	}
	if captured.URL.Path != "/v1/adapters/suricata" || captured.Header.Get("Authorization") != "Bearer "+strings.Repeat("t", 32) || captured.Header.Get("X-ShakerProxy-Source-Version") != "8.0.6" || captured.Header.Get("X-ShakerProxy-Capture-Session-ID") != testSessionID {
		t.Fatalf("delivery headers or path are incorrect: %#v", captured)
	}
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, server.URL, http.StatusFound)
	}))
	defer redirect.Close()
	config.IngestURL = redirect.URL
	sender, err = NewHTTPSender(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.Send(context.Background(), EngineSuricata, testSessionID, []byte(`{"timestamp":"2026-09-01T12:00:00Z","event_type":"flow"}`)); err == nil {
		t.Fatal("ingest redirect was followed")
	}
}

func TestZeekPathAttributionRejectsConflictAndOversizedLine(t *testing.T) {
	if _, err := addZeekPath([]byte(`{"ts":1,"_path":"dns"}`), "conn"); err == nil {
		t.Fatal("conflicting Zeek path was accepted")
	}
	path := filepath.Join(t.TempDir(), "conn.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 200<<10)+"\n"+`{"ts":1788278400.25,"uid":"Cfixture"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sender := &recordingSender{}
	delivered, _, err := deliverEventFiles(context.Background(), sender, EngineZeek, testSessionID, []EventFile{{Path: path, ZeekPath: "conn"}}, 1<<20, MaxEventsPerCapture)
	if err != nil || delivered != 1 || len(sender.events) != 1 || strings.Contains(string(sender.events[0]), "xxxx") {
		t.Fatalf("oversized analyzer line was not skipped in isolation: delivered=%d events=%d err=%v", delivered, len(sender.events), err)
	}
}

func TestOutputDirectoryLimitCountsIgnoredEngineFiles(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "eve.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "engine-debug.log"), []byte(strings.Repeat("x", 1024)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := validateOutputDirectory(directory, 512); err == nil {
		t.Fatal("ignored engine output bypassed the aggregate byte limit")
	}
}

func TestParserEnvironmentIsAnEngineSpecificAllowlist(t *testing.T) {
	t.Setenv("SHAKERPROXY_INGEST_TOKEN_FILE", "/run/secrets/broker-only-token")
	t.Setenv("SHAKERPROXY_INGEST_URL", "http://ingestd:8081")
	for _, engine := range []Engine{EngineZeek, EngineSuricata} {
		environment := parserEnvironment(engine, "/work/job")
		joined := strings.Join(environment, "\n")
		if strings.Contains(joined, "SHAKERPROXY_") || strings.Contains(joined, "broker-only-token") || strings.Contains(joined, "ingestd") {
			t.Fatalf("%s parser inherited broker-only environment: %q", engine, environment)
		}
		for _, required := range []string{"HOME=/nonexistent", "TMPDIR=/work/job", "TZ=UTC", "PATH="} {
			if !strings.Contains(joined, required) {
				t.Fatalf("%s parser environment lacks %q: %q", engine, required, environment)
			}
		}
	}
}

func TestStateStoreRejectsSymlinkMetadataAndInvalidStatusTimeline(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	store := StateStore{Root: root}
	if err := store.Prepare(); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "status.json")
	if err := os.WriteFile(target, []byte(`{"schema":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "status.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadStatus(); err == nil {
		t.Fatal("symlinked analyzer status was accepted")
	}
	if err := os.Remove(filepath.Join(root, "status.json")); err != nil {
		t.Fatal(err)
	}
	started := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	status := Status{Schema: SchemaVersion, Engine: EngineZeek, SourceVersion: "8.2.1", StartedAt: started, UpdatedAt: started.Add(time.Minute), LastScanAt: started.Add(2 * time.Minute)}
	if err := store.WriteStatus(status); err == nil {
		t.Fatal("status with a scan timestamp after its update was accepted")
	}
	status.LastScanAt = started
	status.LastSuccessAt = started.Add(-time.Second)
	if err := store.WriteStatus(status); err == nil {
		t.Fatal("status with a success timestamp before worker start was accepted")
	}
}

func TestLoadTokenUsesBoundedNoFollowRead(t *testing.T) {
	target := filepath.Join(t.TempDir(), "token")
	want := strings.Repeat("t", 32)
	if err := os.WriteFile(target, []byte(want+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token, err := LoadToken(target)
	if err != nil || string(token) != want {
		t.Fatalf("regular bounded token was not loaded: token=%q err=%v", token, err)
	}
	link := filepath.Join(t.TempDir(), "token-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadToken(link); err == nil {
		t.Fatal("symlinked analyzer token was accepted")
	}
}

func TestCheckpointDeletionIsCrashSafeIdempotentAndPreventsReplay(t *testing.T) {
	root, state, work, _ := writeCaptureFixture(t)
	sender := &recordingSender{}
	runner := testRunner(t, root, state, work, EngineZeek, fixtureProcessor{engine: EngineZeek}, sender)
	if result := runner.RunOnce(context.Background()); len(result.Errors) != 0 || result.Completed != 1 {
		t.Fatalf("fixture analysis failed: %#v", result)
	}
	now := time.Date(2026, 9, 1, 12, 5, 0, 0, time.UTC)
	service, err := NewCheckpointDeletionService(runner.State, EngineZeek)
	if err != nil {
		t.Fatal(err)
	}
	service.Now = func() time.Time { return now }
	preview, err := service.Preview(testSessionID)
	if err != nil || preview.Validate() != nil || !preview.CheckpointPresent || preview.CheckpointBytes < 2 || preview.EventsDelivered != 1 {
		t.Fatalf("checkpoint preview is incomplete: %#v err=%v", preview, err)
	}
	request := CheckpointDeletionRequest{Schema: CheckpointDeletionSchema, OperationID: "checkpoint-delete-operation-0001", Actor: "admin", Preview: preview}
	outcome, err := service.Delete(request)
	if err != nil || outcome.Validate() != nil || outcome.Replayed || !outcome.VerifiedAbsent || outcome.DeletedCheckpointBytes != preview.CheckpointBytes {
		t.Fatalf("checkpoint deletion failed: %#v err=%v", outcome, err)
	}
	if _, err := os.Stat(filepath.Join(state, "checkpoints", testSessionID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("checkpoint still exists after deletion: %v", err)
	}
	receiptInfo, err := os.Stat(filepath.Join(state, "deletions", testSessionID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if receiptInfo.Mode().Perm() != 0o600 {
		t.Fatalf("deletion barrier has unsafe mode: %v", receiptInfo.Mode())
	}
	result := runner.RunOnce(context.Background())
	if len(result.Errors) != 0 || result.Skipped != 1 || result.Completed != 0 || len(sender.events) != 1 {
		t.Fatalf("deletion barrier permitted analyzer replay: %#v events=%d", result, len(sender.events))
	}
	service.Now = func() time.Time { return preview.ExpiresAt.Add(time.Hour) }
	replayed, err := service.Delete(request)
	if err != nil || !replayed.Replayed || replayed.CompletedAt != outcome.CompletedAt {
		t.Fatalf("checkpoint deletion replay was not stable: %#v err=%v", replayed, err)
	}
}

func TestCheckpointDeletionBindsAndRemovesActiveRotationProgress(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	store := NewStateStore(filepath.Join(t.TempDir(), "state"))
	if err := store.Prepare(); err != nil {
		t.Fatal(err)
	}
	progress := ActiveProgress{
		Schema: SchemaVersion, Engine: EngineZeek, CaptureSessionID: testSessionID, FeedRevision: 1, LastCompletedSequence: 1, SegmentsProcessed: 1, EventsDelivered: 1, OutputBytes: 64, UpdatedAt: now,
		Recent: []ProcessedSegment{{Sequence: 1, Name: "capture_00001.pcapng", SizeBytes: 20, Modified: now.Add(-time.Minute), SHA256: strings.Repeat("a", 64)}},
	}
	if err := store.WriteActiveProgress(progress); err != nil {
		t.Fatal(err)
	}
	service, err := NewCheckpointDeletionService(store, EngineZeek)
	if err != nil {
		t.Fatal(err)
	}
	service.Now = func() time.Time { return now }
	preview, err := service.Preview(testSessionID)
	if err != nil || preview.Validate() != nil || preview.CheckpointPresent || !preview.ActiveProgressPresent || preview.ActiveProgressBytes < 2 || !validDigest(preview.ActiveProgressSHA256) {
		t.Fatalf("active progress was not bound into deletion preview: %#v err=%v", preview, err)
	}
	request := CheckpointDeletionRequest{Schema: CheckpointDeletionSchema, OperationID: "checkpoint-delete-active-0001", Actor: "admin", Preview: preview}
	outcome, err := service.Delete(request)
	if err != nil || outcome.Validate() != nil || !outcome.ActiveProgressWasPresent || outcome.DeletedActiveProgressBytes != preview.ActiveProgressBytes || !outcome.VerifiedAbsent {
		t.Fatalf("active progress deletion was not acknowledged: %#v err=%v", outcome, err)
	}
	if _, exists, err := store.ReadActiveProgress(EngineZeek, testSessionID); err != nil || exists {
		t.Fatalf("active progress remains after deletion: exists=%v err=%v", exists, err)
	}
	if err := store.WriteActiveProgress(progress); !errors.Is(err, ErrCheckpointDeletionBarrier) {
		t.Fatalf("deletion barrier allowed active progress recreation: %v", err)
	}
}

func TestCheckpointDeletionRejectsStaleEvidenceAndResumesAfterRemove(t *testing.T) {
	root, state, work, _ := writeCaptureFixture(t)
	runner := testRunner(t, root, state, work, EngineSuricata, fixtureProcessor{engine: EngineSuricata}, &recordingSender{})
	if result := runner.RunOnce(context.Background()); len(result.Errors) != 0 || result.Completed != 1 {
		t.Fatalf("fixture analysis failed: %#v", result)
	}
	now := time.Date(2026, 9, 1, 12, 5, 0, 0, time.UTC)
	service, err := NewCheckpointDeletionService(runner.State, EngineSuricata)
	if err != nil {
		t.Fatal(err)
	}
	service.Now = func() time.Time { return now }
	stale, err := service.Preview(testSessionID)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, exists, err := runner.State.ReadCheckpoint(EngineSuricata, testSessionID)
	if err != nil || !exists {
		t.Fatal("fixture checkpoint is unavailable")
	}
	checkpoint.EventsDelivered++
	if err := runner.State.WriteCheckpoint(checkpoint); err != nil {
		t.Fatal(err)
	}
	staleRequest := CheckpointDeletionRequest{Schema: CheckpointDeletionSchema, OperationID: "checkpoint-delete-operation-0002", Actor: "admin", Preview: stale}
	if _, err := service.Delete(staleRequest); !errors.Is(err, ErrCheckpointDeletionPreviewStale) {
		t.Fatalf("changed checkpoint did not invalidate preview: %v", err)
	}
	preview, err := service.Preview(testSessionID)
	if err != nil {
		t.Fatal(err)
	}
	request := CheckpointDeletionRequest{Schema: CheckpointDeletionSchema, OperationID: "checkpoint-delete-operation-0003", Actor: "admin", Preview: preview}
	record := checkpointDeletionRecord{
		Schema: CheckpointDeletionSchema, Engine: EngineSuricata, CaptureSessionID: testSessionID,
		OperationID: request.OperationID, Actor: request.Actor, PreviewSHA256: preview.PreviewSHA256,
		CheckpointWasPresent: true, CreatedAt: now,
	}
	if err := runner.State.writeCheckpointDeletionRecord(record); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(state, "checkpoints", testSessionID+".json")); err != nil {
		t.Fatal(err)
	}
	outcome, err := service.Delete(request)
	if err != nil || !outcome.VerifiedAbsent || outcome.Replayed {
		t.Fatalf("pending deletion did not resume after removal: %#v err=%v", outcome, err)
	}
}

func TestCheckpointDeletionRejectsExpiredUnstartedPreview(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	store := NewStateStore(state)
	service, err := NewCheckpointDeletionService(store, EngineZeek)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 1, 12, 5, 0, 0, time.UTC)
	service.Now = func() time.Time { return now }
	preview, err := service.Preview(testSessionID)
	if err != nil || preview.CheckpointPresent {
		t.Fatalf("absent checkpoint preview failed: %#v err=%v", preview, err)
	}
	service.Now = func() time.Time { return preview.ExpiresAt }
	request := CheckpointDeletionRequest{Schema: CheckpointDeletionSchema, OperationID: "checkpoint-delete-operation-0005", Actor: "admin", Preview: preview}
	if _, err := service.Delete(request); !errors.Is(err, ErrCheckpointDeletionPreviewExpired) {
		t.Fatalf("expired unstarted preview was accepted: %v", err)
	}
	if barrier, err := store.HasCheckpointDeletionBarrier(EngineZeek, testSessionID); err != nil || barrier {
		t.Fatalf("expired request wrote a barrier: barrier=%v err=%v", barrier, err)
	}
}

func TestCheckpointDeletionBarrierWinsAgainstInFlightAnalysis(t *testing.T) {
	root, state, work, _ := writeCaptureFixture(t)
	sender := &recordingSender{}
	runner := testRunner(t, root, state, work, EngineZeek, nil, sender)
	now := time.Date(2026, 9, 1, 12, 5, 0, 0, time.UTC)
	service, err := NewCheckpointDeletionService(runner.State, EngineZeek)
	if err != nil {
		t.Fatal(err)
	}
	service.Now = func() time.Time { return now }
	preview, err := service.Preview(testSessionID)
	if err != nil || preview.CheckpointPresent {
		t.Fatalf("pre-analysis preview failed: %#v err=%v", preview, err)
	}
	request := CheckpointDeletionRequest{Schema: CheckpointDeletionSchema, OperationID: "checkpoint-delete-operation-0006", Actor: "admin", Preview: preview}
	runner.Processor = fixtureProcessor{engine: EngineZeek, mutate: func() {
		outcome, deleteErr := service.Delete(request)
		if deleteErr != nil || !outcome.VerifiedAbsent {
			t.Errorf("in-flight deletion failed: %#v err=%v", outcome, deleteErr)
		}
	}}
	result := runner.RunOnce(context.Background())
	if len(result.Errors) != 1 || !errors.Is(result.Errors[0], ErrCheckpointDeletionBarrier) || result.Completed != 0 || len(sender.events) != 1 {
		t.Fatalf("in-flight analysis crossed deletion barrier: %#v events=%d", result, len(sender.events))
	}
	if _, exists, err := runner.State.ReadCheckpoint(EngineZeek, testSessionID); err != nil || exists {
		t.Fatalf("in-flight analysis recreated checkpoint: exists=%v err=%v", exists, err)
	}
	second := runner.RunOnce(context.Background())
	if len(second.Errors) != 0 || second.Skipped != 1 || len(sender.events) != 1 {
		t.Fatalf("barrier did not suppress later replay: %#v events=%d", second, len(sender.events))
	}
}

func TestAnalyzerMaintenanceHTTPRequiresAuthenticationAndExactPreview(t *testing.T) {
	root, state, work, _ := writeCaptureFixture(t)
	runner := testRunner(t, root, state, work, EngineZeek, fixtureProcessor{engine: EngineZeek}, &recordingSender{})
	if result := runner.RunOnce(context.Background()); len(result.Errors) != 0 {
		t.Fatalf("fixture analysis failed: %#v", result)
	}
	service, err := NewCheckpointDeletionService(runner.State, EngineZeek)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 1, 12, 5, 0, 0, time.UTC)
	service.Now = func() time.Time { return now }
	token := strings.Repeat("m", 32)
	handler, err := NewMaintenanceHandler(service, []byte(token))
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/checkpoints/" + testSessionID + "/deletion-preview"
	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodPost, path, nil))
	if unauthorized.Code != http.StatusUnauthorized || unauthorized.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("maintenance endpoint did not fail closed: %d %s", unauthorized.Code, unauthorized.Body.String())
	}
	previewRequest := httptest.NewRequest(http.MethodPost, path, nil)
	previewRequest.Header.Set("Authorization", "Bearer "+token)
	previewRecorder := httptest.NewRecorder()
	handler.ServeHTTP(previewRecorder, previewRequest)
	var preview CheckpointDeletionPreview
	if previewRecorder.Code != http.StatusOK || json.Unmarshal(previewRecorder.Body.Bytes(), &preview) != nil || preview.Validate() != nil {
		t.Fatalf("authenticated preview failed: %d %s", previewRecorder.Code, previewRecorder.Body.String())
	}
	deletion := CheckpointDeletionRequest{Schema: CheckpointDeletionSchema, OperationID: "checkpoint-delete-operation-0004", Actor: "admin", Preview: preview}
	body, err := json.Marshal(deletion)
	if err != nil {
		t.Fatal(err)
	}
	deleteRequest := httptest.NewRequest(http.MethodPost, "/v1/checkpoints/"+testSessionID+"/deletion", bytes.NewReader(body))
	deleteRequest.Header.Set("Authorization", "Bearer "+token)
	deleteRequest.Header.Set("Content-Type", "application/json")
	deleteRecorder := httptest.NewRecorder()
	handler.ServeHTTP(deleteRecorder, deleteRequest)
	var outcome CheckpointDeletionOutcome
	if deleteRecorder.Code != http.StatusOK || json.Unmarshal(deleteRecorder.Body.Bytes(), &outcome) != nil || outcome.Validate() != nil {
		t.Fatalf("authenticated deletion failed: %d %s", deleteRecorder.Code, deleteRecorder.Body.String())
	}
}

func TestMaintenanceClientAuthenticatesValidatesAndRefusesRedirects(t *testing.T) {
	root, state, work, _ := writeCaptureFixture(t)
	runner := testRunner(t, root, state, work, EngineZeek, fixtureProcessor{engine: EngineZeek}, &recordingSender{})
	if result := runner.RunOnce(context.Background()); len(result.Errors) != 0 {
		t.Fatalf("fixture analysis failed: %#v", result)
	}
	service, err := NewCheckpointDeletionService(runner.State, EngineZeek)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 1, 12, 5, 0, 0, time.UTC)
	service.Now = func() time.Time { return now }
	token := []byte(strings.Repeat("c", 32))
	handler, err := NewMaintenanceHandler(service, token)
	if err != nil {
		t.Fatal(err)
	}
	httpService := httptest.NewServer(handler)
	defer httpService.Close()
	client, err := NewMaintenanceClient(httpService.URL, token, httpService.Client())
	if err != nil {
		t.Fatal(err)
	}
	preview, err := client.Preview(t.Context(), testSessionID)
	if err != nil || !preview.CheckpointPresent {
		t.Fatalf("maintenance client preview failed: %#v err=%v", preview, err)
	}
	request := CheckpointDeletionRequest{Schema: CheckpointDeletionSchema, OperationID: "checkpoint-delete-operation-0007", Actor: "admin", Preview: preview}
	outcome, err := client.Delete(t.Context(), request)
	if err != nil || !outcome.VerifiedAbsent {
		t.Fatalf("maintenance client deletion failed: %#v err=%v", outcome, err)
	}
	reindexRequest := CheckpointReindexRequest{
		Schema: CheckpointReindexSchema, OperationID: "checkpoint-reindex-operation-0007", Actor: request.Actor, Engine: preview.Engine,
		CaptureSessionID: preview.CaptureSessionID, DeletionOperationID: request.OperationID,
		DeletionPreviewSHA256: preview.PreviewSHA256, TargetManifestSHA256: strings.Repeat("f", 64),
	}
	reindex, err := client.AuthorizeReindex(t.Context(), reindexRequest)
	if err != nil || reindex.State != "AUTHORIZED" || reindex.TargetManifestSHA256 != reindexRequest.TargetManifestSHA256 {
		t.Fatalf("maintenance client reindex authorization failed: %#v err=%v", reindex, err)
	}
	mismatchedService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mismatched := outcome
		mismatched.Actor = "different-admin"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mismatched)
	}))
	defer mismatchedService.Close()
	mismatchedClient, err := NewMaintenanceClient(mismatchedService.URL, token, mismatchedService.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mismatchedClient.Delete(t.Context(), request); err == nil {
		t.Fatal("analyzer maintenance client accepted an outcome for a different actor")
	}
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, httpService.URL, http.StatusFound)
	}))
	defer redirect.Close()
	redirectClient, err := NewMaintenanceClient(redirect.URL, token, redirect.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := redirectClient.Preview(t.Context(), testSessionID); err == nil {
		t.Fatal("analyzer maintenance redirect was followed")
	}
	if _, err := NewMaintenanceClient("https://zeek:8082", token, nil); err == nil {
		t.Fatal("unsafe analyzer maintenance origin was accepted")
	}
}

func testRunner(t *testing.T, root, state, work string, engine Engine, processor Processor, sender Sender) *Runner {
	t.Helper()
	store := NewStateStore(state)
	if err := store.Prepare(); err != nil {
		t.Fatal(err)
	}
	return &Runner{
		Config: Config{Engine: engine, CaptureRoot: root, StateRoot: state, WorkRoot: work, IngestURL: "http://ingestd:8081", Token: []byte(strings.Repeat("t", 32)), SourceVersion: "test", PollInterval: time.Second, AnalysisLimit: time.Minute, MaxOutputBytes: 1 << 20},
		State:  store, Processor: processor, Sender: sender, Now: func() time.Time { return time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC) },
	}
}

func writeCaptureFixture(t *testing.T) (string, string, string, string) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "captures")
	state := filepath.Join(base, "state")
	work := filepath.Join(base, "work")
	artifacts := filepath.Join(root, testSessionID, "artifacts")
	runtime := filepath.Join(root, testSessionID, "runtime")
	for _, directory := range []string{artifacts, runtime, state, work} {
		if err := os.MkdirAll(directory, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	contents := []byte("bounded-pcap-fixture")
	artifactPath := filepath.Join(artifacts, "capture_00001.pcapng")
	if err := os.WriteFile(artifactPath, contents, 0o640); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	fileHash := sha256.Sum256(contents)
	manifest := capture.Manifest{
		Schema: capture.SchemaVersion, SessionID: testSessionID, CreatedAt: time.Date(2026, 9, 1, 11, 59, 0, 0, time.UTC), SessionSHA256: strings.Repeat("a", 64),
		Files: []capture.CaptureFile{{Name: "capture_00001.pcapng", SizeBytes: info.Size(), SHA256: hex.EncodeToString(fileHash[:]), Modified: info.ModTime().UTC()}}, TotalSizeBytes: info.Size(),
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(filepath.Join(runtime, "manifest.json"), encoded, 0o640); err != nil {
		t.Fatal(err)
	}
	manifestHash := sha256.Sum256(encoded)
	return root, state, work, hex.EncodeToString(manifestHash[:])
}

func writeJSONFixture(t *testing.T, path string, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o640); err != nil {
		t.Fatal(err)
	}
}

// Suricata failed on a segment, and the lab recording's ring buffer then
// removed it; every later scan failed with "no such file or directory" and
// the capture was never analyzed again.
func TestRunnerSkipsAnActiveSegmentTheRingAlreadyRemoved(t *testing.T) {
	root, state, work, _ := writeCaptureFixture(t)
	if err := os.Remove(filepath.Join(root, testSessionID, "runtime", "manifest.json")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(root, testSessionID, "artifacts", "capture_00001.pcapng"))
	if err != nil {
		t.Fatal(err)
	}
	closedAt := time.Date(2026, 9, 1, 11, 58, 0, 0, time.UTC)
	feed := capture.ActiveSegmentFeed{Schema: capture.SchemaVersion, SessionID: testSessionID, Revision: 2, PublishedAt: closedAt, Segments: []capture.ClosedCaptureSegment{
		{Sequence: 1, Name: "capture_00000.pcapng", SizeBytes: 320, Modified: closedAt.Add(-time.Minute), ClosedAt: closedAt.Add(-time.Minute)},
		{Sequence: 2, Name: info.Name(), SizeBytes: info.Size(), Modified: info.ModTime().UTC(), ClosedAt: closedAt},
	}}
	writeJSONFixture(t, filepath.Join(root, testSessionID, "runtime", "active-segments.json"), feed)
	sender := &recordingSender{}
	runner := testRunner(t, root, state, work, EngineSuricata, fixtureProcessor{engine: EngineSuricata}, sender)
	result := runner.RunOnce(context.Background())
	progress, exists, err := runner.State.ReadActiveProgress(EngineSuricata, testSessionID)
	if len(result.Errors) != 0 || result.Segments != 1 || len(sender.events) != 1 || err != nil || !exists || progress.MissedSegments != 1 || progress.LastCompletedSequence != 2 {
		t.Fatalf("a removed segment blocked analysis: result=%#v progress=%#v exists=%v err=%v", result, progress, exists, err)
	}
}
