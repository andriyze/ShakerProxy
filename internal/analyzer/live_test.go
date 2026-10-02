package analyzer

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
)

// TestLiveFakeZeekProcess is not a test: live follower tests run the test
// binary as a stand-in for Zeek. It reads the pcap stream from stdin and logs
// one conn.log record per packet (carrying the packet's ID), one tick.log
// record per idle tick, and a final.log record when its input ends, the way
// Zeek writes the records of open connections at exit. With a crash marker
// file present it exits abruptly after SHAKERPROXY_LIVE_FAKE_CRASH_AFTER
// packets, removing the marker so its successor runs normally.
func TestLiveFakeZeekProcess(t *testing.T) {
	if os.Getenv("SHAKERPROXY_LIVE_FAKE_ZEEK") != "1" {
		t.Skip("runs only as the fake live Zeek")
	}
	os.Exit(runFakeZeek())
}

func runFakeZeek() int {
	reader := bufio.NewReader(os.Stdin)
	logs := map[string]*os.File{}
	write := func(name, line string) {
		if logs[name] == nil {
			file, err := os.OpenFile(name+".log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
			if err != nil {
				os.Exit(5)
			}
			logs[name] = file
		}
		_, _ = logs[name].WriteString(line + "\n")
	}
	crashAfter, _ := strconv.Atoi(os.Getenv("SHAKERPROXY_LIVE_FAKE_CRASH_AFTER"))
	marker := os.Getenv("SHAKERPROXY_LIVE_FAKE_CRASH_MARKER")
	header := make([]byte, 24)
	packets := 0
	if _, err := io.ReadFull(reader, header); err == nil {
		for {
			record := make([]byte, 16)
			if _, err := io.ReadFull(reader, record); err != nil {
				break
			}
			data := make([]byte, binary.LittleEndian.Uint32(record[8:12]))
			if _, err := io.ReadFull(reader, data); err != nil {
				return 4
			}
			stamp := fmt.Sprintf("%d.%06d", binary.LittleEndian.Uint32(record[:4]), binary.LittleEndian.Uint32(record[4:8]))
			if len(data) == 60 && binary.BigEndian.Uint16(data[12:14]) == 0x88B5 {
				write("tick", `{"ts":`+stamp+`}`)
				continue
			}
			packets++
			write("conn", fmt.Sprintf(`{"ts":%s,"uid":"Cfake","packet":%d}`, stamp, binary.BigEndian.Uint16(data[14:16])))
			if crashAfter > 0 && packets >= crashAfter && marker != "" {
				if os.Remove(marker) == nil {
					return 3
				}
			}
		}
	}
	write("final", fmt.Sprintf(`{"ts":%d.0,"packets":%d}`, time.Now().Unix(), packets))
	return 0
}

func fakeZeekCommand(environment ...string) func(context.Context, string) (*exec.Cmd, error) {
	return func(ctx context.Context, directory string) (*exec.Cmd, error) {
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLiveFakeZeekProcess$")
		command.Dir = directory
		command.Env = append(append(os.Environ(), "SHAKERPROXY_LIVE_FAKE_ZEEK=1"), environment...)
		return command, nil
	}
}

// fakeDumpcap writes ring-buffer segments the way dumpcap does: a new file
// per segment, flushed a packet at a time.
type fakeDumpcap struct {
	t         *testing.T
	root      string
	artifacts string
	number    int
	file      *os.File
	nextID    uint16
}

func newFakeDumpcap(t *testing.T) *fakeDumpcap {
	t.Helper()
	root := filepath.Join(t.TempDir(), "captures")
	session := filepath.Join(root, testSessionID)
	for _, directory := range []string{filepath.Join(session, "artifacts"), filepath.Join(session, "runtime")} {
		if err := os.MkdirAll(directory, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	writeJSONFixture(t, filepath.Join(session, "session.json"), map[string]any{"id": testSessionID, "request": map[string]any{"automatic": true}})
	dumpcap := &fakeDumpcap{t: t, root: root, artifacts: filepath.Join(session, "artifacts"), nextID: 1}
	dumpcap.setState(capture.StateRunning)
	t.Cleanup(func() {
		if dumpcap.file != nil {
			dumpcap.file.Close()
		}
	})
	return dumpcap
}

func (d *fakeDumpcap) setState(state capture.State) {
	writeJSONFixture(d.t, filepath.Join(d.root, testSessionID, "runtime", "worker-status.json"), map[string]any{"schema": capture.SchemaVersion, "session_id": testSessionID, "state": state})
}

func (d *fakeDumpcap) name(number int) string {
	return fmt.Sprintf("capture_%05d_20261002100000.pcapng", number)
}

func (d *fakeDumpcap) rotate() {
	d.t.Helper()
	if d.file != nil {
		d.file.Close()
	}
	d.number++
	file, err := os.OpenFile(filepath.Join(d.artifacts, d.name(d.number)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		d.t.Fatal(err)
	}
	d.file = file
	if _, err := file.Write(pcapngSection(binary.LittleEndian, 1, 0, nil)); err != nil {
		d.t.Fatal(err)
	}
}

func (d *fakeDumpcap) packets(count int) {
	d.t.Helper()
	for range count {
		data := make([]byte, 64)
		binary.BigEndian.PutUint16(data[12:14], 0x0800)
		binary.BigEndian.PutUint16(data[14:16], d.nextID)
		d.nextID++
		section := pcapngSection(binary.LittleEndian, 1, 0, []livePacket{{time.Now(), data}})
		// Skip the section and interface headers; keep the packet block.
		packet := section[len(pcapngSection(binary.LittleEndian, 1, 0, nil)):]
		if _, err := d.file.Write(packet); err != nil {
			d.t.Fatal(err)
		}
	}
}

func (d *fakeDumpcap) artifact(number int) capture.CaptureFile {
	d.t.Helper()
	contents, err := os.ReadFile(filepath.Join(d.artifacts, d.name(number)))
	if err != nil {
		d.t.Fatal(err)
	}
	sum := sha256.Sum256(contents)
	return capture.CaptureFile{Name: d.name(number), SizeBytes: int64(len(contents)), SHA256: hex.EncodeToString(sum[:])}
}

func newTestLiveAnalyzer(t *testing.T, root string, sender Sender, command func(context.Context, string) (*exec.Cmd, error)) *LiveAnalyzer {
	t.Helper()
	state := NewStateStore(filepath.Join(t.TempDir(), "state"))
	if err := state.Prepare(); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(t.TempDir(), "work")
	if err := os.Mkdir(work, 0o711); err != nil {
		t.Fatal(err)
	}
	coverage, err := NewLiveCoverage(state, root, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return &LiveAnalyzer{CaptureRoot: root, WorkRoot: work, State: state, Sender: sender, Coverage: coverage, Now: time.Now, Command: command, Poll: 5 * time.Millisecond, status: LiveStatus{State: LiveStateIdle}}
}

func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func runLive(t *testing.T, live *LiveAnalyzer) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		live.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return cancel, done
}

func deliveredPackets(t *testing.T, sender *liveSender) map[int]int {
	t.Helper()
	counts := map[int]int{}
	for _, event := range sender.byPath(t)["conn"] {
		counts[int(event["packet"].(float64))]++
	}
	return counts
}

// The live path end to end: packets reach ingest while the segment is still
// being written, Zeek's clock keeps moving while the lab is quiet, every
// closed segment is covered with the hash of its bytes, and the records Zeek
// writes when its input ends are delivered when the capture stops.
func TestLiveAnalyzerStreamsTheLabRecordingAndCoversItsSegments(t *testing.T) {
	dumpcap := newFakeDumpcap(t)
	dumpcap.rotate()
	dumpcap.packets(3)
	sender := &liveSender{}
	live := newTestLiveAnalyzer(t, dumpcap.root, sender, fakeZeekCommand())
	_, done := runLive(t, live)
	waitFor(t, "packets of the open segment", func() bool { return len(deliveredPackets(t, sender)) == 3 })
	if decision := live.Coverage.Decide(testSessionID, dumpcap.artifact(1)); decision != LiveWait {
		t.Fatalf("the segment being written was not held for live analysis: %v", decision)
	}
	waitFor(t, "an idle tick", func() bool { return len(sender.byPath(t)["tick"]) > 0 })
	dumpcap.rotate()
	dumpcap.packets(4)
	dumpcap.rotate()
	dumpcap.packets(2)
	waitFor(t, "packets of later segments", func() bool { return len(deliveredPackets(t, sender)) == 9 })
	dumpcap.file.Close()
	dumpcap.file = nil
	dumpcap.setState(capture.StateCompleted)
	waitFor(t, "the records Zeek writes at exit", func() bool { return len(sender.byPath(t)["final"]) == 1 })
	for number := 1; number <= 3; number++ {
		if decision := live.Coverage.Decide(testSessionID, dumpcap.artifact(number)); decision != LiveCovered {
			t.Fatalf("segment %d: %v, want covered", number, decision)
		}
	}
	for id, count := range deliveredPackets(t, sender) {
		if count != 1 {
			t.Fatalf("packet %d delivered %d times", id, count)
		}
	}
	if final := sender.byPath(t)["final"][0]; final["packets"] != float64(9) {
		t.Fatalf("Zeek saw %v packets, want 9", final["packets"])
	}
	status := live.Status()
	if status.SegmentsCovered != 3 || status.SegmentsHandedOff != 0 || status.Restarts != 0 || status.EventsDelivered < 10 || live.TakeDelivered() != status.EventsDelivered || live.TakeDelivered() != 0 {
		t.Fatalf("status %#v", status)
	}
	select {
	case <-done:
		t.Fatal("live analysis stopped instead of waiting for the next lab recording")
	default:
	}
}

// When Zeek dies mid-segment, that segment goes to offline analysis and live
// analysis restarts at the segment being written.
func TestLiveAnalyzerHandsACrashedSegmentToOfflineAnalysis(t *testing.T) {
	dumpcap := newFakeDumpcap(t)
	dumpcap.rotate()
	dumpcap.packets(5)
	marker := filepath.Join(t.TempDir(), "crash-once")
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	sender := &liveSender{}
	live := newTestLiveAnalyzer(t, dumpcap.root, sender, fakeZeekCommand("SHAKERPROXY_LIVE_FAKE_CRASH_AFTER=2", "SHAKERPROXY_LIVE_FAKE_CRASH_MARKER="+marker))
	runLive(t, live)
	waitFor(t, "the crash", func() bool { return live.Status().Restarts == 1 })
	if decision := live.Coverage.Decide(testSessionID, dumpcap.artifact(1)); decision != LiveOffline {
		t.Fatalf("the crashed segment was not handed to offline analysis: %v", decision)
	}
	dumpcap.rotate()
	dumpcap.packets(3)
	waitFor(t, "the restarted Zeek", func() bool { return deliveredPackets(t, sender)[8] == 1 })
	dumpcap.rotate()
	dumpcap.packets(1)
	waitFor(t, "the next segment", func() bool { return deliveredPackets(t, sender)[9] == 1 })
	dumpcap.file.Close()
	dumpcap.file = nil
	dumpcap.setState(capture.StateStopped)
	waitFor(t, "the restarted Zeek to finish", func() bool { return len(sender.byPath(t)["final"]) == 1 })
	for number, want := range map[int]LiveDecision{1: LiveOffline, 2: LiveCovered, 3: LiveCovered} {
		if decision := live.Coverage.Decide(testSessionID, dumpcap.artifact(number)); decision != want {
			t.Fatalf("segment %d: %v, want %v", number, decision, want)
		}
	}
	if status := live.Status(); status.SegmentsHandedOff != 1 || status.SegmentsCovered != 2 || status.LastError == "" {
		t.Fatalf("status %#v", status)
	}
}

// A follower that falls behind covers the segment it was reading, then
// leaves the backlog to offline analysis and starts again at the newest one.
func TestLiveAnalyzerLeavesABacklogToOfflineAnalysis(t *testing.T) {
	dumpcap := newFakeDumpcap(t)
	for range 5 {
		dumpcap.rotate()
		dumpcap.packets(2)
	}
	sender := &liveSender{}
	live := newTestLiveAnalyzer(t, dumpcap.root, sender, fakeZeekCommand())
	result := live.generation(context.Background(), testSessionID, 1)
	if result.outcome != liveLagged || result.err == nil {
		t.Fatalf("outcome %v err %v", result.outcome, result.err)
	}
	for number, want := range map[int]LiveDecision{1: LiveCovered, 2: LiveOffline, 3: LiveOffline, 4: LiveOffline, 5: LiveOffline} {
		if decision := live.Coverage.Decide(testSessionID, dumpcap.artifact(number)); decision != want {
			t.Fatalf("segment %d: %v, want %v", number, decision, want)
		}
	}
	if counts := deliveredPackets(t, sender); len(counts) != 2 || counts[1] != 1 || counts[2] != 1 || len(sender.byPath(t)["final"]) != 1 {
		t.Fatalf("delivered %v", sender.byPath(t))
	}
	if status := live.Status(); status.SegmentsHandedOff != 3 || status.SegmentsCovered != 1 {
		t.Fatalf("status %#v", status)
	}
}

// On shutdown, live analysis waits for the segment being written to close so
// it is covered rather than analyzed twice.
func TestLiveAnalyzerFinishesTheCurrentSegmentOnShutdown(t *testing.T) {
	dumpcap := newFakeDumpcap(t)
	dumpcap.rotate()
	dumpcap.packets(2)
	sender := &liveSender{}
	live := newTestLiveAnalyzer(t, dumpcap.root, sender, fakeZeekCommand())
	cancel, done := runLive(t, live)
	waitFor(t, "the open segment", func() bool { return len(deliveredPackets(t, sender)) == 2 })
	cancel()
	time.Sleep(100 * time.Millisecond)
	dumpcap.packets(1)
	dumpcap.rotate()
	dumpcap.packets(1)
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("live analysis did not stop")
	}
	if decision := live.Coverage.Decide(testSessionID, dumpcap.artifact(1)); decision != LiveCovered {
		t.Fatalf("the finished segment: %v", decision)
	}
	if decision := live.Coverage.Decide(testSessionID, dumpcap.artifact(2)); decision != LiveOffline {
		t.Fatalf("the next segment: %v", decision)
	}
	if counts := deliveredPackets(t, sender); len(counts) != 3 || len(sender.byPath(t)["final"]) != 1 {
		t.Fatalf("delivered %v", sender.byPath(t))
	}
}

// The runner skips what live analysis covered, waits while a claim can still
// cover a segment, and analyzes the rest offline, for running and finalized
// captures alike.
func TestRunnerHandsSegmentsBetweenLiveAndOfflineAnalysis(t *testing.T) {
	root, state, work, _ := writeCaptureFixture(t)
	runtime := filepath.Join(root, testSessionID, "runtime")
	artifacts := filepath.Join(root, testSessionID, "artifacts")
	if err := os.Remove(filepath.Join(runtime, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(artifacts, "capture_00001.pcapng")); err != nil {
		t.Fatal(err)
	}
	closedAt := time.Date(2026, 9, 1, 11, 58, 0, 0, time.UTC)
	var segments []capture.ClosedCaptureSegment
	var files []capture.CaptureFile
	for number := 1; number <= 3; number++ {
		name := fmt.Sprintf("capture_%05d_20260901115800.pcapng", number)
		path := filepath.Join(artifacts, name)
		if err := os.WriteFile(path, []byte("bounded-pcap-fixture"), 0o640); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte("bounded-pcap-fixture"))
		segments = append(segments, capture.ClosedCaptureSegment{Sequence: uint64(number), Name: name, SizeBytes: info.Size(), Modified: info.ModTime().UTC(), ClosedAt: closedAt})
		files = append(files, capture.CaptureFile{Name: name, SizeBytes: info.Size(), SHA256: hex.EncodeToString(sum[:]), Modified: info.ModTime().UTC()})
	}
	writeJSONFixture(t, filepath.Join(runtime, "active-segments.json"), capture.ActiveSegmentFeed{Schema: capture.SchemaVersion, SessionID: testSessionID, Revision: 2, PublishedAt: closedAt, Segments: segments[:2]})
	sender := &recordingSender{}
	runner := testRunner(t, root, state, work, EngineZeek, fixtureProcessor{engine: EngineZeek}, sender)
	coverage, err := NewLiveCoverage(runner.State, root, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	runner.Live = coverage
	claim, err := coverage.Claim(testSessionID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := coverage.Cover(testSessionID, claim, CoveredSegment{Name: files[0].Name, SizeBytes: files[0].SizeBytes, SHA256: files[0].SHA256, CoveredAt: time.Now()}, 2); err != nil {
		t.Fatal(err)
	}
	result := runner.RunOnce(context.Background())
	progress, _, err := runner.State.ReadActiveProgress(EngineZeek, testSessionID)
	if len(result.Errors) != 0 || err != nil || len(sender.events) != 0 || progress.LastCompletedSequence != 1 || progress.SegmentsProcessed != 1 {
		t.Fatalf("covered segment analyzed or claimed one not held: result=%#v progress=%#v err=%v events=%d", result, progress, err, len(sender.events))
	}
	// The capture stops while live analysis still holds segment 2; its
	// finalization waits.
	manifest := capture.Manifest{Schema: capture.SchemaVersion, SessionID: testSessionID, CreatedAt: closedAt, SessionSHA256: files[0].SHA256, Files: files, TotalSizeBytes: 3 * files[0].SizeBytes}
	writeJSONFixture(t, filepath.Join(runtime, "manifest.json"), manifest)
	result = runner.RunOnce(context.Background())
	if _, exists, _ := runner.State.ReadCheckpoint(EngineZeek, testSessionID); len(result.Errors) != 0 || exists || len(sender.events) != 0 || result.Skipped != 1 {
		t.Fatalf("finalized while live analysis held a segment: result=%#v checkpoint=%v events=%d", result, exists, len(sender.events))
	}
	if err := coverage.Cover(testSessionID, claim, CoveredSegment{Name: files[1].Name, SizeBytes: files[1].SizeBytes, SHA256: files[1].SHA256, CoveredAt: time.Now()}, 3); err != nil {
		t.Fatal(err)
	}
	coverage.Release(testSessionID, claim)
	result = runner.RunOnce(context.Background())
	checkpoint, exists, err := runner.State.ReadCheckpoint(EngineZeek, testSessionID)
	if len(result.Errors) != 0 || err != nil || !exists || len(sender.events) != 1 || checkpoint.CaptureFiles != 3 {
		t.Fatalf("only the uncovered segment should be analyzed offline: result=%#v checkpoint=%#v events=%d err=%v", result, checkpoint, len(sender.events), err)
	}
	if _, err := os.Stat(filepath.Join(state, "live", testSessionID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("coverage outlived the checkpoint: %v", err)
	}
}

// With the VPN on, the lab and the VPN each have an automatic recording, and
// each live analyzer follows only its own.
func TestLiveAnalyzersFollowTheirOwnRecording(t *testing.T) {
	root := t.TempDir()
	sessions := map[string]string{
		"capture-0000000000000000000000000000000a": capture.LabRecordingName,
		"capture-0000000000000000000000000000000b": capture.VPNRecordingName,
		"capture-0000000000000000000000000000000c": "Manual capture",
	}
	for id, name := range sessions {
		if err := os.MkdirAll(filepath.Join(root, id, "runtime"), 0o750); err != nil {
			t.Fatal(err)
		}
		writeJSONFixture(t, filepath.Join(root, id, "session.json"), map[string]any{"id": id, "request": map[string]any{"name": name, "automatic": name != "Manual capture"}})
		writeJSONFixture(t, filepath.Join(root, id, "runtime", "worker-status.json"), map[string]any{"schema": capture.SchemaVersion, "session_id": id, "state": capture.StateRunning})
	}
	state := NewStateStore(filepath.Join(t.TempDir(), "state"))
	if err := state.Prepare(); err != nil {
		t.Fatal(err)
	}
	for recording, want := range map[string]string{
		capture.LabRecordingName: "capture-0000000000000000000000000000000a",
		capture.VPNRecordingName: "capture-0000000000000000000000000000000b",
		"Nothing by this name":   "",
	} {
		live := &LiveAnalyzer{Recording: recording, CaptureRoot: root, State: state}
		if got, err := live.labRecording(); err != nil || got != want {
			t.Fatalf("%q follows %q (%v), want %q", recording, got, err, want)
		}
	}
}
