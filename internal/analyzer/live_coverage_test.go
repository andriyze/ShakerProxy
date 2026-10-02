package analyzer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
)

type liveTestClock struct{ now time.Time }

func (c *liveTestClock) Now() time.Time { return c.now }

func newTestCoverage(t *testing.T, captureRoot string, clock *liveTestClock) (*LiveCoverage, StateStore) {
	t.Helper()
	state := NewStateStore(filepath.Join(t.TempDir(), "state"))
	if err := state.Prepare(); err != nil {
		t.Fatal(err)
	}
	coverage, err := NewLiveCoverage(state, captureRoot, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	return coverage, state
}

func liveSegmentName(number int) string {
	return fmt.Sprintf("capture_%05d_20261002100000.pcapng", number)
}

func coveredSegment(number int, hash string, at time.Time) CoveredSegment {
	return CoveredSegment{Name: liveSegmentName(number), SizeBytes: 100, SHA256: hash, CoveredAt: at}
}

func artifactFor(number int, hash string) capture.CaptureFile {
	return capture.CaptureFile{Name: liveSegmentName(number), SizeBytes: 100, SHA256: hash}
}

func TestLiveSegmentNumbersComeFromDumpcapNames(t *testing.T) {
	for name, want := range map[string]uint64{
		"capture_00042_20261002101032.pcapng":  42,
		"capture_123456_20261002101032.pcapng": 123456,
		"capture_00000_20261002101032.pcapng":  0,
		"capture.pcapng":                       0,
		"capture_00042.pcapng":                 0,
		"capture_x_20261002101032.pcapng":      0,
	} {
		if got, ok := liveSegmentNumber(name); got != want || ok != (want != 0) {
			t.Fatalf("%s: got %d %v, want %d", name, got, ok, want)
		}
	}
}

// The handoff that keeps live and offline analysis from both delivering a
// segment, or neither.
func TestLiveCoverageHandsEachSegmentToExactlyOnePass(t *testing.T) {
	clock := &liveTestClock{now: time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)}
	coverage, _ := newTestCoverage(t, t.TempDir(), clock)
	hash := strings.Repeat("a", 64)
	claim, err := coverage.Claim(testSessionID, 5)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coverage.Claim(testSessionID, 6); err == nil {
		t.Fatal("a capture was claimed twice")
	}
	for number, want := range map[int]LiveDecision{4: LiveOffline, 5: LiveWait, 6: LiveWait} {
		if got := coverage.Decide(testSessionID, artifactFor(number, hash)); got != want {
			t.Fatalf("segment %d before cover: %v, want %v", number, got, want)
		}
	}
	if err := coverage.Cover(testSessionID, claim, coveredSegment(6, hash, clock.now), 7); err == nil {
		t.Fatal("covered a segment other than the one being streamed")
	}
	if err := coverage.Cover(testSessionID, claim, coveredSegment(5, hash, clock.now), 6); err != nil {
		t.Fatal(err)
	}
	if got := coverage.Decide(testSessionID, artifactFor(5, hash)); got != LiveCovered {
		t.Fatalf("covered segment: %v", got)
	}
	if got := coverage.Decide(testSessionID, artifactFor(5, strings.Repeat("b", 64))); got != LiveOffline {
		t.Fatalf("a segment whose bytes differ from what live analysis streamed: %v", got)
	}
	coverage.Release(testSessionID, claim)
	if got := coverage.Decide(testSessionID, artifactFor(6, hash)); got != LiveOffline {
		t.Fatalf("a segment the released claim never covered: %v", got)
	}
	if err := coverage.Cover(testSessionID, claim, coveredSegment(6, hash, clock.now), 7); !errors.Is(err, errLiveClaimLost) {
		t.Fatalf("a released claim covered a segment: %v", err)
	}
	if got := coverage.Decide(testSessionID, artifactFor(5, hash)); got != LiveCovered {
		t.Fatalf("release dropped coverage: %v", got)
	}
}

// A follower stuck on a hung Zeek must not hold the runner forever, and once
// the runner moved on it must not cover the segment too.
func TestLiveCoverageRevokesAClaimThatStoppedHeartbeating(t *testing.T) {
	clock := &liveTestClock{now: time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)}
	coverage, _ := newTestCoverage(t, t.TempDir(), clock)
	hash := strings.Repeat("a", 64)
	claim, err := coverage.Claim(testSessionID, 5)
	if err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(DefaultLiveClaimTTL - time.Second)
	if err := coverage.Heartbeat(testSessionID, claim); err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(DefaultLiveClaimTTL + time.Second)
	if got := coverage.Decide(testSessionID, artifactFor(5, hash)); got != LiveOffline {
		t.Fatalf("stalled claim still held the segment: %v", got)
	}
	if err := coverage.Cover(testSessionID, claim, coveredSegment(5, hash, clock.now), 6); !errors.Is(err, errLiveClaimLost) {
		t.Fatalf("a revoked claim covered a segment the runner took: %v", err)
	}
	if err := coverage.Heartbeat(testSessionID, claim); !errors.Is(err, errLiveClaimLost) {
		t.Fatalf("a revoked claim heartbeated: %v", err)
	}
	if _, err := coverage.Claim(testSessionID, 7); err != nil {
		t.Fatalf("a new follower could not claim after revocation: %v", err)
	}
}

// Coverage survives an analyzer restart; claims do not, so a restarted
// worker analyzes offline whatever the previous process did not finish.
func TestLiveCoveragePersistsCoveredSegmentsButNotClaims(t *testing.T) {
	clock := &liveTestClock{now: time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)}
	captureRoot := t.TempDir()
	for _, session := range []string{testSessionID, "capture-ffffffffffffffffffffffffffffffff"} {
		if err := os.Mkdir(filepath.Join(captureRoot, session), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	coverage, state := newTestCoverage(t, captureRoot, clock)
	hash := strings.Repeat("c", 64)
	for _, session := range []string{testSessionID, "capture-ffffffffffffffffffffffffffffffff"} {
		claim, err := coverage.Claim(session, 1)
		if err != nil {
			t.Fatal(err)
		}
		if err := coverage.Cover(session, claim, coveredSegment(1, hash, clock.now), 2); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(filepath.Join(captureRoot, "capture-ffffffffffffffffffffffffffffffff")); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewLiveCoverage(state, captureRoot, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	if got := restarted.Decide(testSessionID, artifactFor(1, hash)); got != LiveCovered {
		t.Fatalf("coverage was lost across a restart: %v", got)
	}
	if got := restarted.Decide(testSessionID, artifactFor(2, hash)); got != LiveOffline {
		t.Fatalf("a claim survived a restart: %v", got)
	}
	if _, err := os.Stat(filepath.Join(state.Root, "live", "capture-ffffffffffffffffffffffffffffffff.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("coverage of a removed capture was kept: %v", err)
	}
	if err := restarted.Forget(testSessionID); err != nil {
		t.Fatal(err)
	}
	if got := restarted.Decide(testSessionID, artifactFor(1, hash)); got != LiveOffline {
		t.Fatalf("forgotten coverage still applied: %v", got)
	}
	if _, err := os.Stat(filepath.Join(state.Root, "live", testSessionID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("forgotten coverage stayed on disk: %v", err)
	}
}
