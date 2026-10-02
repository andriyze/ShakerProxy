package analyzer

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
)

// LiveCoverage hands closed capture segments between live analysis and the
// per-segment offline pass, so the packets of every segment reach ingest
// exactly once. The two passes cannot be deduplicated at ingest: event IDs
// derive from record content, and a live connection record spans segment
// boundaries while an offline one stops at them.
//
// Live analysis claims the capture it follows and records a segment as
// covered once it streamed every byte of the closed file into Zeek; the
// runner later confirms the bytes by their SHA-256. The runner analyzes a
// segment offline only when it is not covered and no live claim can still
// cover it, and it waits while one can. A claim that stops heartbeating is
// revoked by the next decision, and a revoked claim can no longer cover
// anything, so a segment is never both skipped by one pass and lost by the
// other.
type LiveCoverage struct {
	directory string
	now       func() time.Time
	ttl       time.Duration

	mutex     sync.Mutex
	nextClaim uint64
	claims    map[string]*liveClaim
	covered   map[string][]CoveredSegment
}

type LiveDecision int

const (
	// LiveOffline: analyze the segment offline.
	LiveOffline LiveDecision = iota
	// LiveWait: a live claim may still cover the segment; decide later.
	LiveWait
	// LiveCovered: live analysis already delivered the segment's packets.
	LiveCovered
)

type CoveredSegment struct {
	Name      string    `json:"name"`
	SizeBytes int64     `json:"size_bytes"`
	SHA256    string    `json:"sha256"`
	CoveredAt time.Time `json:"covered_at"`
}

type liveCoverageRecord struct {
	Schema    int              `json:"schema"`
	SessionID string           `json:"session_id"`
	Segments  []CoveredSegment `json:"segments"`
}

// liveClaim is a live follower's hold on one capture. Every segment numbered
// from start up to (not including) current is covered; current is being
// streamed and later segments have not been reached yet.
type liveClaim struct {
	id        uint64
	start     uint64
	current   uint64
	heartbeat time.Time
}

const (
	liveCoverageSchema = 1
	// maxLiveCoveredSegments bounds one capture's coverage record; a ring
	// buffer feed holds at most 128 segments.
	maxLiveCoveredSegments = 256
	// DefaultLiveClaimTTL bounds how long the runner waits on a live
	// follower that stopped heartbeating, for example one stuck writing to
	// a hung Zeek.
	DefaultLiveClaimTTL = 60 * time.Second
)

var errLiveClaimLost = errors.New("live analysis claim was revoked or released")

// NewLiveCoverage loads persisted coverage from the analyzer state root and
// drops records of captures that no longer exist under the capture root.
func NewLiveCoverage(state StateStore, captureRoot string, now func() time.Time) (*LiveCoverage, error) {
	if now == nil {
		now = time.Now
	}
	coverage := &LiveCoverage{directory: filepath.Join(state.Root, "live"), now: now, ttl: DefaultLiveClaimTTL, claims: map[string]*liveClaim{}, covered: map[string][]CoveredSegment{}}
	if err := os.Mkdir(coverage.directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if err := safeDirectory(coverage.directory); err != nil {
		return nil, errors.New("live coverage state path is not a safe directory")
	}
	entries, err := os.ReadDir(coverage.directory)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		sessionID, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || !capture.ValidSessionID(sessionID) {
			continue
		}
		path := filepath.Join(coverage.directory, entry.Name())
		if _, statErr := os.Lstat(filepath.Join(captureRoot, sessionID)); errors.Is(statErr, os.ErrNotExist) {
			_ = os.Remove(path)
			continue
		}
		var record liveCoverageRecord
		if err := readBoundedJSON(path, &record); err != nil || !validLiveCoverageRecord(record, sessionID) {
			return nil, errors.New("stored live coverage is invalid")
		}
		coverage.covered[sessionID] = record.Segments
	}
	return coverage, nil
}

// Claim starts a live follower's hold on a capture at the segment it opened.
func (c *LiveCoverage) Claim(sessionID string, number uint64) (uint64, error) {
	if !capture.ValidSessionID(sessionID) {
		return 0, errors.New("live analysis claim identity is invalid")
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if existing := c.liveClaimLocked(sessionID); existing != nil {
		return 0, errors.New("capture already has a live analysis claim")
	}
	c.nextClaim++
	c.claims[sessionID] = &liveClaim{id: c.nextClaim, start: number, current: number, heartbeat: c.now()}
	return c.nextClaim, nil
}

// Heartbeat keeps a claim alive while its follower makes progress.
func (c *LiveCoverage) Heartbeat(sessionID string, claimID uint64) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	claim, err := c.heldLocked(sessionID, claimID)
	if err != nil {
		return err
	}
	claim.heartbeat = c.now()
	return nil
}

// Cover records that the segment being streamed was streamed completely and
// moves the claim to the next segment.
func (c *LiveCoverage) Cover(sessionID string, claimID uint64, segment CoveredSegment, next uint64) error {
	if !safeCaptureName(segment.Name) || segment.SizeBytes < 1 || !sha256Pattern.MatchString(segment.SHA256) || segment.CoveredAt.IsZero() {
		return errors.New("covered live segment is invalid")
	}
	number, ok := liveSegmentNumber(segment.Name)
	c.mutex.Lock()
	defer c.mutex.Unlock()
	claim, err := c.heldLocked(sessionID, claimID)
	if err != nil {
		return err
	}
	if !ok || number != claim.current || next <= number {
		return errors.New("covered live segment is not the one being streamed")
	}
	segments := append(append([]CoveredSegment(nil), c.covered[sessionID]...), segment)
	if overflow := len(segments) - maxLiveCoveredSegments; overflow > 0 {
		segments = segments[overflow:]
	}
	record := liveCoverageRecord{Schema: liveCoverageSchema, SessionID: sessionID, Segments: segments}
	if err := writeJSONAtomic(c.directory, sessionID+".json", record, 0o600); err != nil {
		return err
	}
	c.covered[sessionID] = segments
	claim.current = next
	claim.heartbeat = c.now()
	return nil
}

// Release ends a claim. Segments it did not cover go to offline analysis.
func (c *LiveCoverage) Release(sessionID string, claimID uint64) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if claim := c.claims[sessionID]; claim != nil && claim.id == claimID {
		delete(c.claims, sessionID)
	}
}

// Decide tells the runner what to do with a closed segment whose bytes it
// hashed.
func (c *LiveCoverage) Decide(sessionID string, artifact capture.CaptureFile) LiveDecision {
	if c == nil {
		return LiveOffline
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	for _, segment := range c.covered[sessionID] {
		if segment.Name == artifact.Name {
			if segment.SizeBytes == artifact.SizeBytes && segment.SHA256 == artifact.SHA256 {
				return LiveCovered
			}
			return LiveOffline
		}
	}
	number, ok := liveSegmentNumber(artifact.Name)
	if claim := c.liveClaimLocked(sessionID); claim != nil && ok && number >= claim.current {
		return LiveWait
	}
	return LiveOffline
}

// Forget drops a finished capture's coverage once its analysis checkpoint
// exists. A claim, if any, is left alone.
func (c *LiveCoverage) Forget(sessionID string) error {
	if c == nil {
		return nil
	}
	if !capture.ValidSessionID(sessionID) {
		return errors.New("live coverage identity is invalid")
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.covered, sessionID)
	if err := os.Remove(filepath.Join(c.directory, sessionID+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// liveClaimLocked returns the capture's claim, revoking it when its follower
// stopped heartbeating.
func (c *LiveCoverage) liveClaimLocked(sessionID string) *liveClaim {
	claim := c.claims[sessionID]
	if claim != nil && c.now().Sub(claim.heartbeat) > c.ttl {
		delete(c.claims, sessionID)
		return nil
	}
	return claim
}

func (c *LiveCoverage) heldLocked(sessionID string, claimID uint64) (*liveClaim, error) {
	claim := c.liveClaimLocked(sessionID)
	if claim == nil || claim.id != claimID {
		return nil, errLiveClaimLost
	}
	return claim, nil
}

func validLiveCoverageRecord(record liveCoverageRecord, sessionID string) bool {
	if record.Schema != liveCoverageSchema || record.SessionID != sessionID || len(record.Segments) > maxLiveCoveredSegments {
		return false
	}
	for _, segment := range record.Segments {
		if !safeCaptureName(segment.Name) || segment.SizeBytes < 1 || !sha256Pattern.MatchString(segment.SHA256) || segment.CoveredAt.IsZero() {
			return false
		}
	}
	return true
}

// liveSegmentNumber reads dumpcap's ring-buffer file number from a segment
// name such as capture_00042_20261002101032.pcapng.
func liveSegmentNumber(name string) (uint64, bool) {
	rest, ok := strings.CutPrefix(name, "capture_")
	if !ok || !strings.HasSuffix(rest, ".pcapng") {
		return 0, false
	}
	digits, _, ok := strings.Cut(rest, "_")
	if !ok || digits == "" || len(digits) > 12 {
		return 0, false
	}
	number, err := strconv.ParseUint(digits, 10, 64)
	return number, err == nil && number > 0
}
