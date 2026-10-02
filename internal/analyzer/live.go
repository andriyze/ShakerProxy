package analyzer

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
)

// Live analysis runs one long Zeek over the automatic lab recording while
// dumpcap is still writing it, so packet-derived records reach ingest about a
// second after the packets instead of after the 10-second segment closes.
//
// dumpcap is untouched: it keeps writing and rotating its ring-buffer
// segments, which stay the evidence. The analyzer reads the segment being
// written (the capture worker grants the capture group read access to it)
// and pipes the packets to Zeek's standard input. Zeek runs as the isolated
// parser user with no capture access at all; it sees only the packet stream
// and its own work directory.
//
// Live analysis never blocks capture and never decides on its own what is
// lost: a segment it did not stream completely is handed to the offline
// per-segment pass (see LiveCoverage).

const (
	zeekLiveScript = "/etc/shakerproxy/zeek/live.zeek"

	LiveStateOff        = "OFF"
	LiveStateIdle       = "IDLE"
	LiveStateFollowing  = "FOLLOWING"
	LiveStateRecovering = "RECOVERING"

	// DefaultLivePoll is how often a quiet segment is checked for growth;
	// dumpcap flushes about every 100 ms.
	DefaultLivePoll = 100 * time.Millisecond
	// liveDeliverEvery batches Zeek's records for ingest.
	liveDeliverEvery = 250 * time.Millisecond
	// liveTickAfter and liveTickDelay: once the capture has been quiet this
	// long, Zeek's clock is moved to this far behind now (see Tick). dumpcap
	// writes packets out within about 200 ms, so none older can still come.
	liveTickAfter = 500 * time.Millisecond
	liveTickDelay = 500 * time.Millisecond
	// liveMaxLagSegments: when the newest segment is this many segments past
	// the next one, live analysis jumps to it and leaves the ones in between
	// to offline analysis.
	liveMaxLagSegments = 3
	liveOpenWait       = 5 * time.Second
	liveWriteTimeout   = 20 * time.Second
	liveStopWait       = 15 * time.Second
	// liveFinishWait bounds how long shutdown waits for the current segment
	// to close so it can be covered rather than handed off.
	liveFinishWait = 12 * time.Second
	// liveRotateBytes ends a Zeek at the next segment boundary once it wrote
	// this much (its logs live in the size-limited work tmpfs), and
	// liveMaxBytes ends it at once.
	liveRotateBytes = 64 << 20
	liveMaxBytes    = 128 << 20
	// liveDrainWait bounds retrying delivery of a stopped Zeek's records.
	liveDrainWait  = 5 * time.Minute
	liveMaxBackoff = time.Minute
)

// LiveStatus reports live analysis in the analyzer status and health.
type LiveStatus struct {
	State     string `json:"state"`
	CaptureID string `json:"capture_id,omitempty"`
	Segment   string `json:"segment,omitempty"`
	// LagMillis is how far the packets Zeek has read trail the clock while
	// it catches up; it is zero at the live edge.
	LagMillis         int64  `json:"lag_millis"`
	EventsDelivered   uint64 `json:"events_delivered"`
	SegmentsCovered   uint64 `json:"segments_covered"`
	SegmentsHandedOff uint64 `json:"segments_handed_off"`
	Restarts          uint64 `json:"restarts"`
	LastError         string `json:"last_error,omitempty"`
}

func validLiveStatus(status LiveStatus) bool {
	switch status.State {
	case LiveStateOff, LiveStateIdle, LiveStateFollowing, LiveStateRecovering:
	default:
		return false
	}
	return (status.CaptureID == "" || capture.ValidSessionID(status.CaptureID)) && (status.Segment == "" || safeCaptureName(status.Segment)) &&
		status.LagMillis >= 0 && (status.LastError == "" || validText(status.LastError, 1, 2048))
}

type LiveAnalyzer struct {
	// Recording is the name of the automatic recording to follow, such as
	// "Lab traffic" or "VPN traffic"; empty follows the first one running.
	Recording   string
	CaptureRoot string
	WorkRoot    string
	State       StateStore
	Sender      Sender
	Coverage    *LiveCoverage
	Logger      *slog.Logger
	Now         func() time.Time
	// Command builds the parser for a work directory; nil runs the isolated
	// Zeek.
	Command func(ctx context.Context, workDirectory string) (*exec.Cmd, error)
	Poll    time.Duration

	mutex     sync.Mutex
	status    LiveStatus
	untakenEv uint64
}

func NewLiveAnalyzer(runner *Runner, coverage *LiveCoverage, logger *slog.Logger, recording string) *LiveAnalyzer {
	return &LiveAnalyzer{
		Recording: recording, CaptureRoot: runner.Config.CaptureRoot, WorkRoot: runner.Config.WorkRoot, State: runner.State, Sender: runner.Sender,
		Coverage: coverage, Logger: logger, Now: time.Now, status: LiveStatus{State: LiveStateIdle},
	}
}

// Status returns a snapshot for the analyzer status.
func (l *LiveAnalyzer) Status() LiveStatus {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return l.status
}

// TakeDelivered returns events delivered since the previous call, for the
// analyzer's overall delivered-event count.
func (l *LiveAnalyzer) TakeDelivered() uint64 {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	taken := l.untakenEv
	l.untakenEv = 0
	return taken
}

func (l *LiveAnalyzer) update(change func(*LiveStatus)) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	change(&l.status)
}

func (l *LiveAnalyzer) fail(err error) {
	if err == nil {
		return
	}
	message := boundedLiveError(err)
	l.update(func(status *LiveStatus) { status.LastError = message })
	if l.Logger != nil {
		l.Logger.Warn("live analysis interrupted; offline analysis covers the gap", "error", message)
	}
}

func boundedLiveError(err error) string {
	message := strings.Map(func(char rune) rune {
		if char < 0x20 || char == 0x7f {
			return ' '
		}
		return char
	}, err.Error())
	if len(message) > 512 {
		message = message[:512]
	}
	message = strings.TrimSpace(strings.ToValidUTF8(message, ""))
	if !validText(message, 1, 2048) {
		return "live analysis failed"
	}
	return message
}

// Run follows the automatic lab recording until ctx ends. On cancellation it
// finishes the segment being written when it can, delivers what Zeek
// produced, and returns.
func (l *LiveAnalyzer) Run(ctx context.Context) {
	if l.Now == nil {
		l.Now = time.Now
	}
	if l.Poll <= 0 {
		l.Poll = DefaultLivePoll
	}
	var backoff time.Duration
	for ctx.Err() == nil {
		sessionID, err := l.labRecording()
		if err != nil || sessionID == "" {
			l.update(func(status *LiveStatus) {
				status.State, status.CaptureID, status.Segment, status.LagMillis = LiveStateIdle, "", "", 0
			})
			sleepContext(ctx, time.Second)
			continue
		}
		start := uint64(0)
		for ctx.Err() == nil {
			result := l.generation(ctx, sessionID, start)
			l.fail(result.err)
			if result.outcome == liveFailed {
				backoff = min(max(2*backoff, time.Second), liveMaxBackoff)
				l.update(func(status *LiveStatus) { status.State, status.LagMillis = LiveStateRecovering, 0; status.Restarts++ })
				sleepContext(ctx, backoff)
			} else {
				backoff = 0
			}
			if result.outcome == liveRotate {
				start = result.next
			} else {
				start = 0
			}
			if result.outcome == liveEnded || result.outcome == liveDeleted || result.outcome == liveShutdown {
				break
			}
			if running, _ := l.captureRunning(sessionID); !running {
				break
			}
		}
	}
	l.update(func(status *LiveStatus) { status.State, status.Segment, status.LagMillis = LiveStateIdle, "", 0 })
}

func sleepContext(ctx context.Context, delay time.Duration) {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

// labRecording returns the running automatic recording this analyzer
// follows, if there is one.
func (l *LiveAnalyzer) labRecording() (string, error) {
	entries, err := os.ReadDir(l.CaptureRoot)
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		sessionID := entry.Name()
		if !entry.IsDir() || !capture.ValidSessionID(sessionID) || !l.automatic(sessionID) {
			continue
		}
		if running, _ := l.captureRunning(sessionID); !running {
			continue
		}
		if deleted, err := l.State.HasCheckpointDeletionBarrier(EngineZeek, sessionID); err != nil || deleted {
			continue
		}
		return sessionID, nil
	}
	return "", nil
}

func (l *LiveAnalyzer) automatic(sessionID string) bool {
	contents, err := readNoFollowFile(filepath.Join(l.CaptureRoot, sessionID, "session.json"), maxMetadataBytes)
	if err != nil {
		return false
	}
	var session struct {
		ID      string `json:"id"`
		Request struct {
			Name      string `json:"name"`
			Automatic bool   `json:"automatic"`
		} `json:"request"`
	}
	return json.Unmarshal(contents, &session) == nil && session.ID == sessionID && session.Request.Automatic &&
		(l.Recording == "" || session.Request.Name == l.Recording)
}

// captureRunning reports whether dumpcap may still write the capture. Once
// the worker records any other state, dumpcap has exited and every segment
// is final. An unreadable status counts as running so a transient read
// error does not end a live capture early.
func (l *LiveAnalyzer) captureRunning(sessionID string) (bool, error) {
	runtime := filepath.Join(l.CaptureRoot, sessionID, "runtime")
	if _, err := os.Lstat(filepath.Join(runtime, "manifest.json")); err == nil {
		return false, nil
	}
	contents, err := readNoFollowFile(filepath.Join(runtime, "worker-status.json"), maxMetadataBytes)
	if errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err != nil {
		return true, err
	}
	var status struct {
		SessionID string        `json:"session_id"`
		State     capture.State `json:"state"`
	}
	if err := json.Unmarshal(contents, &status); err != nil || status.SessionID != sessionID {
		return true, errors.New("capture worker status is invalid")
	}
	return status.State == capture.StateRunning, nil
}

type liveOutcome int

const (
	liveFailed liveOutcome = iota
	liveEnded
	liveShutdown
	liveRotate
	liveLagged
	liveDeleted
)

type liveResult struct {
	outcome liveOutcome
	next    uint64
	err     error
}

type liveSegmentFile struct {
	name   string
	number uint64
}

type liveSegment struct {
	liveSegmentFile
	file   *os.File
	offset int64
	hash   hash.Hash
}

func (s *liveSegment) read(buffer []byte) (int, error) {
	count, err := s.file.ReadAt(buffer, s.offset)
	s.offset += int64(count)
	s.hash.Write(buffer[:count])
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return count, err
}

// listLiveSegments returns the ring-buffer segments in a capture's artifact
// directory, oldest first.
func listLiveSegments(directory string) ([]liveSegmentFile, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	files := make([]liveSegmentFile, 0, len(entries))
	for _, entry := range entries {
		if number, ok := liveSegmentNumber(entry.Name()); ok && entry.Type().IsRegular() {
			files = append(files, liveSegmentFile{name: entry.Name(), number: number})
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].number < files[j].number })
	return files, nil
}

// openLiveSegment opens a segment for reading, waiting briefly for the
// capture worker to grant read access to a file dumpcap just created.
func (l *LiveAnalyzer) openLiveSegment(directory string, segment liveSegmentFile) (*liveSegment, error) {
	deadline := l.Now().Add(liveOpenWait)
	for {
		file, err := openRegularNoFollow(filepath.Join(directory, segment.name))
		if err == nil {
			return &liveSegment{liveSegmentFile: segment, file: file, hash: sha256.New()}, nil
		}
		if !errors.Is(err, os.ErrPermission) || l.Now().After(deadline) {
			return nil, fmt.Errorf("open live capture segment %s: %w", segment.name, err)
		}
		time.Sleep(l.Poll)
	}
}

type liveGeneration struct {
	l         *LiveAnalyzer
	sessionID string
	artifacts string
	claim     uint64
	segment   *liveSegment
	converter *pcapngToPcap
	directory string
	input     *os.File
	writer    *bufio.Writer
	cancel    context.CancelFunc
	exited    chan struct{}
	exitErr   error
	logs      *boundedBuffer
	tail      *zeekLogTail
	stopped   bool
}

// generation runs one Zeek from the given segment (0: the newest) until the
// capture ends, live analysis falls behind, Zeek fails, or ctx ends.
func (l *LiveAnalyzer) generation(ctx context.Context, sessionID string, start uint64) liveResult {
	artifacts := filepath.Join(l.CaptureRoot, sessionID, "artifacts")
	files, err := listLiveSegments(artifacts)
	if err != nil {
		return liveResult{outcome: liveFailed, err: err}
	}
	if len(files) == 0 {
		sleepContext(ctx, time.Second)
		return liveResult{outcome: liveLagged}
	}
	first := files[len(files)-1]
	for _, file := range files {
		if file.number == start {
			first = file
		}
	}
	segment, err := l.openLiveSegment(artifacts, first)
	if err != nil {
		return liveResult{outcome: liveFailed, err: err}
	}
	claim, err := l.Coverage.Claim(sessionID, first.number)
	if err != nil {
		segment.file.Close()
		return liveResult{outcome: liveFailed, err: err}
	}
	g := &liveGeneration{l: l, sessionID: sessionID, artifacts: artifacts, claim: claim, segment: segment, converter: newPcapngToPcap(), tail: nil}
	defer g.close()
	if err := g.start(); err != nil {
		return g.stop(ctx, liveFailed, err, false)
	}
	l.update(func(status *LiveStatus) {
		status.State, status.CaptureID, status.Segment = LiveStateFollowing, sessionID, segment.name
	})
	return g.run(ctx)
}

func (g *liveGeneration) start() error {
	directory, err := os.MkdirTemp(g.l.WorkRoot, ".live-")
	if err != nil {
		return err
	}
	g.directory = directory
	if err := os.Chmod(directory, 0o733); err != nil {
		return err
	}
	g.tail = newZeekLogTail(directory)
	// Zeek gets its own context: shutdown first lets it finish the current
	// segment and write the records of open connections.
	parserContext, cancel := context.WithCancel(context.Background())
	g.cancel = cancel
	build := g.l.Command
	if build == nil {
		build = zeekLiveCommand
	}
	command, err := build(parserContext, directory)
	if err != nil {
		return err
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return err
	}
	g.logs = &boundedBuffer{Limit: 64 << 10}
	command.Stdin = reader
	command.Stdout, command.Stderr = g.logs, g.logs
	if err := command.Start(); err != nil {
		reader.Close()
		writer.Close()
		return fmt.Errorf("start live zeek: %w", err)
	}
	reader.Close()
	g.input, g.writer = writer, bufio.NewWriterSize(writer, 256<<10)
	g.exited = make(chan struct{})
	go func() {
		g.exitErr = command.Wait()
		close(g.exited)
	}()
	return nil
}

func zeekLiveCommand(ctx context.Context, workDirectory string) (*exec.Cmd, error) {
	command := exec.CommandContext(ctx, zeekBinary, "-C", "-r", "-", "LogAscii::use_json=T", zeekSiteScript, zeekLiveScript)
	command.Dir = workDirectory
	command.Env = parserEnvironment(EngineZeek, workDirectory)
	command.WaitDelay = 5 * time.Second
	if err := isolateParserCommand(command); err != nil {
		return nil, err
	}
	return command, nil
}

func (g *liveGeneration) run(ctx context.Context) liveResult {
	l := g.l
	buffer := make([]byte, 256<<10)
	var finishBy, nextDelivery, nextStatus, lastData, nextTick time.Time
	lastData = l.Now()
	for {
		now := l.Now()
		if ctx.Err() != nil && finishBy.IsZero() {
			finishBy = now.Add(liveFinishWait)
		}
		if !finishBy.IsZero() && now.After(finishBy) {
			return g.stop(ctx, liveShutdown, nil, false)
		}
		select {
		case <-g.exited:
			return g.stop(ctx, liveFailed, fmt.Errorf("live zeek exited: %v: %s", g.exitErr, g.logs.String()), false)
		default:
		}
		if err := l.Coverage.Heartbeat(g.sessionID, g.claim); err != nil {
			return g.stop(ctx, liveFailed, err, false)
		}
		if !now.Before(nextDelivery) {
			nextDelivery = now.Add(liveDeliverEvery)
			if result, done := g.deliver(ctx, now); done {
				return result
			}
		}
		count, err := g.segment.read(buffer)
		if err != nil {
			return g.stop(ctx, liveFailed, err, false)
		}
		if count > 0 {
			if err := g.feed(buffer[:count]); err != nil {
				return g.stop(ctx, liveFailed, err, false)
			}
			lastData = now
			continue
		}
		files, err := listLiveSegments(g.artifacts)
		if err != nil {
			return g.stop(ctx, liveFailed, err, false)
		}
		var next *liveSegmentFile
		for index := range files {
			if files[index].number > g.segment.number {
				next = &files[index]
				break
			}
		}
		if next != nil {
			// dumpcap closes a segment before it creates the next one, so
			// this segment is final.
			if err := g.drain(buffer); err != nil {
				return g.stop(ctx, liveFailed, err, false)
			}
			if err := g.cover(next.number); err != nil {
				return g.stop(ctx, liveFailed, err, false)
			}
			newest := files[len(files)-1]
			switch {
			case !finishBy.IsZero():
				return g.stop(ctx, liveShutdown, nil, true)
			case next.number != g.segment.number+1 || newest.number-next.number >= liveMaxLagSegments:
				l.update(func(status *LiveStatus) { status.SegmentsHandedOff += newest.number - next.number })
				return g.stop(ctx, liveLagged, fmt.Errorf("live analysis fell behind at %s; offline analysis takes the segments before %s", g.segment.name, newest.name), true)
			case g.tail.ConsumedBytes >= liveRotateBytes:
				result := g.stop(ctx, liveRotate, nil, true)
				result.next = next.number
				return result
			}
			segment, err := l.openLiveSegment(g.artifacts, *next)
			if err != nil {
				return g.stop(ctx, liveFailed, err, true)
			}
			g.segment.file.Close()
			g.segment = segment
			l.update(func(status *LiveStatus) { status.Segment, status.LagMillis = segment.name, 0 })
			continue
		}
		l.update(func(status *LiveStatus) { status.LagMillis = 0 })
		if !now.Before(nextStatus) {
			nextStatus = now.Add(time.Second)
			if running, _ := l.captureRunning(g.sessionID); !running {
				if err := g.drain(buffer); err != nil {
					return g.stop(ctx, liveFailed, err, false)
				}
				if err := g.cover(g.segment.number + 1); err != nil {
					return g.stop(ctx, liveFailed, err, false)
				}
				return g.stop(ctx, liveEnded, nil, true)
			}
		}
		if now.Sub(lastData) >= liveTickAfter && !now.Before(nextTick) {
			nextTick = now.Add(liveTickAfter)
			if ticked, err := g.converter.Tick(now.Add(-liveTickDelay), g.writer); err != nil {
				return g.stop(ctx, liveFailed, err, false)
			} else if ticked {
				if err := g.flush(); err != nil {
					return g.stop(ctx, liveFailed, err, false)
				}
			}
		}
		time.Sleep(l.Poll)
	}
}

func (g *liveGeneration) feed(data []byte) error {
	if err := g.converter.Feed(data, g.writer); err != nil {
		return err
	}
	return g.flush()
}

func (g *liveGeneration) flush() error {
	if err := g.input.SetWriteDeadline(time.Now().Add(liveWriteTimeout)); err != nil {
		return err
	}
	if err := g.writer.Flush(); err != nil {
		return fmt.Errorf("stream packets to live zeek: %w", err)
	}
	return nil
}

// drain streams the rest of a segment that is known to be final.
func (g *liveGeneration) drain(buffer []byte) error {
	for {
		count, err := g.segment.read(buffer)
		if err != nil {
			return err
		}
		if count == 0 {
			return nil
		}
		if err := g.feed(buffer[:count]); err != nil {
			return err
		}
	}
}

// cover records the final segment as streamed in full and moves on to next.
func (g *liveGeneration) cover(next uint64) error {
	if g.converter.Pending() != 0 {
		return fmt.Errorf("capture segment %s ends inside a pcapng block", g.segment.name)
	}
	info, err := g.segment.file.Stat()
	if err != nil || info.Size() != g.segment.offset || g.segment.offset < 1 {
		return fmt.Errorf("capture segment %s changed while it was streamed", g.segment.name)
	}
	covered := CoveredSegment{Name: g.segment.name, SizeBytes: g.segment.offset, SHA256: hex.EncodeToString(g.segment.hash.Sum(nil)), CoveredAt: g.l.Now().UTC()}
	if err := g.l.Coverage.Cover(g.sessionID, g.claim, covered, next); err != nil {
		return err
	}
	g.l.update(func(status *LiveStatus) { status.SegmentsCovered++ })
	return nil
}

// deliver sends Zeek's new records. It ends the generation when the capture's
// results were deleted or Zeek's output outgrew its budget.
func (g *liveGeneration) deliver(ctx context.Context, now time.Time) (liveResult, bool) {
	if deleted, err := g.l.State.HasCheckpointDeletionBarrier(EngineZeek, g.sessionID); err == nil && deleted {
		g.tail.Discard()
		return g.stop(ctx, liveDeleted, nil, false), true
	}
	if err := g.tail.Poll(); err != nil {
		return g.stop(ctx, liveFailed, err, false), true
	}
	if g.tail.ConsumedBytes >= liveMaxBytes {
		return g.stop(ctx, liveFailed, errors.New("live zeek output exceeded its byte limit"), false), true
	}
	delivered, err := g.tail.Deliver(ctx, g.l.Sender, g.sessionID)
	g.l.record(delivered)
	if err != nil {
		// Records stay pending and are retried; offline analysis takes over
		// if the backlog stalls streaming for long enough.
		g.l.fail(fmt.Errorf("deliver live records: %w", err))
	}
	if last := g.converter.lastPacket; !last.IsZero() && now.Sub(last) > 2*liveTickDelay {
		g.l.update(func(status *LiveStatus) { status.LagMillis = now.Sub(last).Milliseconds() })
	}
	return liveResult{}, false
}

func (l *LiveAnalyzer) record(delivered int) {
	if delivered <= 0 {
		return
	}
	l.update(func(status *LiveStatus) { status.EventsDelivered += uint64(delivered) })
	l.mutex.Lock()
	l.untakenEv += uint64(delivered)
	l.mutex.Unlock()
}

// stop ends the generation: it releases the claim so the runner can take
// what was not covered, lets Zeek write the records of connections still
// open, and delivers everything Zeek wrote.
func (g *liveGeneration) stop(ctx context.Context, outcome liveOutcome, cause error, segmentCovered bool) liveResult {
	l := g.l
	g.stopped = true
	l.Coverage.Release(g.sessionID, g.claim)
	if !segmentCovered {
		l.update(func(status *LiveStatus) { status.SegmentsHandedOff++ })
	}
	if g.input != nil {
		_ = g.writer.Flush()
		g.input.Close()
		timer := time.NewTimer(liveStopWait)
		select {
		case <-g.exited:
		case <-timer.C:
			g.cancel()
			<-g.exited
		}
		timer.Stop()
	}
	if g.tail != nil && outcome != liveDeleted {
		deadline := l.Now().Add(liveDrainWait)
		if ctx.Err() != nil {
			deadline = l.Now().Add(5 * time.Second)
		}
		deliveryContext, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()
		delay := 250 * time.Millisecond
		for {
			before := g.tail.ConsumedBytes
			if err := g.tail.Poll(); err != nil {
				cause = errors.Join(cause, err)
				break
			}
			if g.tail.Pending() == 0 {
				if g.tail.ConsumedBytes == before {
					break
				}
				continue
			}
			delivered, err := g.tail.Deliver(deliveryContext, l.Sender, g.sessionID)
			l.record(delivered)
			if err == nil {
				continue
			}
			if deliveryContext.Err() != nil {
				cause = errors.Join(cause, fmt.Errorf("live records were not delivered before the drain deadline: %w", err))
				break
			}
			sleepContext(deliveryContext, delay)
			delay = min(2*delay, 10*time.Second)
		}
	}
	return liveResult{outcome: outcome, err: cause}
}

func (g *liveGeneration) close() {
	if !g.stopped {
		g.l.Coverage.Release(g.sessionID, g.claim)
	}
	if g.cancel != nil {
		g.cancel()
	}
	if g.input != nil {
		g.input.Close()
		<-g.exited
	}
	if g.tail != nil {
		g.tail.Close()
	}
	if g.segment != nil {
		g.segment.file.Close()
	}
	if g.directory != "" {
		_ = os.RemoveAll(g.directory)
	}
}
