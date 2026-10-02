package capture

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

var (
	packetCountPattern = regexp.MustCompile(`(?:Packets:|Packets captured:)\s*([0-9]+)`)
	dropCountPattern   = regexp.MustCompile(`Packets received/dropped on interface '([^']+)':\s*([0-9]+)/([0-9]+)\s*\(pcap:([0-9]+)/dumpcap:([0-9]+)/flushed:([0-9]+)/ps_ifdrop:([0-9]+)\)`)
	// dumpcap 4.2 prints "File: <path>" on its own line at each rotation;
	// dumpcap 4.6 (Ubuntu 26.04) appends it to the packet counter line,
	// "Packets: 14 File: <path>".
	outputFilePattern = regexp.MustCompile(`(?:^|\s)File:\s+(.+)$`)
)

func BuildDumpcapArguments(session Session, directory string, now time.Time) ([]string, error) {
	if err := session.Validate(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(directory) || filepath.Base(directory) != "artifacts" || filepath.Base(filepath.Dir(directory)) != session.ID {
		return nil, errors.New("capture output directory is invalid")
	}
	remaining := session.StopAt.Sub(now)
	if remaining <= 0 {
		return nil, errors.New("capture stop deadline has elapsed")
	}
	seconds := int((remaining + time.Second - 1) / time.Second)
	// The snapshot length and buffer follow each -i, so they apply to every
	// recorded interface.
	arguments := []string{}
	for _, name := range session.Source.Interfaces() {
		arguments = append(arguments, "-i", name, "-s", strconv.Itoa(session.Request.SnapLength), "-B", "8")
	}
	arguments = append(arguments,
		"-n",
		"--temp-dir", directory,
		"-w", filepath.Join(directory, session.OutputBaseName),
		"-b", "filesize:"+strconv.Itoa(session.Request.SegmentSizeMiB*1024),
		"-b", "duration:"+strconv.Itoa(session.Request.SegmentSeconds),
		"-b", "files:"+strconv.Itoa(session.Request.MaxFiles),
		"-a", "duration:"+strconv.Itoa(seconds),
	)
	if session.Source.SingleArmGateway != "" {
		filter, err := session.Source.singleArmFilter()
		if err != nil {
			return nil, err
		}
		arguments = append(arguments, "-f", filter)
	}
	return arguments, nil
}

type Worker struct {
	Store        Store
	DumpcapPath  string
	Now          func() time.Time
	PollInterval time.Duration
}

func (w Worker) Run(ctx context.Context, id string) error {
	if w.DumpcapPath == "" {
		w.DumpcapPath = "/usr/bin/dumpcap"
	}
	if w.DumpcapPath != "/usr/bin/dumpcap" {
		return errors.New("capture worker dumpcap path is not approved")
	}
	session, err := w.Store.ReadSession(id)
	if err != nil {
		return err
	}
	directory, err := w.Store.ArtifactDirectory(id)
	if err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("capture session directory is unsafe")
	}
	now := w.now()
	arguments, err := BuildDumpcapArguments(session, directory, now)
	if err != nil {
		status := WorkerStatus{Schema: SchemaVersion, SessionID: id, State: StateCompleted, StartedAt: now, EndedAt: now, UpdatedAt: now, StopReason: "capture deadline elapsed before worker start"}
		_ = w.Store.WriteWorkerStatus(status)
		return nil
	}
	executable, err := os.Lstat(w.DumpcapPath)
	if err != nil || !executable.Mode().IsRegular() || executable.Mode().Perm()&0o111 == 0 {
		return errors.New("approved dumpcap executable is unavailable")
	}
	command := exec.Command(w.DumpcapPath, arguments...)
	command.Env = []string{"HOME=/nonexistent", "LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "TMPDIR=" + directory}
	stderr, err := command.StderrPipe()
	if err != nil {
		return err
	}
	command.Stdout = io.Discard
	if err := command.Start(); err != nil {
		return err
	}
	status := WorkerStatus{Schema: SchemaVersion, SessionID: id, State: StateRunning, StartedAt: now, UpdatedAt: now}
	if err := w.Store.WriteWorkerStatus(status); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return err
	}
	tracker := &captureOutputTracker{status: status, shareStarted: func(name string) {
		// Live analysis is best effort: without read access it leaves the
		// segment to offline analysis once it closes.
		_ = w.Store.ShareActiveSegment(id, name)
	}}
	outputDone := make(chan struct{})
	go func() {
		tracker.consume(stderr)
		close(outputDone)
	}()
	processDone := make(chan error, 1)
	go func() { processDone <- command.Wait() }()
	interval := w.PollInterval
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	stopReason := ""
	var processErr error
	running := true
	for running {
		select {
		case processErr = <-processDone:
			running = false
		case <-ctx.Done():
			stopReason = "operator or service requested stop"
			processErr = interruptAndWait(command, processDone)
			running = false
		case <-ticker.C:
			available, statErr := w.Store.AvailableBytes()
			if statErr != nil || available <= session.ReserveBytes {
				stopReason = "emergency free-space reserve reached"
				processErr = interruptAndWait(command, processDone)
				running = false
				break
			}
			latest := tracker.snapshot()
			for _, closedName := range tracker.drainClosedFiles() {
				feed, publishErr := w.Store.PublishClosedSegment(id, closedName, w.now())
				if publishErr != nil {
					tracker.recordAnalyzerFeedError(publishErr)
					continue
				}
				tracker.recordAnalyzerFeedEvictions(feed.EvictedSegments)
			}
			latest = tracker.snapshot()
			latest.UpdatedAt = w.now()
			_ = w.Store.WriteWorkerStatus(latest)
		}
	}
	<-outputDone
	final := tracker.snapshot()
	final.UpdatedAt = w.now()
	final.EndedAt = final.UpdatedAt
	final.StopReason = stopReason
	switch {
	case stopReason == "emergency free-space reserve reached":
		final.State = StateStoragePressure
	case stopReason != "":
		final.State = StateStopped
	case processErr == nil:
		final.State = StateCompleted
		final.StopReason = "capture deadline or dumpcap stop condition reached"
	default:
		final.State = StateFailed
		final.Failure = tracker.failure()
		if final.Failure == "" {
			final.Failure = "dumpcap exited unsuccessfully"
		}
	}
	if err := w.Store.WriteWorkerStatus(final); err != nil {
		return err
	}
	if final.State == StateFailed {
		return errors.New(final.Failure)
	}
	manifest, err := w.Store.CollectFiles(id, w.now())
	if err != nil {
		final.State = StateFailed
		final.Failure = "capture manifest finalization failed"
		final.UpdatedAt = w.now()
		_ = w.Store.WriteWorkerStatus(final)
		return err
	}
	if err := w.Store.WriteManifest(manifest); err != nil {
		return err
	}
	return nil
}

func interruptAndWait(command *exec.Cmd, done <-chan error) error {
	if command.Process != nil {
		_ = command.Process.Signal(os.Interrupt)
	}
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		return <-done
	}
}

type captureOutputTracker struct {
	mu           sync.Mutex
	status       WorkerStatus
	lastOutput   string
	currentFile  string
	closedFiles  []string
	queueEvicted uint64
	feedEvicted  uint64
	// shareStarted lets the analyzers read a segment as soon as dumpcap
	// starts it, for live analysis.
	shareStarted func(name string)
	// interfaceCounts holds dumpcap's latest counters per interface.
	interfaceCounts map[string]interfaceCounts
}

type interfaceCounts struct {
	received, kernel, dumpcap uint64
}

// maxCaptureInterfaces bounds the per-interface counters; a recording has
// at most the device port and an access point.
const maxCaptureInterfaces = 4

func (t *captureOutputTracker) consume(reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	scanner.Split(splitDumpcapOutput)
	scanner.Buffer(make([]byte, 1024), 16<<10)
	for scanner.Scan() {
		if started := t.observe(strings.TrimSpace(scanner.Text())); started != "" && t.shareStarted != nil {
			t.shareStarted(started)
		}
	}
	if err := scanner.Err(); err != nil {
		t.observe("dumpcap status stream failed")
	}
}

func splitDumpcapOutput(data []byte, atEOF bool) (advance int, token []byte, err error) {
	for index, value := range data {
		if value == '\n' || value == '\r' {
			return index + 1, data[:index], nil
		}
	}
	if atEOF && len(data) != 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// observe records one dumpcap status line and returns the name of a segment
// dumpcap just started writing, if the line announces one.
func (t *captureOutputTracker) observe(line string) (started string) {
	if line == "" {
		return ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if match := packetCountPattern.FindStringSubmatch(line); len(match) == 2 {
		if count, err := strconv.ParseUint(match[1], 10, 64); err == nil {
			t.status.PacketsCaptured = count
		}
	}
	if match := dropCountPattern.FindStringSubmatch(line); len(match) == 8 {
		values := make([]uint64, 6)
		for index := range values {
			values[index], _ = strconv.ParseUint(match[index+2], 10, 64)
		}
		// dumpcap reports each recorded interface on its own line; the
		// status is their sum.
		if t.interfaceCounts == nil {
			t.interfaceCounts = map[string]interfaceCounts{}
		}
		if _, known := t.interfaceCounts[match[1]]; known || len(t.interfaceCounts) < maxCaptureInterfaces {
			t.interfaceCounts[match[1]] = interfaceCounts{received: values[0], kernel: values[2] + values[5], dumpcap: values[3] + values[4]}
		}
		t.status.PacketsReceived, t.status.KernelDrops, t.status.DumpcapDrops = 0, 0, 0
		for _, counts := range t.interfaceCounts {
			t.status.PacketsReceived += counts.received
			t.status.KernelDrops += counts.kernel
			t.status.DumpcapDrops += counts.dumpcap
		}
	}
	if match := outputFilePattern.FindStringSubmatch(line); len(match) == 2 {
		name := filepath.Base(strings.TrimSpace(match[1]))
		if captureFileName(name) {
			if t.currentFile != "" && t.currentFile != name {
				t.closedFiles = append(t.closedFiles, t.currentFile)
				if len(t.closedFiles) > maxActiveFeedSegments {
					t.closedFiles = t.closedFiles[len(t.closedFiles)-maxActiveFeedSegments:]
					t.queueEvicted++
					t.status.AnalyzerFeedEvicted = t.queueEvicted + t.feedEvicted
				}
			}
			if t.currentFile != name {
				started = name
			}
			t.currentFile = name
		}
	}
	if len(line) > 512 {
		line = line[:512]
	}
	t.lastOutput = line
	return started
}

func (t *captureOutputTracker) drainClosedFiles() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	result := append([]string(nil), t.closedFiles...)
	t.closedFiles = t.closedFiles[:0]
	return result
}

func (t *captureOutputTracker) recordAnalyzerFeedError(err error) {
	if err == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	message := strings.TrimSpace(strings.ToValidUTF8(err.Error(), "?"))
	if len(message) > 256 {
		message = message[:256]
		for !utf8.ValidString(message) {
			_, size := utf8.DecodeLastRuneInString(message)
			message = message[:len(message)-size]
		}
	}
	t.status.AnalyzerFeedError = message
}

func (t *captureOutputTracker) recordAnalyzerFeedEvictions(evicted uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.feedEvicted = evicted
	t.status.AnalyzerFeedEvicted = t.queueEvicted + t.feedEvicted
}

func (t *captureOutputTracker) snapshot() WorkerStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.status
}

func (t *captureOutputTracker) failure() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastOutput
}

func (w Worker) now() time.Time {
	if w.Now != nil {
		return w.Now().UTC()
	}
	return time.Now().UTC()
}

func FormatQuota(request StartRequest) string {
	request = request.WithDefaults()
	return fmt.Sprintf("%d MiB across %d files", request.SegmentSizeMiB*request.MaxFiles, request.MaxFiles)
}
