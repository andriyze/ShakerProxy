package analyzer

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"shakerproxy.dev/shakerproxy/internal/capture"
)

type Runner struct {
	Config    Config
	State     StateStore
	Processor Processor
	Sender    Sender
	Now       func() time.Time
	Ruleset   *RulesetManifest

	failures map[string]captureFailure
	seedKey  []byte
	// Live hands segments between live Zeek analysis and this offline pass;
	// nil means every segment is analyzed offline.
	Live *LiveCoverage
}

// captureFailure tracks consecutive analysis failures for one capture so the
// runner backs off instead of re-running a parser on every poll.
type captureFailure struct {
	count     int
	retryAt   time.Time
	lastError error
}

type captureJob struct {
	Manifest       capture.Manifest
	ManifestBytes  []byte
	ManifestSHA256 string
}

type activeCaptureJob struct {
	Feed capture.ActiveSegmentFeed
}

func NewRunner(config Config) (*Runner, error) {
	config = config.WithDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}
	sender, err := NewHTTPSender(config)
	if err != nil {
		return nil, err
	}
	state := NewStateStore(config.StateRoot)
	if err := state.Prepare(); err != nil {
		return nil, err
	}
	if err := prepareDirectory(config.WorkRoot, 0o711); err != nil {
		return nil, fmt.Errorf("prepare analyzer work root: %w", err)
	}
	if err := safeDirectory(config.CaptureRoot); err != nil {
		return nil, fmt.Errorf("inspect analyzer capture root: %w", err)
	}
	runner := &Runner{Config: config, State: state, Processor: CommandProcessor{Engine: config.Engine}, Sender: sender, Now: time.Now}
	if config.Engine == EngineSuricata {
		ruleset, err := LoadRulesetManifest(suricataRules, suricataRuleset)
		if err != nil {
			return nil, fmt.Errorf("validate Suricata ruleset: %w", err)
		}
		runner.Ruleset = &ruleset
	}
	return runner, nil
}

func (r *Runner) RunOnce(ctx context.Context) ScanResult {
	result := ScanResult{}
	if r == nil || r.Processor == nil || r.Sender == nil || r.Now == nil {
		result.Errors = append(result.Errors, errors.New("analyzer runner is incomplete"))
		return result
	}
	entries, err := os.ReadDir(r.Config.CaptureRoot)
	if err != nil {
		result.Errors = append(result.Errors, err)
		return result
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if ctx.Err() != nil {
			result.Errors = append(result.Errors, ctx.Err())
			break
		}
		if !entry.IsDir() || !capture.ValidSessionID(entry.Name()) {
			continue
		}
		if r.deferred(entry.Name()) {
			result.Discovered++
			result.Deferred++
			continue
		}
		errorsBefore := len(result.Errors)
		r.runCapture(ctx, entry.Name(), &result)
		if ctx.Err() != nil {
			continue
		}
		if len(result.Errors) > errorsBefore {
			r.recordFailure(entry.Name(), result.Errors[len(result.Errors)-1])
		} else {
			r.clearFailure(entry.Name())
		}
	}
	return result
}

func (r *Runner) runCapture(ctx context.Context, sessionID string, result *ScanResult) {
	job, loadErr := loadCaptureJob(r.Config.CaptureRoot, sessionID)
	if errors.Is(loadErr, os.ErrNotExist) {
		activeJob, activeErr := loadActiveCaptureJob(r.Config.CaptureRoot, sessionID)
		if errors.Is(activeErr, os.ErrNotExist) {
			return
		}
		result.Discovered++
		if activeErr != nil {
			result.Errors = append(result.Errors, fmt.Errorf("capture %s: %w", sessionID, activeErr))
			return
		}
		deleted, deletionErr := r.State.HasCheckpointDeletionBarrier(r.Config.Engine, sessionID)
		if deletionErr != nil {
			result.Errors = append(result.Errors, fmt.Errorf("capture %s: %w", sessionID, deletionErr))
			return
		}
		if deleted {
			result.Skipped++
			return
		}
		events, segments, processErr := r.processActiveJob(ctx, activeJob)
		if processErr != nil {
			result.Errors = append(result.Errors, fmt.Errorf("capture %s: %w", sessionID, processErr))
			return
		}
		result.Events += events
		result.Segments += segments
		if segments == 0 {
			result.Skipped++
		}
		return
	}
	result.Discovered++
	if loadErr != nil {
		result.Errors = append(result.Errors, fmt.Errorf("capture %s: %w", sessionID, loadErr))
		return
	}
	checkpoint, exists, checkpointErr := r.State.ReadCheckpoint(r.Config.Engine, sessionID)
	if checkpointErr != nil {
		result.Errors = append(result.Errors, fmt.Errorf("capture %s: %w", sessionID, checkpointErr))
		return
	}
	if exists {
		if checkpoint.ManifestSHA256 != job.ManifestSHA256 {
			result.Errors = append(result.Errors, fmt.Errorf("capture %s: finalized manifest changed after analysis", sessionID))
			return
		}
		if finalizeErr := r.State.FinalizeCheckpointReindex(checkpoint); finalizeErr != nil {
			result.Errors = append(result.Errors, fmt.Errorf("capture %s: finalize checkpoint reindex: %w", sessionID, finalizeErr))
			return
		}
		if cleanupErr := r.State.DeleteActiveProgress(sessionID); cleanupErr != nil {
			result.Errors = append(result.Errors, fmt.Errorf("capture %s: clean active analyzer progress: %w", sessionID, cleanupErr))
			return
		}
		if cleanupErr := r.Live.Forget(sessionID); cleanupErr != nil {
			result.Errors = append(result.Errors, fmt.Errorf("capture %s: clean live coverage: %w", sessionID, cleanupErr))
			return
		}
		result.Skipped++
		return
	}
	deleted, deletionErr := r.State.HasCheckpointDeletionBarrier(r.Config.Engine, sessionID)
	if deletionErr != nil {
		result.Errors = append(result.Errors, fmt.Errorf("capture %s: %w", sessionID, deletionErr))
		return
	}
	if deleted {
		authorized, authorizationErr := r.State.HasCheckpointReindexAuthorization(r.Config.Engine, sessionID, job.ManifestSHA256)
		if authorizationErr != nil {
			result.Errors = append(result.Errors, fmt.Errorf("capture %s: %w", sessionID, authorizationErr))
			return
		}
		if !authorized {
			result.Skipped++
			return
		}
	}
	events, processErr := r.processJob(ctx, job)
	if errors.Is(processErr, errLiveSegmentPending) {
		result.Events += events
		result.Skipped++
		return
	}
	if processErr != nil {
		result.Errors = append(result.Errors, fmt.Errorf("capture %s: %w", sessionID, processErr))
		return
	}
	result.Completed++
	result.Events += events
}

func (r *Runner) deferred(sessionID string) bool {
	failure, exists := r.failures[sessionID]
	return exists && r.Now().Before(failure.retryAt)
}

func (r *Runner) recordFailure(sessionID string, err error) {
	if r.failures == nil {
		r.failures = make(map[string]captureFailure)
	}
	if errors.Is(err, ErrCheckpointDeletionBarrier) {
		// A deletion barrier is an operator decision, not a parser failure;
		// the next scan must observe it and skip the capture.
		delete(r.failures, sessionID)
		return
	}
	failure := r.failures[sessionID]
	failure.count++
	failure.lastError = err
	// The first failure retries on the next poll as before; repeated failures
	// back off exponentially so a capture that can never succeed stops
	// re-running a parser over the whole capture every poll interval.
	var delay time.Duration
	if failure.count > 1 {
		delay = r.Config.PollInterval
		if delay <= 0 {
			delay = DefaultPollInterval
		}
		for attempt := 1; attempt < failure.count && delay < MaxCaptureRetryDelay; attempt++ {
			delay *= 2
		}
	}
	failure.retryAt = r.Now().Add(min(delay, MaxCaptureRetryDelay))
	r.failures[sessionID] = failure
}

func (r *Runner) clearFailure(sessionID string) {
	delete(r.failures, sessionID)
}

func (r *Runner) processJob(ctx context.Context, job captureJob) (int, error) {
	analysisContext, cancel := context.WithTimeout(ctx, r.Config.AnalysisLimit)
	defer cancel()
	progress, exists, err := r.State.ReadActiveProgress(r.Config.Engine, job.Manifest.SessionID)
	if err != nil {
		return 0, err
	}
	if !exists {
		progress = ActiveProgress{Schema: SchemaVersion, Engine: r.Config.Engine, CaptureSessionID: job.Manifest.SessionID, Recent: []ProcessedSegment{}}
	}
	totalEvents := progress.EventsDelivered
	initialEvents := totalEvents
	totalOutputBytes := progress.OutputBytes
	processed := make(map[string]ProcessedSegment, len(progress.Recent))
	for _, segment := range progress.Recent {
		processed[segment.Name] = segment
	}
	// A reindex runs behind a deletion barrier after the capture's events
	// were deleted, so it analyzes everything regardless of live coverage.
	reindexing, err := r.State.HasCheckpointDeletionBarrier(r.Config.Engine, job.Manifest.SessionID)
	if err != nil {
		return 0, err
	}
	persistProgress := true
	for _, artifact := range job.Manifest.Files {
		if segment, ok := processed[artifact.Name]; ok && segment.SizeBytes == artifact.SizeBytes && segment.Modified.Equal(artifact.Modified) && segment.SHA256 == artifact.SHA256 {
			continue
		}
		var delivered int
		var outputBytes int64
		var processErr error
		decision := LiveOffline
		if !reindexing {
			decision = r.liveDecision(job.Manifest.SessionID, artifact)
		}
		switch decision {
		case LiveWait:
			return totalEvents - initialEvents, errLiveSegmentPending
		case LiveCovered:
		default:
			delivered, outputBytes, processErr = r.processArtifact(analysisContext, job.Manifest.SessionID, artifact, r.Config.MaxOutputBytes-totalOutputBytes, MaxEventsPerCapture-totalEvents)
		}
		totalEvents += delivered
		totalOutputBytes += outputBytes
		if processErr != nil {
			return totalEvents - initialEvents, processErr
		}
		if !persistProgress {
			continue
		}
		// Record each completed manifest member so a later failure or restart
		// resumes after it instead of re-analyzing and re-delivering it.
		sequence := progress.LastCompletedSequence + 1
		progress.LastCompletedSequence = sequence
		progress.SegmentsProcessed++
		progress.FeedRevision = max(progress.FeedRevision, sequence)
		progress.EventsDelivered = totalEvents
		progress.OutputBytes = totalOutputBytes
		progress.Recent = append(progress.Recent, ProcessedSegment{Sequence: sequence, Name: artifact.Name, SizeBytes: artifact.SizeBytes, Modified: artifact.Modified, SHA256: artifact.SHA256, Finalized: true})
		if overflow := len(progress.Recent) - MaxActiveRecent; overflow > 0 {
			progress.Recent = append([]ProcessedSegment(nil), progress.Recent[overflow:]...)
		}
		progress.UpdatedAt = r.Now().UTC()
		if err := r.State.WriteActiveProgress(progress); err != nil {
			if !errors.Is(err, ErrCheckpointDeletionBarrier) {
				return totalEvents - initialEvents, err
			}
			// An authorized reindex still runs behind a deletion barrier; it
			// simply cannot checkpoint intermediate progress.
			persistProgress = false
		}
	}
	activeSegments := progress.SegmentsProcessed
	for _, segment := range progress.Recent {
		if segment.Finalized && activeSegments > 0 {
			activeSegments--
		}
	}
	current, err := loadCaptureJob(r.Config.CaptureRoot, job.Manifest.SessionID)
	if err != nil || !bytes.Equal(current.ManifestBytes, job.ManifestBytes) || current.ManifestSHA256 != job.ManifestSHA256 {
		return totalEvents - initialEvents, errors.New("finalized capture manifest changed during analysis")
	}
	checkpoint := Checkpoint{
		Schema: SchemaVersion, Engine: r.Config.Engine, CaptureSessionID: job.Manifest.SessionID,
		ManifestSHA256: job.ManifestSHA256, CaptureFiles: len(job.Manifest.Files), EventsDelivered: totalEvents,
		OutputBytes: totalOutputBytes, AnalysisCompletedAt: r.Now().UTC(), ActiveSegments: activeSegments, MissedSegments: progress.MissedSegments,
	}
	if err := r.State.WriteCheckpoint(checkpoint); err != nil {
		return totalEvents - initialEvents, err
	}
	if err := r.State.DeleteActiveProgress(job.Manifest.SessionID); err != nil {
		return totalEvents - initialEvents, err
	}
	if err := r.Live.Forget(job.Manifest.SessionID); err != nil {
		return totalEvents - initialEvents, err
	}
	return totalEvents - initialEvents, nil
}

// errLiveSegmentPending defers a finalized capture while live analysis may
// still cover one of its segments.
var errLiveSegmentPending = errors.New("live analysis may still cover a capture segment")

// liveDecision reports whether live analysis covers a closed segment; only
// Zeek runs live.
func (r *Runner) liveDecision(sessionID string, artifact capture.CaptureFile) LiveDecision {
	if r.Config.Engine != EngineZeek || r.Live == nil {
		return LiveOffline
	}
	return r.Live.Decide(sessionID, artifact)
}

func (r *Runner) processActiveJob(ctx context.Context, job activeCaptureJob) (int, int, error) {
	progress, exists, err := r.State.ReadActiveProgress(r.Config.Engine, job.Feed.SessionID)
	if err != nil {
		return 0, 0, err
	}
	if !exists {
		progress = ActiveProgress{Schema: SchemaVersion, Engine: r.Config.Engine, CaptureSessionID: job.Feed.SessionID, Recent: []ProcessedSegment{}}
	}
	if job.Feed.Revision < progress.FeedRevision || job.Feed.EvictedSegments < progress.FeedEvictedSegments {
		return 0, 0, errors.New("active capture feed moved backwards")
	}
	progress.FeedRevision = job.Feed.Revision
	progress.FeedEvictedSegments = job.Feed.EvictedSegments
	analysisContext, cancel := context.WithTimeout(ctx, r.Config.AnalysisLimit)
	defer cancel()
	newEvents := 0
	processed := 0
segments:
	for _, segment := range job.Feed.Segments {
		if segment.Sequence <= progress.LastCompletedSequence {
			continue
		}
		if segment.Sequence > progress.LastCompletedSequence+1 {
			gap := segment.Sequence - progress.LastCompletedSequence - 1
			progress.MissedSegments += gap
			progress.LastCompletedSequence += gap
		}
		artifact, snapshotErr := snapshotClosedArtifact(r.Config.CaptureRoot, job.Feed.SessionID, segment)
		var delivered int
		var outputBytes int64
		processErr := snapshotErr
		if processErr == nil {
			switch r.liveDecision(job.Feed.SessionID, artifact) {
			case LiveWait:
				// Live analysis may still cover this segment; later ones
				// wait behind it so progress stays in order.
				break segments
			case LiveCovered:
				// Live analysis already delivered this segment's packets.
			default:
				delivered, outputBytes, processErr = r.processArtifact(analysisContext, job.Feed.SessionID, artifact, r.Config.MaxOutputBytes-progress.OutputBytes, MaxEventsPerCapture-progress.EventsDelivered)
			}
		}
		if errors.Is(processErr, os.ErrNotExist) {
			// The capture's ring buffer removed the segment before it was
			// analyzed. Waiting for it would stop analysis of this capture
			// for good, so it is counted as missed and analysis moves on.
			progress.MissedSegments++
			progress.LastCompletedSequence = segment.Sequence
			progress.UpdatedAt = r.Now().UTC()
			if err := r.State.WriteActiveProgress(progress); err != nil {
				return newEvents, processed, err
			}
			continue
		}
		if processErr != nil {
			return newEvents, processed, processErr
		}
		progress.LastCompletedSequence = segment.Sequence
		progress.SegmentsProcessed++
		progress.EventsDelivered += delivered
		progress.OutputBytes += outputBytes
		progress.Recent = append(progress.Recent, ProcessedSegment{Sequence: segment.Sequence, Name: artifact.Name, SizeBytes: artifact.SizeBytes, Modified: artifact.Modified, SHA256: artifact.SHA256})
		if overflow := len(progress.Recent) - MaxActiveRecent; overflow > 0 {
			progress.Recent = append([]ProcessedSegment(nil), progress.Recent[overflow:]...)
		}
		progress.UpdatedAt = r.Now().UTC()
		if err := r.State.WriteActiveProgress(progress); err != nil {
			return newEvents, processed, err
		}
		newEvents += delivered
		processed++
	}
	if !exists && processed == 0 {
		progress.UpdatedAt = r.Now().UTC()
		if err := r.State.WriteActiveProgress(progress); err != nil {
			return 0, 0, err
		}
	}
	return newEvents, processed, nil
}

func (r *Runner) processArtifact(ctx context.Context, sessionID string, artifact capture.CaptureFile, remainingOutput int64, remainingEvents int) (int, int64, error) {
	captureFile, err := openVerifiedArtifact(r.Config.CaptureRoot, sessionID, artifact)
	if err != nil {
		return 0, 0, err
	}
	workDirectory, err := os.MkdirTemp(r.Config.WorkRoot, ".analysis-")
	if err != nil {
		captureFile.Close()
		return 0, 0, err
	}
	if err := os.Chmod(workDirectory, 0o733); err != nil {
		captureFile.Close()
		os.RemoveAll(workDirectory)
		return 0, 0, err
	}
	analysisContext := ctx
	if r.Config.Engine == EngineZeek {
		if r.seedKey == nil {
			key, keyErr := r.State.AnalysisSeedKey()
			if keyErr != nil {
				captureFile.Close()
				os.RemoveAll(workDirectory)
				return 0, 0, fmt.Errorf("load analyzer seed key: %w", keyErr)
			}
			r.seedKey = key
		}
		mac := hmac.New(sha256.New, r.seedKey)
		mac.Write([]byte(sessionID + "\x00" + artifact.SHA256))
		analysisContext = withAnalysisSeed(ctx, mac.Sum(nil))
	}
	eventFiles, analyzeErr := r.Processor.Analyze(analysisContext, captureFile, workDirectory)
	verifyErr := verifyOpenArtifact(captureFile, artifact)
	closeErr := captureFile.Close()
	if analyzeErr != nil || verifyErr != nil || closeErr != nil {
		os.RemoveAll(workDirectory)
		return 0, 0, errors.Join(analyzeErr, verifyErr, closeErr)
	}
	outputBytes, outputErr := validateOutputDirectory(workDirectory, remainingOutput)
	if outputErr != nil {
		os.RemoveAll(workDirectory)
		return 0, 0, outputErr
	}
	delivered, _, deliveryErr := deliverEventFiles(ctx, r.Sender, r.Config.Engine, sessionID, eventFiles, remainingOutput, remainingEvents)
	removeErr := os.RemoveAll(workDirectory)
	return delivered, outputBytes, errors.Join(deliveryErr, removeErr)
}

func validateOutputDirectory(directory string, limit int64) (int64, error) {
	if limit < 0 {
		return 0, errors.New("analyzer output exceeds its byte limit")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return 0, err
	}
	if len(entries) > MaxOutputFiles+8 {
		return 0, errors.New("analyzer output file count exceeds its safety limit")
	}
	var total int64
	for _, entry := range entries {
		path := filepath.Join(directory, entry.Name())
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return 0, errors.New("analyzer output directory contains an unsafe entry")
		}
		if info.Size() < 0 || info.Size() > limit-total {
			return 0, errors.New("analyzer output exceeds its byte limit")
		}
		total += info.Size()
	}
	return total, nil
}

func loadCaptureJob(root, sessionID string) (captureJob, error) {
	if !capture.ValidSessionID(sessionID) {
		return captureJob{}, errors.New("capture session identity is invalid")
	}
	for _, directory := range []string{root, filepath.Join(root, sessionID), filepath.Join(root, sessionID, "runtime"), filepath.Join(root, sessionID, "artifacts")} {
		if err := safeDirectory(directory); err != nil {
			return captureJob{}, err
		}
	}
	manifestPath := filepath.Join(root, sessionID, "runtime", "manifest.json")
	contents, err := readNoFollowFile(manifestPath, maxMetadataBytes)
	if err != nil {
		return captureJob{}, err
	}
	var manifest capture.Manifest
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return captureJob{}, errors.New("capture manifest does not match its schema")
	}
	if err := validateManifest(manifest, sessionID); err != nil {
		return captureJob{}, err
	}
	digest := sha256.Sum256(contents)
	return captureJob{Manifest: manifest, ManifestBytes: contents, ManifestSHA256: hex.EncodeToString(digest[:])}, nil
}

func loadActiveCaptureJob(root, sessionID string) (activeCaptureJob, error) {
	if !capture.ValidSessionID(sessionID) {
		return activeCaptureJob{}, errors.New("capture session identity is invalid")
	}
	for _, directory := range []string{root, filepath.Join(root, sessionID), filepath.Join(root, sessionID, "runtime"), filepath.Join(root, sessionID, "artifacts")} {
		if err := safeDirectory(directory); err != nil {
			return activeCaptureJob{}, err
		}
	}
	contents, err := readNoFollowFile(filepath.Join(root, sessionID, "runtime", "active-segments.json"), maxMetadataBytes)
	if err != nil {
		return activeCaptureJob{}, err
	}
	var feed capture.ActiveSegmentFeed
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&feed); err != nil || decoder.Decode(&struct{}{}) != io.EOF || feed.SessionID != sessionID || feed.Validate() != nil {
		return activeCaptureJob{}, errors.New("active capture feed does not match its schema")
	}
	return activeCaptureJob{Feed: feed}, nil
}

func snapshotClosedArtifact(root, sessionID string, segment capture.ClosedCaptureSegment) (capture.CaptureFile, error) {
	artifact := capture.CaptureFile{Name: segment.Name, SizeBytes: segment.SizeBytes, Modified: segment.Modified}
	if !capture.ValidSessionID(sessionID) || !safeCaptureName(segment.Name) || segment.SizeBytes < 1 || segment.Modified.IsZero() {
		return capture.CaptureFile{}, errors.New("closed capture segment identity is invalid")
	}
	path := filepath.Join(root, sessionID, "artifacts", segment.Name)
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return capture.CaptureFile{}, err
	}
	file := os.NewFile(uintptr(descriptor), segment.Name)
	if file == nil {
		unix.Close(descriptor)
		return capture.CaptureFile{}, errors.New("open closed capture segment descriptor")
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() != segment.SizeBytes || !before.ModTime().Equal(segment.Modified) {
		return capture.CaptureFile{}, errors.New("closed capture segment no longer matches its feed metadata")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return capture.CaptureFile{}, err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return capture.CaptureFile{}, errors.New("closed capture segment changed while hashing")
	}
	artifact.SHA256 = hex.EncodeToString(hash.Sum(nil))
	return artifact, nil
}

func readNoFollowFile(path string, limit int64) ([]byte, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), filepath.Base(path))
	if file == nil {
		unix.Close(descriptor)
		return nil, errors.New("open bounded file descriptor")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 2 || info.Size() > limit {
		return nil, errors.New("file is not a bounded regular file")
	}
	contents, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(contents)) != info.Size() || int64(len(contents)) > limit {
		return nil, errors.New("bounded file changed during validation")
	}
	return contents, nil
}

func validateManifest(manifest capture.Manifest, sessionID string) error {
	if manifest.Schema != capture.SchemaVersion || manifest.SessionID != sessionID || manifest.CreatedAt.IsZero() || !sha256Pattern.MatchString(manifest.SessionSHA256) {
		return errors.New("capture manifest identity or provenance is invalid")
	}
	if len(manifest.Files) < 1 || len(manifest.Files) > 128 {
		return errors.New("capture manifest file count is invalid")
	}
	seen := make(map[string]struct{}, len(manifest.Files))
	var total int64
	for _, artifact := range manifest.Files {
		if !safeCaptureName(artifact.Name) || artifact.SizeBytes < 1 || !sha256Pattern.MatchString(artifact.SHA256) || artifact.Modified.IsZero() || artifact.PacketMembership != nil && artifact.PacketMembership.Validate() != nil || artifact.RewriteManifestID != "" && !capture.ValidPCAPRewriteID(artifact.RewriteManifestID) {
			return errors.New("capture manifest member is invalid")
		}
		if _, duplicate := seen[artifact.Name]; duplicate {
			return errors.New("capture manifest contains duplicate members")
		}
		seen[artifact.Name] = struct{}{}
		if artifact.SizeBytes > int64(capture.MaxSessionBytes)+(1<<30)-total {
			return errors.New("capture manifest exceeds its byte limit")
		}
		total += artifact.SizeBytes
	}
	if total != manifest.TotalSizeBytes {
		return errors.New("capture manifest total does not match its members")
	}
	return nil
}

func openVerifiedArtifact(root, sessionID string, artifact capture.CaptureFile) (*os.File, error) {
	if !capture.ValidSessionID(sessionID) || !safeCaptureName(artifact.Name) {
		return nil, errors.New("capture artifact identity is invalid")
	}
	path := filepath.Join(root, sessionID, "artifacts", artifact.Name)
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), artifact.Name)
	if file == nil {
		unix.Close(descriptor)
		return nil, errors.New("open capture artifact descriptor")
	}
	if err := verifyOpenArtifact(file, artifact); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func verifyOpenArtifact(file *os.File, artifact capture.CaptureFile) error {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != artifact.SizeBytes || !info.ModTime().Equal(artifact.Modified) {
		return errors.New("capture artifact no longer matches its manifest metadata")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != artifact.SHA256 {
		return errors.New("capture artifact hash does not match its manifest")
	}
	_, err = file.Seek(0, io.SeekStart)
	return err
}

func safeCaptureName(name string) bool {
	return name == filepath.Base(name) && !strings.Contains(name, "..") && (name == "capture.pcapng" || strings.HasPrefix(name, "capture_") && strings.HasSuffix(name, ".pcapng"))
}

func safeDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("analyzer path is not a safe directory")
	}
	return nil
}

func prepareDirectory(path string, mode os.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	if err := safeDirectory(path); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}
