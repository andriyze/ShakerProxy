package capture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"shakerproxy.dev/shakerproxy/internal/pcapng"
)

const (
	PCAPRewriteSchema = 1
	PCAPRewriteTool   = "shakerproxy-pcap-rewriter"
)

type PCAPRewriteState string

const (
	PCAPRewriteRunning   PCAPRewriteState = "RUNNING"
	PCAPRewriteVerified  PCAPRewriteState = "VERIFIED"
	PCAPRewriteCompleted PCAPRewriteState = "COMPLETED"
	PCAPRewritePartial   PCAPRewriteState = "PARTIAL"
	PCAPRewriteFailed    PCAPRewriteState = "FAILED"
)

var (
	pcapRewriteIDPattern      = regexp.MustCompile(`^pcap-rewrite-[a-f0-9]{32}$`)
	pcapRewriteFailurePattern = regexp.MustCompile(`^[A-Z0-9_]{1,64}$`)
	pcapRewriteMu             sync.Mutex
)

type PCAPRewriteRequest struct {
	Schema         int                  `json:"schema"`
	ID             string               `json:"id"`
	SessionID      string               `json:"session_id"`
	FileName       string               `json:"file_name"`
	OriginalSHA256 string               `json:"original_sha256"`
	Selection      pcapng.SelectionRule `json:"selection_rule"`
	ToolVersion    string               `json:"tool_version"`
}

type PCAPRewriteRecord struct {
	Schema                   int                  `json:"schema"`
	ID                       string               `json:"id"`
	SessionID                string               `json:"session_id"`
	FileName                 string               `json:"file_name"`
	State                    PCAPRewriteState     `json:"state"`
	OriginalSHA256           string               `json:"original_sha256"`
	OriginalManifestSHA256   string               `json:"original_manifest_sha256"`
	Selection                pcapng.SelectionRule `json:"selection_rule"`
	SelectionSHA256          string               `json:"selection_sha256"`
	Tool                     string               `json:"tool"`
	ToolVersion              string               `json:"tool_version"`
	OutputSHA256             string               `json:"output_sha256,omitempty"`
	OutputManifestSHA256     string               `json:"output_manifest_sha256,omitempty"`
	OutputManifestFileSHA256 string               `json:"output_manifest_file_sha256,omitempty"`
	OriginalBytes            int64                `json:"original_bytes"`
	OutputBytes              int64                `json:"output_bytes"`
	PacketsRead              uint64               `json:"packets_read"`
	PacketsWritten           uint64               `json:"packets_written"`
	PacketsRemoved           uint64               `json:"packets_removed"`
	OutputMembership         *pcapng.Membership   `json:"output_membership,omitempty"`
	ArtifactReplaced         bool                 `json:"artifact_replaced"`
	ReindexRequired          bool                 `json:"reindex_required"`
	IndexInvalidationState   string               `json:"index_invalidation_state"`
	SecureErasureGuaranteed  bool                 `json:"secure_erasure_guaranteed"`
	Failures                 []string             `json:"failures"`
	StartedAt                time.Time            `json:"started_at"`
	CompletedAt              *time.Time           `json:"completed_at,omitempty"`
}

func ValidPCAPRewriteID(id string) bool { return pcapRewriteIDPattern.MatchString(id) }

func (r PCAPRewriteRecord) Validate() error { return validatePCAPRewriteRecord(r) }

func (r PCAPRewriteRequest) Validate() error {
	if r.Schema != PCAPRewriteSchema || !ValidPCAPRewriteID(r.ID) || !ValidSessionID(r.SessionID) || !captureFileName(r.FileName) || strings.ContainsAny(r.FileName, `/\`) || !validSHA256String(r.OriginalSHA256) {
		return errors.New("PCAP rewrite request identity is invalid")
	}
	if err := r.Selection.Validate(); err != nil {
		return err
	}
	return validateText("PCAP rewrite tool version", r.ToolVersion, 1, 64)
}

// RewritePCAP verifies a finalized manifest member, writes and verifies a
// separate replacement, then atomically renames it over the source. A hard-link
// rollback copy keeps the original inode available until the manifest commit.
func (s Store) RewritePCAP(ctx context.Context, request PCAPRewriteRequest, now time.Time) (PCAPRewriteRecord, error) {
	pcapRewriteMu.Lock()
	defer pcapRewriteMu.Unlock()
	if err := request.Validate(); err != nil || now.IsZero() || ctx == nil {
		return PCAPRewriteRecord{}, errors.Join(errors.New("PCAP rewrite request is invalid"), err)
	}
	selectionSHA, err := hashRewriteSelection(request.Selection)
	if err != nil {
		return PCAPRewriteRecord{}, err
	}
	if existing, readErr := s.ReadPCAPRewriteRecord(request.ID); readErr == nil {
		if !rewriteRecordMatchesRequest(existing, request, selectionSHA) {
			return PCAPRewriteRecord{}, errors.New("PCAP rewrite ID is already bound to another request")
		}
		if existing.State == PCAPRewriteCompleted {
			return existing, nil
		}
		return existing, errors.New("PCAP rewrite requires explicit recovery before it can continue")
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return PCAPRewriteRecord{}, readErr
	}
	session, err := s.ReadSession(request.SessionID)
	if err != nil || session.Validate() != nil {
		return PCAPRewriteRecord{}, errors.New("PCAP rewrite session is invalid")
	}
	status, err := s.ReadWorkerStatus(request.SessionID)
	if err != nil || !terminalRewriteState(status.State) {
		return PCAPRewriteRecord{}, errors.New("active or unfinalized capture cannot be rewritten")
	}
	manifest, err := s.ReadManifest(request.SessionID)
	if err != nil {
		return PCAPRewriteRecord{}, errors.New("PCAP rewrite manifest is unavailable")
	}
	_, manifestSHA, err := s.DeletionFootprint(request.SessionID, manifest)
	if err != nil {
		return PCAPRewriteRecord{}, errors.New("PCAP rewrite manifest footprint is invalid")
	}
	selectedIndex := -1
	for index := range manifest.Files {
		if manifest.Files[index].Name == request.FileName {
			selectedIndex = index
			break
		}
	}
	if selectedIndex < 0 || manifest.Files[selectedIndex].SHA256 != request.OriginalSHA256 || manifest.Files[selectedIndex].SizeBytes < 1 {
		return PCAPRewriteRecord{}, errors.New("PCAP rewrite source is not bound to the requested manifest hash")
	}
	record := PCAPRewriteRecord{
		Schema: PCAPRewriteSchema, ID: request.ID, SessionID: request.SessionID, FileName: request.FileName,
		State: PCAPRewriteRunning, OriginalSHA256: request.OriginalSHA256, OriginalManifestSHA256: manifestSHA,
		Selection: request.Selection, SelectionSHA256: selectionSHA, Tool: PCAPRewriteTool, ToolVersion: request.ToolVersion,
		OriginalBytes: manifest.Files[selectedIndex].SizeBytes, IndexInvalidationState: "NOT_REQUIRED", SecureErasureGuaranteed: false,
		Failures: []string{}, StartedAt: now.UTC(),
	}
	if err := s.writePCAPRewriteRecord(record); err != nil {
		return PCAPRewriteRecord{}, err
	}
	available, err := s.AvailableBytes()
	required := uint64(record.OriginalBytes)
	if session.ReserveBytes > ^uint64(0)-required {
		return s.failPCAPRewrite(record, "TEMPORARY_CAPACITY_OVERFLOW", now, errors.New("PCAP rewrite capacity calculation overflowed"))
	}
	required += session.ReserveBytes
	if err != nil || available < required {
		return s.failPCAPRewrite(record, "INSUFFICIENT_TEMPORARY_CAPACITY", now, errors.New("PCAP rewrite requires space for a separate verified replacement plus the capture reserve"))
	}
	artifactDirectory, _ := s.ArtifactDirectory(request.SessionID)
	sourcePath := filepath.Join(artifactDirectory, request.FileName)
	before, err := os.Lstat(sourcePath)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() != record.OriginalBytes || !before.ModTime().Equal(manifest.Files[selectedIndex].Modified) {
		return s.failPCAPRewrite(record, "SOURCE_VALIDATION_FAILED", now, errors.New("PCAP rewrite source no longer matches its manifest"))
	}
	stagingDirectory, err := s.pcapRewriteDirectory(".pcap-rewrite-staging")
	if err != nil {
		return s.failPCAPRewrite(record, "STAGING_DIRECTORY_FAILED", now, err)
	}
	replacementPath := filepath.Join(stagingDirectory, request.ID+".replacement")
	backupPath := filepath.Join(stagingDirectory, request.ID+".original")
	if _, err := os.Lstat(replacementPath); !errors.Is(err, os.ErrNotExist) {
		return s.failPCAPRewrite(record, "STAGING_COLLISION", now, errors.New("PCAP rewrite staging file already exists"))
	}
	replacement, err := os.OpenFile(replacementPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return s.failPCAPRewrite(record, "STAGING_CREATE_FAILED", now, err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		replacement.Close()
		os.Remove(replacementPath)
		return s.failPCAPRewrite(record, "SOURCE_OPEN_FAILED", now, err)
	}
	opened, err := source.Stat()
	if err != nil || !os.SameFile(before, opened) {
		source.Close()
		replacement.Close()
		os.Remove(replacementPath)
		return s.failPCAPRewrite(record, "SOURCE_VALIDATION_FAILED", now, errors.New("PCAP rewrite source changed while it was opened"))
	}
	originalHash := sha256.New()
	outputHash := sha256.New()
	result, rewriteErr := pcapng.RewriteContext(ctx, io.TeeReader(source, originalHash), io.MultiWriter(replacement, outputHash), request.Selection)
	after, statErr := source.Stat()
	closeSourceErr := source.Close()
	syncErr := replacement.Sync()
	closeReplacementErr := replacement.Close()
	if rewriteErr != nil || statErr != nil || closeSourceErr != nil || syncErr != nil || closeReplacementErr != nil {
		os.Remove(replacementPath)
		code := "REWRITE_IO_FAILED"
		if errors.Is(rewriteErr, context.Canceled) || errors.Is(rewriteErr, context.DeadlineExceeded) {
			code = "REWRITE_CANCELLED"
		} else if errors.Is(rewriteErr, pcapng.ErrInexactSelection) || errors.Is(rewriteErr, pcapng.ErrInvalidPCAPNG) {
			code = "REWRITE_NOT_EXACT"
		}
		return s.failPCAPRewrite(record, code, now, errors.Join(rewriteErr, statErr, closeSourceErr, syncErr, closeReplacementErr))
	}
	if !os.SameFile(opened, after) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || result.InputBytes != uint64(before.Size()) || hex.EncodeToString(originalHash.Sum(nil)) != request.OriginalSHA256 {
		os.Remove(replacementPath)
		return s.failPCAPRewrite(record, "SOURCE_CHANGED", now, errors.New("PCAP rewrite source changed or failed hash verification"))
	}
	outputSHA := hex.EncodeToString(outputHash.Sum(nil))
	verifiedMembership, outputInfo, err := verifyPCAPRewriteOutput(replacementPath, outputSHA, result)
	if err != nil {
		os.Remove(replacementPath)
		return s.failPCAPRewrite(record, "OUTPUT_VERIFICATION_FAILED", now, err)
	}
	record.State = PCAPRewriteVerified
	record.OutputSHA256 = outputSHA
	record.OutputBytes = outputInfo.Size()
	record.PacketsRead = result.PacketsRead
	record.PacketsWritten = result.PacketsWritten
	record.PacketsRemoved = result.PacketsRemoved
	record.OutputMembership = &verifiedMembership
	record.ReindexRequired = result.PacketsRemoved > 0
	if record.ReindexRequired {
		record.IndexInvalidationState = "PENDING"
	}
	if err := s.writePCAPRewriteRecord(record); err != nil {
		os.Remove(replacementPath)
		return record, err
	}
	if result.PacketsRemoved == 0 {
		if err := os.Remove(replacementPath); err != nil {
			return s.partialPCAPRewrite(record, "STAGING_CLEANUP_FAILED", now, err)
		}
		completed := now.UTC()
		record.State, record.CompletedAt = PCAPRewriteCompleted, &completed
		if err := s.writePCAPRewriteRecord(record); err != nil {
			return record, err
		}
		return record, nil
	}
	current, err := os.Lstat(sourcePath)
	if err != nil || !os.SameFile(before, current) {
		os.Remove(replacementPath)
		return s.failPCAPRewrite(record, "SOURCE_CHANGED", now, errors.New("PCAP rewrite source path changed before replacement"))
	}
	if err := os.Link(sourcePath, backupPath); err != nil {
		os.Remove(replacementPath)
		return s.failPCAPRewrite(record, "ROLLBACK_LINK_FAILED", now, err)
	}
	backupInfo, err := os.Lstat(backupPath)
	if err != nil || !os.SameFile(before, backupInfo) {
		os.Remove(backupPath)
		os.Remove(replacementPath)
		return s.failPCAPRewrite(record, "SOURCE_CHANGED", now, errors.New("PCAP rewrite rollback link does not identify the verified source"))
	}
	if err := syncDirectory(stagingDirectory); err != nil {
		os.Remove(backupPath)
		os.Remove(replacementPath)
		return s.failPCAPRewrite(record, "ROLLBACK_LINK_FAILED", now, err)
	}
	if err := os.Rename(replacementPath, sourcePath); err != nil {
		os.Remove(backupPath)
		os.Remove(replacementPath)
		return s.failPCAPRewrite(record, "ATOMIC_REPLACEMENT_FAILED", now, err)
	}
	record.ArtifactReplaced = true
	if err := syncDirectory(artifactDirectory); err != nil {
		return s.rollbackPCAPRewrite(record, manifest, sourcePath, backupPath, artifactDirectory, now, err)
	}
	installed, err := os.Lstat(sourcePath)
	if err != nil || !installed.Mode().IsRegular() || installed.Mode()&os.ModeSymlink != 0 || !os.SameFile(outputInfo, installed) || installed.Size() != record.OutputBytes {
		return s.rollbackPCAPRewrite(record, manifest, sourcePath, backupPath, artifactDirectory, now, errors.New("installed PCAP rewrite output is invalid"))
	}
	updatedManifest := manifest
	updatedManifest.Files = append([]CaptureFile(nil), manifest.Files...)
	updatedManifest.TotalSizeBytes = updatedManifest.TotalSizeBytes - updatedManifest.Files[selectedIndex].SizeBytes + record.OutputBytes
	updatedManifest.Files[selectedIndex].SizeBytes = record.OutputBytes
	updatedManifest.Files[selectedIndex].SHA256 = record.OutputSHA256
	updatedManifest.Files[selectedIndex].Modified = installed.ModTime().UTC()
	updatedManifest.Files[selectedIndex].PacketMembership = record.OutputMembership
	updatedManifest.Files[selectedIndex].RewriteManifestID = record.ID
	outputManifestSHA, err := hashJSON(updatedManifest)
	if err != nil {
		return s.rollbackPCAPRewrite(record, manifest, sourcePath, backupPath, artifactDirectory, now, err)
	}
	record.OutputManifestSHA256 = outputManifestSHA
	record.OutputManifestFileSHA256, err = manifestFileSHA256(updatedManifest)
	if err != nil {
		return s.rollbackPCAPRewrite(record, manifest, sourcePath, backupPath, artifactDirectory, now, err)
	}
	if err := s.WriteManifest(updatedManifest); err != nil {
		return s.rollbackPCAPRewrite(record, manifest, sourcePath, backupPath, artifactDirectory, now, err)
	}
	if err := os.Remove(backupPath); err != nil {
		return s.partialPCAPRewrite(record, "ORIGINAL_CLEANUP_FAILED", now, err)
	}
	if err := syncDirectory(stagingDirectory); err != nil {
		return s.partialPCAPRewrite(record, "ORIGINAL_CLEANUP_FAILED", now, err)
	}
	completed := now.UTC()
	record.State, record.CompletedAt = PCAPRewriteCompleted, &completed
	if err := s.writePCAPRewriteRecord(record); err != nil {
		return record, err
	}
	return record, nil
}

// RewritePCAP serializes packet replacement with capture deletion and selection
// previews so a reviewed manifest member cannot be removed or re-described
// while its replacement is being verified and committed.
func (m *Manager) RewritePCAP(ctx context.Context, request PCAPRewriteRequest) (PCAPRewriteRecord, error) {
	m.deletionMu.Lock()
	defer m.deletionMu.Unlock()
	return m.Store.RewritePCAP(ctx, request, m.now())
}

func (s Store) ReadPCAPRewriteRecord(id string) (PCAPRewriteRecord, error) {
	if !ValidPCAPRewriteID(id) {
		return PCAPRewriteRecord{}, errors.New("PCAP rewrite ID is invalid")
	}
	directory, err := s.pcapRewriteDirectory(".pcap-rewrites")
	if err != nil {
		return PCAPRewriteRecord{}, err
	}
	var record PCAPRewriteRecord
	if err := readBoundedJSON(filepath.Join(directory, id+".json"), &record); err != nil {
		return PCAPRewriteRecord{}, err
	}
	if err := validatePCAPRewriteRecord(record); err != nil {
		return PCAPRewriteRecord{}, err
	}
	return record, nil
}

func (s Store) writePCAPRewriteRecord(record PCAPRewriteRecord) error {
	if err := validatePCAPRewriteRecord(record); err != nil {
		return err
	}
	directory, err := s.pcapRewriteDirectory(".pcap-rewrites")
	if err != nil {
		return err
	}
	return writeJSONAtomic(directory, record.ID+".json", record, 0o640)
}

func (s Store) pcapRewriteDirectory(name string) (string, error) {
	if name != ".pcap-rewrites" && name != ".pcap-rewrite-staging" {
		return "", errors.New("PCAP rewrite directory is invalid")
	}
	if err := s.ensureRoot(); err != nil {
		return "", err
	}
	path := filepath.Join(s.Root, name)
	if err := os.Mkdir(path, 0o750); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("PCAP rewrite state directory is unsafe")
	}
	return path, nil
}

func verifyPCAPRewriteOutput(path, expectedSHA string, result pcapng.RewriteResult) (pcapng.Membership, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() != int64(result.OutputBytes) {
		return pcapng.Membership{}, nil, errors.New("PCAP rewrite output file is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return pcapng.Membership{}, nil, err
	}
	hash := sha256.New()
	membership, inspectErr := pcapng.Inspect(io.TeeReader(file, hash))
	_, copyErr := io.Copy(io.Discard, file)
	after, statErr := file.Stat()
	closeErr := file.Close()
	if inspectErr != nil || copyErr != nil || statErr != nil || closeErr != nil {
		return pcapng.Membership{}, nil, errors.Join(inspectErr, copyErr, statErr, closeErr)
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || hex.EncodeToString(hash.Sum(nil)) != expectedSHA || !reflect.DeepEqual(membership, result.OutputMembership) {
		return pcapng.Membership{}, nil, errors.New("PCAP rewrite output failed independent verification")
	}
	return membership, after, nil
}

func (s Store) failPCAPRewrite(record PCAPRewriteRecord, code string, now time.Time, cause error) (PCAPRewriteRecord, error) {
	if !record.ArtifactReplaced {
		record.ReindexRequired = false
		record.IndexInvalidationState = "NOT_REQUIRED"
	}
	completed := now.UTC()
	record.State, record.Failures, record.CompletedAt = PCAPRewriteFailed, []string{code}, &completed
	writeErr := s.writePCAPRewriteRecord(record)
	return record, errors.Join(cause, writeErr)
}

func (s Store) partialPCAPRewrite(record PCAPRewriteRecord, code string, now time.Time, cause error) (PCAPRewriteRecord, error) {
	record.State, record.Failures, record.CompletedAt = PCAPRewritePartial, []string{code}, nil
	writeErr := s.writePCAPRewriteRecord(record)
	return record, errors.Join(cause, writeErr)
}

func (s Store) rollbackPCAPRewrite(record PCAPRewriteRecord, original Manifest, sourcePath, backupPath, artifactDirectory string, now time.Time, cause error) (PCAPRewriteRecord, error) {
	restoreErr := os.Rename(backupPath, sourcePath)
	syncErr := syncDirectory(artifactDirectory)
	manifestErr := s.WriteManifest(original)
	if restoreErr != nil || syncErr != nil || manifestErr != nil {
		return s.partialPCAPRewrite(record, "ROLLBACK_FAILED", now, errors.Join(cause, restoreErr, syncErr, manifestErr))
	}
	record.ArtifactReplaced = false
	return s.failPCAPRewrite(record, "MANIFEST_COMMIT_FAILED", now, cause)
}

func hashRewriteSelection(selection pcapng.SelectionRule) (string, error) {
	encoded, err := json.Marshal(selection)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func rewriteRecordMatchesRequest(record PCAPRewriteRecord, request PCAPRewriteRequest, selectionSHA string) bool {
	return record.ID == request.ID && record.SessionID == request.SessionID && record.FileName == request.FileName && record.OriginalSHA256 == request.OriginalSHA256 && record.SelectionSHA256 == selectionSHA && record.ToolVersion == request.ToolVersion
}

func validatePCAPRewriteRecord(record PCAPRewriteRecord) error {
	if record.Schema != PCAPRewriteSchema || !ValidPCAPRewriteID(record.ID) || !ValidSessionID(record.SessionID) || !captureFileName(record.FileName) || strings.ContainsAny(record.FileName, `/\`) || !validSHA256String(record.OriginalSHA256) || !validSHA256String(record.OriginalManifestSHA256) || record.Tool != PCAPRewriteTool || validateText("PCAP rewrite tool version", record.ToolVersion, 1, 64) != nil || record.OriginalBytes < 1 || record.OutputBytes < 0 || record.StartedAt.IsZero() || record.SecureErasureGuaranteed || record.Failures == nil || len(record.Failures) > 1 || record.IndexInvalidationState != "NOT_REQUIRED" && record.IndexInvalidationState != "PENDING" {
		return errors.New("PCAP rewrite record is invalid")
	}
	if err := record.Selection.Validate(); err != nil {
		return err
	}
	selectionSHA, err := hashRewriteSelection(record.Selection)
	if err != nil || selectionSHA != record.SelectionSHA256 {
		return errors.New("PCAP rewrite selection digest is invalid")
	}
	if record.OutputMembership != nil && record.OutputMembership.Validate() != nil {
		return errors.New("PCAP rewrite output membership is invalid")
	}
	if len(record.Failures) == 1 && !pcapRewriteFailurePattern.MatchString(record.Failures[0]) {
		return errors.New("PCAP rewrite failure code is invalid")
	}
	switch record.State {
	case PCAPRewriteRunning:
		if record.CompletedAt != nil || record.OutputSHA256 != "" || record.OutputManifestSHA256 != "" || record.OutputManifestFileSHA256 != "" || record.OutputBytes != 0 || record.OutputMembership != nil || record.PacketsRead != 0 || record.PacketsWritten != 0 || record.PacketsRemoved != 0 || record.ArtifactReplaced || record.ReindexRequired || record.IndexInvalidationState != "NOT_REQUIRED" || len(record.Failures) != 0 {
			return errors.New("running PCAP rewrite record is inconsistent")
		}
	case PCAPRewriteVerified:
		if record.CompletedAt != nil || !validSHA256String(record.OutputSHA256) || record.OutputManifestSHA256 != "" || record.OutputManifestFileSHA256 != "" || record.OutputBytes < 28 || record.OutputBytes > record.OriginalBytes || record.OutputMembership == nil || record.OutputMembership.PacketCount != record.PacketsWritten || record.PacketsRead != record.PacketsWritten+record.PacketsRemoved || record.ArtifactReplaced || len(record.Failures) != 0 || record.ReindexRequired != (record.PacketsRemoved > 0) || record.IndexInvalidationState != rewriteIndexState(record.PacketsRemoved) {
			return errors.New("verified PCAP rewrite record is inconsistent")
		}
	case PCAPRewriteCompleted:
		if record.CompletedAt == nil || record.CompletedAt.Before(record.StartedAt) || !validSHA256String(record.OutputSHA256) || record.OutputBytes < 28 || record.OutputBytes > record.OriginalBytes || record.OutputMembership == nil || record.OutputMembership.PacketCount != record.PacketsWritten || record.PacketsRead != record.PacketsWritten+record.PacketsRemoved || len(record.Failures) != 0 || record.ArtifactReplaced != (record.PacketsRemoved > 0) || record.ReindexRequired != (record.PacketsRemoved > 0) || record.IndexInvalidationState != rewriteIndexState(record.PacketsRemoved) || record.ArtifactReplaced && (!validSHA256String(record.OutputManifestSHA256) || !validSHA256String(record.OutputManifestFileSHA256)) || !record.ArtifactReplaced && (record.OutputManifestSHA256 != "" || record.OutputManifestFileSHA256 != "" || record.OutputSHA256 != record.OriginalSHA256 || record.OutputBytes != record.OriginalBytes) {
			return errors.New("completed PCAP rewrite record is inconsistent")
		}
	case PCAPRewritePartial:
		if record.CompletedAt != nil || len(record.Failures) != 1 {
			return errors.New("partial PCAP rewrite record is inconsistent")
		}
	case PCAPRewriteFailed:
		if record.CompletedAt == nil || record.CompletedAt.Before(record.StartedAt) || len(record.Failures) != 1 {
			return errors.New("failed PCAP rewrite record is inconsistent")
		}
	default:
		return errors.New("PCAP rewrite state is invalid")
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func terminalRewriteState(state State) bool {
	switch state {
	case StateStopped, StateCompleted, StateFailed, StateStoragePressure:
		return true
	default:
		return false
	}
}

func rewriteIndexState(removed uint64) string {
	if removed > 0 {
		return "PENDING"
	}
	return "NOT_REQUIRED"
}
