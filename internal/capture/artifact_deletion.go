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
	"regexp"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/pcapng"
)

const PCAPArtifactDeletionSchema = 1

type PCAPArtifactDeletionState string

const (
	PCAPArtifactDeletionRunning   PCAPArtifactDeletionState = "RUNNING"
	PCAPArtifactDeletionCompleted PCAPArtifactDeletionState = "COMPLETED"
	PCAPArtifactDeletionPartial   PCAPArtifactDeletionState = "PARTIAL"
	PCAPArtifactDeletionFailed    PCAPArtifactDeletionState = "FAILED"
)

var pcapArtifactDeletionIDPattern = regexp.MustCompile(`^pcap-delete-[a-f0-9]{32}$`)

type PCAPArtifactDeletionRequest struct {
	Schema                    int                  `json:"schema"`
	ID                        string               `json:"id"`
	SessionID                 string               `json:"session_id"`
	FileName                  string               `json:"file_name"`
	OriginalSHA256            string               `json:"original_sha256"`
	Selection                 pcapng.SelectionRule `json:"selection_rule"`
	ExpectedPackets           uint64               `json:"expected_packets"`
	ExpectedMatchedPackets    uint64               `json:"expected_matched_packets"`
	ExpectedCollateralPackets uint64               `json:"expected_collateral_packets"`
}

type PCAPArtifactDeletionRecord struct {
	Schema                    int                       `json:"schema"`
	ID                        string                    `json:"id"`
	SessionID                 string                    `json:"session_id"`
	FileName                  string                    `json:"file_name"`
	State                     PCAPArtifactDeletionState `json:"state"`
	OriginalSHA256            string                    `json:"original_sha256"`
	OriginalManifestSHA256    string                    `json:"original_manifest_sha256"`
	OutputManifestSHA256      string                    `json:"output_manifest_sha256,omitempty"`
	OutputManifestFileSHA256  string                    `json:"output_manifest_file_sha256,omitempty"`
	Selection                 pcapng.SelectionRule      `json:"selection_rule"`
	SelectionSHA256           string                    `json:"selection_sha256"`
	OriginalBytes             int64                     `json:"original_bytes"`
	ExpectedPackets           uint64                    `json:"expected_packets"`
	ExpectedMatchedPackets    uint64                    `json:"expected_matched_packets"`
	ExpectedCollateralPackets uint64                    `json:"expected_collateral_packets"`
	PacketsRead               uint64                    `json:"packets_read"`
	MatchedPacketsRemoved     uint64                    `json:"matched_packets_removed"`
	CollateralPacketsRemoved  uint64                    `json:"collateral_packets_removed"`
	ArtifactRemoved           bool                      `json:"artifact_removed"`
	ReindexRequired           bool                      `json:"reindex_required"`
	IndexInvalidationState    string                    `json:"index_invalidation_state"`
	SecureErasureGuaranteed   bool                      `json:"secure_erasure_guaranteed"`
	Failure                   string                    `json:"failure,omitempty"`
	StartedAt                 time.Time                 `json:"started_at"`
	CompletedAt               *time.Time                `json:"completed_at,omitempty"`
}

func (r PCAPArtifactDeletionRecord) Validate() error {
	return validatePCAPArtifactDeletionRecord(r)
}

func (r PCAPArtifactDeletionRequest) Validate() error {
	if r.Schema != PCAPArtifactDeletionSchema || !pcapArtifactDeletionIDPattern.MatchString(r.ID) || !ValidSessionID(r.SessionID) || !captureFileName(r.FileName) || strings.ContainsAny(r.FileName, `/\`) || !validSHA256String(r.OriginalSHA256) || r.ExpectedPackets == 0 || r.ExpectedMatchedPackets == 0 || r.ExpectedMatchedPackets > r.ExpectedPackets || r.ExpectedCollateralPackets != r.ExpectedPackets-r.ExpectedMatchedPackets {
		return errors.New("PCAP artifact deletion request is invalid")
	}
	return r.Selection.Validate()
}

func (m *Manager) DeletePCAPArtifact(ctx context.Context, request PCAPArtifactDeletionRequest) (PCAPArtifactDeletionRecord, error) {
	m.deletionMu.Lock()
	defer m.deletionMu.Unlock()
	return m.Store.DeletePCAPArtifact(ctx, request, m.now())
}

func (s Store) DeletePCAPArtifact(ctx context.Context, request PCAPArtifactDeletionRequest, now time.Time) (PCAPArtifactDeletionRecord, error) {
	pcapRewriteMu.Lock()
	defer pcapRewriteMu.Unlock()
	if ctx == nil || now.IsZero() || request.Validate() != nil {
		return PCAPArtifactDeletionRecord{}, errors.New("PCAP artifact deletion request is invalid")
	}
	selectionSHA, err := hashRewriteSelection(request.Selection)
	if err != nil {
		return PCAPArtifactDeletionRecord{}, err
	}
	if existing, readErr := s.ReadPCAPArtifactDeletionRecord(request.ID); readErr == nil {
		if !pcapArtifactDeletionMatches(existing, request, selectionSHA) {
			return PCAPArtifactDeletionRecord{}, errors.New("PCAP artifact deletion ID is already bound to another request")
		}
		if existing.State == PCAPArtifactDeletionCompleted {
			return existing, nil
		}
		return existing, errors.New("PCAP artifact deletion requires explicit recovery before it can continue")
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return PCAPArtifactDeletionRecord{}, readErr
	}
	status, err := s.ReadWorkerStatus(request.SessionID)
	if err != nil || !terminalRewriteState(status.State) {
		return PCAPArtifactDeletionRecord{}, errors.New("active or unfinalized capture cannot lose an artifact")
	}
	manifest, err := s.ReadManifest(request.SessionID)
	if err != nil {
		return PCAPArtifactDeletionRecord{}, errors.New("PCAP artifact deletion manifest is unavailable")
	}
	_, manifestSHA, err := s.DeletionFootprint(request.SessionID, manifest)
	if err != nil {
		return PCAPArtifactDeletionRecord{}, errors.New("PCAP artifact deletion manifest footprint is invalid")
	}
	selected := -1
	for index := range manifest.Files {
		if manifest.Files[index].Name == request.FileName {
			selected = index
			break
		}
	}
	if selected < 0 || manifest.Files[selected].SHA256 != request.OriginalSHA256 || manifest.Files[selected].PacketMembership == nil || !manifest.Files[selected].PacketMembership.Exact() || manifest.Files[selected].PacketMembership.PacketCount != request.ExpectedPackets {
		return PCAPArtifactDeletionRecord{}, errors.New("PCAP artifact deletion source is not bound to the reviewed manifest evidence")
	}
	record := PCAPArtifactDeletionRecord{
		Schema: PCAPArtifactDeletionSchema, ID: request.ID, SessionID: request.SessionID, FileName: request.FileName,
		State: PCAPArtifactDeletionRunning, OriginalSHA256: request.OriginalSHA256, OriginalManifestSHA256: manifestSHA,
		Selection: request.Selection, SelectionSHA256: selectionSHA, OriginalBytes: manifest.Files[selected].SizeBytes,
		ExpectedPackets: request.ExpectedPackets, ExpectedMatchedPackets: request.ExpectedMatchedPackets, ExpectedCollateralPackets: request.ExpectedCollateralPackets,
		IndexInvalidationState: "NOT_REQUIRED", StartedAt: now.UTC(),
	}
	if err := s.writePCAPArtifactDeletionRecord(record); err != nil {
		return PCAPArtifactDeletionRecord{}, err
	}
	artifactDirectory, _ := s.ArtifactDirectory(request.SessionID)
	sourcePath := filepath.Join(artifactDirectory, request.FileName)
	before, err := os.Lstat(sourcePath)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() != record.OriginalBytes || !before.ModTime().Equal(manifest.Files[selected].Modified) {
		return s.failPCAPArtifactDeletion(record, "SOURCE_VALIDATION_FAILED", now, errors.New("PCAP artifact no longer matches its manifest"))
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return s.failPCAPArtifactDeletion(record, "SOURCE_OPEN_FAILED", now, err)
	}
	opened, err := source.Stat()
	if err != nil || !os.SameFile(before, opened) {
		source.Close()
		return s.failPCAPArtifactDeletion(record, "SOURCE_VALIDATION_FAILED", now, errors.New("PCAP artifact changed while opening"))
	}
	hash := sha256.New()
	result, inspectErr := pcapng.RewriteContext(ctx, io.TeeReader(source, hash), io.Discard, request.Selection)
	after, statErr := source.Stat()
	closeErr := source.Close()
	if inspectErr != nil || statErr != nil || closeErr != nil {
		return s.failPCAPArtifactDeletion(record, "SELECTION_VERIFICATION_FAILED", now, errors.Join(inspectErr, statErr, closeErr))
	}
	if !os.SameFile(opened, after) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || result.InputBytes != uint64(before.Size()) || hex.EncodeToString(hash.Sum(nil)) != request.OriginalSHA256 || result.PacketsRead != request.ExpectedPackets || result.PacketsRemoved != request.ExpectedMatchedPackets || result.PacketsWritten != request.ExpectedCollateralPackets {
		return s.failPCAPArtifactDeletion(record, "REVIEWED_IMPACT_CHANGED", now, errors.New("PCAP artifact deletion impact no longer matches the reviewed preview"))
	}
	record.PacketsRead = result.PacketsRead
	record.MatchedPacketsRemoved = result.PacketsRemoved
	record.CollateralPacketsRemoved = result.PacketsWritten
	stagingDirectory, err := s.pcapArtifactDeletionDirectory(".pcap-artifact-deletion-staging")
	if err != nil {
		return s.failPCAPArtifactDeletion(record, "STAGING_DIRECTORY_FAILED", now, err)
	}
	backupPath := filepath.Join(stagingDirectory, request.ID+".original")
	if _, err := os.Lstat(backupPath); !errors.Is(err, os.ErrNotExist) {
		return s.failPCAPArtifactDeletion(record, "STAGING_COLLISION", now, errors.New("PCAP artifact deletion staging file already exists"))
	}
	if err := os.Rename(sourcePath, backupPath); err != nil {
		return s.failPCAPArtifactDeletion(record, "ATOMIC_REMOVE_FAILED", now, err)
	}
	record.ArtifactRemoved = true
	record.ReindexRequired = true
	record.IndexInvalidationState = "PENDING"
	if err := syncDirectory(artifactDirectory); err != nil {
		return s.rollbackPCAPArtifactDeletion(record, manifest, sourcePath, backupPath, artifactDirectory, now, err)
	}
	updated := manifest
	updated.Files = append([]CaptureFile(nil), manifest.Files[:selected]...)
	updated.Files = append(updated.Files, manifest.Files[selected+1:]...)
	updated.TotalSizeBytes -= record.OriginalBytes
	manifestBytes, err := json.Marshal(updated)
	if err != nil {
		return s.rollbackPCAPArtifactDeletion(record, manifest, sourcePath, backupPath, artifactDirectory, now, err)
	}
	manifestDigest := sha256.Sum256(manifestBytes)
	record.OutputManifestSHA256 = hex.EncodeToString(manifestDigest[:])
	record.OutputManifestFileSHA256, err = manifestFileSHA256(updated)
	if err != nil {
		return s.rollbackPCAPArtifactDeletion(record, manifest, sourcePath, backupPath, artifactDirectory, now, err)
	}
	if err := s.WriteManifest(updated); err != nil {
		return s.rollbackPCAPArtifactDeletion(record, manifest, sourcePath, backupPath, artifactDirectory, now, err)
	}
	if err := os.Remove(backupPath); err != nil {
		return s.partialPCAPArtifactDeletion(record, "ORIGINAL_CLEANUP_FAILED", err)
	}
	if err := syncDirectory(stagingDirectory); err != nil {
		return s.partialPCAPArtifactDeletion(record, "ORIGINAL_CLEANUP_FAILED", err)
	}
	completed := now.UTC()
	record.State, record.CompletedAt = PCAPArtifactDeletionCompleted, &completed
	if err := s.writePCAPArtifactDeletionRecord(record); err != nil {
		return record, err
	}
	return record, nil
}

func (s Store) ReadPCAPArtifactDeletionRecord(id string) (PCAPArtifactDeletionRecord, error) {
	if !pcapArtifactDeletionIDPattern.MatchString(id) {
		return PCAPArtifactDeletionRecord{}, errors.New("PCAP artifact deletion ID is invalid")
	}
	directory, err := s.pcapArtifactDeletionDirectory(".pcap-artifact-deletions")
	if err != nil {
		return PCAPArtifactDeletionRecord{}, err
	}
	var record PCAPArtifactDeletionRecord
	if err := readBoundedJSON(filepath.Join(directory, id+".json"), &record); err != nil {
		return PCAPArtifactDeletionRecord{}, err
	}
	if err := validatePCAPArtifactDeletionRecord(record); err != nil {
		return PCAPArtifactDeletionRecord{}, err
	}
	return record, nil
}

func (s Store) writePCAPArtifactDeletionRecord(record PCAPArtifactDeletionRecord) error {
	if err := validatePCAPArtifactDeletionRecord(record); err != nil {
		return err
	}
	directory, err := s.pcapArtifactDeletionDirectory(".pcap-artifact-deletions")
	if err != nil {
		return err
	}
	return writeJSONAtomic(directory, record.ID+".json", record, 0o640)
}

func (s Store) pcapArtifactDeletionDirectory(name string) (string, error) {
	if name != ".pcap-artifact-deletions" && name != ".pcap-artifact-deletion-staging" {
		return "", errors.New("PCAP artifact deletion directory is invalid")
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
		return "", errors.New("PCAP artifact deletion state directory is unsafe")
	}
	return path, nil
}

func (s Store) failPCAPArtifactDeletion(record PCAPArtifactDeletionRecord, code string, now time.Time, cause error) (PCAPArtifactDeletionRecord, error) {
	completed := now.UTC()
	record.State, record.Failure, record.CompletedAt = PCAPArtifactDeletionFailed, code, &completed
	writeErr := s.writePCAPArtifactDeletionRecord(record)
	return record, errors.Join(cause, writeErr)
}

func (s Store) partialPCAPArtifactDeletion(record PCAPArtifactDeletionRecord, code string, cause error) (PCAPArtifactDeletionRecord, error) {
	record.State, record.Failure, record.CompletedAt = PCAPArtifactDeletionPartial, code, nil
	writeErr := s.writePCAPArtifactDeletionRecord(record)
	return record, errors.Join(cause, writeErr)
}

func (s Store) rollbackPCAPArtifactDeletion(record PCAPArtifactDeletionRecord, original Manifest, sourcePath, backupPath, artifactDirectory string, now time.Time, cause error) (PCAPArtifactDeletionRecord, error) {
	restoreErr := os.Rename(backupPath, sourcePath)
	syncErr := syncDirectory(artifactDirectory)
	manifestErr := s.WriteManifest(original)
	if restoreErr != nil || syncErr != nil || manifestErr != nil {
		return s.partialPCAPArtifactDeletion(record, "ROLLBACK_FAILED", errors.Join(cause, restoreErr, syncErr, manifestErr))
	}
	record.ArtifactRemoved = false
	record.ReindexRequired = false
	record.IndexInvalidationState = "NOT_REQUIRED"
	record.OutputManifestSHA256 = ""
	record.OutputManifestFileSHA256 = ""
	return s.failPCAPArtifactDeletion(record, "MANIFEST_COMMIT_FAILED", now, cause)
}

func pcapArtifactDeletionMatches(record PCAPArtifactDeletionRecord, request PCAPArtifactDeletionRequest, selectionSHA string) bool {
	return record.ID == request.ID && record.SessionID == request.SessionID && record.FileName == request.FileName && record.OriginalSHA256 == request.OriginalSHA256 && record.SelectionSHA256 == selectionSHA && record.ExpectedPackets == request.ExpectedPackets && record.ExpectedMatchedPackets == request.ExpectedMatchedPackets && record.ExpectedCollateralPackets == request.ExpectedCollateralPackets
}

func validatePCAPArtifactDeletionRecord(record PCAPArtifactDeletionRecord) error {
	if record.Schema != PCAPArtifactDeletionSchema || !pcapArtifactDeletionIDPattern.MatchString(record.ID) || !ValidSessionID(record.SessionID) || !captureFileName(record.FileName) || strings.ContainsAny(record.FileName, `/\`) || !validSHA256String(record.OriginalSHA256) || !validSHA256String(record.OriginalManifestSHA256) || record.OriginalBytes < 28 || record.ExpectedPackets == 0 || record.ExpectedMatchedPackets == 0 || record.ExpectedMatchedPackets > record.ExpectedPackets || record.ExpectedCollateralPackets != record.ExpectedPackets-record.ExpectedMatchedPackets || record.StartedAt.IsZero() || record.SecureErasureGuaranteed || record.Failure != "" && !pcapRewriteFailurePattern.MatchString(record.Failure) || record.IndexInvalidationState != "NOT_REQUIRED" && record.IndexInvalidationState != "PENDING" {
		return errors.New("PCAP artifact deletion record is invalid")
	}
	if record.Selection.Validate() != nil {
		return errors.New("PCAP artifact deletion selection is invalid")
	}
	selectionSHA, err := hashRewriteSelection(record.Selection)
	if err != nil || selectionSHA != record.SelectionSHA256 {
		return errors.New("PCAP artifact deletion selection digest is invalid")
	}
	switch record.State {
	case PCAPArtifactDeletionRunning:
		if record.CompletedAt != nil || record.OutputManifestSHA256 != "" || record.OutputManifestFileSHA256 != "" || record.PacketsRead != 0 || record.MatchedPacketsRemoved != 0 || record.CollateralPacketsRemoved != 0 || record.ArtifactRemoved || record.ReindexRequired || record.IndexInvalidationState != "NOT_REQUIRED" || record.Failure != "" {
			return errors.New("running PCAP artifact deletion record is inconsistent")
		}
	case PCAPArtifactDeletionCompleted:
		if record.CompletedAt == nil || record.CompletedAt.Before(record.StartedAt) || !validSHA256String(record.OutputManifestSHA256) || !validSHA256String(record.OutputManifestFileSHA256) || record.PacketsRead == 0 || record.MatchedPacketsRemoved == 0 || record.PacketsRead != record.MatchedPacketsRemoved+record.CollateralPacketsRemoved || !record.ArtifactRemoved || !record.ReindexRequired || record.IndexInvalidationState != "PENDING" || record.Failure != "" {
			return errors.New("completed PCAP artifact deletion record is inconsistent")
		}
	case PCAPArtifactDeletionPartial:
		if record.CompletedAt != nil || !record.ArtifactRemoved || !record.ReindexRequired || record.IndexInvalidationState != "PENDING" || record.Failure == "" {
			return errors.New("partial PCAP artifact deletion record is inconsistent")
		}
	case PCAPArtifactDeletionFailed:
		if record.CompletedAt == nil || record.CompletedAt.Before(record.StartedAt) || record.ArtifactRemoved || record.ReindexRequired || record.IndexInvalidationState != "NOT_REQUIRED" || record.Failure == "" {
			return errors.New("failed PCAP artifact deletion record is inconsistent")
		}
	default:
		return errors.New("PCAP artifact deletion state is invalid")
	}
	return nil
}
