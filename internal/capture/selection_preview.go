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
	"sort"
	"time"

	"shakerproxy.dev/shakerproxy/internal/pcapng"
)

const (
	MaxSelectionPreviewSessions = 1024
	MaxSelectionPreviewFiles    = 512
	MaxCollateralIdentitySample = 8
)

var selectionBlockerCodePattern = regexp.MustCompile(`^[A-Z0-9_]{1,64}$`)

type SharedPCAPDisposition string

const (
	DeleteMetadataOnly       SharedPCAPDisposition = "DELETE_METADATA_ONLY"
	DeleteDerivedContentOnly SharedPCAPDisposition = "DELETE_DERIVED_CONTENT_ONLY"
	DeleteWholeCaptureFiles  SharedPCAPDisposition = "DELETE_WHOLE_CAPTURE_FILES"
	SanitizeAndRewritePCAP   SharedPCAPDisposition = "SANITIZE_AND_REWRITE_PCAP"
)

type PCAPSelectionFileImpact struct {
	SessionID                      string   `json:"session_id"`
	CaseID                         string   `json:"case_id,omitempty"`
	FileName                       string   `json:"file_name"`
	OriginalSHA256                 string   `json:"original_sha256"`
	OriginalBytes                  int64    `json:"original_bytes"`
	SanitizedBytes                 int64    `json:"sanitized_bytes"`
	PacketsRead                    uint64   `json:"packets_read"`
	MatchedPackets                 uint64   `json:"matched_packets"`
	CollateralPacketsInWholeDelete uint64   `json:"collateral_packets_in_whole_delete"`
	RetainedMACAddresses           int      `json:"retained_mac_addresses"`
	RetainedIPAddresses            int      `json:"retained_ip_addresses"`
	RetainedIdentitySHA256         string   `json:"retained_identity_sha256"`
	RetainedMACSample              []string `json:"retained_mac_sample"`
	RetainedIPSample               []string `json:"retained_ip_sample"`
	RetentionLocked                bool     `json:"retention_locked"`
	TemporaryBytesRequired         uint64   `json:"temporary_bytes_required"`
	TemporaryCapacityAvailable     bool     `json:"temporary_capacity_available"`
}

type PCAPSelectionBlocker struct {
	SessionID string `json:"session_id"`
	FileName  string `json:"file_name,omitempty"`
	Code      string `json:"code"`
	Reason    string `json:"reason"`
}

type PCAPSelectionImpact struct {
	Schema                  int                       `json:"schema"`
	Selection               pcapng.SelectionRule      `json:"selection_rule"`
	SelectionSHA256         string                    `json:"selection_sha256"`
	GeneratedAt             time.Time                 `json:"generated_at"`
	EvaluatedSessions       int                       `json:"evaluated_sessions"`
	EvaluatedFiles          int                       `json:"evaluated_files"`
	ScannedBytes            int64                     `json:"scanned_bytes"`
	AvailableBytes          uint64                    `json:"available_bytes"`
	ImpactedFiles           []PCAPSelectionFileImpact `json:"impacted_files"`
	Blockers                []PCAPSelectionBlocker    `json:"blockers"`
	Exact                   bool                      `json:"exact"`
	SecureErasureGuaranteed bool                      `json:"secure_erasure_guaranteed"`
}

func (p PCAPSelectionImpact) Validate() error {
	selectionSHA, err := hashRewriteSelection(p.Selection)
	if p.Schema != 1 || err != nil || p.Selection.Validate() != nil || p.SelectionSHA256 != selectionSHA || p.GeneratedAt.IsZero() || p.EvaluatedSessions < 0 || p.EvaluatedSessions > MaxSelectionPreviewSessions || p.EvaluatedFiles < 0 || p.EvaluatedFiles > MaxSelectionPreviewSessions*maxCaptureFiles || p.ScannedBytes < 0 || len(p.ImpactedFiles) > MaxSelectionPreviewFiles || len(p.Blockers) > MaxSelectionPreviewFiles || p.SecureErasureGuaranteed || p.Exact != (len(p.Blockers) == 0) {
		return errors.New("PCAP selection impact is invalid")
	}
	seen := make(map[string]struct{}, len(p.ImpactedFiles))
	var minimumScanned int64
	var matchedPackets uint64
	var collateralPackets uint64
	for index, impact := range p.ImpactedFiles {
		key := impact.SessionID + "\x00" + impact.FileName
		expectedCapacity := impact.TemporaryBytesRequired != ^uint64(0) && p.AvailableBytes >= impact.TemporaryBytesRequired
		if !ValidSessionID(impact.SessionID) || validateText("case ID", impact.CaseID, 0, 96) != nil || !captureFileName(impact.FileName) || stringsContainsPathSeparator(impact.FileName) || !validSHA256String(impact.OriginalSHA256) || impact.OriginalBytes < 28 || impact.SanitizedBytes < 28 || impact.SanitizedBytes > impact.OriginalBytes || impact.PacketsRead == 0 || impact.MatchedPackets == 0 || impact.MatchedPackets > impact.PacketsRead || impact.CollateralPacketsInWholeDelete != impact.PacketsRead-impact.MatchedPackets || impact.RetainedMACAddresses < 0 || impact.RetainedIPAddresses < 0 || impact.RetainedMACAddresses+impact.RetainedIPAddresses > pcapng.MaxObservedIdentities || !validSHA256String(impact.RetainedIdentitySHA256) || len(impact.RetainedMACSample) > MaxCollateralIdentitySample || len(impact.RetainedIPSample) > MaxCollateralIdentitySample || len(impact.RetainedMACSample) > impact.RetainedMACAddresses || len(impact.RetainedIPSample) > impact.RetainedIPAddresses || !sortedUniquePreviewSample(impact.RetainedMACSample) || !sortedUniquePreviewSample(impact.RetainedIPSample) || impact.TemporaryBytesRequired < uint64(impact.OriginalBytes) || impact.TemporaryCapacityAvailable != expectedCapacity || impact.MatchedPackets > ^uint64(0)-matchedPackets || impact.CollateralPacketsInWholeDelete > ^uint64(0)-collateralPackets {
			return errors.New("PCAP selection file impact is invalid")
		}
		matchedPackets += impact.MatchedPackets
		collateralPackets += impact.CollateralPacketsInWholeDelete
		if _, duplicate := seen[key]; duplicate {
			return errors.New("PCAP selection impact contains duplicate files")
		}
		seen[key] = struct{}{}
		if index > 0 {
			previous := p.ImpactedFiles[index-1]
			if impact.SessionID < previous.SessionID || impact.SessionID == previous.SessionID && impact.FileName <= previous.FileName {
				return errors.New("PCAP selection impacts are not sorted")
			}
		}
		if impact.OriginalBytes > int64(^uint64(0)>>1)-minimumScanned {
			return errors.New("PCAP selection scan bytes overflow")
		}
		minimumScanned += impact.OriginalBytes
	}
	if p.ScannedBytes < minimumScanned {
		return errors.New("PCAP selection scanned-byte count is incomplete")
	}
	for _, blocker := range p.Blockers {
		if !ValidSessionID(blocker.SessionID) || blocker.FileName != "" && (!captureFileName(blocker.FileName) || stringsContainsPathSeparator(blocker.FileName)) || !selectionBlockerCodePattern.MatchString(blocker.Code) || blocker.Reason == "" || len(blocker.Reason) > 256 {
			return errors.New("PCAP selection blocker is invalid")
		}
	}
	return nil
}

// PreviewPCAPSelection computes an exact packet/file impact without creating a
// replacement. Active captures and legacy/inexact membership evidence are
// explicit blockers rather than silently omitted populations.
func (s Store) PreviewPCAPSelection(ctx context.Context, selection pcapng.SelectionRule, now time.Time) (PCAPSelectionImpact, error) {
	if ctx == nil || selection.Validate() != nil || now.IsZero() {
		return PCAPSelectionImpact{}, errors.New("PCAP selection preview input is invalid")
	}
	selectionSHA, err := hashRewriteSelection(selection)
	if err != nil {
		return PCAPSelectionImpact{}, err
	}
	preview := PCAPSelectionImpact{Schema: 1, Selection: selection, SelectionSHA256: selectionSHA, GeneratedAt: now.UTC(), ImpactedFiles: []PCAPSelectionFileImpact{}, Blockers: []PCAPSelectionBlocker{}, SecureErasureGuaranteed: false}
	preview.AvailableBytes, err = s.AvailableBytes()
	if err != nil {
		return PCAPSelectionImpact{}, err
	}
	sessionIDs, err := s.ListSessionIDs()
	if err != nil {
		return PCAPSelectionImpact{}, err
	}
	if len(sessionIDs) > MaxSelectionPreviewSessions {
		return PCAPSelectionImpact{}, errors.New("PCAP selection preview session limit exceeded")
	}
	for _, sessionID := range sessionIDs {
		if err := ctx.Err(); err != nil {
			return PCAPSelectionImpact{}, err
		}
		session, err := s.ReadSession(sessionID)
		if err != nil {
			return PCAPSelectionImpact{}, err
		}
		status, err := s.ReadWorkerStatus(sessionID)
		if err != nil {
			return PCAPSelectionImpact{}, err
		}
		terminal := terminalRewriteState(status.State)
		endedAt := status.EndedAt
		if endedAt.IsZero() {
			endedAt = session.StopAt
		}
		if !terminal && now.After(endedAt) {
			endedAt = now
		}
		if !selection.Overlaps(session.StartedAt.UTC(), endedAt.UTC()) {
			continue
		}
		preview.EvaluatedSessions++
		if !terminal {
			if err := addSelectionBlocker(&preview, PCAPSelectionBlocker{SessionID: sessionID, Code: "ACTIVE_CAPTURE", Reason: "active capture files are not deletion-eligible"}); err != nil {
				return PCAPSelectionImpact{}, err
			}
			continue
		}
		manifest, err := s.ReadManifest(sessionID)
		if err != nil {
			if err := addSelectionBlocker(&preview, PCAPSelectionBlocker{SessionID: sessionID, Code: "MANIFEST_UNAVAILABLE", Reason: "final capture manifest is unavailable"}); err != nil {
				return PCAPSelectionImpact{}, err
			}
			continue
		}
		if _, _, err := s.DeletionFootprint(sessionID, manifest); err != nil {
			if err := addSelectionBlocker(&preview, PCAPSelectionBlocker{SessionID: sessionID, Code: "MANIFEST_INVALID", Reason: "capture artifacts do not match the final manifest"}); err != nil {
				return PCAPSelectionImpact{}, err
			}
			continue
		}
		retentionLock, _, err := (&Manager{Store: s}).effectiveRetentionLock(sessionID, session.Request.RetentionLock)
		if err != nil {
			return PCAPSelectionImpact{}, err
		}
		for _, artifact := range manifest.Files {
			preview.EvaluatedFiles++
			if artifact.PacketMembership == nil || !artifact.PacketMembership.Exact() {
				if err := addSelectionBlocker(&preview, PCAPSelectionBlocker{SessionID: sessionID, FileName: artifact.Name, Code: "MEMBERSHIP_NOT_EXACT", Reason: "packet membership was not indexed exactly for this capture file"}); err != nil {
					return PCAPSelectionImpact{}, err
				}
				continue
			}
			if !selection.MayMatch(*artifact.PacketMembership) {
				continue
			}
			result, err := s.previewSelectionFile(ctx, sessionID, artifact, selection)
			if err != nil {
				if err := addSelectionBlocker(&preview, PCAPSelectionBlocker{SessionID: sessionID, FileName: artifact.Name, Code: "PACKET_SELECTION_NOT_EXACT", Reason: "packet timestamps or headers cannot support an exact selection"}); err != nil {
					return PCAPSelectionImpact{}, err
				}
				continue
			}
			preview.ScannedBytes += artifact.SizeBytes
			if result.PacketsRemoved == 0 {
				continue
			}
			if len(preview.ImpactedFiles) >= MaxSelectionPreviewFiles {
				return PCAPSelectionImpact{}, errors.New("PCAP selection preview impacted-file limit exceeded")
			}
			identitySHA, err := hashMembershipIdentities(result.OutputMembership)
			if err != nil {
				return PCAPSelectionImpact{}, err
			}
			required, capacityAvailable := rewriteTemporaryCapacity(artifact.SizeBytes, session.ReserveBytes, preview.AvailableBytes)
			preview.ImpactedFiles = append(preview.ImpactedFiles, PCAPSelectionFileImpact{
				SessionID: sessionID, CaseID: session.Request.CaseID, FileName: artifact.Name, OriginalSHA256: artifact.SHA256,
				OriginalBytes: artifact.SizeBytes, SanitizedBytes: int64(result.OutputBytes), PacketsRead: result.PacketsRead,
				MatchedPackets: result.PacketsRemoved, CollateralPacketsInWholeDelete: result.PacketsWritten,
				RetainedMACAddresses: len(result.OutputMembership.MACAddresses), RetainedIPAddresses: len(result.OutputMembership.IPAddresses),
				RetainedIdentitySHA256: identitySHA, RetainedMACSample: sampleStrings(result.OutputMembership.MACAddresses),
				RetainedIPSample: sampleStrings(result.OutputMembership.IPAddresses), RetentionLocked: retentionLock,
				TemporaryBytesRequired: required, TemporaryCapacityAvailable: capacityAvailable,
			})
		}
	}
	sort.Slice(preview.ImpactedFiles, func(i, j int) bool {
		if preview.ImpactedFiles[i].SessionID != preview.ImpactedFiles[j].SessionID {
			return preview.ImpactedFiles[i].SessionID < preview.ImpactedFiles[j].SessionID
		}
		return preview.ImpactedFiles[i].FileName < preview.ImpactedFiles[j].FileName
	})
	preview.Exact = len(preview.Blockers) == 0
	if err := preview.Validate(); err != nil {
		return PCAPSelectionImpact{}, err
	}
	return preview, nil
}

func (s Store) previewSelectionFile(ctx context.Context, sessionID string, artifact CaptureFile, selection pcapng.SelectionRule) (pcapng.RewriteResult, error) {
	directory, err := s.ArtifactDirectory(sessionID)
	if err != nil {
		return pcapng.RewriteResult{}, err
	}
	path := filepath.Join(directory, artifact.Name)
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() != artifact.SizeBytes || !before.ModTime().Equal(artifact.Modified) {
		return pcapng.RewriteResult{}, errors.New("capture artifact does not match its manifest")
	}
	file, err := os.Open(path)
	if err != nil {
		return pcapng.RewriteResult{}, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		file.Close()
		return pcapng.RewriteResult{}, errors.New("capture artifact changed while opening")
	}
	hash := sha256.New()
	result, rewriteErr := pcapng.RewriteContext(ctx, io.TeeReader(file, hash), io.Discard, selection)
	after, statErr := file.Stat()
	closeErr := file.Close()
	if rewriteErr != nil || statErr != nil || closeErr != nil {
		return pcapng.RewriteResult{}, errors.Join(rewriteErr, statErr, closeErr)
	}
	if !os.SameFile(opened, after) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || result.InputBytes != uint64(before.Size()) || hex.EncodeToString(hash.Sum(nil)) != artifact.SHA256 || artifact.PacketMembership == nil || artifact.PacketMembership.PacketCount != result.PacketsRead {
		return pcapng.RewriteResult{}, errors.New("capture artifact changed or packet count disagrees with its manifest")
	}
	return result, nil
}

func addSelectionBlocker(preview *PCAPSelectionImpact, blocker PCAPSelectionBlocker) error {
	if len(preview.Blockers) >= MaxSelectionPreviewFiles {
		return errors.New("PCAP selection preview blocker limit exceeded")
	}
	preview.Blockers = append(preview.Blockers, blocker)
	return nil
}

func hashMembershipIdentities(membership pcapng.Membership) (string, error) {
	encoded, err := json.Marshal(struct {
		MACAddresses []string `json:"mac_addresses"`
		IPAddresses  []string `json:"ip_addresses"`
	}{membership.MACAddresses, membership.IPAddresses})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func sampleStrings(values []string) []string {
	if len(values) > MaxCollateralIdentitySample {
		values = values[:MaxCollateralIdentitySample]
	}
	return append([]string{}, values...)
}

func rewriteTemporaryCapacity(originalBytes int64, reserveBytes, availableBytes uint64) (uint64, bool) {
	if originalBytes < 0 || uint64(originalBytes) > ^uint64(0)-reserveBytes {
		return ^uint64(0), false
	}
	required := uint64(originalBytes) + reserveBytes
	return required, availableBytes >= required
}

func sortedUniquePreviewSample(values []string) bool {
	for index, value := range values {
		if value == "" || index > 0 && value <= values[index-1] {
			return false
		}
	}
	return true
}

func stringsContainsPathSeparator(value string) bool {
	for _, character := range value {
		if character == '/' || character == '\\' {
			return true
		}
	}
	return false
}

func (m *Manager) PreviewPCAPSelection(ctx context.Context, selection pcapng.SelectionRule) (PCAPSelectionImpact, error) {
	m.deletionMu.Lock()
	defer m.deletionMu.Unlock()
	return m.Store.PreviewPCAPSelection(ctx, selection, m.now())
}
