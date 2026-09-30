package capture

import (
	"context"
	"errors"
	"sort"
	"time"
)

const (
	RetentionPreviewLifetime = 10 * time.Minute
	// MaxRetentionCandidates bounds how many sessions one retention run may
	// select (or report as lock-blocked); remaining work is picked up by the
	// next run.
	MaxRetentionCandidates = 1024
	// MaxRetentionEvaluatedSessions bounds how many sessions one preview may
	// inspect. It is deliberately larger than the per-run selection bound so a
	// long-lived lab with more than MaxRetentionCandidates captures can still
	// apply retention instead of failing every scheduled run.
	MaxRetentionEvaluatedSessions = 16384
)

type RetentionPolicyInput struct {
	MaxAgeSeconds int64 `json:"max_age_seconds"`
	MaxPCAPBytes  int64 `json:"max_pcap_bytes"`
}

func (p RetentionPolicyInput) Validate() error {
	const tenYears = int64(10 * 365 * 24 * 60 * 60)
	if p.MaxAgeSeconds < 0 || p.MaxAgeSeconds > tenYears || p.MaxPCAPBytes < 0 || p.MaxPCAPBytes > 1<<50 {
		return errors.New("capture retention policy is outside bounded limits")
	}
	if p.MaxAgeSeconds == 0 && p.MaxPCAPBytes == 0 {
		return errors.New("capture retention policy must set an age or PCAP byte limit")
	}
	return nil
}

type RetentionCandidate struct {
	SessionID     string            `json:"session_id"`
	Name          string            `json:"name"`
	FinalizedAt   time.Time         `json:"finalized_at"`
	RetentionLock bool              `json:"retention_lock"`
	Footprint     DeletionFootprint `json:"footprint"`
	Reasons       []string          `json:"reasons"`
}

type RetentionPreview struct {
	Schema                      int                  `json:"schema"`
	PreviewSHA256               string               `json:"preview_sha256"`
	GeneratedAt                 time.Time            `json:"generated_at"`
	ExpiresAt                   time.Time            `json:"expires_at"`
	Policy                      RetentionPolicyInput `json:"policy"`
	EvaluatedSessions           int                  `json:"evaluated_sessions"`
	EvaluatedPCAPBytes          int64                `json:"evaluated_pcap_bytes"`
	ExcludedSessions            int                  `json:"excluded_sessions"`
	ExcludedPCAPBytes           int64                `json:"excluded_pcap_bytes"`
	Selected                    []RetentionCandidate `json:"selected"`
	BlockedByRetentionLock      []RetentionCandidate `json:"blocked_by_retention_lock"`
	DeleteFiles                 int                  `json:"delete_files"`
	ImmediatelyRecoverableBytes int64                `json:"immediately_recoverable_bytes"`
	ProjectedPCAPBytes          int64                `json:"projected_pcap_bytes"`
	PCAPByteTargetMet           bool                 `json:"pcap_byte_target_met"`
	DeletedDataClasses          []string             `json:"deleted_data_classes"`
	RetainedDataClasses         []string             `json:"retained_data_classes"`
	SharedPCAPCollateralKnown   bool                 `json:"shared_pcap_collateral_known"`
}

type retentionPreviewEvidence struct {
	Schema                      int                  `json:"schema"`
	ExpiresAt                   time.Time            `json:"expires_at"`
	Policy                      RetentionPolicyInput `json:"policy"`
	EvaluatedSessions           int                  `json:"evaluated_sessions"`
	EvaluatedPCAPBytes          int64                `json:"evaluated_pcap_bytes"`
	ExcludedSessions            int                  `json:"excluded_sessions"`
	ExcludedPCAPBytes           int64                `json:"excluded_pcap_bytes"`
	Selected                    []RetentionCandidate `json:"selected"`
	BlockedByRetentionLock      []RetentionCandidate `json:"blocked_by_retention_lock"`
	DeleteFiles                 int                  `json:"delete_files"`
	ImmediatelyRecoverableBytes int64                `json:"immediately_recoverable_bytes"`
	ProjectedPCAPBytes          int64                `json:"projected_pcap_bytes"`
	PCAPByteTargetMet           bool                 `json:"pcap_byte_target_met"`
}

func (m *Manager) PreviewRetention(ctx context.Context, policy RetentionPolicyInput) (RetentionPreview, error) {
	return m.previewRetention(ctx, policy, m.now().Add(RetentionPreviewLifetime))
}

func (m *Manager) previewRetention(ctx context.Context, policy RetentionPolicyInput, expiresAt time.Time) (RetentionPreview, error) {
	if err := policy.Validate(); err != nil {
		return RetentionPreview{}, err
	}
	now := m.now()
	expiresAt = expiresAt.UTC()
	if !expiresAt.After(now) || expiresAt.After(now.Add(RetentionPreviewLifetime)) {
		return RetentionPreview{}, errors.New("capture retention preview expiry is invalid")
	}
	views, err := m.List(ctx)
	if err != nil {
		return RetentionPreview{}, err
	}
	if len(views) > MaxRetentionEvaluatedSessions {
		return RetentionPreview{}, errors.New("capture retention candidate limit exceeded")
	}
	candidates := make([]RetentionCandidate, 0, len(views))
	preview := RetentionPreview{
		Schema: 1, GeneratedAt: now, ExpiresAt: expiresAt, Policy: policy,
		Selected: []RetentionCandidate{}, BlockedByRetentionLock: []RetentionCandidate{},
		DeletedDataClasses:  []string{"capture_session_metadata", "pcap_artifacts"},
		RetainedDataClasses: retainedCaptureDeletionClasses(), SharedPCAPCollateralKnown: false,
	}
	for _, view := range views {
		if err := ctx.Err(); err != nil {
			return RetentionPreview{}, err
		}
		if view.Active || view.Manifest == nil || !finalizedCaptureState(view.State) {
			preview.ExcludedSessions++
			preview.ExcludedPCAPBytes += view.CurrentBytes
			continue
		}
		if view.Manifest.CreatedAt.IsZero() || view.Manifest.CreatedAt.After(now) {
			return RetentionPreview{}, errors.New("finalized capture timestamp is invalid")
		}
		footprint, _, err := m.Store.DeletionFootprint(view.Session.ID, *view.Manifest)
		if err != nil {
			return RetentionPreview{}, err
		}
		retentionLock, _, err := m.effectiveRetentionLock(view.Session.ID, view.Session.Request.RetentionLock)
		if err != nil {
			return RetentionPreview{}, err
		}
		candidates = append(candidates, RetentionCandidate{SessionID: view.Session.ID, Name: view.Session.Request.Name, FinalizedAt: view.Manifest.CreatedAt, RetentionLock: retentionLock, Footprint: footprint, Reasons: []string{}})
		preview.EvaluatedSessions++
		preview.EvaluatedPCAPBytes += footprint.CaptureBytes
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].FinalizedAt.Equal(candidates[j].FinalizedAt) {
			return candidates[i].SessionID < candidates[j].SessionID
		}
		return candidates[i].FinalizedAt.Before(candidates[j].FinalizedAt)
	})
	selected := make(map[string]int)
	blocked := make(map[string]int)
	add := func(candidate RetentionCandidate, reason string) {
		if candidate.RetentionLock {
			if index, exists := blocked[candidate.SessionID]; exists {
				preview.BlockedByRetentionLock[index].Reasons = appendReason(preview.BlockedByRetentionLock[index].Reasons, reason)
				return
			}
			if len(preview.BlockedByRetentionLock) >= MaxRetentionCandidates {
				return
			}
			candidate.Reasons = []string{reason}
			blocked[candidate.SessionID] = len(preview.BlockedByRetentionLock)
			preview.BlockedByRetentionLock = append(preview.BlockedByRetentionLock, candidate)
			return
		}
		if index, exists := selected[candidate.SessionID]; exists {
			preview.Selected[index].Reasons = appendReason(preview.Selected[index].Reasons, reason)
			return
		}
		if len(preview.Selected) >= MaxRetentionCandidates {
			// Candidates are visited oldest first; the rest wait for the next
			// run and PCAPByteTargetMet reports that more work remains.
			return
		}
		candidate.Reasons = []string{reason}
		selected[candidate.SessionID] = len(preview.Selected)
		preview.Selected = append(preview.Selected, candidate)
		preview.DeleteFiles += candidate.Footprint.TotalFiles()
		preview.ImmediatelyRecoverableBytes += candidate.Footprint.TotalBytes()
		preview.ProjectedPCAPBytes -= candidate.Footprint.CaptureBytes
	}
	preview.ProjectedPCAPBytes = preview.EvaluatedPCAPBytes
	if policy.MaxAgeSeconds > 0 {
		cutoff := now.Add(-time.Duration(policy.MaxAgeSeconds) * time.Second)
		for _, candidate := range candidates {
			if !candidate.FinalizedAt.After(cutoff) {
				add(candidate, "MAX_AGE")
			}
		}
	}
	if policy.MaxPCAPBytes > 0 && preview.ProjectedPCAPBytes > policy.MaxPCAPBytes {
		for _, candidate := range candidates {
			if preview.ProjectedPCAPBytes <= policy.MaxPCAPBytes {
				break
			}
			if _, exists := selected[candidate.SessionID]; exists {
				continue
			}
			add(candidate, "MAX_PCAP_BYTES")
		}
	}
	preview.PCAPByteTargetMet = policy.MaxPCAPBytes == 0 || preview.ProjectedPCAPBytes <= policy.MaxPCAPBytes
	evidence := retentionPreviewEvidence{
		Schema: preview.Schema, ExpiresAt: preview.ExpiresAt, Policy: preview.Policy,
		EvaluatedSessions: preview.EvaluatedSessions, EvaluatedPCAPBytes: preview.EvaluatedPCAPBytes,
		ExcludedSessions: preview.ExcludedSessions, ExcludedPCAPBytes: preview.ExcludedPCAPBytes,
		Selected: preview.Selected, BlockedByRetentionLock: preview.BlockedByRetentionLock,
		DeleteFiles: preview.DeleteFiles, ImmediatelyRecoverableBytes: preview.ImmediatelyRecoverableBytes,
		ProjectedPCAPBytes: preview.ProjectedPCAPBytes, PCAPByteTargetMet: preview.PCAPByteTargetMet,
	}
	preview.PreviewSHA256, err = hashJSON(evidence)
	return preview, err
}

func finalizedCaptureState(state State) bool {
	return state == StateCompleted || state == StateStopped || state == StateStoragePressure || state == StateFailed
}

func appendReason(reasons []string, reason string) []string {
	for _, existing := range reasons {
		if existing == reason {
			return reasons
		}
	}
	return append(reasons, reason)
}
