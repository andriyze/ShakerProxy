package capture

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"
)

const MaxRetentionPolicyOperations = 1024

type RetentionPolicy struct {
	Schema          int                  `json:"schema"`
	Revision        uint64               `json:"revision"`
	Enabled         bool                 `json:"enabled"`
	Rules           RetentionPolicyInput `json:"rules"`
	RunEverySeconds int64                `json:"run_every_seconds"`
	PreviewSHA256   string               `json:"preview_sha256,omitempty"`
	UpdatedBy       string               `json:"updated_by,omitempty"`
	UpdatedAt       time.Time            `json:"updated_at,omitempty"`
}

type ApplyRetentionPolicyRequest struct {
	ExpectedRevision uint64               `json:"expected_revision"`
	Enabled          bool                 `json:"enabled"`
	Rules            RetentionPolicyInput `json:"rules"`
	RunEverySeconds  int64                `json:"run_every_seconds"`
	PreviewSHA256    string               `json:"preview_sha256"`
	PreviewExpiresAt time.Time            `json:"preview_expires_at"`
	Administrator    string               `json:"administrator"`
	IdempotencyKey   string               `json:"idempotency_key"`
}

type retentionPolicyOperation struct {
	IdempotencyKey string          `json:"idempotency_key"`
	RequestSHA256  string          `json:"request_sha256"`
	Result         RetentionPolicy `json:"result"`
}

type retentionPolicyState struct {
	Schema     int                        `json:"schema"`
	Policy     RetentionPolicy            `json:"policy"`
	Operations []retentionPolicyOperation `json:"operations"`
}

func DefaultRetentionPolicy() RetentionPolicy {
	return RetentionPolicy{Schema: 1, Revision: 0, Enabled: false, Rules: RetentionPolicyInput{MaxAgeSeconds: 7 * 24 * 60 * 60, MaxPCAPBytes: 2 << 30}, RunEverySeconds: 60 * 60}
}

func (m *Manager) GetRetentionPolicy() (RetentionPolicy, error) {
	state, err := m.Store.ReadRetentionPolicyState()
	return state.Policy, err
}

func (m *Manager) ApplyRetentionPolicy(ctx context.Context, request ApplyRetentionPolicyRequest) (RetentionPolicy, error) {
	m.retentionMu.Lock()
	defer m.retentionMu.Unlock()
	if err := validateApplyRetentionPolicyRequest(request); err != nil {
		return RetentionPolicy{}, err
	}
	requestHash, err := hashJSON(request)
	if err != nil {
		return RetentionPolicy{}, err
	}
	state, err := m.Store.ReadRetentionPolicyState()
	if err != nil {
		return RetentionPolicy{}, err
	}
	for _, operation := range state.Operations {
		if operation.IdempotencyKey != request.IdempotencyKey {
			continue
		}
		if operation.RequestSHA256 != requestHash {
			return RetentionPolicy{}, errors.New("capture retention idempotency key conflicts with an existing request")
		}
		return operation.Result, nil
	}
	if len(state.Operations) >= MaxRetentionPolicyOperations {
		return RetentionPolicy{}, errors.New("capture retention policy operation limit exceeded")
	}
	if state.Policy.Revision != request.ExpectedRevision {
		return RetentionPolicy{}, errors.New("capture retention policy revision conflict")
	}
	preview, err := m.previewRetention(ctx, request.Rules, request.PreviewExpiresAt)
	if err != nil {
		return RetentionPolicy{}, err
	}
	if preview.PreviewSHA256 != request.PreviewSHA256 {
		return RetentionPolicy{}, errors.New("capture retention preview is stale")
	}
	policy := RetentionPolicy{Schema: 1, Revision: state.Policy.Revision + 1, Enabled: request.Enabled, Rules: request.Rules, RunEverySeconds: request.RunEverySeconds, PreviewSHA256: request.PreviewSHA256, UpdatedBy: request.Administrator, UpdatedAt: m.now()}
	state.Policy = policy
	state.Operations = append(state.Operations, retentionPolicyOperation{IdempotencyKey: request.IdempotencyKey, RequestSHA256: requestHash, Result: policy})
	if err := m.Store.WriteRetentionPolicyState(state); err != nil {
		return RetentionPolicy{}, err
	}
	return policy, nil
}

func validateApplyRetentionPolicyRequest(request ApplyRetentionPolicyRequest) error {
	if request.Rules.Validate() != nil || request.RunEverySeconds < 300 || request.RunEverySeconds > 86400 || !validSHA256String(request.PreviewSHA256) || !validOpaqueKey(request.IdempotencyKey) || request.PreviewExpiresAt.IsZero() || validateText("administrator", request.Administrator, 1, 96) != nil {
		return errors.New("capture retention policy request is invalid")
	}
	return nil
}

func (s Store) ReadRetentionPolicyState() (retentionPolicyState, error) {
	directory, err := s.retentionDirectory()
	if err != nil {
		return retentionPolicyState{}, err
	}
	state := retentionPolicyState{Schema: 1, Policy: DefaultRetentionPolicy(), Operations: []retentionPolicyOperation{}}
	if err := readBoundedJSON(filepath.Join(directory, "state.json"), &state); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return state, nil
		}
		return retentionPolicyState{}, err
	}
	if err := validateRetentionPolicyState(state); err != nil {
		return retentionPolicyState{}, err
	}
	return state, nil
}

func (s Store) WriteRetentionPolicyState(state retentionPolicyState) error {
	if err := validateRetentionPolicyState(state); err != nil {
		return err
	}
	directory, err := s.retentionDirectory()
	if err != nil {
		return err
	}
	return writeJSONAtomic(directory, "state.json", state, 0o640)
}

func (s Store) retentionDirectory() (string, error) {
	if err := s.ensureRoot(); err != nil {
		return "", err
	}
	directory := filepath.Join(s.Root, ".retention")
	if err := os.Mkdir(directory, 0o750); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("capture retention state directory is unsafe")
	}
	return directory, nil
}

func validateRetentionPolicyState(state retentionPolicyState) error {
	if state.Schema != 1 || validateRetentionPolicy(state.Policy) != nil || len(state.Operations) > MaxRetentionPolicyOperations || uint64(len(state.Operations)) != state.Policy.Revision {
		return errors.New("capture retention policy state is invalid")
	}
	keys := make(map[string]struct{}, len(state.Operations))
	for index, operation := range state.Operations {
		if !validOpaqueKey(operation.IdempotencyKey) || !validSHA256String(operation.RequestSHA256) || validateRetentionPolicy(operation.Result) != nil || operation.Result.Revision != uint64(index+1) {
			return errors.New("capture retention policy operation is invalid")
		}
		if _, duplicate := keys[operation.IdempotencyKey]; duplicate {
			return errors.New("capture retention policy operation is duplicated")
		}
		keys[operation.IdempotencyKey] = struct{}{}
	}
	if len(state.Operations) > 0 && state.Operations[len(state.Operations)-1].Result != state.Policy {
		return errors.New("capture retention policy does not match its operation log")
	}
	return nil
}

func validateRetentionPolicy(policy RetentionPolicy) error {
	if policy.Schema != 1 || policy.Rules.Validate() != nil || policy.RunEverySeconds < 300 || policy.RunEverySeconds > 86400 {
		return errors.New("capture retention policy is invalid")
	}
	if policy.Revision == 0 {
		if policy.Enabled || policy.PreviewSHA256 != "" || policy.UpdatedBy != "" || !policy.UpdatedAt.IsZero() {
			return errors.New("default capture retention policy is invalid")
		}
		return nil
	}
	if !validSHA256String(policy.PreviewSHA256) || validateText("retention policy administrator", policy.UpdatedBy, 1, 96) != nil || policy.UpdatedAt.IsZero() {
		return errors.New("capture retention policy provenance is invalid")
	}
	return nil
}
