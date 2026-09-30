package daemon

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

type persistedState struct {
	OperatingMode     string                  `json:"operating_mode"`
	EmergencyBypass   bool                    `json:"emergency_bypass"`
	StagedNetworkPlan *networkplan.StagedPlan `json:"staged_network_plan,omitempty"`
	// ConfirmedNetworkPlan is the last plan whose transaction was confirmed.
	// Staging (and discarding) a candidate replaces StagedNetworkPlan, which
	// must never make the gateway forget the plan the host is still running.
	ConfirmedNetworkPlan *networkplan.StagedPlan `json:"confirmed_network_plan,omitempty"`
}

// activeNetworkPlan is the plan the host is running: the staged plan once it
// is confirmed, otherwise the last confirmed plan. While a candidate
// transaction is changing the host, or after its rollback failed, no plan
// can be vouched for.
func (p persistedState) activeNetworkPlan() *networkplan.StagedPlan {
	if staged := p.StagedNetworkPlan; staged != nil && staged.Transaction != nil {
		switch staged.Transaction.Phase {
		case networktransaction.PhaseConfirmed:
			return staged
		case networktransaction.PhasePreparing, networktransaction.PhaseRolledBack:
		default:
			return nil
		}
	}
	return p.ConfirmedNetworkPlan
}

type StateStore struct {
	path  string
	mu    sync.RWMutex
	state persistedState
}

func OpenStateStore(path string) (*StateStore, error) {
	s := &StateStore{path: path, state: persistedState{OperatingMode: gatewayprotocol.ModeSetupSafe}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	if err := json.Unmarshal(b, &s.state); err != nil {
		return nil, fmt.Errorf("decode state: %w", err)
	}
	if s.state.OperatingMode != gatewayprotocol.ModeSetupSafe && s.state.OperatingMode != gatewayprotocol.ModeRouted && s.state.OperatingMode != gatewayprotocol.ModeEmergency {
		return nil, fmt.Errorf("unsafe or unknown persisted operating mode %q", s.state.OperatingMode)
	}
	if staged := s.state.StagedNetworkPlan; staged != nil && staged.Transaction != nil {
		if staged.ApplyID != staged.Transaction.ApplyID || staged.PlanHash != staged.Transaction.PlanHash {
			return nil, errors.New("persisted network transaction identity does not match its staged plan")
		}
		if staged.Status != string(staged.Transaction.Phase) {
			return nil, errors.New("persisted network transaction status does not match its phase")
		}
		if err := staged.Transaction.Validate(); err != nil {
			return nil, fmt.Errorf("validate persisted network transaction: %w", err)
		}
	}
	return s, nil
}

func (s *StateStore) Get() persistedState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

func (s *StateStore) Set(mode string, bypass bool) error {
	if mode != gatewayprotocol.ModeSetupSafe && mode != gatewayprotocol.ModeEmergency {
		return fmt.Errorf("mode %q is unavailable in this build", mode)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.state
	next.OperatingMode = mode
	next.EmergencyBypass = bypass
	return s.persistLocked(next)
}

func (s *StateStore) SetEmergencyBypass(enabled bool) (persistedState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.state
	if enabled {
		next.OperatingMode = gatewayprotocol.ModeEmergency
		next.EmergencyBypass = true
	} else {
		if staged := next.StagedNetworkPlan; staged != nil && staged.Transaction != nil && staged.Transaction.Phase == networktransaction.PhaseRollbackFailed {
			return s.state, errors.New("emergency bypass cannot be disabled while rollback is failed")
		}
		next.OperatingMode = gatewayprotocol.ModeSetupSafe
		if next.activeNetworkPlan() != nil {
			next.OperatingMode = gatewayprotocol.ModeRouted
		}
		next.EmergencyBypass = false
	}
	if err := s.persistLocked(next); err != nil {
		return s.state, err
	}
	return next, nil
}

func (s *StateStore) StageNetworkPlan(plan networkplan.Plan, preview networkplan.Preview, idempotencyKey string, now time.Time, ttl time.Duration) (networkplan.StagedPlan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current := s.state.StagedNetworkPlan; current != nil {
		if current.IdempotencyKey == idempotencyKey && current.PlanHash == preview.Validation.PlanHash {
			return *current, nil
		}
		if current.Transaction != nil && !current.Transaction.Terminal() {
			return networkplan.StagedPlan{}, errors.New("an active network transaction prevents replacement")
		}
		// Only a plan that has not started applying is protected until it
		// expires; a finished (confirmed or rolled back) one never blocks a
		// retry.
		if current.Transaction == nil && now.Before(current.ExpiresAt) {
			return networkplan.StagedPlan{}, errors.New("another unexpired network plan is already staged")
		}
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return networkplan.StagedPlan{}, err
	}
	staged := networkplan.StagedPlan{ApplyID: fmt.Sprintf("apply-%x", idBytes), IdempotencyKey: idempotencyKey, PlanHash: preview.Validation.PlanHash, Plan: plan, Preview: preview, StagedAt: now.UTC(), ExpiresAt: now.Add(ttl).UTC(), Status: "STAGED_NOT_APPLIED"}
	next := s.state
	next.ConfirmedNetworkPlan = next.activeNetworkPlan()
	next.StagedNetworkPlan = &staged
	if err := s.persistLocked(next); err != nil {
		return networkplan.StagedPlan{}, err
	}
	return staged, nil
}

func (s *StateStore) RollbackStagedNetworkPlan(applyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.StagedNetworkPlan == nil {
		return errors.New("no network plan is staged")
	}
	if s.state.StagedNetworkPlan.ApplyID != applyID {
		return errors.New("apply ID does not match the staged plan")
	}
	if transaction := s.state.StagedNetworkPlan.Transaction; transaction != nil && transaction.Phase != networktransaction.PhasePreparing {
		return errors.New("a guarded network transaction cannot be discarded through pre-apply rollback")
	}
	next := s.state
	next.StagedNetworkPlan = nil
	return s.persistLocked(next)
}

// RevertNetworkPlan records that the running plan was undone and the host
// network restored as it was before it: the gateway is back in setup mode.
func (s *StateStore) RevertNetworkPlan(applyID string) (persistedState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if active := s.state.activeNetworkPlan(); active != nil && active.ApplyID != applyID {
		return s.state, errors.New("the running network plan changed during revert")
	}
	next := s.state
	next.ConfirmedNetworkPlan = nil
	if next.StagedNetworkPlan != nil && next.StagedNetworkPlan.ApplyID == applyID {
		next.StagedNetworkPlan = nil
	}
	next.OperatingMode = gatewayprotocol.ModeSetupSafe
	next.EmergencyBypass = false
	if err := s.persistLocked(next); err != nil {
		return s.state, err
	}
	return next, nil
}

func (s *StateStore) BeginNetworkTransaction(applyID string, now time.Time) (networkplan.StagedPlan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	staged, err := s.stagedForUpdateLocked(applyID)
	if err != nil {
		return networkplan.StagedPlan{}, err
	}
	if staged.Transaction != nil {
		if staged.Transaction.Phase == networktransaction.PhasePreparing {
			return staged, nil
		}
		return networkplan.StagedPlan{}, errors.New("network transaction has already started")
	}
	record, err := networktransaction.New(staged.ApplyID, staged.PlanHash, now)
	if err != nil {
		return networkplan.StagedPlan{}, err
	}
	return s.persistTransactionLocked(staged, record)
}

func (s *StateStore) ArmNetworkWatchdog(applyID string, now time.Time, window time.Duration) (networkplan.StagedPlan, error) {
	return s.transitionNetworkTransaction(applyID, func(record networktransaction.Record) (networktransaction.Record, error) {
		return record.ArmWatchdog(now, window)
	})
}

func (s *StateStore) BeginNetworkHostApply(applyID string, now time.Time) (networkplan.StagedPlan, error) {
	return s.transitionNetworkTransaction(applyID, func(record networktransaction.Record) (networktransaction.Record, error) {
		return record.BeginApply(now)
	})
}

func (s *StateStore) MarkNetworkApplied(applyID string, now time.Time) (networkplan.StagedPlan, error) {
	return s.transitionNetworkTransaction(applyID, func(record networktransaction.Record) (networktransaction.Record, error) {
		return record.MarkApplied(now)
	})
}

func (s *StateStore) RecordNetworkHealth(applyID string, report networktransaction.HealthReport) (networkplan.StagedPlan, error) {
	return s.transitionNetworkTransaction(applyID, func(record networktransaction.Record) (networktransaction.Record, error) {
		return record.RecordHealth(report)
	})
}

func (s *StateStore) ConfirmNetworkTransaction(applyID string, now time.Time) (networkplan.StagedPlan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	staged, err := s.stagedForUpdateLocked(applyID)
	if err != nil {
		return networkplan.StagedPlan{}, err
	}
	if staged.Transaction == nil {
		return networkplan.StagedPlan{}, errors.New("network transaction has not started")
	}
	if err := staged.Transaction.Validate(); err != nil {
		return networkplan.StagedPlan{}, fmt.Errorf("validate network transaction: %w", err)
	}
	record, err := staged.Transaction.Confirm(now)
	if err != nil {
		return networkplan.StagedPlan{}, err
	}
	if err := record.Validate(); err != nil {
		return networkplan.StagedPlan{}, fmt.Errorf("validate network transaction: %w", err)
	}
	staged.Transaction = &record
	staged.Status = string(record.Phase)
	next := s.state
	next.StagedNetworkPlan = &staged
	confirmed := staged
	next.ConfirmedNetworkPlan = &confirmed
	next.OperatingMode = gatewayprotocol.ModeRouted
	next.EmergencyBypass = false
	if err := s.persistLocked(next); err != nil {
		return networkplan.StagedPlan{}, err
	}
	return staged, nil
}

func (s *StateStore) RequireNetworkRollback(applyID, reason string) (networkplan.StagedPlan, error) {
	return s.transitionNetworkTransaction(applyID, func(record networktransaction.Record) (networktransaction.Record, error) {
		return record.RequireRollback(reason)
	})
}

func (s *StateStore) BeginNetworkRollback(applyID string, now time.Time) (networkplan.StagedPlan, error) {
	return s.transitionNetworkTransaction(applyID, func(record networktransaction.Record) (networktransaction.Record, error) {
		return record.BeginRollback(now)
	})
}

func (s *StateStore) CompleteNetworkRollback(applyID string, now time.Time) (networkplan.StagedPlan, error) {
	return s.transitionNetworkTransaction(applyID, func(record networktransaction.Record) (networktransaction.Record, error) {
		return record.CompleteRollback(now)
	})
}

func (s *StateStore) FailNetworkRollback(applyID string, now time.Time, reason string) (networkplan.StagedPlan, error) {
	return s.transitionNetworkTransaction(applyID, func(record networktransaction.Record) (networktransaction.Record, error) {
		return record.FailRollback(now, reason)
	})
}

func (s *StateStore) ReconcileNetworkOutcome(files networktransaction.FileStore) (networkplan.StagedPlan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.StagedNetworkPlan == nil || s.state.StagedNetworkPlan.Transaction == nil {
		return networkplan.StagedPlan{}, nil
	}
	staged := *s.state.StagedNetworkPlan
	record := *staged.Transaction
	outcome, err := files.ReadOutcome(staged.ApplyID)
	if errors.Is(err, os.ErrNotExist) {
		return staged, nil
	}
	if err != nil {
		return staged, fmt.Errorf("read independent watchdog outcome: %w", err)
	}
	if outcome.PlanHash != staged.PlanHash || outcome.ApplyID != staged.ApplyID || outcome.FinishedAt.Before(record.CreatedAt) {
		return staged, errors.New("independent watchdog outcome does not match the active transaction")
	}
	next := s.state
	switch outcome.Status {
	case "CONFIRMED":
		if record.Phase != networktransaction.PhaseConfirmed {
			confirmation, err := files.ReadConfirmation(staged.ApplyID)
			if err != nil {
				return staged, fmt.Errorf("read independent watchdog confirmation: %w", err)
			}
			record, err = record.Confirm(confirmation.ConfirmedAt)
			if err != nil {
				return staged, fmt.Errorf("reconcile confirmed network transaction: %w", err)
			}
		}
		if next.EmergencyBypass {
			next.OperatingMode = gatewayprotocol.ModeEmergency
		} else {
			next.OperatingMode = gatewayprotocol.ModeRouted
		}
	case "ROLLED_BACK", "ROLLBACK_FAILED":
		if record.Phase == networktransaction.PhaseConfirmed || record.Phase == networktransaction.PhaseRolledBack {
			if outcome.Status == "ROLLED_BACK" && record.Phase == networktransaction.PhaseRolledBack {
				return staged, nil
			}
			return staged, errors.New("watchdog outcome conflicts with terminal transaction state")
		}
		if record.Phase == networktransaction.PhaseRollbackFailed {
			if outcome.Status == "ROLLBACK_FAILED" {
				next.OperatingMode = gatewayprotocol.ModeEmergency
				next.EmergencyBypass = true
				break
			}
			record, err = record.RetryRollback(outcome.FinishedAt)
			if err != nil {
				return staged, fmt.Errorf("reconcile rollback retry: %w", err)
			}
		}
		if record.Phase != networktransaction.PhaseRollbackRequired && record.Phase != networktransaction.PhaseRollingBack {
			record, err = record.RequireRollback("independent watchdog required rollback")
			if err != nil {
				return staged, fmt.Errorf("reconcile rollback requirement: %w", err)
			}
		}
		if record.Phase == networktransaction.PhaseRollbackRequired {
			record, err = record.BeginRollback(outcome.FinishedAt)
			if err != nil {
				return staged, fmt.Errorf("reconcile rollback start: %w", err)
			}
		}
		if outcome.Status == "ROLLED_BACK" {
			record, err = record.CompleteRollback(outcome.FinishedAt)
			// The rollback restored the host as it was before this candidate:
			// routing the last confirmed plan, if there was one.
			next.OperatingMode = gatewayprotocol.ModeSetupSafe
			if next.ConfirmedNetworkPlan != nil && next.ConfirmedNetworkPlan.ApplyID != staged.ApplyID {
				next.OperatingMode = gatewayprotocol.ModeRouted
			}
			next.EmergencyBypass = false
		} else {
			record, err = record.FailRollback(outcome.FinishedAt, outcome.Detail)
			next.OperatingMode = gatewayprotocol.ModeEmergency
			next.EmergencyBypass = true
		}
		if err != nil {
			return staged, fmt.Errorf("reconcile rollback completion: %w", err)
		}
	default:
		return staged, errors.New("independent watchdog outcome status is unsupported")
	}
	if err := record.Validate(); err != nil {
		return staged, fmt.Errorf("validate reconciled transaction: %w", err)
	}
	staged.Transaction = &record
	staged.Status = string(record.Phase)
	next.StagedNetworkPlan = &staged
	if outcome.Status == "CONFIRMED" {
		confirmed := staged
		next.ConfirmedNetworkPlan = &confirmed
	}
	if err := s.persistLocked(next); err != nil {
		return staged, err
	}
	return staged, nil
}

func (s *StateStore) RecoverUnarmedNetworkTransaction(applyID string, now time.Time) (networkplan.StagedPlan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	staged, err := s.stagedForUpdateLocked(applyID)
	if err != nil {
		return networkplan.StagedPlan{}, err
	}
	if staged.Transaction == nil {
		return networkplan.StagedPlan{}, errors.New("network transaction has not started")
	}
	record := *staged.Transaction
	if err := record.Validate(); err != nil {
		return networkplan.StagedPlan{}, fmt.Errorf("validate network transaction: %w", err)
	}
	if record.WatchdogArmedAt != nil || record.ConfirmBy != nil || record.ApplyStartedAt != nil || record.AppliedAt != nil {
		return staged, errors.New("armed or applied network transaction cannot use unarmed recovery")
	}
	switch record.Phase {
	case networktransaction.PhasePreparing:
		record, err = record.RequireRollback("daemon restarted before watchdog arming")
		if err == nil {
			record, err = record.BeginRollback(now)
		}
	case networktransaction.PhaseRollbackRequired:
		record, err = record.BeginRollback(now)
	case networktransaction.PhaseRollingBack:
	default:
		return staged, errors.New("network transaction phase is not eligible for unarmed recovery")
	}
	if err != nil {
		return staged, err
	}
	record, err = record.CompleteRollback(now)
	if err != nil {
		return staged, err
	}
	if err := record.Validate(); err != nil {
		return staged, fmt.Errorf("validate recovered network transaction: %w", err)
	}
	staged.Transaction = &record
	staged.Status = string(record.Phase)
	next := s.state
	next.StagedNetworkPlan = &staged
	next.OperatingMode = gatewayprotocol.ModeSetupSafe
	next.EmergencyBypass = false
	if err := s.persistLocked(next); err != nil {
		return staged, err
	}
	return staged, nil
}

func (s *StateStore) transitionNetworkTransaction(applyID string, transition func(networktransaction.Record) (networktransaction.Record, error)) (networkplan.StagedPlan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	staged, err := s.stagedForUpdateLocked(applyID)
	if err != nil {
		return networkplan.StagedPlan{}, err
	}
	if staged.Transaction == nil {
		return networkplan.StagedPlan{}, errors.New("network transaction has not started")
	}
	if err := staged.Transaction.Validate(); err != nil {
		return networkplan.StagedPlan{}, fmt.Errorf("validate network transaction: %w", err)
	}
	record, err := transition(*staged.Transaction)
	if err != nil {
		return networkplan.StagedPlan{}, err
	}
	return s.persistTransactionLocked(staged, record)
}

func (s *StateStore) stagedForUpdateLocked(applyID string) (networkplan.StagedPlan, error) {
	if s.state.StagedNetworkPlan == nil {
		return networkplan.StagedPlan{}, errors.New("no network plan is staged")
	}
	if s.state.StagedNetworkPlan.ApplyID != applyID {
		return networkplan.StagedPlan{}, errors.New("apply ID does not match the staged plan")
	}
	return *s.state.StagedNetworkPlan, nil
}

func (s *StateStore) persistTransactionLocked(staged networkplan.StagedPlan, record networktransaction.Record) (networkplan.StagedPlan, error) {
	if err := record.Validate(); err != nil {
		return networkplan.StagedPlan{}, fmt.Errorf("validate network transaction: %w", err)
	}
	staged.Transaction = &record
	staged.Status = string(record.Phase)
	next := s.state
	next.StagedNetworkPlan = &staged
	if err := s.persistLocked(next); err != nil {
		return networkplan.StagedPlan{}, err
	}
	return staged, nil
}

func (s *StateStore) persistLocked(next persistedState) error {
	b, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".state-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o640); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return err
	}
	s.state = next
	return nil
}
