package daemon

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"shakerproxy.dev/shakerproxy/internal/configlock"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkhealth"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

const (
	activationSecretBytes = 32
	maxActivationRecords  = 64
)

type transactionCoordinator interface {
	Apply(context.Context, string) (networkplan.StagedPlan, error)
	Confirm(context.Context, string, string) (networkplan.StagedPlan, error)
}

type coordinatorFactory func(time.Duration) transactionCoordinator

type commitIntent struct {
	planHash       string
	idempotencyKey string
	window         time.Duration
	result         gatewayprotocol.CommitNetworkPlanResult
	done           chan struct{}
}

type confirmationIntent struct {
	planHash       string
	idempotencyKey string
	done           chan struct{}
	result         networkplan.StagedPlan
	err            error
	finishedAt     time.Time
}

type NetworkActivation struct {
	Store       *StateStore
	Files       networktransaction.FileStore
	Heartbeats  *networkhealth.HeartbeatGate
	Coordinator coordinatorFactory
	Secret      []byte
	Now         func() time.Time
	ConfigLock  *configlock.Manager

	// Runtime re-establishes a confirmed plan's kernel runtime state after
	// a reboot and whenever it drifts.
	Runtime *NetworkRuntimeKeeper

	// Rollback restores a transaction's pre-apply host state; Revert uses it
	// to undo the running plan with the same executor as the watchdog.
	Rollback func(context.Context, networktransaction.WatchdogManifest) error

	mu            sync.Mutex
	commits       map[string]*commitIntent
	confirmations map[string]*confirmationIntent
}

func (a *NetworkActivation) Commit(ctx context.Context, params gatewayprotocol.CommitNetworkPlanParams) (gatewayprotocol.CommitNetworkPlanResult, error) {
	window := time.Duration(params.RollbackWindowSeconds) * time.Second
	if a.Store == nil || a.Heartbeats == nil || a.Coordinator == nil || len(a.Secret) != activationSecretBytes {
		return gatewayprotocol.CommitNetworkPlanResult{}, errors.New("network activation is unavailable")
	}
	if !networktransaction.ValidApplyID(params.ApplyID) || !networktransaction.ValidPlanHash(params.PlanHash) || !validIdempotencyKey(params.IdempotencyKey) {
		return gatewayprotocol.CommitNetworkPlanResult{}, errors.New("network commit identity is invalid")
	}
	if window < networktransaction.MinRollbackWindow || window > networktransaction.MaxRollbackWindow {
		return gatewayprotocol.CommitNetworkPlanResult{}, errors.New("network commit rollback window is invalid")
	}

	now := a.now()
	a.mu.Lock()
	if a.commits == nil {
		a.commits = map[string]*commitIntent{}
	}
	a.pruneLocked(now)
	if current, exists := a.commits[params.ApplyID]; exists {
		if current.planHash != params.PlanHash || current.idempotencyKey != params.IdempotencyKey || current.window != window {
			a.mu.Unlock()
			return gatewayprotocol.CommitNetworkPlanResult{}, errors.New("network commit idempotency conflict")
		}
		result := current.result
		result.HealthToken = a.deriveToken(params.ApplyID, params.PlanHash, params.IdempotencyKey)
		a.mu.Unlock()
		return result, nil
	}
	if len(a.commits) >= maxActivationRecords {
		a.mu.Unlock()
		return gatewayprotocol.CommitNetworkPlanResult{}, errors.New("too many network activation records are retained")
	}
	state := a.Store.Get()
	staged := state.StagedNetworkPlan
	if staged == nil || staged.ApplyID != params.ApplyID || staged.PlanHash != params.PlanHash {
		a.mu.Unlock()
		return gatewayprotocol.CommitNetworkPlanResult{}, errors.New("network commit does not match the staged plan")
	}
	if staged.Transaction != nil || staged.Status != "STAGED_NOT_APPLIED" || !now.Before(staged.ExpiresAt) {
		a.mu.Unlock()
		return gatewayprotocol.CommitNetworkPlanResult{}, errors.New("staged network plan is not eligible for commit")
	}
	if !staged.Preview.Validation.Valid || !staged.Preview.FirewallEnvironment.ApplyReady {
		a.mu.Unlock()
		return gatewayprotocol.CommitNetworkPlanResult{}, errors.New("staged network plan is not apply-ready")
	}
	deadline := now.Add(window).UTC()
	token := a.deriveToken(params.ApplyID, params.PlanHash, params.IdempotencyKey)
	if err := a.Heartbeats.OpenWithToken(params.ApplyID, params.PlanHash, token, deadline); err != nil {
		a.mu.Unlock()
		return gatewayprotocol.CommitNetworkPlanResult{}, err
	}
	result := gatewayprotocol.CommitNetworkPlanResult{
		ApplyID:        params.ApplyID,
		PlanHash:       params.PlanHash,
		Status:         "ACCEPTED",
		HealthToken:    token,
		HealthDeadline: deadline,
	}
	storedResult := result
	storedResult.HealthToken = ""
	a.commits[params.ApplyID] = &commitIntent{planHash: params.PlanHash, idempotencyKey: params.IdempotencyKey, window: window, result: storedResult, done: make(chan struct{})}
	a.mu.Unlock()

	go a.runCommit(ctx, params.ApplyID, window)
	return result, nil
}

func (a *NetworkActivation) Reconcile() error {
	if a.Store == nil || a.Files.Root == "" {
		return nil
	}
	staged := a.Store.Get().StagedNetworkPlan
	if staged == nil || staged.Transaction == nil {
		return nil
	}
	if _, err := a.Files.ReadOutcome(staged.ApplyID); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	var guard *configlock.Guard
	if a.ConfigLock != nil {
		lockContext, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		var err error
		guard, err = a.ConfigLock.Acquire(lockContext, configlock.Request{OperationID: "network-reconcile", Category: configlock.CategoryNetwork, Actor: "gatewayd"})
		if err != nil {
			return err
		}
		defer guard.Release()
	}
	_, err := a.Store.ReconcileNetworkOutcome(a.Files)
	return err
}

func (a *NetworkActivation) Signal(params gatewayprotocol.SignalNetworkHealthParams) error {
	if a.Heartbeats == nil {
		return errors.New("network activation is unavailable")
	}
	return a.Heartbeats.Signal(params.ApplyID, params.PlanHash, params.Token)
}

func (a *NetworkActivation) Confirm(ctx context.Context, params gatewayprotocol.ConfirmNetworkPlanParams) (networkplan.StagedPlan, error) {
	if a.Coordinator == nil || !networktransaction.ValidApplyID(params.ApplyID) || !networktransaction.ValidPlanHash(params.PlanHash) || !validIdempotencyKey(params.IdempotencyKey) {
		return networkplan.StagedPlan{}, errors.New("network confirmation identity is invalid")
	}
	now := a.now()
	a.mu.Lock()
	if a.confirmations == nil {
		a.confirmations = map[string]*confirmationIntent{}
	}
	a.pruneLocked(now)
	intent, exists := a.confirmations[params.ApplyID]
	if exists {
		if intent.planHash != params.PlanHash || intent.idempotencyKey != params.IdempotencyKey {
			a.mu.Unlock()
			return networkplan.StagedPlan{}, errors.New("network confirmation idempotency conflict")
		}
		done := intent.done
		a.mu.Unlock()
		select {
		case <-done:
			return intent.result, intent.err
		case <-ctx.Done():
			return networkplan.StagedPlan{}, ctx.Err()
		}
	}
	if len(a.confirmations) >= maxActivationRecords {
		a.mu.Unlock()
		return networkplan.StagedPlan{}, errors.New("too many network confirmation records are retained")
	}
	intent = &confirmationIntent{planHash: params.PlanHash, idempotencyKey: params.IdempotencyKey, done: make(chan struct{})}
	a.confirmations[params.ApplyID] = intent
	a.mu.Unlock()

	result, err := a.Coordinator(networktransaction.MinRollbackWindow).Confirm(ctx, params.ApplyID, params.PlanHash)
	a.mu.Lock()
	intent.result = result
	intent.err = err
	intent.finishedAt = a.now()
	close(intent.done)
	if err != nil {
		delete(a.confirmations, params.ApplyID)
	}
	a.mu.Unlock()
	return result, err
}

func (a *NetworkActivation) runCommit(ctx context.Context, applyID string, window time.Duration) {
	var guard *configlock.Guard
	var err error
	if a.ConfigLock != nil {
		lockContext, cancel := context.WithTimeout(ctx, 2*time.Second)
		guard, err = a.ConfigLock.Acquire(lockContext, configlock.Request{OperationID: "network-" + strings.TrimPrefix(applyID, "apply-"), Category: configlock.CategoryNetwork, Actor: "gatewayd"})
		cancel()
	}
	var staged networkplan.StagedPlan
	if err == nil {
		staged, err = a.Coordinator(window).Apply(ctx, applyID)
	}
	if guard != nil {
		_ = guard.Release()
	}
	a.Heartbeats.Close(applyID)
	a.mu.Lock()
	defer a.mu.Unlock()
	intent := a.commits[applyID]
	if intent == nil {
		return
	}
	if staged.Status != "" {
		intent.result.Status = staged.Status
	} else if err != nil {
		intent.result.Status = "FAILED"
	}
	if err != nil {
		intent.result.Failure = boundedActivationFailure(err)
	}
	close(intent.done)
}

func (a *NetworkActivation) deriveToken(applyID, planHash, idempotencyKey string) string {
	mac := hmac.New(sha256.New, a.Secret)
	_, _ = mac.Write([]byte(applyID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(planHash))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(idempotencyKey))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (a *NetworkActivation) now() time.Time {
	if a.Now != nil {
		return a.Now().UTC()
	}
	return time.Now().UTC()
}

func (a *NetworkActivation) pruneLocked(now time.Time) {
	for applyID, intent := range a.commits {
		if now.Before(intent.result.HealthDeadline) {
			continue
		}
		select {
		case <-intent.done:
			delete(a.commits, applyID)
			delete(a.confirmations, applyID)
		default:
		}
	}
	for applyID, intent := range a.confirmations {
		if !intent.finishedAt.IsZero() && !now.Before(intent.finishedAt.Add(networktransaction.MaxRollbackWindow)) {
			delete(a.confirmations, applyID)
		}
	}
}

func boundedActivationFailure(err error) string {
	detail := strings.TrimSpace(err.Error())
	if len(detail) > 512 {
		detail = detail[:512]
	}
	return detail
}

// Revert stops routing the lab: it restores the host network exactly as it
// was before the running plan was applied, from that plan's retained
// transaction snapshot, using the watchdog's rollback executor. If the
// restore fails, emergency bypass is enabled so lab traffic fails open.
func (a *NetworkActivation) Revert(ctx context.Context) (persistedState, error) {
	if a.Rollback == nil || a.Store == nil {
		return persistedState{}, errors.New("network revert is unavailable in this daemon profile")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ConfigLock != nil {
		lockContext, cancel := context.WithTimeout(ctx, 2*time.Second)
		guard, err := a.ConfigLock.Acquire(lockContext, configlock.Request{OperationID: "network-revert", Category: configlock.CategoryNetwork, Actor: "gatewayd"})
		cancel()
		if err != nil {
			return a.Store.Get(), fmt.Errorf("another network or policy change is running: %w", err)
		}
		defer func() { _ = guard.Release() }()
	}
	state := a.Store.Get()
	var manifest networktransaction.WatchdogManifest
	var err error
	switch active := state.activeNetworkPlan(); {
	case active != nil:
		manifest, err = a.Files.ReadManifest(active.ApplyID)
	case state.OperatingMode == gatewayprotocol.ModeRouted || state.OperatingMode == gatewayprotocol.ModeEmergency:
		// Routing without a plan on record (an older gateway could lose it):
		// the newest confirmed transaction holds the pre-apply snapshot.
		manifest, err = a.Files.LatestConfirmed()
	default:
		return state, errors.New("no confirmed network plan is running")
	}
	if err != nil {
		return state, fmt.Errorf("the running plan's rollback snapshot is unavailable: %w", err)
	}
	if err := a.Rollback(context.WithoutCancel(ctx), manifest); err != nil {
		state, bypassErr := a.Store.SetEmergencyBypass(true)
		return state, errors.Join(fmt.Errorf("the previous network could not be fully restored, so emergency bypass is on: %w", err), bypassErr)
	}
	return a.Store.RevertNetworkPlan(manifest.ApplyID)
}
