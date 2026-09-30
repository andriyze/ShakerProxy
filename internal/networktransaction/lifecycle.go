package networktransaction

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

const (
	SchemaVersion     = 1
	MinRollbackWindow = 60 * time.Second
	MaxRollbackWindow = 15 * time.Minute
)

type Phase string

const (
	PhasePreparing            Phase = "PREPARING"
	PhaseWatchdogArmed        Phase = "WATCHDOG_ARMED"
	PhaseApplying             Phase = "APPLYING"
	PhaseAwaitingHealth       Phase = "AWAITING_HEALTH"
	PhaseAwaitingConfirmation Phase = "AWAITING_CONFIRMATION"
	PhaseConfirmed            Phase = "CONFIRMED"
	PhaseRollbackRequired     Phase = "ROLLBACK_REQUIRED"
	PhaseRollingBack          Phase = "ROLLING_BACK"
	PhaseRolledBack           Phase = "ROLLED_BACK"
	PhaseRollbackFailed       Phase = "ROLLBACK_FAILED"
)

type CheckName string

const (
	CheckManagement     CheckName = "MANAGEMENT"
	CheckWAN            CheckName = "WAN"
	CheckDNS            CheckName = "DNS"
	CheckIPv4Forwarding CheckName = "IPV4_FORWARDING"
	CheckDHCP4          CheckName = "DHCP4"
	CheckIPv6           CheckName = "IPV6"
	CheckWiFiAP         CheckName = "WIFI_AP"
)

type CheckStatus string

const (
	CheckPass CheckStatus = "PASS"
	CheckFail CheckStatus = "FAIL"
	CheckSkip CheckStatus = "SKIP"
)

var (
	applyIDPattern  = regexp.MustCompile(`^apply-[0-9a-f]{32}$`)
	planHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	requiredChecks  = []CheckName{CheckManagement, CheckWAN, CheckDNS, CheckIPv4Forwarding, CheckDHCP4}
)

func ValidApplyID(value string) bool  { return applyIDPattern.MatchString(value) }
func ValidPlanHash(value string) bool { return planHashPattern.MatchString(value) }

type HealthCheck struct {
	Name   CheckName   `json:"name"`
	Status CheckStatus `json:"status"`
	Detail string      `json:"detail,omitempty"`
}

type HealthReport struct {
	CheckedAt time.Time     `json:"checked_at"`
	Checks    []HealthCheck `json:"checks"`
}

type Record struct {
	Schema             int           `json:"schema"`
	ApplyID            string        `json:"apply_id"`
	PlanHash           string        `json:"plan_hash"`
	Phase              Phase         `json:"phase"`
	CreatedAt          time.Time     `json:"created_at"`
	WatchdogArmedAt    *time.Time    `json:"watchdog_armed_at,omitempty"`
	ApplyStartedAt     *time.Time    `json:"apply_started_at,omitempty"`
	AppliedAt          *time.Time    `json:"applied_at,omitempty"`
	ConfirmBy          *time.Time    `json:"confirm_by,omitempty"`
	Health             *HealthReport `json:"health,omitempty"`
	ConfirmedAt        *time.Time    `json:"confirmed_at,omitempty"`
	RollbackStartedAt  *time.Time    `json:"rollback_started_at,omitempty"`
	RollbackFinishedAt *time.Time    `json:"rollback_finished_at,omitempty"`
	Failure            string        `json:"failure,omitempty"`
}

func New(applyID, planHash string, now time.Time) (Record, error) {
	if !applyIDPattern.MatchString(applyID) {
		return Record{}, errors.New("invalid apply ID")
	}
	if !planHashPattern.MatchString(planHash) {
		return Record{}, errors.New("invalid plan hash")
	}
	if now.IsZero() {
		return Record{}, errors.New("creation time is required")
	}
	return Record{Schema: SchemaVersion, ApplyID: applyID, PlanHash: planHash, Phase: PhasePreparing, CreatedAt: now.UTC()}, nil
}

func (r Record) Validate() error {
	if r.Schema != SchemaVersion {
		return fmt.Errorf("unsupported network transaction schema %d", r.Schema)
	}
	if !applyIDPattern.MatchString(r.ApplyID) || !planHashPattern.MatchString(r.PlanHash) {
		return errors.New("network transaction identity is invalid")
	}
	if r.CreatedAt.IsZero() {
		return errors.New("network transaction creation time is required")
	}
	switch r.Phase {
	case PhasePreparing, PhaseWatchdogArmed, PhaseApplying, PhaseAwaitingHealth, PhaseAwaitingConfirmation, PhaseConfirmed, PhaseRollbackRequired, PhaseRollingBack, PhaseRolledBack, PhaseRollbackFailed:
	default:
		return fmt.Errorf("unknown network transaction phase %q", r.Phase)
	}
	if r.Phase == PhaseWatchdogArmed || r.Phase == PhaseApplying || r.Phase == PhaseAwaitingHealth || r.Phase == PhaseAwaitingConfirmation || r.Phase == PhaseConfirmed {
		if r.WatchdogArmedAt == nil || r.WatchdogArmedAt.Before(r.CreatedAt) || r.ConfirmBy == nil || r.ConfirmBy.Sub(*r.WatchdogArmedAt) < MinRollbackWindow || r.ConfirmBy.Sub(*r.WatchdogArmedAt) > MaxRollbackWindow {
			return errors.New("armed watchdog timestamps are invalid")
		}
	}
	if r.Phase == PhaseApplying || r.Phase == PhaseAwaitingHealth || r.Phase == PhaseAwaitingConfirmation || r.Phase == PhaseConfirmed {
		if r.ApplyStartedAt == nil || r.ApplyStartedAt.Before(*r.WatchdogArmedAt) {
			return errors.New("apply start timestamp is invalid")
		}
	}
	if r.Phase == PhaseAwaitingHealth || r.Phase == PhaseAwaitingConfirmation || r.Phase == PhaseConfirmed {
		if r.AppliedAt == nil || r.AppliedAt.Before(*r.ApplyStartedAt) {
			return errors.New("applied timestamp is required")
		}
	}
	if r.Phase == PhaseAwaitingConfirmation || r.Phase == PhaseConfirmed {
		if r.Health == nil || r.Health.CheckedAt.Before(*r.AppliedAt) || !r.Health.Healthy() {
			return errors.New("healthy connectivity evidence is required")
		}
	}
	if r.Phase == PhaseConfirmed {
		if r.ConfirmedAt == nil || r.ConfirmedAt.Before(r.Health.CheckedAt) || !r.ConfirmedAt.Before(*r.ConfirmBy) {
			return errors.New("confirmation timestamp is invalid")
		}
	}
	if (r.Phase == PhaseRollbackRequired || r.Phase == PhaseRollingBack || r.Phase == PhaseRolledBack || r.Phase == PhaseRollbackFailed) && r.Failure == "" {
		return errors.New("rollback reason is required")
	}
	if r.Phase == PhaseRollingBack || r.Phase == PhaseRolledBack || r.Phase == PhaseRollbackFailed {
		if r.RollbackStartedAt == nil || r.RollbackStartedAt.Before(r.CreatedAt) {
			return errors.New("rollback start timestamp is required")
		}
	}
	if r.Phase == PhaseRolledBack || r.Phase == PhaseRollbackFailed {
		if r.RollbackFinishedAt == nil || r.RollbackFinishedAt.Before(*r.RollbackStartedAt) {
			return errors.New("rollback completion timestamp is invalid")
		}
	}
	return nil
}

func (r Record) ArmWatchdog(now time.Time, window time.Duration) (Record, error) {
	if r.Phase != PhasePreparing {
		return r, invalidTransition(r.Phase, PhaseWatchdogArmed)
	}
	if window < MinRollbackWindow || window > MaxRollbackWindow {
		return r, fmt.Errorf("rollback window must be between %s and %s", MinRollbackWindow, MaxRollbackWindow)
	}
	if now.Before(r.CreatedAt) {
		return r, errors.New("watchdog arm time precedes transaction creation")
	}
	armedAt := now.UTC()
	confirmBy := armedAt.Add(window)
	r.Phase = PhaseWatchdogArmed
	r.WatchdogArmedAt = &armedAt
	r.ConfirmBy = &confirmBy
	return r, nil
}

func (r Record) BeginApply(now time.Time) (Record, error) {
	if r.Phase != PhaseWatchdogArmed || r.ConfirmBy == nil {
		return r, invalidTransition(r.Phase, PhaseApplying)
	}
	if !now.Before(*r.ConfirmBy) {
		return r.requireRollback("watchdog deadline elapsed before apply")
	}
	if r.WatchdogArmedAt == nil || now.Before(*r.WatchdogArmedAt) {
		return r, errors.New("apply start time precedes watchdog arming")
	}
	startedAt := now.UTC()
	r.Phase = PhaseApplying
	r.ApplyStartedAt = &startedAt
	return r, nil
}

func (r Record) MarkApplied(now time.Time) (Record, error) {
	if r.Phase != PhaseApplying {
		return r, invalidTransition(r.Phase, PhaseAwaitingHealth)
	}
	if r.deadlineElapsed(now) {
		return r.requireRollback("watchdog deadline elapsed during apply")
	}
	if r.ApplyStartedAt == nil || now.Before(*r.ApplyStartedAt) {
		return r, errors.New("applied time precedes apply start")
	}
	appliedAt := now.UTC()
	r.AppliedAt = &appliedAt
	r.Phase = PhaseAwaitingHealth
	return r, nil
}

func (r Record) RecordHealth(report HealthReport) (Record, error) {
	if r.Phase != PhaseAwaitingHealth {
		return r, invalidTransition(r.Phase, PhaseAwaitingConfirmation)
	}
	if r.deadlineElapsed(report.CheckedAt) {
		return r.requireRollback("watchdog deadline elapsed before health validation")
	}
	if r.AppliedAt == nil || report.CheckedAt.Before(*r.AppliedAt) {
		return r, errors.New("health check time precedes apply completion")
	}
	if err := report.Validate(); err != nil {
		return r, err
	}
	report.CheckedAt = report.CheckedAt.UTC()
	r.Health = &report
	if !report.Healthy() {
		return r.requireRollback("one or more required connectivity checks failed")
	}
	r.Phase = PhaseAwaitingConfirmation
	return r, nil
}

func (r Record) Confirm(now time.Time) (Record, error) {
	if r.Phase != PhaseAwaitingConfirmation || r.Health == nil || !r.Health.Healthy() {
		return r, invalidTransition(r.Phase, PhaseConfirmed)
	}
	if r.deadlineElapsed(now) {
		return r.requireRollback("confirmation deadline elapsed")
	}
	if now.Before(r.Health.CheckedAt) {
		return r, errors.New("confirmation time precedes health validation")
	}
	confirmedAt := now.UTC()
	r.ConfirmedAt = &confirmedAt
	r.Phase = PhaseConfirmed
	return r, nil
}

func (r Record) RequireRollback(reason string) (Record, error) {
	if r.terminal() || r.Phase == PhaseRollingBack {
		return r, invalidTransition(r.Phase, PhaseRollbackRequired)
	}
	return r.requireRollback(reason)
}

func (r Record) BeginRollback(now time.Time) (Record, error) {
	if r.Phase != PhaseRollbackRequired {
		return r, invalidTransition(r.Phase, PhaseRollingBack)
	}
	if now.Before(r.CreatedAt) {
		return r, errors.New("rollback start time precedes transaction creation")
	}
	startedAt := now.UTC()
	r.RollbackStartedAt = &startedAt
	r.Phase = PhaseRollingBack
	return r, nil
}

func (r Record) CompleteRollback(now time.Time) (Record, error) {
	if r.Phase != PhaseRollingBack {
		return r, invalidTransition(r.Phase, PhaseRolledBack)
	}
	if r.RollbackStartedAt == nil || now.Before(*r.RollbackStartedAt) {
		return r, errors.New("rollback completion time precedes rollback start")
	}
	finishedAt := now.UTC()
	r.RollbackFinishedAt = &finishedAt
	r.Phase = PhaseRolledBack
	return r, nil
}

func (r Record) FailRollback(now time.Time, reason string) (Record, error) {
	if r.Phase != PhaseRollingBack {
		return r, invalidTransition(r.Phase, PhaseRollbackFailed)
	}
	if reason == "" {
		return r, errors.New("rollback failure reason is required")
	}
	if r.RollbackStartedAt == nil || now.Before(*r.RollbackStartedAt) {
		return r, errors.New("rollback failure time precedes rollback start")
	}
	failedAt := now.UTC()
	r.RollbackFinishedAt = &failedAt
	r.Failure = reason
	r.Phase = PhaseRollbackFailed
	return r, nil
}

func (r Record) RetryRollback(now time.Time) (Record, error) {
	if r.Phase != PhaseRollbackFailed {
		return r, invalidTransition(r.Phase, PhaseRollingBack)
	}
	if now.Before(r.CreatedAt) {
		return r, errors.New("rollback retry time precedes transaction creation")
	}
	startedAt := now.UTC()
	r.RollbackStartedAt = &startedAt
	r.RollbackFinishedAt = nil
	r.Phase = PhaseRollingBack
	return r, nil
}

func (r Record) NeedsRollback(now time.Time) bool {
	if r.Phase == PhaseRollbackRequired || r.Phase == PhaseRollingBack || r.Phase == PhaseRollbackFailed {
		return true
	}
	return !r.terminal() && r.deadlineElapsed(now)
}

func (r Record) Terminal() bool { return r.terminal() }

func (r Record) requireRollback(reason string) (Record, error) {
	if reason == "" {
		return r, errors.New("rollback reason is required")
	}
	r.Phase = PhaseRollbackRequired
	r.Failure = reason
	return r, nil
}

func (r Record) deadlineElapsed(now time.Time) bool {
	return r.ConfirmBy != nil && !now.Before(*r.ConfirmBy)
}

func (r Record) terminal() bool {
	return r.Phase == PhaseConfirmed || r.Phase == PhaseRolledBack || r.Phase == PhaseRollbackFailed
}

func (h HealthReport) Validate() error {
	if h.CheckedAt.IsZero() {
		return errors.New("health check time is required")
	}
	seen := map[CheckName]bool{}
	for _, check := range h.Checks {
		switch check.Name {
		case CheckManagement, CheckWAN, CheckDNS, CheckIPv4Forwarding, CheckDHCP4, CheckIPv6, CheckWiFiAP:
		default:
			return fmt.Errorf("unknown health check %q", check.Name)
		}
		if seen[check.Name] {
			return fmt.Errorf("duplicate health check %q", check.Name)
		}
		seen[check.Name] = true
		switch check.Status {
		case CheckPass, CheckFail:
		case CheckSkip:
			if check.Name != CheckIPv6 && check.Name != CheckDHCP4 {
				return fmt.Errorf("required health check %q cannot be skipped", check.Name)
			}
		default:
			return fmt.Errorf("invalid health status %q", check.Status)
		}
	}
	for _, name := range requiredChecks {
		if !seen[name] {
			return fmt.Errorf("required health check %q is missing", name)
		}
	}
	return nil
}

func (h HealthReport) Healthy() bool {
	if h.Validate() != nil {
		return false
	}
	for _, check := range h.Checks {
		if check.Status == CheckFail {
			return false
		}
	}
	return true
}

func invalidTransition(from, to Phase) error {
	return fmt.Errorf("network transaction cannot transition from %s to %s", from, to)
}
