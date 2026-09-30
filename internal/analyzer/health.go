package analyzer

import (
	"errors"
	"time"
)

type HealthState string

const (
	HealthHealthy  HealthState = "HEALTHY"
	HealthScanning HealthState = "SCANNING"
	HealthStale    HealthState = "STALE"
)

type HealthSnapshot struct {
	Schema             int         `json:"schema"`
	Engine             Engine      `json:"engine"`
	State              HealthState `json:"state"`
	Healthy            bool        `json:"healthy"`
	SourceVersion      string      `json:"source_version"`
	RulesetID          string      `json:"ruleset_id,omitempty"`
	RulesetVersion     string      `json:"ruleset_version,omitempty"`
	RulesetSHA256      string      `json:"ruleset_sha256,omitempty"`
	ScanInProgress     bool        `json:"scan_in_progress"`
	CompletedCaptures  uint64      `json:"completed_captures"`
	DeliveredEvents    uint64      `json:"delivered_events"`
	LastScanAt         time.Time   `json:"last_scan_at,omitzero"`
	LastSuccessAt      time.Time   `json:"last_success_at,omitzero"`
	HeartbeatAt        time.Time   `json:"heartbeat_at"`
	HeartbeatAgeMillis int64       `json:"heartbeat_age_millis"`
	LastError          string      `json:"last_error,omitempty"`
	CheckedAt          time.Time   `json:"checked_at"`
}

func (s StateStore) Health(now time.Time) (HealthSnapshot, error) {
	now = now.UTC()
	status, err := s.ReadStatus()
	if err != nil || now.IsZero() {
		return HealthSnapshot{}, errors.New("analyzer status is unavailable")
	}
	age := now.Sub(status.UpdatedAt)
	snapshot := HealthSnapshot{
		Schema: SchemaVersion, Engine: status.Engine, State: HealthStale, SourceVersion: status.SourceVersion,
		RulesetID: status.RulesetID, RulesetVersion: status.RulesetVersion, RulesetSHA256: status.RulesetSHA256,
		ScanInProgress: status.ScanInProgress, CompletedCaptures: status.CompletedCaptures, DeliveredEvents: status.DeliveredEvents,
		LastScanAt: status.LastScanAt, LastSuccessAt: status.LastSuccessAt, HeartbeatAt: status.UpdatedAt,
		HeartbeatAgeMillis: age.Milliseconds(), LastError: status.LastError, CheckedAt: now,
	}
	if age < -5*time.Second || age > 2*time.Minute {
		return snapshot, nil
	}
	if status.ScanInProgress {
		snapshot.State, snapshot.Healthy = HealthScanning, true
		return snapshot, nil
	}
	if !status.LastSuccessAt.IsZero() && !status.LastSuccessAt.After(now.Add(5*time.Second)) && now.Sub(status.LastSuccessAt) <= 2*time.Minute {
		snapshot.State, snapshot.Healthy = HealthHealthy, true
	}
	return snapshot, nil
}

func (h HealthSnapshot) Validate() error {
	if h.Schema != SchemaVersion || h.CheckedAt.IsZero() || h.HeartbeatAt.IsZero() || h.HeartbeatAgeMillis != h.CheckedAt.Sub(h.HeartbeatAt).Milliseconds() {
		return errors.New("analyzer health snapshot is invalid")
	}
	if _, err := ParseEngine(string(h.Engine)); err != nil {
		return errors.New("analyzer health snapshot is invalid")
	}
	if !validText(h.SourceVersion, 1, 64) || len(h.LastError) > 2048 || h.LastError != "" && !validText(h.LastError, 1, 2048) {
		return errors.New("analyzer health snapshot is invalid")
	}
	rulesetPresent := h.RulesetID != "" || h.RulesetVersion != "" || h.RulesetSHA256 != ""
	if h.Engine == EngineSuricata {
		if !rulesetPresent || !rulesetIDPattern.MatchString(h.RulesetID) || !rulesetVersionPattern.MatchString(h.RulesetVersion) || !sha256Pattern.MatchString(h.RulesetSHA256) {
			return errors.New("analyzer health snapshot is invalid")
		}
	} else if rulesetPresent {
		return errors.New("analyzer health snapshot is invalid")
	}
	switch h.State {
	case HealthHealthy:
		if !h.Healthy || h.ScanInProgress || h.LastSuccessAt.IsZero() || h.LastSuccessAt.After(h.CheckedAt.Add(5*time.Second)) || h.CheckedAt.Sub(h.LastSuccessAt) > 2*time.Minute || h.HeartbeatAgeMillis < -5000 || h.HeartbeatAgeMillis > int64((2*time.Minute)/time.Millisecond) {
			return errors.New("analyzer health snapshot is inconsistent")
		}
	case HealthScanning:
		if !h.Healthy || !h.ScanInProgress || h.HeartbeatAgeMillis < -5000 || h.HeartbeatAgeMillis > int64((2*time.Minute)/time.Millisecond) {
			return errors.New("analyzer health snapshot is inconsistent")
		}
	case HealthStale:
		if h.Healthy {
			return errors.New("analyzer health snapshot is inconsistent")
		}
	default:
		return errors.New("analyzer health snapshot is invalid")
	}
	return nil
}
