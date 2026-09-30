package capture

import (
	"errors"
	"os"
	"regexp"
	"time"
)

const MaxHoldEvents = 128

var caseIDPattern = regexp.MustCompile(`^case-[a-f0-9]{32}$`)

type HoldAction string

const (
	HoldApplied  HoldAction = "APPLIED"
	HoldReleased HoldAction = "RELEASED"
)

type HoldEvent struct {
	Revision       uint64     `json:"revision"`
	Action         HoldAction `json:"action"`
	CaseID         string     `json:"case_id"`
	Actor          string     `json:"actor"`
	Reason         string     `json:"reason"`
	RequestSHA256  string     `json:"request_sha256"`
	IdempotencyKey string     `json:"idempotency_key"`
	OccurredAt     time.Time  `json:"occurred_at"`
}

type EvidenceHold struct {
	Schema    int         `json:"schema"`
	SessionID string      `json:"session_id"`
	Revision  uint64      `json:"revision"`
	Active    bool        `json:"active"`
	CaseID    string      `json:"case_id,omitempty"`
	Actor     string      `json:"actor"`
	Reason    string      `json:"reason"`
	UpdatedAt time.Time   `json:"updated_at"`
	History   []HoldEvent `json:"history"`
}

type SetHoldRequest struct {
	SessionID        string `json:"session_id"`
	CaseID           string `json:"case_id"`
	Active           bool   `json:"active"`
	ExpectedRevision uint64 `json:"expected_revision"`
	Actor            string `json:"actor"`
	Reason           string `json:"reason"`
	IdempotencyKey   string `json:"idempotency_key"`
}

func ValidCaseID(id string) bool { return caseIDPattern.MatchString(id) }

func (r SetHoldRequest) Validate() error {
	if !ValidSessionID(r.SessionID) || !ValidCaseID(r.CaseID) || !validOpaqueKey(r.IdempotencyKey) {
		return errors.New("evidence hold identity is invalid")
	}
	if err := validateText("hold actor", r.Actor, 1, 96); err != nil {
		return err
	}
	if err := validateText("hold reason", r.Reason, 1, 512); err != nil {
		return err
	}
	return nil
}

func (h EvidenceHold) Validate() error {
	if h.Schema != 1 || !ValidSessionID(h.SessionID) || h.Revision == 0 || h.Revision != uint64(len(h.History)) || h.UpdatedAt.IsZero() || len(h.History) > MaxHoldEvents {
		return errors.New("evidence hold is invalid")
	}
	if h.Active && !ValidCaseID(h.CaseID) {
		return errors.New("active evidence hold has invalid case identity")
	}
	if !h.Active && h.CaseID != "" {
		return errors.New("released evidence hold retains an active case identity")
	}
	if err := validateText("hold actor", h.Actor, 1, 96); err != nil {
		return err
	}
	if err := validateText("hold reason", h.Reason, 1, 512); err != nil {
		return err
	}
	var previous uint64
	var previousTime time.Time
	for _, event := range h.History {
		if event.Revision != previous+1 || !ValidCaseID(event.CaseID) || !validOpaqueKey(event.IdempotencyKey) || !validSHA256String(event.RequestSHA256) || event.OccurredAt.IsZero() || (!previousTime.IsZero() && event.OccurredAt.Before(previousTime)) || (event.Action != HoldApplied && event.Action != HoldReleased) {
			return errors.New("evidence hold history is invalid")
		}
		if err := validateText("hold event actor", event.Actor, 1, 96); err != nil {
			return err
		}
		if err := validateText("hold event reason", event.Reason, 1, 512); err != nil {
			return err
		}
		request := SetHoldRequest{SessionID: h.SessionID, CaseID: event.CaseID, Active: event.Action == HoldApplied, ExpectedRevision: event.Revision - 1, Actor: event.Actor, Reason: event.Reason, IdempotencyKey: event.IdempotencyKey}
		requestSHA, err := hashJSON(request)
		if err != nil || requestSHA != event.RequestSHA256 {
			return errors.New("evidence hold request evidence is invalid")
		}
		previous = event.Revision
		previousTime = event.OccurredAt
	}
	last := h.History[len(h.History)-1]
	if last.Revision != h.Revision || last.Actor != h.Actor || last.Reason != h.Reason || !last.OccurredAt.Equal(h.UpdatedAt) || h.Active != (last.Action == HoldApplied) || h.Active && h.CaseID != last.CaseID {
		return errors.New("evidence hold current state does not match history")
	}
	return nil
}

func (m *Manager) SetEvidenceHold(request SetHoldRequest) (EvidenceHold, error) {
	m.retentionMu.Lock()
	defer m.retentionMu.Unlock()
	if err := request.Validate(); err != nil {
		return EvidenceHold{}, err
	}
	if _, err := m.Store.ReadSession(request.SessionID); err != nil {
		return EvidenceHold{}, err
	}
	requestSHA, err := hashJSON(request)
	if err != nil {
		return EvidenceHold{}, err
	}
	hold, err := m.Store.ReadEvidenceHold(request.SessionID)
	if errors.Is(err, os.ErrNotExist) {
		hold = EvidenceHold{Schema: 1, SessionID: request.SessionID, History: []HoldEvent{}}
	} else if err != nil {
		return EvidenceHold{}, err
	}
	for index, event := range hold.History {
		if event.IdempotencyKey != request.IdempotencyKey {
			continue
		}
		if event.RequestSHA256 != requestSHA {
			return EvidenceHold{}, errors.New("evidence hold idempotency key conflicts with an existing request")
		}
		return holdAtEvent(hold, index), nil
	}
	if hold.Revision != request.ExpectedRevision {
		return EvidenceHold{}, errors.New("evidence hold revision changed")
	}
	if len(hold.History) >= MaxHoldEvents {
		return EvidenceHold{}, errors.New("evidence hold history is full")
	}
	if request.Active {
		if hold.Active {
			return EvidenceHold{}, errors.New("capture already has an active evidence hold")
		}
	} else if !hold.Active || hold.CaseID != request.CaseID {
		return EvidenceHold{}, errors.New("only the owning case can release the active evidence hold")
	}
	now := m.now()
	action := HoldReleased
	if request.Active {
		action = HoldApplied
	}
	event := HoldEvent{Revision: hold.Revision + 1, Action: action, CaseID: request.CaseID, Actor: request.Actor, Reason: request.Reason, RequestSHA256: requestSHA, IdempotencyKey: request.IdempotencyKey, OccurredAt: now}
	hold.Revision, hold.Active, hold.Actor, hold.Reason, hold.UpdatedAt = event.Revision, request.Active, request.Actor, request.Reason, now
	if request.Active {
		hold.CaseID = request.CaseID
	} else {
		hold.CaseID = ""
	}
	hold.History = append(hold.History, event)
	if err := hold.Validate(); err != nil {
		return EvidenceHold{}, err
	}
	if err := m.Store.WriteEvidenceHold(hold); err != nil {
		return EvidenceHold{}, err
	}
	return hold, nil
}

func holdAtEvent(current EvidenceHold, index int) EvidenceHold {
	event := current.History[index]
	history := append([]HoldEvent(nil), current.History[:index+1]...)
	result := EvidenceHold{Schema: 1, SessionID: current.SessionID, Revision: event.Revision, Active: event.Action == HoldApplied, Actor: event.Actor, Reason: event.Reason, UpdatedAt: event.OccurredAt, History: history}
	if result.Active {
		result.CaseID = event.CaseID
	}
	return result
}

func (s Store) ReadEvidenceHold(id string) (EvidenceHold, error) {
	var hold EvidenceHold
	if err := s.readJSON(id, "hold.json", &hold); err != nil {
		return EvidenceHold{}, err
	}
	if hold.SessionID != id || hold.Validate() != nil {
		return EvidenceHold{}, errors.New("stored evidence hold is invalid")
	}
	return hold, nil
}

func (s Store) WriteEvidenceHold(hold EvidenceHold) error {
	if err := hold.Validate(); err != nil {
		return err
	}
	directory, err := s.SessionDirectory(hold.SessionID)
	if err != nil {
		return err
	}
	return writeJSONAtomic(directory, "hold.json", hold, 0o640)
}

func (m *Manager) effectiveRetentionLock(id string, immutable bool) (bool, *EvidenceHold, error) {
	hold, err := m.Store.ReadEvidenceHold(id)
	if errors.Is(err, os.ErrNotExist) {
		return immutable, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	return immutable || hold.Active, &hold, nil
}
