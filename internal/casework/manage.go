package casework

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

const maxDescriptionBytes = 2048

// Update renames a case or edits its description. expectedRevision zero skips
// the optimistic-concurrency check. A request that matches the stored values
// returns the case unchanged without a new timeline event.
func (s *Store) Update(caseID string, expectedRevision uint64, update Update, actor, reason string) (Case, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if update.Name == nil && update.Description == nil {
		return Case{}, false, errors.New("case update must include name or description")
	}
	if update.Name != nil {
		name := strings.TrimSpace(*update.Name)
		if err := validateText("case name", name, 1, 96); err != nil {
			return Case{}, false, err
		}
		update.Name = &name
	}
	if update.Description != nil {
		description := normalizeDescription(*update.Description)
		if err := validateDescription(description); err != nil {
			return Case{}, false, err
		}
		update.Description = &description
	}
	if err := validateText("case actor", actor, 1, 96); err != nil {
		return Case{}, false, err
	}
	current, err := s.read()
	if err != nil {
		return Case{}, false, err
	}
	index, item := findCase(current.Cases, caseID)
	if item == nil {
		return Case{}, false, os.ErrNotExist
	}
	if expectedRevision != 0 && item.Revision != expectedRevision {
		return Case{}, false, ErrRevisionChanged
	}
	changes := make([]string, 0, 2)
	if update.Name != nil && *update.Name != item.Name {
		changes = append(changes, "renamed")
	}
	if update.Description != nil && *update.Description != item.Description {
		changes = append(changes, "description edited")
	}
	if len(changes) == 0 {
		return *item, false, nil
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "Case " + strings.Join(changes, " and ")
	}
	if err := validateText("case reason", reason, 1, 512); err != nil {
		return Case{}, false, err
	}
	now := s.now()
	item.Revision++
	item.UpdatedAt = now
	if update.Name != nil {
		item.Name = *update.Name
	}
	if update.Description != nil {
		item.Description = *update.Description
	}
	if err := appendTimeline(item, "CASE_UPDATED", actor, reason, now); err != nil {
		return Case{}, false, err
	}
	if err := item.Validate(); err != nil {
		return Case{}, false, err
	}
	current.Cases[index] = *item
	if err := s.write(current); err != nil {
		return Case{}, false, err
	}
	return *item, true, nil
}

// RemoveEvidence detaches one evidence reference. A capture that the case
// hold currently protects cannot be removed: release the hold first so the
// host-side hold is lifted too. Removing evidence never deletes the artifact.
func (s *Store) RemoveEvidence(caseID, evidenceID string, expectedRevision uint64, actor, reason string) (Case, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !evidenceIDPattern.MatchString(evidenceID) {
		return Case{}, errors.New("evidence ID is invalid")
	}
	if err := validateText("case actor", actor, 1, 96); err != nil {
		return Case{}, err
	}
	current, err := s.read()
	if err != nil {
		return Case{}, err
	}
	index, item := findCase(current.Cases, caseID)
	if item == nil {
		return Case{}, os.ErrNotExist
	}
	if expectedRevision != 0 && item.Revision != expectedRevision {
		return Case{}, ErrRevisionChanged
	}
	if item.Status != StatusOpen {
		return Case{}, errors.New("closed cases cannot change evidence; reopen the case first")
	}
	position := -1
	for candidate, evidence := range item.Evidence {
		if evidence.ID == evidenceID {
			position = candidate
		}
	}
	if position < 0 {
		return Case{}, os.ErrNotExist
	}
	removed := item.Evidence[position]
	for _, result := range item.Hold.Results {
		if result.EvidenceID == evidenceID && result.Protected {
			return Case{}, fmt.Errorf("%w: this capture is protected by the case hold; release the hold before removing it", ErrHoldActive)
		}
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "Removed evidence " + removed.Label
		if len(reason) > 512 {
			reason = reason[:512]
		}
		reason = strings.TrimSpace(reason)
	}
	if err := validateText("case reason", reason, 1, 512); err != nil {
		return Case{}, err
	}
	now := s.now()
	item.Revision++
	item.UpdatedAt = now
	item.Evidence = append(append([]Evidence{}, item.Evidence[:position]...), item.Evidence[position+1:]...)
	if removed.Kind == EvidenceCapture && !item.Hold.UpdatedAt.IsZero() {
		results := make([]HoldResult, 0, len(item.Hold.Results))
		for _, result := range item.Hold.Results {
			if result.EvidenceID != evidenceID {
				results = append(results, result)
			}
		}
		item.Hold.Results = results
		if len(captureEvidenceMap(item.Evidence)) == 0 {
			item.Hold = Hold{State: HoldInactive, Results: []HoldResult{}}
		} else {
			item.Hold.State = aggregateHoldState(item.Hold)
		}
	}
	if err := appendTimeline(item, "EVIDENCE_REMOVED", actor, reason, now); err != nil {
		return Case{}, err
	}
	if err := item.Validate(); err != nil {
		return Case{}, err
	}
	current.Cases[index] = *item
	if err := s.write(current); err != nil {
		return Case{}, err
	}
	return *item, nil
}

// Delete removes a case record and its timeline. Evidence artifacts are not
// deleted. A case whose hold still protects any capture cannot be deleted:
// release the hold first so captures do not stay held by a missing case.
func (s *Store) Delete(caseID string, expectedRevision uint64) (Case, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.read()
	if err != nil {
		return Case{}, err
	}
	index, item := findCase(current.Cases, caseID)
	if item == nil {
		return Case{}, os.ErrNotExist
	}
	if expectedRevision != 0 && item.Revision != expectedRevision {
		return Case{}, ErrRevisionChanged
	}
	if item.Hold.DesiredActive || item.Hold.State != HoldInactive {
		return Case{}, fmt.Errorf("%w: release the case hold before deleting the case", ErrHoldActive)
	}
	for _, result := range item.Hold.Results {
		if result.Protected {
			return Case{}, fmt.Errorf("%w: release the case hold before deleting the case", ErrHoldActive)
		}
	}
	deleted := *item
	current.Cases = append(append([]Case{}, current.Cases[:index]...), current.Cases[index+1:]...)
	if err := s.write(current); err != nil {
		return Case{}, err
	}
	return deleted, nil
}

func aggregateHoldState(hold Hold) HoldState {
	for _, result := range hold.Results {
		if result.Protected != hold.DesiredActive || result.Failure != "" {
			return HoldPartial
		}
	}
	if hold.DesiredActive {
		return HoldActive
	}
	return HoldInactive
}

// normalizeDescription accepts multi-line descriptions: CRLF becomes LF and
// surrounding whitespace is trimmed.
func normalizeDescription(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	return strings.TrimSpace(value)
}

// validateDescription allows newlines and tabs but no other control
// characters.
func validateDescription(value string) error {
	if len(value) > maxDescriptionBytes || value != strings.TrimSpace(value) {
		return fmt.Errorf("case description must contain at most %d trimmed bytes", maxDescriptionBytes)
	}
	for _, char := range value {
		if (char < 0x20 && char != '\n' && char != '\t') || char == 0x7f {
			return errors.New("case description contains a control character")
		}
	}
	return nil
}

func validateQueryPin(kind EvidenceKind, pin *QuerySnapshotPin) error {
	if kind != EvidenceQuerySnapshot {
		if pin != nil {
			return errors.New("only query snapshot evidence carries a pinned query")
		}
		return nil
	}
	if pin == nil {
		return errors.New("query snapshot evidence must pin its canonical query and dataset watermark")
	}
	if len(pin.CanonicalQuery) > 2048 || strings.ContainsAny(pin.CanonicalQuery, "\x00\r\n") || pin.MatchedCount < 0 || pin.CountRelation != "eq" && pin.CountRelation != "gte" || pin.SnapshotCreatedAt.IsZero() || !validSHA(pin.SnapshotSHA256) || pin.DatasetWatermark.IngestSequence < 0 || pin.DatasetWatermark.ReceivedAt.IsZero() || !validSHA(pin.DatasetWatermark.RecordID) {
		return errors.New("query snapshot pin is invalid")
	}
	if pin.QueryAnchor != nil && pin.QueryAnchor.IsZero() {
		return errors.New("query snapshot anchor is invalid")
	}
	return nil
}

func cloneQueryPin(pin *QuerySnapshotPin) *QuerySnapshotPin {
	if pin == nil {
		return nil
	}
	copy := *pin
	copy.SnapshotCreatedAt = copy.SnapshotCreatedAt.UTC()
	copy.DatasetWatermark.ReceivedAt = copy.DatasetWatermark.ReceivedAt.UTC()
	if pin.QueryAnchor != nil {
		anchor := pin.QueryAnchor.UTC()
		copy.QueryAnchor = &anchor
	}
	return &copy
}
