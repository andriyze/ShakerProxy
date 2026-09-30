package inventory

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"
)

var ErrAddressAliasRevisionConflict = errors.New("address alias revision conflict")

func (s *Store) CreateAddressAlias(actor, operationID string, input AddressAliasInput) (AddressAliasMutationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateMutationIdentity(actor, operationID); err != nil {
		return AddressAliasMutationResult{}, fmt.Errorf("%w: %v", ErrMutationRejected, err)
	}
	normalized, err := normalizeAddressAliasInput(input)
	if err != nil {
		return AddressAliasMutationResult{}, fmt.Errorf("%w: %v", ErrMutationRejected, err)
	}
	requestSHA256, err := mutationRequestDigest(AuditAddressAliasCreated, nil, normalized)
	if err != nil {
		return AddressAliasMutationResult{}, err
	}
	doc, err := s.load()
	if err != nil {
		return AddressAliasMutationResult{}, err
	}
	if replay, found, replayErr := addressAliasMutationReplay(doc, operationID, AuditAddressAliasCreated, nil, requestSHA256); found || replayErr != nil {
		return replay, replayErr
	}
	if len(doc.AddressAliases) >= MaxAddressAliases {
		return AddressAliasMutationResult{}, newCapacityError("the maximum of %d address aliases is reached; delete unused aliases first", MaxAddressAliases)
	}
	id, err := s.newUniqueAddressAliasID(doc.AddressAliases)
	if err != nil {
		return AddressAliasMutationResult{}, err
	}
	now := s.now()
	alias := addressAliasFromInput(id, 1, actor, now, normalized)
	if err := validateAddressAlias(alias); err != nil {
		return AddressAliasMutationResult{}, err
	}
	doc.AddressAliases = append(doc.AddressAliases, alias)
	sortAddressAliases(doc.AddressAliases)
	audit := newAddressAliasAuditEvent(operationID, requestSHA256, AuditAddressAliasCreated, actor, now, nil, []string{id}, []string{"address alias created"})
	if err := appendAudit(&doc, &audit); err != nil {
		return AddressAliasMutationResult{}, err
	}
	doc.UpdatedAt = now
	if err := s.save(doc); err != nil {
		return AddressAliasMutationResult{}, err
	}
	alias = annotatedAddressAlias(doc, id)
	return AddressAliasMutationResult{Schema: SchemaVersion, Alias: alias, Audit: audit}, nil
}

func (s *Store) UpdateAddressAlias(id, actor, operationID string, update AddressAliasUpdate) (AddressAliasMutationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ValidAddressAliasID(id) {
		return AddressAliasMutationResult{}, fmt.Errorf("%w: invalid address alias ID", ErrMutationRejected)
	}
	if err := validateMutationIdentity(actor, operationID); err != nil {
		return AddressAliasMutationResult{}, fmt.Errorf("%w: %v", ErrMutationRejected, err)
	}
	normalized, err := normalizeAddressAliasInput(update.AddressAliasInput)
	if err != nil {
		return AddressAliasMutationResult{}, fmt.Errorf("%w: %v", ErrMutationRejected, err)
	}
	update.AddressAliasInput = normalized
	requestSHA256, err := mutationRequestDigest(AuditAddressAliasUpdated, nil, struct {
		ID string `json:"id"`
		AddressAliasUpdate
	}{ID: id, AddressAliasUpdate: update})
	if err != nil {
		return AddressAliasMutationResult{}, err
	}
	doc, err := s.load()
	if err != nil {
		return AddressAliasMutationResult{}, err
	}
	sourceIDs := []string{id}
	if replay, found, replayErr := addressAliasMutationReplay(doc, operationID, AuditAddressAliasUpdated, sourceIDs, requestSHA256); found || replayErr != nil {
		return replay, replayErr
	}
	index := addressAliasIndex(doc.AddressAliases, id)
	if index < 0 {
		return AddressAliasMutationResult{}, os.ErrNotExist
	}
	previous := doc.AddressAliases[index]
	if previous.Revision != update.ExpectedRevision {
		return AddressAliasMutationResult{}, ErrAddressAliasRevisionConflict
	}
	changes := addressAliasChanges(previous, normalized)
	if len(changes) == 0 {
		return AddressAliasMutationResult{Schema: SchemaVersion, Alias: annotatedAddressAlias(doc, id), Unchanged: true}, nil
	}
	now := s.now()
	alias := addressAliasFromInput(id, previous.Revision+1, actor, now, normalized)
	alias.CreatedAt, alias.CreatedBy = previous.CreatedAt, previous.CreatedBy
	if err := validateAddressAlias(alias); err != nil {
		return AddressAliasMutationResult{}, err
	}
	doc.AddressAliases[index] = alias
	sortAddressAliases(doc.AddressAliases)
	audit := newAddressAliasAuditEvent(operationID, requestSHA256, AuditAddressAliasUpdated, actor, now, sourceIDs, sourceIDs, changes)
	if err := appendAudit(&doc, &audit); err != nil {
		return AddressAliasMutationResult{}, err
	}
	doc.UpdatedAt = now
	if err := s.save(doc); err != nil {
		return AddressAliasMutationResult{}, err
	}
	alias = annotatedAddressAlias(doc, id)
	return AddressAliasMutationResult{Schema: SchemaVersion, Alias: alias, Audit: audit}, nil
}

// ListAddressAliases returns every manual address alias with conflict
// annotations, ordered like resolution ranks them.
func (s *Store) ListAddressAliases() ([]AddressAlias, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := s.load()
	if err != nil {
		return nil, err
	}
	aliases := append([]AddressAlias{}, doc.AddressAliases...)
	annotateAddressAliasConflicts(aliases, doc.Devices)
	return aliases, nil
}

// DeleteAddressAlias removes a manual address alias and records the removal in
// the device audit ledger. expectedRevision guards against deleting an alias
// that changed after the caller loaded it; zero skips the check.
func (s *Store) DeleteAddressAlias(id, actor, operationID string, expectedRevision uint64, reason string) (AddressAliasMutationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ValidAddressAliasID(id) {
		return AddressAliasMutationResult{}, fmt.Errorf("%w: invalid address alias ID", ErrMutationRejected)
	}
	if err := validateMutationIdentity(actor, operationID); err != nil {
		return AddressAliasMutationResult{}, fmt.Errorf("%w: %v", ErrMutationRejected, err)
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "address alias deleted"
	}
	if !validSingleLine(reason, 1, 128) {
		return AddressAliasMutationResult{}, fmt.Errorf("%w: deletion reason must be a single line of at most 128 characters", ErrMutationRejected)
	}
	requestSHA256, err := mutationRequestDigest(AuditAddressAliasDeleted, nil, struct {
		ID               string `json:"id"`
		ExpectedRevision uint64 `json:"expected_revision"`
	}{id, expectedRevision})
	if err != nil {
		return AddressAliasMutationResult{}, err
	}
	doc, err := s.load()
	if err != nil {
		return AddressAliasMutationResult{}, err
	}
	for _, event := range doc.AuditEvents {
		if event.OperationID != operationID {
			continue
		}
		if event.Action != AuditAddressAliasDeleted || !sameStrings(event.SourceAddressAliasIDs, []string{id}) || event.RequestSHA256 != requestSHA256 {
			return AddressAliasMutationResult{}, ErrOperationConflict
		}
		return AddressAliasMutationResult{Schema: SchemaVersion, Alias: AddressAlias{Schema: SchemaVersion, ID: id}, Audit: event, Replayed: true, Deleted: true}, nil
	}
	index := addressAliasIndex(doc.AddressAliases, id)
	if index < 0 {
		return AddressAliasMutationResult{}, os.ErrNotExist
	}
	removed := doc.AddressAliases[index]
	if expectedRevision != 0 && removed.Revision != expectedRevision {
		return AddressAliasMutationResult{}, ErrAddressAliasRevisionConflict
	}
	doc.AddressAliases = append(append([]AddressAlias(nil), doc.AddressAliases[:index]...), doc.AddressAliases[index+1:]...)
	now := s.now()
	audit := newAddressAliasAuditEvent(operationID, requestSHA256, AuditAddressAliasDeleted, actor, now, []string{id}, nil, []string{reason})
	if err := appendAudit(&doc, &audit); err != nil {
		return AddressAliasMutationResult{}, err
	}
	doc.UpdatedAt = now
	if err := s.save(doc); err != nil {
		return AddressAliasMutationResult{}, err
	}
	removed.Conflict, removed.ConflictWarnings = false, nil
	return AddressAliasMutationResult{Schema: SchemaVersion, Alias: removed, Audit: audit, Deleted: true}, nil
}

func (s *Store) ResolveAddressAlias(address netip.Addr, interfaceName string, vlanID *int, occurredAt time.Time) (AddressAliasResolution, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	interfaceName = strings.TrimSpace(interfaceName)
	address = address.Unmap()
	if !address.IsValid() || !interfaceScopePattern.MatchString(interfaceName) || occurredAt.IsZero() || vlanID != nil && (*vlanID < 1 || *vlanID > 4094) {
		return AddressAliasResolution{}, errors.New("address alias lookup scope is invalid")
	}
	doc, err := s.load()
	if err != nil {
		return AddressAliasResolution{}, err
	}
	candidates := make([]AddressAlias, 0)
	for _, alias := range doc.AddressAliases {
		prefix, _ := netip.ParsePrefix(alias.Prefix)
		if alias.Interface != interfaceName || alias.VLANID != nil && (vlanID == nil || *alias.VLANID != *vlanID) || !prefix.Contains(address) || occurredAt.Before(alias.ValidFrom) || alias.ValidUntil != nil && !occurredAt.Before(*alias.ValidUntil) {
			continue
		}
		candidates = append(candidates, alias)
	}
	sort.Slice(candidates, func(i, j int) bool { return addressAliasRanksBefore(candidates[i], candidates[j]) })
	result := AddressAliasResolution{Schema: SchemaVersion, Address: address.String(), Interface: interfaceName, VLANID: cloneInt(vlanID), OccurredAt: occurredAt.UTC(), Candidates: candidates}
	if len(candidates) == 0 {
		return result, nil
	}
	result.Matched = true
	if len(candidates) > 1 && sameAddressAliasRank(candidates[0], candidates[1]) && candidates[0].Name != candidates[1].Name {
		result.Conflict = true
		return result, nil
	}
	winner := candidates[0]
	result.Alias = &winner
	return result, nil
}

func normalizeAddressAliasInput(input AddressAliasInput) (AddressAliasInput, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.Prefix = strings.TrimSpace(input.Prefix)
	input.Interface = strings.TrimSpace(input.Interface)
	input.Reason = strings.TrimSpace(input.Reason)
	if !validSingleLine(input.Name, 1, 128) || !interfaceScopePattern.MatchString(input.Interface) || !validSingleLine(input.Reason, 1, 256) {
		return AddressAliasInput{}, errors.New("address alias name, interface, or reason is invalid")
	}
	prefix, err := parseAddressAliasPrefix(input.Prefix)
	if err != nil {
		return AddressAliasInput{}, err
	}
	input.Prefix = prefix.String()
	if input.ValidFrom.IsZero() {
		return AddressAliasInput{}, errors.New("address alias valid_from is required")
	}
	input.ValidFrom = input.ValidFrom.UTC()
	if input.ValidUntil != nil {
		validUntil := input.ValidUntil.UTC()
		if !validUntil.After(input.ValidFrom) {
			return AddressAliasInput{}, errors.New("address alias valid_until must be after valid_from")
		}
		input.ValidUntil = &validUntil
	}
	if input.VLANID != nil {
		vlanID := *input.VLANID
		if vlanID < 1 || vlanID > 4094 {
			return AddressAliasInput{}, errors.New("address alias VLAN ID must be between 1 and 4094")
		}
		input.VLANID = &vlanID
	}
	if input.Priority < 0 || input.Priority > 1000 || input.Confidence < 1 || input.Confidence > 100 {
		return AddressAliasInput{}, errors.New("address alias priority or confidence is invalid")
	}
	return input, nil
}

func validateAddressAlias(alias AddressAlias) error {
	if alias.Schema != SchemaVersion || !ValidAddressAliasID(alias.ID) || alias.Revision < 1 || !validSingleLine(alias.CreatedBy, 1, 96) || !validSingleLine(alias.UpdatedBy, 1, 96) || alias.CreatedAt.IsZero() || alias.UpdatedAt.Before(alias.CreatedAt) || alias.Conflict || len(alias.ConflictWarnings) != 0 {
		return errors.New("address alias identity or audit fields are invalid")
	}
	normalized, err := normalizeAddressAliasInput(AddressAliasInput{Name: alias.Name, Prefix: alias.Prefix, Interface: alias.Interface, VLANID: alias.VLANID, ValidFrom: alias.ValidFrom, ValidUntil: alias.ValidUntil, Priority: alias.Priority, Confidence: alias.Confidence, Reason: alias.Reason})
	if err != nil || normalized.Name != alias.Name || normalized.Prefix != alias.Prefix || normalized.Interface != alias.Interface || !sameOptionalInt(normalized.VLANID, alias.VLANID) || !normalized.ValidFrom.Equal(alias.ValidFrom) || !sameOptionalTime(normalized.ValidUntil, alias.ValidUntil) || normalized.Priority != alias.Priority || normalized.Confidence != alias.Confidence || normalized.Reason != alias.Reason {
		return errors.New("address alias scope is invalid")
	}
	return nil
}

func parseAddressAliasPrefix(value string) (netip.Prefix, error) {
	if address, err := netip.ParseAddr(value); err == nil {
		address = address.Unmap()
		bits := 128
		if address.Is4() {
			bits = 32
		}
		return netip.PrefixFrom(address, bits), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, errors.New("address alias prefix must be an IPv4/IPv6 address or CIDR")
	}
	prefix = prefix.Masked()
	if prefix.Addr().Is4In6() {
		return netip.Prefix{}, errors.New("address alias prefix must use canonical IPv4 notation")
	}
	return prefix, nil
}

func addressAliasFromInput(id string, revision uint64, actor string, now time.Time, input AddressAliasInput) AddressAlias {
	return AddressAlias{Schema: SchemaVersion, ID: id, Revision: revision, Name: input.Name, Prefix: input.Prefix, Interface: input.Interface, VLANID: cloneInt(input.VLANID), ValidFrom: input.ValidFrom, ValidUntil: cloneTime(input.ValidUntil), Priority: input.Priority, Confidence: input.Confidence, Reason: input.Reason, CreatedBy: actor, UpdatedBy: actor, CreatedAt: now.UTC(), UpdatedAt: now.UTC()}
}

func addressAliasMutationReplay(doc document, operationID string, action AuditAction, sourceIDs []string, requestSHA256 string) (AddressAliasMutationResult, bool, error) {
	for _, event := range doc.AuditEvents {
		if event.OperationID != operationID {
			continue
		}
		if event.Action != action || !sameStrings(event.SourceAddressAliasIDs, sourceIDs) || event.RequestSHA256 != requestSHA256 || len(event.ResultAddressAliasIDs) != 1 {
			return AddressAliasMutationResult{}, true, ErrOperationConflict
		}
		index := addressAliasIndex(doc.AddressAliases, event.ResultAddressAliasIDs[0])
		if index < 0 {
			return AddressAliasMutationResult{}, true, errors.New("address alias audit result is unavailable")
		}
		alias := annotatedAddressAlias(doc, event.ResultAddressAliasIDs[0])
		return AddressAliasMutationResult{Schema: SchemaVersion, Alias: alias, Audit: event, Replayed: true}, true, nil
	}
	return AddressAliasMutationResult{}, false, nil
}

func newAddressAliasAuditEvent(operationID, requestSHA256 string, action AuditAction, actor string, occurredAt time.Time, sourceIDs, resultIDs, changes []string) AuditEvent {
	event := newAuditEvent(operationID, requestSHA256, action, actor, occurredAt, nil, nil, changes)
	event.SourceAddressAliasIDs = append([]string(nil), sourceIDs...)
	event.ResultAddressAliasIDs = append([]string(nil), resultIDs...)
	return event
}

func addressAliasChanges(previous AddressAlias, next AddressAliasInput) []string {
	changes := make([]string, 0, 9)
	if previous.Name != next.Name {
		changes = append(changes, "address alias name changed")
	}
	if previous.Prefix != next.Prefix {
		changes = append(changes, "address alias prefix changed")
	}
	if previous.Interface != next.Interface {
		changes = append(changes, "address alias interface changed")
	}
	if !sameOptionalInt(previous.VLANID, next.VLANID) {
		changes = append(changes, "address alias VLAN changed")
	}
	if !previous.ValidFrom.Equal(next.ValidFrom) || !sameOptionalTime(previous.ValidUntil, next.ValidUntil) {
		changes = append(changes, "address alias validity changed")
	}
	if previous.Priority != next.Priority {
		changes = append(changes, "address alias priority changed")
	}
	if previous.Confidence != next.Confidence {
		changes = append(changes, "address alias confidence changed")
	}
	if previous.Reason != next.Reason {
		changes = append(changes, "address alias reason changed")
	}
	return changes
}

func annotateAddressAliasConflicts(aliases []AddressAlias, devices []Device) {
	for index := range aliases {
		aliases[index].Conflict, aliases[index].ConflictWarnings = false, nil
		prefix, _ := netip.ParsePrefix(aliases[index].Prefix)
		for otherIndex := range aliases {
			if index == otherIndex || aliases[index].Name == aliases[otherIndex].Name || !addressAliasScopesOverlap(aliases[index], aliases[otherIndex]) {
				continue
			}
			otherPrefix, _ := netip.ParsePrefix(aliases[otherIndex].Prefix)
			if prefix.Contains(otherPrefix.Addr()) || otherPrefix.Contains(prefix.Addr()) {
				addAddressAliasWarning(&aliases[index], "Overlaps a differently named manual alias in the same interface, VLAN, and time scope")
				break
			}
		}
		for _, device := range devices {
			for _, observation := range device.Addresses {
				address, err := netip.ParseAddr(observation.Address)
				if err == nil && prefix.Contains(address) && timeRangesOverlap(aliases[index].ValidFrom, aliases[index].ValidUntil, observation.ValidFrom, &observation.ValidUntil) {
					if observation.Interface != "" {
						if aliases[index].Interface != observation.Interface || aliases[index].VLANID != nil && (observation.VLANID == nil || *aliases[index].VLANID != *observation.VLANID) {
							continue
						}
						addAddressAliasWarning(&aliases[index], "Overlaps observed device attribution in the same interface, VLAN, and time scope")
					} else {
						addAddressAliasWarning(&aliases[index], "Overlaps observed device attribution; legacy lease evidence lacks interface/VLAN scope, so the conflict cannot be dismissed automatically")
					}
					break
				}
			}
		}
	}
}

func annotatedAddressAlias(doc document, id string) AddressAlias {
	aliases := append([]AddressAlias(nil), doc.AddressAliases...)
	annotateAddressAliasConflicts(aliases, doc.Devices)
	index := addressAliasIndex(aliases, id)
	if index < 0 {
		return AddressAlias{}
	}
	return aliases[index]
}

func addAddressAliasWarning(alias *AddressAlias, warning string) {
	alias.Conflict = true
	for _, existing := range alias.ConflictWarnings {
		if existing == warning {
			return
		}
	}
	if len(alias.ConflictWarnings) < MaxWarnings {
		alias.ConflictWarnings = append(alias.ConflictWarnings, warning)
	}
}

func addressAliasScopesOverlap(left, right AddressAlias) bool {
	if left.Interface != right.Interface || left.VLANID != nil && right.VLANID != nil && *left.VLANID != *right.VLANID {
		return false
	}
	return timeRangesOverlap(left.ValidFrom, left.ValidUntil, right.ValidFrom, right.ValidUntil)
}

func timeRangesOverlap(leftStart time.Time, leftEnd *time.Time, rightStart time.Time, rightEnd *time.Time) bool {
	return (rightEnd == nil || leftStart.Before(*rightEnd)) && (leftEnd == nil || rightStart.Before(*leftEnd))
}

func addressAliasRanksBefore(left, right AddressAlias) bool {
	leftPrefix, _ := netip.ParsePrefix(left.Prefix)
	rightPrefix, _ := netip.ParsePrefix(right.Prefix)
	if leftPrefix.Bits() != rightPrefix.Bits() {
		return leftPrefix.Bits() > rightPrefix.Bits()
	}
	if (left.VLANID != nil) != (right.VLANID != nil) {
		return left.VLANID != nil
	}
	if left.Priority != right.Priority {
		return left.Priority > right.Priority
	}
	if left.Confidence != right.Confidence {
		return left.Confidence > right.Confidence
	}
	if !left.UpdatedAt.Equal(right.UpdatedAt) {
		return left.UpdatedAt.After(right.UpdatedAt)
	}
	return left.ID < right.ID
}

func sameAddressAliasRank(left, right AddressAlias) bool {
	leftPrefix, _ := netip.ParsePrefix(left.Prefix)
	rightPrefix, _ := netip.ParsePrefix(right.Prefix)
	return leftPrefix.Bits() == rightPrefix.Bits() && (left.VLANID != nil) == (right.VLANID != nil) && left.Priority == right.Priority && left.Confidence == right.Confidence
}

func sortAddressAliases(aliases []AddressAlias) {
	sort.Slice(aliases, func(i, j int) bool {
		if aliases[i].UpdatedAt.Equal(aliases[j].UpdatedAt) {
			return aliases[i].ID < aliases[j].ID
		}
		return aliases[i].UpdatedAt.After(aliases[j].UpdatedAt)
	})
}

func addressAliasIndex(aliases []AddressAlias, id string) int {
	for index := range aliases {
		if aliases[index].ID == id {
			return index
		}
	}
	return -1
}

func sameOptionalInt(left, right *int) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}
func sameOptionalTime(left, right *time.Time) bool {
	return left == nil && right == nil || left != nil && right != nil && left.Equal(*right)
}
func cloneInt(value *int) *int {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := value.UTC()
	return &cloned
}
