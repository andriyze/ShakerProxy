package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"
)

var (
	ErrMutationRejected      = errors.New("device mutation is invalid")
	ErrOperationConflict     = errors.New("device mutation operation conflicts with an existing audit record")
	ErrAliasRevisionConflict = errors.New("device alias revision conflict")
)

func (s *Store) UpdateMetadata(deviceID, actor, operationID string, metadata DeviceMetadata) (MutationResult, error) {
	return s.PatchMetadata(deviceID, actor, operationID, DeviceMetadataPatch{
		FriendlyName: &metadata.FriendlyName, Owner: &metadata.Owner, Location: &metadata.Location,
		Category: &metadata.Category, Icon: &metadata.Icon, Tags: &metadata.Tags, Notes: &metadata.Notes,
	})
}

func (s *Store) PatchMetadata(deviceID, actor, operationID string, patch DeviceMetadataPatch) (MutationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ValidDeviceID(deviceID) {
		return MutationResult{}, fmt.Errorf("%w: invalid device ID", ErrMutationRejected)
	}
	if err := validateMutationIdentity(actor, operationID); err != nil {
		return MutationResult{}, fmt.Errorf("%w: %v", ErrMutationRejected, err)
	}
	patch, err := normalizeMetadataPatch(patch)
	if err != nil {
		return MutationResult{}, fmt.Errorf("%w: %v", ErrMutationRejected, err)
	}
	requestSHA256, err := mutationRequestDigest(AuditMetadataUpdated, []string{deviceID}, patch)
	if err != nil {
		return MutationResult{}, err
	}
	doc, err := s.load()
	if err != nil {
		return MutationResult{}, err
	}
	replay, found, replayErr := mutationReplay(doc, operationID, AuditMetadataUpdated, []string{deviceID}, requestSHA256)
	if found && replayErr != nil && patch.Location == nil && patch.Category == nil && patch.Icon == nil {
		legacyPayload := applyMetadataPatch(DeviceMetadata{}, patch)
		legacySHA256, digestErr := mutationRequestDigest(AuditMetadataUpdated, []string{deviceID}, legacyPayload)
		if digestErr != nil {
			return MutationResult{}, digestErr
		}
		if legacyReplay, legacyFound, legacyErr := mutationReplay(doc, operationID, AuditMetadataUpdated, []string{deviceID}, legacySHA256); legacyFound {
			return legacyReplay, legacyErr
		}
	}
	if found || replayErr != nil {
		return replay, replayErr
	}
	index := deviceIndex(doc.Devices, deviceID)
	if index < 0 {
		return MutationResult{}, os.ErrNotExist
	}
	device := &doc.Devices[index]
	metadata := applyMetadataPatch(DeviceMetadata{
		FriendlyName: device.FriendlyName, Owner: device.Owner, Location: device.Location,
		Category: device.Category, Icon: device.Icon, Tags: append([]string(nil), device.Tags...), Notes: device.Notes,
	}, patch)
	changes := metadataChanges(*device, metadata)
	if len(changes) == 0 {
		refreshFriendlyNameConflicts(doc.Devices)
		return MutationResult{Schema: SchemaVersion, Devices: []Device{projectDevice(*device)}, Unchanged: true}, nil
	}
	now := s.now()
	if device.FriendlyName != metadata.FriendlyName {
		if err := appendAliasChange(device, metadata.FriendlyName, actor, "Administrator metadata update", now); err != nil {
			return MutationResult{}, fmt.Errorf("%w: %v", ErrMutationRejected, err)
		}
	}
	device.Owner, device.Location, device.Category, device.Icon = metadata.Owner, metadata.Location, metadata.Category, metadata.Icon
	device.Tags, device.Notes = append([]string(nil), metadata.Tags...), metadata.Notes
	refreshFriendlyNameConflicts(doc.Devices)
	if err := validateDevice(*device); err != nil {
		return MutationResult{}, err
	}
	audit := newAuditEvent(operationID, requestSHA256, AuditMetadataUpdated, actor, now, []string{deviceID}, []string{deviceID}, changes)
	if err := appendAudit(&doc, &audit); err != nil {
		return MutationResult{}, err
	}
	doc.UpdatedAt = audit.OccurredAt
	if err := s.save(doc); err != nil {
		return MutationResult{}, err
	}
	return MutationResult{Schema: SchemaVersion, Devices: []Device{projectDevice(*device)}, Audit: audit}, nil
}

func normalizeMetadataPatch(patch DeviceMetadataPatch) (DeviceMetadataPatch, error) {
	if patch.FriendlyName == nil && patch.Owner == nil && patch.Location == nil && patch.Category == nil && patch.Icon == nil && patch.Tags == nil && patch.Notes == nil {
		return DeviceMetadataPatch{}, errors.New("device metadata patch is empty")
	}
	metadata := applyMetadataPatch(DeviceMetadata{}, patch)
	normalized, err := normalizeMetadata(metadata)
	if err != nil {
		return DeviceMetadataPatch{}, err
	}
	if patch.FriendlyName != nil {
		patch.FriendlyName = &normalized.FriendlyName
	}
	if patch.Owner != nil {
		patch.Owner = &normalized.Owner
	}
	if patch.Location != nil {
		patch.Location = &normalized.Location
	}
	if patch.Category != nil {
		patch.Category = &normalized.Category
	}
	if patch.Icon != nil {
		patch.Icon = &normalized.Icon
	}
	if patch.Tags != nil {
		tags := append([]string(nil), normalized.Tags...)
		patch.Tags = &tags
	}
	if patch.Notes != nil {
		patch.Notes = &normalized.Notes
	}
	return patch, nil
}

func applyMetadataPatch(metadata DeviceMetadata, patch DeviceMetadataPatch) DeviceMetadata {
	if patch.FriendlyName != nil {
		metadata.FriendlyName = *patch.FriendlyName
	}
	if patch.Owner != nil {
		metadata.Owner = *patch.Owner
	}
	if patch.Location != nil {
		metadata.Location = *patch.Location
	}
	if patch.Category != nil {
		metadata.Category = *patch.Category
	}
	if patch.Icon != nil {
		metadata.Icon = *patch.Icon
	}
	if patch.Tags != nil {
		metadata.Tags = append([]string(nil), (*patch.Tags)...)
	}
	if patch.Notes != nil {
		metadata.Notes = *patch.Notes
	}
	return metadata
}

func (s *Store) UpdateAlias(deviceID, actor, operationID string, update AliasUpdate) (MutationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ValidDeviceID(deviceID) {
		return MutationResult{}, fmt.Errorf("%w: invalid device ID", ErrMutationRejected)
	}
	if err := validateMutationIdentity(actor, operationID); err != nil {
		return MutationResult{}, fmt.Errorf("%w: %v", ErrMutationRejected, err)
	}
	update.FriendlyName = normalizeFriendlyName(update.FriendlyName)
	update.Reason = strings.TrimSpace(update.Reason)
	if !validFriendlyName(update.FriendlyName) || !validSingleLine(update.Reason, 1, 256) {
		return MutationResult{}, fmt.Errorf("%w: alias name or reason is invalid", ErrMutationRejected)
	}
	requestSHA256, err := mutationRequestDigest(AuditAliasUpdated, []string{deviceID}, update)
	if err != nil {
		return MutationResult{}, err
	}
	doc, err := s.load()
	if err != nil {
		return MutationResult{}, err
	}
	if replay, found, replayErr := mutationReplay(doc, operationID, AuditAliasUpdated, []string{deviceID}, requestSHA256); found || replayErr != nil {
		return replay, replayErr
	}
	index := deviceIndex(doc.Devices, deviceID)
	if index < 0 {
		return MutationResult{}, os.ErrNotExist
	}
	device := &doc.Devices[index]
	if device.AliasRevision != update.ExpectedRevision {
		return MutationResult{}, ErrAliasRevisionConflict
	}
	if device.FriendlyName == update.FriendlyName {
		refreshFriendlyNameConflicts(doc.Devices)
		return MutationResult{Schema: SchemaVersion, Devices: []Device{projectDevice(*device)}, Unchanged: true}, nil
	}
	now := s.now()
	if err := appendAliasChange(device, update.FriendlyName, actor, update.Reason, now); err != nil {
		return MutationResult{}, fmt.Errorf("%w: %v", ErrMutationRejected, err)
	}
	refreshFriendlyNameConflicts(doc.Devices)
	if err := validateDevice(*device); err != nil {
		return MutationResult{}, err
	}
	audit := newAuditEvent(operationID, requestSHA256, AuditAliasUpdated, actor, now, []string{deviceID}, []string{deviceID}, []string{"friendly name changed"})
	if err := appendAudit(&doc, &audit); err != nil {
		return MutationResult{}, err
	}
	doc.UpdatedAt = now
	if err := s.save(doc); err != nil {
		return MutationResult{}, err
	}
	return MutationResult{Schema: SchemaVersion, Devices: []Device{projectDevice(*device)}, Audit: audit}, nil
}

func appendAliasChange(device *Device, friendlyName, actor, reason string, changedAt time.Time) error {
	if device == nil || !validFriendlyName(friendlyName) || !validSingleLine(actor, 1, 96) || !validSingleLine(reason, 1, 256) || changedAt.IsZero() || device.FriendlyName == friendlyName || device.AliasRevision == math.MaxUint64 {
		return errors.New("device alias change is invalid")
	}
	change := AliasChange{Revision: device.AliasRevision + 1, FriendlyName: friendlyName, PreviousFriendlyName: device.FriendlyName, Actor: actor, Reason: reason, ChangedAt: changedAt.UTC()}
	device.AliasRevision = change.Revision
	device.FriendlyName = friendlyName
	device.AliasHistory = append(device.AliasHistory, change)
	if len(device.AliasHistory) > MaxAliasHistory {
		device.AliasHistory = append([]AliasChange(nil), device.AliasHistory[len(device.AliasHistory)-MaxAliasHistory:]...)
		device.AliasHistoryTruncated = true
	}
	return nil
}

func (s *Store) MergeDevices(targetDeviceID, sourceDeviceID, actor, operationID string) (MutationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ValidDeviceID(targetDeviceID) || !ValidDeviceID(sourceDeviceID) || targetDeviceID == sourceDeviceID {
		return MutationResult{}, fmt.Errorf("%w: device merge identities are invalid", ErrMutationRejected)
	}
	if err := validateMutationIdentity(actor, operationID); err != nil {
		return MutationResult{}, fmt.Errorf("%w: %v", ErrMutationRejected, err)
	}
	sources := []string{targetDeviceID, sourceDeviceID}
	requestSHA256, err := mutationRequestDigest(AuditDevicesMerged, sources, nil)
	if err != nil {
		return MutationResult{}, err
	}
	doc, err := s.load()
	if err != nil {
		return MutationResult{}, err
	}
	if replay, found, replayErr := mutationReplay(doc, operationID, AuditDevicesMerged, sources, requestSHA256); found || replayErr != nil {
		return replay, replayErr
	}
	targetIndex, sourceIndex := deviceIndex(doc.Devices, targetDeviceID), deviceIndex(doc.Devices, sourceDeviceID)
	if targetIndex < 0 || sourceIndex < 0 {
		return MutationResult{}, os.ErrNotExist
	}
	now := s.now()
	target := doc.Devices[targetIndex]
	source := doc.Devices[sourceIndex]
	previousFriendlyName := target.FriendlyName
	changes, err := mergeDeviceEvidence(&target, source)
	if err != nil {
		return MutationResult{}, fmt.Errorf("%w: %v", ErrMutationRejected, err)
	}
	if target.FriendlyName != previousFriendlyName {
		adoptedFriendlyName := target.FriendlyName
		target.FriendlyName = previousFriendlyName
		if err := appendAliasChange(&target, adoptedFriendlyName, actor, "Adopted while merging device records", now); err != nil {
			return MutationResult{}, fmt.Errorf("%w: %v", ErrMutationRejected, err)
		}
		changes = append(changes, "friendly name adopted")
	}
	target.LastReconciled = now
	if err := applyVendor(&target, s.Vendors, target.LastReconciled); err != nil {
		return MutationResult{}, fmt.Errorf("enrich merged device vendor: %w", err)
	}
	if err := validateDevice(target); err != nil {
		return MutationResult{}, err
	}
	devices := make([]Device, 0, len(doc.Devices)-1)
	for _, device := range doc.Devices {
		switch device.ID {
		case targetDeviceID:
			devices = append(devices, target)
		case sourceDeviceID:
			continue
		default:
			devices = append(devices, device)
		}
	}
	doc.Devices = devices
	refreshFriendlyNameConflicts(doc.Devices)
	sortDevices(doc.Devices)
	target = doc.Devices[deviceIndex(doc.Devices, targetDeviceID)]
	audit := newAuditEvent(operationID, requestSHA256, AuditDevicesMerged, actor, now, sources, []string{targetDeviceID}, changes)
	if err := appendAudit(&doc, &audit); err != nil {
		return MutationResult{}, err
	}
	doc.UpdatedAt = audit.OccurredAt
	if err := s.save(doc); err != nil {
		return MutationResult{}, err
	}
	return MutationResult{Schema: SchemaVersion, Devices: []Device{projectDevice(target)}, Audit: audit}, nil
}

func (s *Store) SplitDevice(sourceDeviceID, actor, operationID string, selection SplitSelection) (MutationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ValidDeviceID(sourceDeviceID) {
		return MutationResult{}, fmt.Errorf("%w: invalid device ID", ErrMutationRejected)
	}
	if err := validateMutationIdentity(actor, operationID); err != nil {
		return MutationResult{}, fmt.Errorf("%w: %v", ErrMutationRejected, err)
	}
	selection, err := normalizeSplitSelection(selection)
	if err != nil {
		return MutationResult{}, fmt.Errorf("%w: %v", ErrMutationRejected, err)
	}
	requestSHA256, err := mutationRequestDigest(AuditDeviceSplit, []string{sourceDeviceID}, selection)
	if err != nil {
		return MutationResult{}, err
	}
	doc, err := s.load()
	if err != nil {
		return MutationResult{}, err
	}
	if replay, found, replayErr := mutationReplay(doc, operationID, AuditDeviceSplit, []string{sourceDeviceID}, requestSHA256); found || replayErr != nil {
		return replay, replayErr
	}
	index := deviceIndex(doc.Devices, sourceDeviceID)
	if index < 0 {
		return MutationResult{}, os.ErrNotExist
	}
	if len(doc.Devices) >= MaxDevices {
		return MutationResult{}, newCapacityError("the device inventory already holds the maximum of %d devices", MaxDevices)
	}
	source := doc.Devices[index]
	remainingIdentities, movedIdentities, err := selectIdentities(source.Identities, selection.Identities)
	if err != nil {
		return MutationResult{}, fmt.Errorf("%w: %v", ErrMutationRejected, err)
	}
	if len(movedIdentities) == 0 || len(remainingIdentities) == 0 {
		return MutationResult{}, fmt.Errorf("%w: device split must move at least one identity and leave at least one identity", ErrMutationRejected)
	}
	remainingAddresses, movedAddresses, err := selectAddresses(source.Addresses, selection.Addresses)
	if err != nil {
		return MutationResult{}, fmt.Errorf("%w: %v", ErrMutationRejected, err)
	}
	remainingHostnames, movedHostnames, err := selectHostnames(source.Hostnames, selection.Hostnames)
	if err != nil {
		return MutationResult{}, fmt.Errorf("%w: %v", ErrMutationRejected, err)
	}
	newID, err := s.newUniqueDeviceID(doc.Devices)
	if err != nil {
		return MutationResult{}, err
	}
	now := s.now()
	source.Identities, source.Addresses, source.Hostnames = remainingIdentities, remainingAddresses, remainingHostnames
	refreshDerivedFields(&source, now)
	created := Device{
		Schema: SchemaVersion, ID: newID, Owner: selection.Metadata.Owner, Location: selection.Metadata.Location,
		Category: selection.Metadata.Category, Icon: selection.Metadata.Icon,
		Tags: append([]string(nil), selection.Metadata.Tags...), Notes: selection.Metadata.Notes, Identities: movedIdentities,
		Addresses: movedAddresses, Hostnames: movedHostnames, LastReconciled: now,
	}
	if selection.Metadata.FriendlyName != "" {
		if err := appendAliasChange(&created, selection.Metadata.FriendlyName, actor, "Assigned while splitting device evidence", now); err != nil {
			return MutationResult{}, fmt.Errorf("%w: %v", ErrMutationRejected, err)
		}
	}
	refreshDerivedFields(&created, now)
	if err := applyVendor(&source, s.Vendors, now); err != nil {
		return MutationResult{}, fmt.Errorf("enrich split source vendor: %w", err)
	}
	if err := applyVendor(&created, s.Vendors, now); err != nil {
		return MutationResult{}, fmt.Errorf("enrich split result vendor: %w", err)
	}
	if err := validateDevice(source); err != nil {
		return MutationResult{}, fmt.Errorf("validate split source: %w", err)
	}
	if err := validateDevice(created); err != nil {
		return MutationResult{}, fmt.Errorf("validate split result: %w", err)
	}
	doc.Devices[index] = source
	doc.Devices = append(doc.Devices, created)
	refreshFriendlyNameConflicts(doc.Devices)
	sortDevices(doc.Devices)
	source = doc.Devices[deviceIndex(doc.Devices, sourceDeviceID)]
	created = doc.Devices[deviceIndex(doc.Devices, newID)]
	changes := []string{
		fmt.Sprintf("moved %d identities", len(movedIdentities)),
		fmt.Sprintf("moved %d address observations", len(movedAddresses)),
		fmt.Sprintf("moved %d hostname observations", len(movedHostnames)),
	}
	audit := newAuditEvent(operationID, requestSHA256, AuditDeviceSplit, actor, now, []string{sourceDeviceID}, []string{sourceDeviceID, newID}, changes)
	if err := appendAudit(&doc, &audit); err != nil {
		return MutationResult{}, err
	}
	doc.UpdatedAt = now
	if err := s.save(doc); err != nil {
		return MutationResult{}, err
	}
	return MutationResult{Schema: SchemaVersion, Devices: []Device{projectDevice(source), projectDevice(created)}, Audit: audit}, nil
}

func (s *Store) AuditLog(limit int) ([]AuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit < 1 || limit > 500 {
		return nil, errors.New("device audit limit must be between 1 and 500")
	}
	doc, err := s.load()
	if err != nil {
		return nil, err
	}
	start := max(0, len(doc.AuditEvents)-limit)
	events := append([]AuditEvent(nil), doc.AuditEvents[start:]...)
	for left, right := 0, len(events)-1; left < right; left, right = left+1, right-1 {
		events[left], events[right] = events[right], events[left]
	}
	return events, nil
}

func validateMutationIdentity(actor, operationID string) error {
	if !validSingleLine(actor, 1, 96) || !operationIDPattern.MatchString(operationID) {
		return errors.New("device mutation actor or operation ID is invalid")
	}
	return nil
}

func mutationReplay(doc document, operationID string, action AuditAction, sourceIDs []string, requestSHA256 string) (MutationResult, bool, error) {
	for _, event := range doc.AuditEvents {
		if event.OperationID != operationID {
			continue
		}
		if event.Action != action || !sameStrings(event.SourceDeviceIDs, sourceIDs) || event.RequestSHA256 != requestSHA256 {
			return MutationResult{}, true, ErrOperationConflict
		}
		devices := make([]Device, 0, len(event.ResultDeviceIDs))
		for _, resultID := range event.ResultDeviceIDs {
			if index := deviceIndex(doc.Devices, resultID); index >= 0 {
				devices = append(devices, projectDevice(doc.Devices[index]))
			}
		}
		return MutationResult{Schema: SchemaVersion, Devices: devices, Audit: event, Replayed: true}, true, nil
	}
	return MutationResult{}, false, nil
}

func newAuditEvent(operationID, requestSHA256 string, action AuditAction, actor string, occurredAt time.Time, sourceIDs, resultIDs, changes []string) AuditEvent {
	digest := sha256.Sum256([]byte(string(action) + "\x00" + operationID))
	changes = append([]string(nil), changes...)
	sort.Strings(changes)
	return AuditEvent{
		Schema: SchemaVersion, ID: "audit-" + hex.EncodeToString(digest[:16]), OperationID: operationID, RequestSHA256: requestSHA256,
		Action: action, Actor: actor, OccurredAt: occurredAt.UTC(), SourceDeviceIDs: append([]string(nil), sourceIDs...),
		ResultDeviceIDs: append([]string(nil), resultIDs...), Changes: changes,
	}
}

func mutationRequestDigest(action AuditAction, sourceIDs []string, payload any) (string, error) {
	encoded, err := json.Marshal(struct {
		Action    AuditAction `json:"action"`
		SourceIDs []string    `json:"source_device_ids"`
		Payload   any         `json:"payload,omitempty"`
	}{Action: action, SourceIDs: sourceIDs, Payload: payload})
	if err != nil {
		return "", fmt.Errorf("encode device mutation request: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func normalizeSplitSelection(selection SplitSelection) (SplitSelection, error) {
	metadata, err := normalizeMetadata(selection.Metadata)
	if err != nil {
		return SplitSelection{}, err
	}
	selection.Metadata = metadata
	selection.Identities = append([]IdentitySelector(nil), selection.Identities...)
	for index := range selection.Identities {
		selector := selection.Identities[index]
		if selector.Value == "" || !validIdentitySource(selector.Source) || selector.Kind != IdentityMAC && selector.Kind != IdentityDHCPClientID {
			return SplitSelection{}, errors.New("device split identity selector is invalid")
		}
	}
	sort.Slice(selection.Identities, func(i, j int) bool {
		left, right := selection.Identities[i], selection.Identities[j]
		return string(left.Kind)+"\x00"+left.Value+"\x00"+string(left.Source) < string(right.Kind)+"\x00"+right.Value+"\x00"+string(right.Source)
	})
	for index := 1; index < len(selection.Identities); index++ {
		if selection.Identities[index] == selection.Identities[index-1] {
			return SplitSelection{}, errors.New("device split contains a duplicate identity selector")
		}
	}
	selection.Addresses = append([]AddressSelector(nil), selection.Addresses...)
	for index := range selection.Addresses {
		selector := &selection.Addresses[index]
		address, parseErr := netip.ParseAddr(selector.Address)
		if parseErr != nil || !validAddressSelector(address, selector.Source) || selector.ValidFrom.IsZero() || !selector.ValidUntil.After(selector.ValidFrom) || !validAddressScope(selector.Interface, selector.VLANID, selector.ScopePlanSHA256) {
			return SplitSelection{}, errors.New("device split address selector is invalid")
		}
		selector.Address, selector.ValidFrom, selector.ValidUntil = address.String(), selector.ValidFrom.UTC(), selector.ValidUntil.UTC()
	}
	sort.Slice(selection.Addresses, func(i, j int) bool {
		left, right := selection.Addresses[i], selection.Addresses[j]
		return left.Address+"\x00"+string(left.Source)+"\x00"+left.ValidFrom.Format(time.RFC3339Nano)+"\x00"+left.ValidUntil.Format(time.RFC3339Nano)+"\x00"+addressScopeKey(left.Interface, left.VLANID, left.ScopePlanSHA256) < right.Address+"\x00"+string(right.Source)+"\x00"+right.ValidFrom.Format(time.RFC3339Nano)+"\x00"+right.ValidUntil.Format(time.RFC3339Nano)+"\x00"+addressScopeKey(right.Interface, right.VLANID, right.ScopePlanSHA256)
	})
	for index := 1; index < len(selection.Addresses); index++ {
		if selection.Addresses[index].Address == selection.Addresses[index-1].Address && selection.Addresses[index].Source == selection.Addresses[index-1].Source && selection.Addresses[index].ValidFrom.Equal(selection.Addresses[index-1].ValidFrom) && selection.Addresses[index].ValidUntil.Equal(selection.Addresses[index-1].ValidUntil) && addressScopeKey(selection.Addresses[index].Interface, selection.Addresses[index].VLANID, selection.Addresses[index].ScopePlanSHA256) == addressScopeKey(selection.Addresses[index-1].Interface, selection.Addresses[index-1].VLANID, selection.Addresses[index-1].ScopePlanSHA256) {
			return SplitSelection{}, errors.New("device split contains a duplicate address selector")
		}
	}
	selection.Hostnames = append([]HostnameSelector(nil), selection.Hostnames...)
	for index := range selection.Hostnames {
		selector := &selection.Hostnames[index]
		selector.Hostname = normalizeHostname(selector.Hostname)
		if selector.Hostname == "" || selector.Source != SourceDHCP4Lease {
			return SplitSelection{}, errors.New("device split hostname selector is invalid")
		}
	}
	sort.Slice(selection.Hostnames, func(i, j int) bool {
		left, right := selection.Hostnames[i], selection.Hostnames[j]
		return string(left.Source)+"\x00"+left.Hostname < string(right.Source)+"\x00"+right.Hostname
	})
	for index := 1; index < len(selection.Hostnames); index++ {
		if selection.Hostnames[index] == selection.Hostnames[index-1] {
			return SplitSelection{}, errors.New("device split contains a duplicate hostname selector")
		}
	}
	return selection, nil
}

func appendAudit(doc *document, event *AuditEvent) error {
	if event == nil {
		return errors.New("device audit event is required")
	}
	for _, existing := range doc.AuditEvents {
		if existing.ID == event.ID || existing.OperationID == event.OperationID {
			return ErrOperationConflict
		}
	}
	if len(doc.AuditEvents) >= MaxAuditEvents {
		rollAuditArchive(doc)
	}
	event.PreviousSHA256 = doc.AuditAnchorSHA256
	if len(doc.AuditEvents) > 0 {
		event.PreviousSHA256 = doc.AuditEvents[len(doc.AuditEvents)-1].EntrySHA256
	}
	digest, err := auditEventDigest(*event)
	if err != nil {
		return err
	}
	event.EntrySHA256 = digest
	if err := validateAuditEvent(*event); err != nil {
		return err
	}
	doc.AuditEvents = append(doc.AuditEvents, *event)
	return nil
}

func auditEventDigest(event AuditEvent) (string, error) {
	event.EntrySHA256 = ""
	encoded, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func metadataChanges(device Device, metadata DeviceMetadata) []string {
	changes := make([]string, 0, 7)
	if device.FriendlyName != metadata.FriendlyName {
		changes = append(changes, "friendly name changed")
	}
	if device.Owner != metadata.Owner {
		changes = append(changes, "owner changed")
	}
	if device.Location != metadata.Location {
		changes = append(changes, "location changed")
	}
	if device.Category != metadata.Category {
		changes = append(changes, "category changed")
	}
	if device.Icon != metadata.Icon {
		changes = append(changes, "icon changed")
	}
	if !sameStrings(device.Tags, metadata.Tags) {
		changes = append(changes, "tags changed")
	}
	if device.Notes != metadata.Notes {
		changes = append(changes, "notes changed")
	}
	return changes
}

func mergeDeviceEvidence(target *Device, source Device) ([]string, error) {
	identityCount, addressCount, hostnameCount := len(target.Identities), len(target.Addresses), len(target.Hostnames)
	for _, identity := range source.Identities {
		merged := false
		for index := range target.Identities {
			candidate := &target.Identities[index]
			if candidate.Kind == identity.Kind && candidate.Value == identity.Value {
				candidate.FirstSeen = earlier(candidate.FirstSeen, identity.FirstSeen)
				candidate.LastSeen = later(candidate.LastSeen, identity.LastSeen)
				candidate.Confidence = max(candidate.Confidence, identity.Confidence)
				merged = true
				break
			}
		}
		if !merged {
			target.Identities = append(target.Identities, identity)
		}
	}
	for _, address := range source.Addresses {
		merged := false
		for index := range target.Addresses {
			candidate := &target.Addresses[index]
			if candidate.Address == address.Address && candidate.Source == address.Source && candidate.ValidFrom.Equal(address.ValidFrom) && candidate.ValidUntil.Equal(address.ValidUntil) && addressScopeKey(candidate.Interface, candidate.VLANID, candidate.ScopePlanSHA256) == addressScopeKey(address.Interface, address.VLANID, address.ScopePlanSHA256) {
				candidate.ObservedAt = later(candidate.ObservedAt, address.ObservedAt)
				candidate.Confidence = max(candidate.Confidence, address.Confidence)
				candidate.Active = candidate.Active || address.Active
				merged = true
				break
			}
		}
		if !merged {
			target.Addresses = append(target.Addresses, address)
		}
	}
	for _, hostname := range source.Hostnames {
		merged := false
		for index := range target.Hostnames {
			candidate := &target.Hostnames[index]
			if candidate.Hostname == hostname.Hostname && candidate.Source == hostname.Source {
				candidate.FirstSeen = earlier(candidate.FirstSeen, hostname.FirstSeen)
				candidate.LastSeen = later(candidate.LastSeen, hostname.LastSeen)
				candidate.Confidence = max(candidate.Confidence, hostname.Confidence)
				merged = true
				break
			}
		}
		if !merged {
			target.Hostnames = append(target.Hostnames, hostname)
		}
	}
	if len(target.Identities) > MaxIdentities || len(target.Addresses) > MaxAddresses || len(target.Hostnames) > MaxHostnames {
		return nil, errors.New("device merge would exceed evidence bounds")
	}
	if target.FriendlyName == "" {
		target.FriendlyName = source.FriendlyName
	} else if source.FriendlyName != "" && source.FriendlyName != target.FriendlyName {
		addWarning(target, "Merged device had a different friendly name; target metadata was retained")
	}
	if target.Owner == "" {
		target.Owner = source.Owner
	} else if source.Owner != "" && source.Owner != target.Owner {
		addWarning(target, "Merged device had a different owner; target metadata was retained")
	}
	if target.Location == "" {
		target.Location = source.Location
	} else if source.Location != "" && source.Location != target.Location {
		addWarning(target, "Merged device had a different location; target metadata was retained")
	}
	if target.Category == "" {
		target.Category = source.Category
	} else if source.Category != "" && source.Category != target.Category {
		addWarning(target, "Merged device had a different category; target metadata was retained")
	}
	if target.Icon == "" {
		target.Icon = source.Icon
	} else if source.Icon != "" && source.Icon != target.Icon {
		addWarning(target, "Merged device had a different icon; target metadata was retained")
	}
	if target.Notes == "" {
		target.Notes = source.Notes
	} else if source.Notes != "" && source.Notes != target.Notes {
		addWarning(target, "Merged device had different notes; target metadata was retained")
	}
	mergeCATrust(target, source)
	mergeFormerIDs(target, source)
	tags, err := normalizeMetadata(DeviceMetadata{Tags: append(append([]string(nil), target.Tags...), source.Tags...)})
	if err != nil {
		return nil, err
	}
	target.Tags = tags.Tags
	for _, warning := range source.AttributionWarnings {
		addWarning(target, warning)
	}
	target.FirstSeen = earlier(target.FirstSeen, source.FirstSeen)
	target.LastSeen = later(target.LastSeen, source.LastSeen)
	target.Online = target.Online || source.Online
	target.AttributionConfidence = max(target.AttributionConfidence, source.AttributionConfidence)
	sortDeviceEvidence(target)
	return []string{
		fmt.Sprintf("merged %d identities", len(target.Identities)-identityCount),
		fmt.Sprintf("merged %d address observations", len(target.Addresses)-addressCount),
		fmt.Sprintf("merged %d hostname observations", len(target.Hostnames)-hostnameCount),
	}, nil
}

func selectIdentities(existing []Identity, selectors []IdentitySelector) ([]Identity, []Identity, error) {
	selected := make(map[string]struct{}, len(selectors))
	for _, selector := range selectors {
		key := string(selector.Kind) + "\x00" + selector.Value + "\x00" + string(selector.Source)
		if selector.Value == "" || !validIdentitySource(selector.Source) || (selector.Kind != IdentityMAC && selector.Kind != IdentityDHCPClientID) {
			return nil, nil, errors.New("device split identity selector is invalid")
		}
		if _, duplicate := selected[key]; duplicate {
			return nil, nil, errors.New("device split contains a duplicate identity selector")
		}
		selected[key] = struct{}{}
	}
	remaining, moved := make([]Identity, 0, len(existing)), make([]Identity, 0, len(selectors))
	for _, identity := range existing {
		key := string(identity.Kind) + "\x00" + identity.Value + "\x00" + string(identity.Source)
		if _, ok := selected[key]; ok {
			moved = append(moved, identity)
			delete(selected, key)
		} else {
			remaining = append(remaining, identity)
		}
	}
	if len(selected) != 0 {
		return nil, nil, errors.New("device split identity selector did not match exact evidence")
	}
	return remaining, moved, nil
}

func selectAddresses(existing []AddressObservation, selectors []AddressSelector) ([]AddressObservation, []AddressObservation, error) {
	selected := make(map[string]struct{}, len(selectors))
	for _, selector := range selectors {
		address, err := netip.ParseAddr(selector.Address)
		if err != nil || !validAddressSelector(address, selector.Source) || selector.ValidFrom.IsZero() || !selector.ValidUntil.After(selector.ValidFrom) {
			return nil, nil, errors.New("device split address selector is invalid")
		}
		if !validAddressScope(selector.Interface, selector.VLANID, selector.ScopePlanSHA256) {
			return nil, nil, errors.New("device split address selector scope is invalid")
		}
		key := address.String() + "\x00" + string(selector.Source) + "\x00" + selector.ValidFrom.UTC().Format(time.RFC3339Nano) + "\x00" + selector.ValidUntil.UTC().Format(time.RFC3339Nano) + "\x00" + addressScopeKey(selector.Interface, selector.VLANID, selector.ScopePlanSHA256)
		if _, duplicate := selected[key]; duplicate {
			return nil, nil, errors.New("device split contains a duplicate address selector")
		}
		selected[key] = struct{}{}
	}
	remaining, moved := make([]AddressObservation, 0, len(existing)), make([]AddressObservation, 0, len(selectors))
	for _, address := range existing {
		key := address.Address + "\x00" + string(address.Source) + "\x00" + address.ValidFrom.UTC().Format(time.RFC3339Nano) + "\x00" + address.ValidUntil.UTC().Format(time.RFC3339Nano) + "\x00" + addressScopeKey(address.Interface, address.VLANID, address.ScopePlanSHA256)
		if _, ok := selected[key]; ok {
			moved = append(moved, address)
			delete(selected, key)
		} else {
			remaining = append(remaining, address)
		}
	}
	if len(selected) != 0 {
		return nil, nil, errors.New("device split address selector did not match exact evidence")
	}
	return remaining, moved, nil
}

func selectHostnames(existing []HostnameObservation, selectors []HostnameSelector) ([]HostnameObservation, []HostnameObservation, error) {
	selected := make(map[string]struct{}, len(selectors))
	for _, selector := range selectors {
		hostname := normalizeHostname(selector.Hostname)
		if hostname == "" || selector.Source != SourceDHCP4Lease {
			return nil, nil, errors.New("device split hostname selector is invalid")
		}
		key := string(selector.Source) + "\x00" + hostname
		if _, duplicate := selected[key]; duplicate {
			return nil, nil, errors.New("device split contains a duplicate hostname selector")
		}
		selected[key] = struct{}{}
	}
	remaining, moved := make([]HostnameObservation, 0, len(existing)), make([]HostnameObservation, 0, len(selectors))
	for _, hostname := range existing {
		key := string(hostname.Source) + "\x00" + hostname.Hostname
		if _, ok := selected[key]; ok {
			moved = append(moved, hostname)
			delete(selected, key)
		} else {
			remaining = append(remaining, hostname)
		}
	}
	if len(selected) != 0 {
		return nil, nil, errors.New("device split hostname selector did not match exact evidence")
	}
	return remaining, moved, nil
}

func refreshDerivedFields(device *Device, now time.Time) {
	first, last := time.Time{}, time.Time{}
	confidence := 0
	for _, identity := range device.Identities {
		first = firstNonZero(first, identity.FirstSeen)
		last = later(last, identity.LastSeen)
		confidence = max(confidence, identity.Confidence)
	}
	for _, address := range device.Addresses {
		first = firstNonZero(first, address.ValidFrom)
		observed := address.ObservedAt
		if observed.After(address.ValidUntil) {
			observed = address.ValidUntil
		}
		last = later(last, observed)
		confidence = max(confidence, address.Confidence)
	}
	for _, hostname := range device.Hostnames {
		first = firstNonZero(first, hostname.FirstSeen)
		last = later(last, hostname.LastSeen)
		confidence = max(confidence, hostname.Confidence)
	}
	device.FirstSeen, device.LastSeen, device.AttributionConfidence = first, last, confidence
	device.Online = false
	for _, address := range device.Addresses {
		if address.Active && address.ValidUntil.After(now) {
			device.Online = true
			break
		}
	}
	device.LastReconciled = now
	sortDeviceEvidence(device)
}

func sortDevices(devices []Device) {
	sort.Slice(devices, func(i, j int) bool {
		if devices[i].Online != devices[j].Online {
			return devices[i].Online
		}
		if !devices[i].LastSeen.Equal(devices[j].LastSeen) {
			return devices[i].LastSeen.After(devices[j].LastSeen)
		}
		return devices[i].ID < devices[j].ID
	})
}

func deviceIndex(devices []Device, id string) int {
	for index := range devices {
		if devices[index].ID == id {
			return index
		}
	}
	return -1
}

func sameStrings(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func earlier(first, second time.Time) time.Time {
	if first.IsZero() || !second.IsZero() && second.Before(first) {
		return second
	}
	return first
}

func firstNonZero(first, second time.Time) time.Time { return earlier(first, second) }

func later(first, second time.Time) time.Time {
	if second.After(first) {
		return second
	}
	return first
}
