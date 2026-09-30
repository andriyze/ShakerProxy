package inventory

import (
	"fmt"
	"os"
)

// AuditCATrustUpdated records a change to whether the ShakerProxy interception
// CA is installed on a device.
const AuditCATrustUpdated AuditAction = "DEVICE_CA_TRUST_UPDATED"

// CA trust states. The empty stored value means UNKNOWN so inventories that
// never recorded a state stay byte-for-byte unchanged.
const (
	CATrustUnknown      = "UNKNOWN"
	CATrustInstalled    = "INSTALLED"
	CATrustNotInstalled = "NOT_INSTALLED"
)

func validCATrust(value string) bool {
	return value == "" || value == CATrustInstalled || value == CATrustNotInstalled
}

// CATrustState returns the device's CA trust as UNKNOWN, INSTALLED, or
// NOT_INSTALLED.
func (d Device) CATrustState() string {
	if d.CATrust == "" {
		return CATrustUnknown
	}
	return d.CATrust
}

// SetCATrust records whether the ShakerProxy interception CA is installed on a
// device. The change is idempotent by operation ID and audited in the device
// audit log. Setting the current state again returns Unchanged without an
// audit event.
func (s *Store) SetCATrust(deviceID, actor, operationID, state string) (MutationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ValidDeviceID(deviceID) {
		return MutationResult{}, fmt.Errorf("%w: invalid device ID", ErrMutationRejected)
	}
	if err := validateMutationIdentity(actor, operationID); err != nil {
		return MutationResult{}, fmt.Errorf("%w: %v", ErrMutationRejected, err)
	}
	stored := state
	switch state {
	case CATrustUnknown:
		stored = ""
	case CATrustInstalled, CATrustNotInstalled:
	default:
		return MutationResult{}, fmt.Errorf("%w: CA trust must be UNKNOWN, INSTALLED, or NOT_INSTALLED", ErrMutationRejected)
	}
	payload := struct {
		CATrust string `json:"ca_trust"`
	}{CATrust: state}
	requestSHA256, err := mutationRequestDigest(AuditCATrustUpdated, []string{deviceID}, payload)
	if err != nil {
		return MutationResult{}, err
	}
	doc, err := s.load()
	if err != nil {
		return MutationResult{}, err
	}
	if replay, found, replayErr := mutationReplay(doc, operationID, AuditCATrustUpdated, []string{deviceID}, requestSHA256); found || replayErr != nil {
		return replay, replayErr
	}
	index := deviceIndex(doc.Devices, deviceID)
	if index < 0 {
		return MutationResult{}, os.ErrNotExist
	}
	device := &doc.Devices[index]
	if device.CATrust == stored {
		refreshFriendlyNameConflicts(doc.Devices)
		return MutationResult{Schema: SchemaVersion, Devices: []Device{projectDevice(*device)}, Unchanged: true}, nil
	}
	previous := device.CATrustState()
	device.CATrust = stored
	if err := validateDevice(*device); err != nil {
		return MutationResult{}, err
	}
	change := fmt.Sprintf("CA trust changed from %s to %s", previous, device.CATrustState())
	audit := newAuditEvent(operationID, requestSHA256, AuditCATrustUpdated, actor, s.now(), []string{deviceID}, []string{deviceID}, []string{change})
	if err := appendAudit(&doc, &audit); err != nil {
		return MutationResult{}, err
	}
	doc.UpdatedAt = audit.OccurredAt
	if err := s.save(doc); err != nil {
		return MutationResult{}, err
	}
	return MutationResult{Schema: SchemaVersion, Devices: []Device{projectDevice(*device)}, Audit: audit}, nil
}

// mergeCATrust keeps the target's CA trust and adopts the merged device's
// state when the target has none, so a recorded NOT_INSTALLED survives a
// merge.
func mergeCATrust(target *Device, source Device) {
	if target.CATrust == "" {
		target.CATrust = source.CATrust
	} else if source.CATrust != "" && source.CATrust != target.CATrust {
		addWarning(target, "Merged device had a different CA trust state; target metadata was retained")
	}
}
