package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// Naming a device by its IP address works like a router's client alias: the
// administrator says "192.168.10.201 is Pixel 9" and the address becomes the
// device's identity. Phones rotate their private Wi-Fi MAC, so every MAC that
// appears at a named address joins the named device.

// AddressName names the device at an IP address. DeviceID, when set, names
// that device and pins the address to it; otherwise the device currently or
// most recently at the address is named, or a new one is created that waits
// to be seen.
type AddressName struct {
	Name     string `json:"name"`
	Address  string `json:"address"`
	DeviceID string `json:"device_id,omitempty"`
}

var ErrAddressAlreadyNamed = errors.New("address is already named for another device")

func pinnableAddress(address netip.Addr) bool {
	return address.IsValid() && address.Zone() == "" && !address.Is4In6() && !address.IsUnspecified() && !address.IsLoopback() && !address.IsMulticast() && !address.IsLinkLocalUnicast() && !address.IsLinkLocalMulticast()
}

// pinnedDevice returns the device an administrator named by this address.
func pinnedDevice(devices []Device, address netip.Addr) (int, bool) {
	if !address.IsValid() {
		return 0, false
	}
	value := address.Unmap().String()
	for index, device := range devices {
		if device.PinnedAddress == value {
			return index, true
		}
	}
	return 0, false
}

// addressHolder returns the device seen at the address most recently,
// preferring one that holds it now.
func addressHolder(devices []Device, address string) int {
	best, bestActive := -1, false
	var bestSeen AddressObservation
	for index, device := range devices {
		for _, held := range device.Addresses {
			if held.Address != address {
				continue
			}
			if best < 0 || held.Active && !bestActive || held.Active == bestActive && held.ObservedAt.After(bestSeen.ObservedAt) {
				best, bestActive, bestSeen = index, held.Active, held
			}
		}
	}
	return best
}

// onlySeenAt reports a device known only from the neighbor tables and only
// ever at this IPv4 address: an earlier record of the device now named by it.
func onlySeenAt(device Device, address string) bool {
	if device.PinnedAddress != "" || len(device.Identities) == 0 {
		return false
	}
	for _, identity := range device.Identities {
		if identity.Source == SourceDHCP4Lease || identity.Kind != IdentityMAC {
			return false
		}
	}
	seen := false
	for _, held := range device.Addresses {
		if held.Source == SourceDHCP4Lease {
			return false
		}
		parsed, err := netip.ParseAddr(held.Address)
		if err != nil || !parsed.Is4() {
			continue
		}
		if held.Address != address {
			return false
		}
		seen = true
	}
	return seen
}

func (s *Store) NameAddress(actor, operationID string, request AddressName) (MutationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateMutationIdentity(actor, operationID); err != nil {
		return MutationResult{}, fmt.Errorf("%w: %v", ErrMutationRejected, err)
	}
	request.Name = normalizeFriendlyName(request.Name)
	if request.Name == "" || !validFriendlyName(request.Name) {
		return MutationResult{}, fmt.Errorf("%w: give the device a name", ErrMutationRejected)
	}
	address, err := netip.ParseAddr(strings.TrimSpace(request.Address))
	if err == nil {
		address = address.Unmap()
	}
	if err != nil || !pinnableAddress(address) {
		return MutationResult{}, fmt.Errorf("%w: enter a device's IP address, such as 192.168.10.201", ErrMutationRejected)
	}
	request.Address = address.String()
	sources := []string{}
	if request.DeviceID != "" {
		if !ValidDeviceID(request.DeviceID) {
			return MutationResult{}, fmt.Errorf("%w: invalid device ID", ErrMutationRejected)
		}
		sources = []string{request.DeviceID}
	}
	requestSHA256, err := mutationRequestDigest(AuditDeviceAddressPinned, sources, request)
	if err != nil {
		return MutationResult{}, err
	}
	doc, err := s.load()
	if err != nil {
		return MutationResult{}, err
	}
	if replay, found, replayErr := mutationReplay(doc, operationID, AuditDeviceAddressPinned, sources, requestSHA256); found || replayErr != nil {
		return replay, replayErr
	}
	now := s.now()
	pinnedIndex, pinned := pinnedDevice(doc.Devices, address)
	target := -1
	switch {
	case request.DeviceID != "":
		if target = deviceIndex(doc.Devices, request.DeviceID); target < 0 {
			return MutationResult{}, os.ErrNotExist
		}
		if pinned && pinnedIndex != target {
			return MutationResult{}, fmt.Errorf("%w: %s is already the address of %q", ErrAddressAlreadyNamed, request.Address, doc.Devices[pinnedIndex].FriendlyName)
		}
	case pinned:
		target = pinnedIndex
	default:
		target = addressHolder(doc.Devices, request.Address)
	}
	changes := []string{"named by its address " + request.Address}
	if target < 0 {
		if len(doc.Devices) >= MaxDevices {
			return MutationResult{}, errors.New("device inventory limit exceeded")
		}
		id, idErr := s.newUniqueDeviceID(doc.Devices)
		if idErr != nil {
			return MutationResult{}, idErr
		}
		doc.Devices = append(doc.Devices, Device{Schema: SchemaVersion, ID: id, Identities: []Identity{}, Addresses: []AddressObservation{}, Hostnames: []HostnameObservation{}, FirstSeen: now, LastSeen: now, LastReconciled: now})
		target = len(doc.Devices) - 1
		changes = append(changes, "added before it was seen")
	}
	device := &doc.Devices[target]
	if device.PinnedAddress != "" && device.PinnedAddress != request.Address {
		changes = append(changes, "address changed from "+device.PinnedAddress)
	}
	device.PinnedAddress = request.Address
	if device.FriendlyName != request.Name {
		if err := appendAliasChange(device, request.Name, actor, "Named with its IP address "+request.Address, now); err != nil {
			return MutationResult{}, fmt.Errorf("%w: %v", ErrMutationRejected, err)
		}
	}
	if err := applyVendor(device, s.Vendors, now); err != nil {
		return MutationResult{}, fmt.Errorf("enrich named device vendor: %w", err)
	}
	targetID := device.ID
	// Earlier records of the same device, made before its address was named
	// (one per private MAC it used there), join it.
	absorbed := map[string]bool{}
	for index := range doc.Devices {
		source := doc.Devices[index]
		if index == target || !onlySeenAt(source, request.Address) {
			continue
		}
		named := &doc.Devices[target]
		trimmed := trimForMerge(*named, source)
		previousFriendlyName := named.FriendlyName
		merged, mergeErr := mergeDeviceEvidence(named, trimmed)
		if mergeErr != nil {
			return MutationResult{}, fmt.Errorf("%w: %v", ErrMutationRejected, mergeErr)
		}
		named.FriendlyName = previousFriendlyName
		pair := []string{targetID, source.ID}
		pairSHA256, digestErr := mutationRequestDigest(AuditDevicesMerged, pair, nil)
		if digestErr != nil {
			return MutationResult{}, digestErr
		}
		digest := sha256.Sum256([]byte(operationID + "|" + source.ID + "|" + strconv.FormatInt(now.UnixNano(), 10)))
		audit := newAuditEvent("address-name-"+hex.EncodeToString(digest[:16]), pairSHA256, AuditDevicesMerged, actor, now, pair, []string{targetID}, append(merged, "seen only at "+request.Address))
		if err := appendAudit(&doc, &audit); err != nil {
			return MutationResult{}, err
		}
		absorbed[source.ID] = true
		changes = append(changes, "joined the earlier record "+source.ID)
	}
	if len(absorbed) > 0 {
		kept := doc.Devices[:0]
		for _, candidate := range doc.Devices {
			if !absorbed[candidate.ID] {
				kept = append(kept, candidate)
			}
		}
		doc.Devices = kept
	}
	index := deviceIndex(doc.Devices, targetID)
	named := &doc.Devices[index]
	named.LastReconciled = now
	named.Online = hasActiveAddress(*named)
	sortDeviceEvidence(named)
	refreshFriendlyNameConflicts(doc.Devices)
	if err := validateDevice(*named); err != nil {
		return MutationResult{}, err
	}
	audit := newAuditEvent(operationID, requestSHA256, AuditDeviceAddressPinned, actor, now, sources, []string{targetID}, changes)
	if err := appendAudit(&doc, &audit); err != nil {
		return MutationResult{}, err
	}
	doc.UpdatedAt = now
	if err := s.save(doc); err != nil {
		return MutationResult{}, err
	}
	return MutationResult{Schema: SchemaVersion, Devices: []Device{projectDevice(doc.Devices[deviceIndex(doc.Devices, targetID)])}, Audit: audit}, nil
}

// UnpinAddress stops naming a device by its address. The device keeps its
// name; a device added by address that was never seen is removed.
func (s *Store) UnpinAddress(deviceID, actor, operationID string) (MutationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ValidDeviceID(deviceID) {
		return MutationResult{}, fmt.Errorf("%w: invalid device ID", ErrMutationRejected)
	}
	if err := validateMutationIdentity(actor, operationID); err != nil {
		return MutationResult{}, fmt.Errorf("%w: %v", ErrMutationRejected, err)
	}
	sources := []string{deviceID}
	requestSHA256, err := mutationRequestDigest(AuditDeviceAddressPinned, sources, map[string]string{"unpin": deviceID})
	if err != nil {
		return MutationResult{}, err
	}
	doc, err := s.load()
	if err != nil {
		return MutationResult{}, err
	}
	if replay, found, replayErr := mutationReplay(doc, operationID, AuditDeviceAddressPinned, sources, requestSHA256); found || replayErr != nil {
		return replay, replayErr
	}
	index := deviceIndex(doc.Devices, deviceID)
	if index < 0 {
		return MutationResult{}, os.ErrNotExist
	}
	device := doc.Devices[index]
	if device.PinnedAddress == "" {
		return MutationResult{Schema: SchemaVersion, Devices: []Device{projectDevice(device)}, Unchanged: true}, nil
	}
	now := s.now()
	var audit AuditEvent
	var result []Device
	if len(device.Identities) == 0 {
		doc.Devices = append(doc.Devices[:index], doc.Devices[index+1:]...)
		audit = newAuditEvent(operationID, requestSHA256, AuditDeviceAddressPinned, actor, now, sources, nil, []string{"removed " + device.PinnedAddress + " before it was seen"})
	} else {
		changes := []string{"no longer named by its address " + device.PinnedAddress}
		doc.Devices[index].PinnedAddress = ""
		doc.Devices[index].LastReconciled = now
		if err := validateDevice(doc.Devices[index]); err != nil {
			return MutationResult{}, err
		}
		audit = newAuditEvent(operationID, requestSHA256, AuditDeviceAddressPinned, actor, now, sources, sources, changes)
		result = []Device{projectDevice(doc.Devices[index])}
	}
	refreshFriendlyNameConflicts(doc.Devices)
	if err := appendAudit(&doc, &audit); err != nil {
		return MutationResult{}, err
	}
	doc.UpdatedAt = now
	if err := s.save(doc); err != nil {
		return MutationResult{}, err
	}
	return MutationResult{Schema: SchemaVersion, Devices: result, Audit: audit}, nil
}
