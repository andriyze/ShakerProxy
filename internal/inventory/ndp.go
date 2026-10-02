package inventory

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"time"
)

// Neighbor-table evidence: IPv6 neighbor discovery (NDP) and IPv4 ARP.
//
// SLAAC addresses never appear in DHCP leases, and neither do devices with a
// static IPv4 address or the clients of a single-arm lab, which has no
// ShakerProxy DHCP. The gateway reports the lab interface's neighbor tables
// (MAC -> address plus the time the kernel last confirmed reachability).
// Each observation opens or extends an address window [first confirmation,
// last confirmation + NDPValidity). Neighbor evidence is weaker than a DHCP
// lease (a device can answer for another host's address), so it carries a
// lower confidence; ARP is the weakest.

const (
	SourceNDP               EvidenceSource = "NDP"
	SourceARP               EvidenceSource = "ARP"
	NDPConfidence                          = 80
	ARPConfidence                          = 70
	NDPValidity                            = 10 * time.Minute
	MaxNeighborObservations                = 4096
)

// neighborSource is the evidence source for a neighbor-table address.
func neighborSource(address netip.Addr) (EvidenceSource, int, string) {
	if address.Is4() {
		return SourceARP, ARPConfidence, "IPv4"
	}
	return SourceNDP, NDPConfidence, "IPv6"
}

func isNeighborSource(source EvidenceSource) bool {
	return source == SourceNDP || source == SourceARP
}

// NeighborObservation is one validated IPv6 or IPv4 neighbor entry from the lab.
type NeighborObservation struct {
	Address         netip.Addr
	HardwareAddr    string
	SeenAt          time.Time
	Interface       string
	VLANID          *int
	ScopePlanSHA256 string
}

// ReconcileNeighbors merges IPv6 neighbor observations into the inventory.
// Devices are matched by MAC; an unknown MAC creates a device so IPv6-only
// devices still appear.
func (s *Store) ReconcileNeighbors(observations []NeighborObservation) (Snapshot, error) {
	if len(observations) > MaxNeighborObservations {
		return Snapshot{}, errors.New("too many neighbor observations")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	normalized := make([]NeighborObservation, 0, len(observations))
	for _, observation := range observations {
		value, err := normalizeNeighborObservation(observation, now)
		if err != nil {
			return Snapshot{}, err
		}
		normalized = append(normalized, value)
	}
	doc, err := s.load()
	if err != nil {
		return Snapshot{}, err
	}
	if len(doc.Devices) > MaxDevices {
		return Snapshot{}, errors.New("device inventory limit exceeded")
	}
	macIndex, _ := identityIndexes(doc.Devices)
	touched := map[string]bool{}
	for _, observation := range normalized {
		deviceIndex, known := macIndex[observation.HardwareAddr]
		if !known {
			// Phones (GrapheneOS, Android, iOS) pick a new random MAC when
			// they reconnect. The same address taken over by a randomized
			// MAC, from a device that also used randomized MACs, is that
			// device reconnecting, not a new one.
			if index, ok := pinnedDevice(doc.Devices, observation.Address); ok {
				deviceIndex, known = index, true
				macIndex[observation.HardwareAddr] = index
			} else if index, ok := rotatedMACDevice(doc.Devices, observation); ok {
				deviceIndex, known = index, true
				macIndex[observation.HardwareAddr] = index
			}
		}
		if !known {
			if len(doc.Devices) >= MaxDevices {
				return Snapshot{}, errors.New("device inventory limit exceeded")
			}
			id, idErr := s.newUniqueDeviceID(doc.Devices)
			if idErr != nil {
				return Snapshot{}, idErr
			}
			doc.Devices = append(doc.Devices, Device{Schema: SchemaVersion, ID: id, FirstSeen: observation.SeenAt, LastSeen: observation.SeenAt, LastReconciled: now})
			deviceIndex = len(doc.Devices) - 1
			macIndex[observation.HardwareAddr] = deviceIndex
		}
		device := &doc.Devices[deviceIndex]
		upsertNeighborIdentity(device, observation)
		upsertNeighborAddress(device, observation, now)
		if observation.SeenAt.Before(device.FirstSeen) {
			device.FirstSeen = observation.SeenAt
		}
		if observation.SeenAt.After(device.LastSeen) {
			device.LastSeen = observation.SeenAt
		}
		if _, confidence, _ := neighborSource(observation.Address); device.AttributionConfidence < confidence {
			device.AttributionConfidence = confidence
		}
		touched[device.ID] = true
	}
	merged, err := consolidateRotatedMACDevices(&doc, now)
	if err != nil {
		return Snapshot{}, err
	}
	for _, id := range merged {
		touched[id] = true
	}
	for index := range doc.Devices {
		device := &doc.Devices[index]
		refreshNeighborActivity(device, now)
		device.Online = hasActiveAddress(*device)
		if touched[device.ID] {
			device.LastReconciled = now
			sortDeviceEvidence(device)
			if err := applyVendor(device, s.Vendors, now); err != nil {
				return Snapshot{}, fmt.Errorf("enrich device %s vendor: %w", device.ID, err)
			}
		}
		if err := validateDevice(*device); err != nil {
			return Snapshot{}, fmt.Errorf("validate device %s: %w", device.ID, err)
		}
	}
	refreshFriendlyNameConflicts(doc.Devices)
	sort.Slice(doc.Devices, func(i, j int) bool {
		if doc.Devices[i].Online != doc.Devices[j].Online {
			return doc.Devices[i].Online
		}
		if !doc.Devices[i].LastSeen.Equal(doc.Devices[j].LastSeen) {
			return doc.Devices[i].LastSeen.After(doc.Devices[j].LastSeen)
		}
		return doc.Devices[i].ID < doc.Devices[j].ID
	})
	doc.Schema = SchemaVersion
	doc.UpdatedAt = now
	doc.EvidenceAsOf = now
	if err := s.save(doc); err != nil {
		return Snapshot{}, err
	}
	return snapshot(doc, now), nil
}

func normalizeNeighborObservation(observation NeighborObservation, now time.Time) (NeighborObservation, error) {
	address := observation.Address
	if !(address.Is4() || address.Is6()) || address.Is4In6() || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() || address == netip.IPv4Unspecified() || address == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return NeighborObservation{}, errors.New("neighbor address is invalid")
	}
	hardware, err := net.ParseMAC(observation.HardwareAddr)
	if err != nil || len(hardware) != 6 || !usableHardwareAddress(hardware) {
		return NeighborObservation{}, errors.New("neighbor hardware address is invalid")
	}
	if observation.SeenAt.IsZero() {
		return NeighborObservation{}, errors.New("neighbor observation time is missing")
	}
	if !validAddressScope(observation.Interface, observation.VLANID, observation.ScopePlanSHA256) {
		return NeighborObservation{}, errors.New("neighbor scope is invalid")
	}
	seenAt := observation.SeenAt.UTC()
	if seenAt.After(now) {
		seenAt = now
	}
	return NeighborObservation{Address: address, HardwareAddr: hardware.String(), SeenAt: seenAt, Interface: observation.Interface, VLANID: cloneInt(observation.VLANID), ScopePlanSHA256: observation.ScopePlanSHA256}, nil
}

func usableHardwareAddress(address net.HardwareAddr) bool {
	if address[0]&1 != 0 {
		return false
	}
	for _, octet := range address {
		if octet != 0 {
			return true
		}
	}
	return false
}

func upsertNeighborIdentity(device *Device, observation NeighborObservation) {
	source, confidence, _ := neighborSource(observation.Address)
	for index := range device.Identities {
		identity := &device.Identities[index]
		if identity.Kind != IdentityMAC || identity.Value != observation.HardwareAddr {
			continue
		}
		if isNeighborSource(identity.Source) {
			if observation.SeenAt.Before(identity.FirstSeen) {
				identity.FirstSeen = observation.SeenAt
			}
			if observation.SeenAt.After(identity.LastSeen) {
				identity.LastSeen = observation.SeenAt
			}
		}
		return
	}
	if len(device.Identities) >= MaxIdentities && locallyAdministeredMAC(observation.HardwareAddr) {
		// A phone that rotates its private MAC on every connection would
		// otherwise stop recording new MACs once the list is full.
		dropOldestRandomizedMAC(device)
	}
	if len(device.Identities) < MaxIdentities {
		device.Identities = append(device.Identities, Identity{Kind: IdentityMAC, Value: observation.HardwareAddr, Source: source, Confidence: confidence, FirstSeen: observation.SeenAt, LastSeen: observation.SeenAt})
	}
}

// upsertNeighborAddress extends an overlapping window for the same address and
// scope, or opens a new one when the address was absent for longer than the
// validity period.
func upsertNeighborAddress(device *Device, observation NeighborObservation, now time.Time) {
	address := observation.Address.String()
	source, confidence, family := neighborSource(observation.Address)
	scope := addressScopeKey(observation.Interface, observation.VLANID, observation.ScopePlanSHA256)
	from, until := observation.SeenAt, observation.SeenAt.Add(NDPValidity)
	for index := range device.Addresses {
		item := &device.Addresses[index]
		if item.Source != source || item.Address != address || addressScopeKey(item.Interface, item.VLANID, item.ScopePlanSHA256) != scope {
			continue
		}
		if until.Before(item.ValidFrom) || from.After(item.ValidUntil) {
			continue
		}
		if from.Before(item.ValidFrom) {
			item.ValidFrom = from
		}
		if until.After(item.ValidUntil) {
			item.ValidUntil = until
		}
		item.ObservedAt = now
		item.Active = item.ValidUntil.After(now)
		return
	}
	if len(device.Addresses) >= MaxAddresses {
		sortDeviceEvidence(device)
		device.Addresses = append([]AddressObservation(nil), device.Addresses[len(device.Addresses)-MaxAddresses+1:]...)
	}
	device.Addresses = append(device.Addresses, AddressObservation{
		Address: address, Family: family, Source: source, Confidence: confidence,
		ValidFrom: from, ValidUntil: until, ObservedAt: now, Active: until.After(now),
		Interface: observation.Interface, VLANID: cloneInt(observation.VLANID), ScopePlanSHA256: observation.ScopePlanSHA256,
	})
}

// refreshNeighborActivity recomputes the time-based Active flag of NDP and
// ARP address windows; DHCP windows keep the lease state set by ReconcileDHCP4.
func refreshNeighborActivity(device *Device, now time.Time) {
	for index := range device.Addresses {
		if isNeighborSource(device.Addresses[index].Source) {
			device.Addresses[index].Active = device.Addresses[index].ValidUntil.After(now)
		}
	}
}

func hasActiveAddress(device Device) bool {
	for _, address := range device.Addresses {
		if address.Active {
			return true
		}
	}
	return false
}

func hasActiveNeighborAddress(device Device) bool {
	for _, address := range device.Addresses {
		if isNeighborSource(address.Source) && address.Active {
			return true
		}
	}
	return false
}

func validIdentitySource(source EvidenceSource) bool {
	return source == SourceDHCP4Lease || isNeighborSource(source)
}

// validAddressEvidence accepts DHCPv4 lease windows for IPv4 and NDP windows
// for IPv6, each in canonical form.
func validAddressEvidence(address AddressObservation) bool {
	parsed, err := netip.ParseAddr(address.Address)
	if err != nil || parsed.String() != address.Address {
		return false
	}
	switch address.Source {
	case SourceDHCP4Lease:
		return parsed.Is4() && address.Family == "IPv4"
	case SourceNDP:
		return parsed.Is6() && !parsed.Is4In6() && parsed.Zone() == "" && address.Family == "IPv6"
	case SourceARP:
		return parsed.Is4() && address.Family == "IPv4"
	}
	return false
}

// validAddressSelector accepts split selectors for either evidence family.
func validAddressSelector(address netip.Addr, source EvidenceSource) bool {
	switch source {
	case SourceDHCP4Lease:
		return address.Is4()
	case SourceNDP:
		return address.Is6() && !address.Is4In6() && address.Zone() == ""
	case SourceARP:
		return address.Is4()
	}
	return false
}
