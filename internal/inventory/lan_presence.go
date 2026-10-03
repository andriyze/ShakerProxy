package inventory

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"
)

// A device on the lab segment shows itself even when its traffic never goes
// through ShakerProxy: in a single-arm lab whose router serves DHCP, a phone
// gets the router as its gateway, and all ShakerProxy records of it is its
// DHCP broadcasts (with the address it asks for) and its multicast (mDNS,
// SSDP, with its MAC and address). That is the weakest evidence the
// inventory takes, below ARP, but it makes the device appear, so the tester
// sees it and why its traffic is missing.

const (
	SourceObservedLAN EvidenceSource = "OBSERVED_LAN"
	// ObservedLANConfidence ranks broadcast and multicast evidence below
	// every other source (ARP: 70).
	ObservedLANConfidence = 50
	// ObservedLANValidity is how long an address stays attributed after the
	// last frame that showed it.
	ObservedLANValidity = 15 * time.Minute
	MaxLANPresence      = 4096
)

// LANPresence is one MAC and IPv4 address seen together on the lab segment
// (a DHCP request for the address, or multicast sent from it), and the name
// the device gave itself in DHCP.
type LANPresence struct {
	HardwareAddr string
	Address      netip.Addr
	HostName     string
	FirstSeen    time.Time
	LastSeen     time.Time
}

// ReconcileLANPresence adds devices seen on the lab segment. A known MAC
// gains the evidence; an unknown one joins the device an administrator named
// the address after, or the device a phone was before it rotated its private
// MAC, or else becomes a new device. The caller keeps only addresses inside
// the lab's prefix. Names an administrator chose are never touched.
func (s *Store) ReconcileLANPresence(observations []LANPresence, scope ObservedDHCPScope) (Snapshot, error) {
	if len(observations) > MaxLANPresence {
		return Snapshot{}, errors.New("too many LAN presence observations")
	}
	if !validAddressScope(scope.Interface, scope.VLANID, scope.ScopePlanSHA256) {
		return Snapshot{}, errors.New("LAN presence scope is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	normalized := make([]LANPresence, 0, len(observations))
	for _, observation := range observations {
		value, err := normalizeLANPresence(observation, now)
		if err != nil {
			return Snapshot{}, err
		}
		normalized = append(normalized, value)
	}
	sort.SliceStable(normalized, func(i, j int) bool { return normalized[i].LastSeen.Before(normalized[j].LastSeen) })
	doc, err := s.load()
	if err != nil {
		return Snapshot{}, err
	}
	if len(doc.Devices) > MaxDevices {
		return Snapshot{}, errors.New("device inventory limit exceeded")
	}
	before, err := reconcileFingerprint(doc)
	if err != nil {
		return Snapshot{}, err
	}
	macIndex, _ := identityIndexes(doc.Devices)
	touched := map[string]bool{}
	for _, observation := range normalized {
		deviceIndex, known := macIndex[observation.HardwareAddr]
		if !known {
			if index, ok := pinnedDevice(doc.Devices, observation.Address); ok {
				deviceIndex, known = index, true
			} else if index, ok := rotatedMACDevice(doc.Devices, NeighborObservation{Address: observation.Address, HardwareAddr: observation.HardwareAddr, SeenAt: observation.LastSeen, Interface: scope.Interface, VLANID: scope.VLANID, ScopePlanSHA256: scope.ScopePlanSHA256}); ok {
				deviceIndex, known = index, true
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
			doc.Devices = append(doc.Devices, Device{Schema: SchemaVersion, ID: id, FirstSeen: observation.FirstSeen, LastSeen: observation.LastSeen, LastReconciled: now})
			deviceIndex = len(doc.Devices) - 1
		}
		macIndex[observation.HardwareAddr] = deviceIndex
		device := &doc.Devices[deviceIndex]
		upsertLANIdentity(device, observation)
		upsertLANAddress(device, observation, scope, now)
		if observation.HostName != "" {
			upsertObservedHostname(device, normalizeHostname(observation.HostName), observation.FirstSeen, observation.LastSeen)
		}
		if device.AttributionConfidence < ObservedLANConfidence {
			device.AttributionConfidence = ObservedLANConfidence
		}
		if observation.FirstSeen.Before(device.FirstSeen) {
			device.FirstSeen = observation.FirstSeen
		}
		if observation.LastSeen.After(device.LastSeen) {
			device.LastSeen = observation.LastSeen
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
	after, err := reconcileFingerprint(doc)
	if err != nil {
		return Snapshot{}, err
	}
	if before == after {
		return snapshot(doc, now), nil
	}
	doc.Schema = SchemaVersion
	doc.UpdatedAt = now
	doc.EvidenceAsOf = now
	if err := s.save(doc); err != nil {
		return Snapshot{}, err
	}
	return snapshot(doc, now), nil
}

func normalizeLANPresence(observation LANPresence, now time.Time) (LANPresence, error) {
	if mac := normalizeMACIdentity(observation.HardwareAddr); mac == "" || observation.HardwareAddr != mac || !unicastMAC(mac) {
		return LANPresence{}, errors.New("LAN presence hardware address is invalid")
	}
	if !observableDHCPAddress(observation.Address) {
		return LANPresence{}, errors.New("LAN presence address is invalid")
	}
	if observation.FirstSeen.IsZero() || observation.LastSeen.Before(observation.FirstSeen) {
		return LANPresence{}, errors.New("LAN presence times are invalid")
	}
	if observation.HostName != "" && (normalizeHostname(observation.HostName) == "" || !validSingleLine(observation.HostName, 1, 253)) {
		return LANPresence{}, errors.New("LAN presence host name is invalid")
	}
	observation.FirstSeen, observation.LastSeen = observation.FirstSeen.UTC(), observation.LastSeen.UTC()
	if observation.LastSeen.After(now) {
		observation.LastSeen = now
	}
	if observation.FirstSeen.After(observation.LastSeen) {
		observation.FirstSeen = observation.LastSeen
	}
	return observation, nil
}

func upsertLANIdentity(device *Device, observation LANPresence) {
	for index := range device.Identities {
		identity := &device.Identities[index]
		if identity.Kind != IdentityMAC || identity.Value != observation.HardwareAddr {
			continue
		}
		if timedAddressSource(identity.Source) {
			identity.FirstSeen = earlier(identity.FirstSeen, observation.FirstSeen)
			identity.LastSeen = later(identity.LastSeen, observation.LastSeen)
		}
		return
	}
	if len(device.Identities) >= MaxIdentities && locallyAdministeredMAC(observation.HardwareAddr) {
		dropOldestRandomizedMAC(device)
	}
	if len(device.Identities) < MaxIdentities {
		device.Identities = append(device.Identities, Identity{Kind: IdentityMAC, Value: observation.HardwareAddr, Source: SourceObservedLAN, Confidence: ObservedLANConfidence, FirstSeen: observation.FirstSeen, LastSeen: observation.LastSeen})
	}
}

// upsertLANAddress extends an overlapping window for the same address and
// scope, or opens a new one.
func upsertLANAddress(device *Device, observation LANPresence, scope ObservedDHCPScope, now time.Time) {
	address := observation.Address.String()
	key := addressScopeKey(scope.Interface, scope.VLANID, scope.ScopePlanSHA256)
	from, until := observation.FirstSeen, observation.LastSeen.Add(ObservedLANValidity)
	for index := range device.Addresses {
		item := &device.Addresses[index]
		if item.Source != SourceObservedLAN || item.Address != address || addressScopeKey(item.Interface, item.VLANID, item.ScopePlanSHA256) != key {
			continue
		}
		if until.Before(item.ValidFrom) || from.After(item.ValidUntil) {
			continue
		}
		item.ValidFrom = earlier(item.ValidFrom, from)
		item.ValidUntil = later(item.ValidUntil, until)
		item.ObservedAt = now
		item.Active = item.ValidUntil.After(now)
		return
	}
	if len(device.Addresses) >= MaxAddresses {
		sortDeviceEvidence(device)
		device.Addresses = append([]AddressObservation(nil), device.Addresses[len(device.Addresses)-MaxAddresses+1:]...)
	}
	device.Addresses = append(device.Addresses, AddressObservation{
		Address: address, Family: "IPv4", Source: SourceObservedLAN, Confidence: ObservedLANConfidence,
		ValidFrom: from, ValidUntil: until, ObservedAt: now, Active: until.After(now),
		Interface: scope.Interface, VLANID: cloneInt(scope.VLANID), ScopePlanSHA256: scope.ScopePlanSHA256,
	})
}
