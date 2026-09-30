package inventory

import (
	"errors"
	"net/netip"
	"sync"
	"time"
)

const DefaultAttributionRefreshInterval = 2 * time.Second

type AddressAttribution struct {
	DeviceID        string
	Address         string
	Confidence      int
	Source          EvidenceSource
	ValidFrom       time.Time
	ValidUntil      time.Time
	Interface       string
	VLANID          *int
	ScopePlanSHA256 string
	Matched         bool
	Ambiguous       bool
}

type addressWindow struct {
	deviceID        string
	address         string
	confidence      int
	source          EvidenceSource
	validFrom       time.Time
	validUntil      time.Time
	interfaceName   string
	vlanID          *int
	scopePlanSHA256 string
}

type Attributor struct {
	Store           *Store
	RefreshInterval time.Duration
	Now             func() time.Time

	mu        sync.Mutex
	loadedAt  time.Time
	addresses map[string][]addressWindow
}

// ResolveIPv4 keeps the original IPv4-only contract.
func (a *Attributor) ResolveIPv4(address netip.Addr, occurredAt time.Time) (AddressAttribution, error) {
	if !address.Is4() {
		return AddressAttribution{}, errors.New("device attribution input is invalid")
	}
	return a.ResolveAddress(address, occurredAt)
}

// ResolveAddress attributes an IPv4 address (DHCPv4 lease windows) or an IPv6
// address (NDP windows) to at most one device at the given time.
func (a *Attributor) ResolveAddress(address netip.Addr, occurredAt time.Time) (AddressAttribution, error) {
	address = address.Unmap()
	if a == nil || a.Store == nil || !(address.Is4() || address.Is6()) || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || occurredAt.IsZero() {
		return AddressAttribution{}, errors.New("device attribution input is invalid")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now().UTC()
	if a.Now != nil {
		now = a.Now().UTC()
	}
	interval := a.RefreshInterval
	if interval == 0 {
		interval = DefaultAttributionRefreshInterval
	}
	if interval < 0 || interval > time.Minute {
		return AddressAttribution{}, errors.New("device attribution refresh interval is invalid")
	}
	if a.addresses == nil || now.Sub(a.loadedAt) >= interval || now.Before(a.loadedAt) {
		snapshot, err := a.Store.Snapshot()
		if err != nil {
			a.addresses = nil
			return AddressAttribution{}, err
		}
		a.addresses = buildAddressIndex(snapshot)
		a.loadedAt = now
	}
	return resolveAddressWindows(a.addresses[address.String()], occurredAt.UTC()), nil
}

func buildAddressIndex(snapshot Snapshot) map[string][]addressWindow {
	index := make(map[string][]addressWindow)
	for _, device := range snapshot.Devices {
		for _, address := range device.Addresses {
			index[address.Address] = append(index[address.Address], addressWindow{
				deviceID: device.ID, address: address.Address, confidence: address.Confidence, source: address.Source,
				validFrom: address.ValidFrom.UTC(), validUntil: address.ValidUntil.UTC(), interfaceName: address.Interface,
				vlanID: cloneInt(address.VLANID), scopePlanSHA256: address.ScopePlanSHA256,
			})
		}
	}
	return index
}

func resolveAddressWindows(windows []addressWindow, occurredAt time.Time) AddressAttribution {
	matches := make(map[string]AddressAttribution)
	for _, window := range windows {
		if occurredAt.Before(window.validFrom) || !occurredAt.Before(window.validUntil) {
			continue
		}
		candidate := matches[window.deviceID]
		next := AddressAttribution{
			DeviceID: window.deviceID, Address: window.address, Confidence: window.confidence, Source: window.source,
			ValidFrom: window.validFrom, ValidUntil: window.validUntil, Interface: window.interfaceName,
			VLANID: cloneInt(window.vlanID), ScopePlanSHA256: window.scopePlanSHA256, Matched: true,
		}
		if strongerAddressAttribution(next, candidate) {
			matches[window.deviceID] = next
		}
	}
	if len(matches) == 0 {
		return AddressAttribution{}
	}
	if len(matches) > 1 {
		return AddressAttribution{Ambiguous: true}
	}
	for _, match := range matches {
		return match
	}
	return AddressAttribution{}
}

func strongerAddressAttribution(next, current AddressAttribution) bool {
	if !current.Matched || next.Confidence != current.Confidence {
		return !current.Matched || next.Confidence > current.Confidence
	}
	if (next.Interface != "") != (current.Interface != "") {
		return next.Interface != ""
	}
	if !next.ValidFrom.Equal(current.ValidFrom) {
		return next.ValidFrom.After(current.ValidFrom)
	}
	if !next.ValidUntil.Equal(current.ValidUntil) {
		return next.ValidUntil.Before(current.ValidUntil)
	}
	return addressScopeKey(next.Interface, next.VLANID, next.ScopePlanSHA256) < addressScopeKey(current.Interface, current.VLANID, current.ScopePlanSHA256)
}
