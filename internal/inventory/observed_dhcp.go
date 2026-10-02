package inventory

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"time"
)

// DHCP observed on the lab: when the network's router serves DHCP (a
// single-arm lab, an inline bridge), ShakerProxy's own lease file is empty,
// but the lab recording sees the clients' DHCP exchanges. A router's
// acknowledgement binds a MAC to an address for the lease time: weaker than
// ShakerProxy's own lease (it was observed, not granted), stronger than a
// neighbor entry (a device can answer ARP for another's address). The name a
// client gives itself becomes a suggested name, below the one it gives
// ShakerProxy's own DHCP server, and never replaces a name an administrator
// chose.

const (
	SourceObservedDHCP EvidenceSource = "OBSERVED_DHCP"
	// ObservedDHCPConfidence is the confidence of a MAC and address seen in a
	// router's DHCP acknowledgement (ShakerProxy's own lease: 95; NDP: 80;
	// ARP: 70).
	ObservedDHCPConfidence = 90
	// ObservedDHCPHostnameConfidence ranks the observed name below the one a
	// device gives ShakerProxy's own DHCP server (75).
	ObservedDHCPHostnameConfidence = 70
	// DefaultObservedDHCPLease is the address window when the acknowledgement
	// carried no lease time.
	DefaultObservedDHCPLease = time.Hour
	// MaxObservedDHCPLease bounds a window a router (or a forged reply) could
	// otherwise make last for decades.
	MaxObservedDHCPLease   = 7 * 24 * time.Hour
	MaxObservedDHCPClients = 4096
)

var dhcpParameterListPattern = regexp.MustCompile(`^[0-9]{1,3}(,[0-9]{1,3}){0,63}$`)

// ObservedDHCPClient is what the recorded exchanges of one MAC said.
// AssignedAddr is set only when a server's acknowledgement was seen.
type ObservedDHCPClient struct {
	HardwareAddr  string
	HostName      string
	ClientFQDN    string
	VendorClass   string
	ParameterList string
	AssignedAddr  netip.Addr
	AssignedAt    time.Time
	LeaseTime     time.Duration
	Server        netip.Addr
	Router        netip.Addr
	FirstSeen     time.Time
	LastSeen      time.Time
}

// ObservedDHCPScope is the lab interface, VLAN and plan the observations
// belong to, as the gateway's neighbor table reports it; empty when unknown.
type ObservedDHCPScope struct {
	Interface       string
	VLANID          *int
	ScopePlanSHA256 string
}

// ObservedDHCPIdentity is the newest DHCP identity a device showed on the
// lab: the name it gave itself (with its own capitalization), its DHCP
// implementation and the server that answered it.
type ObservedDHCPIdentity struct {
	HardwareAddr  string    `json:"hardware_addr"`
	HostName      string    `json:"host_name,omitempty"`
	ClientFQDN    string    `json:"client_fqdn,omitempty"`
	VendorClass   string    `json:"vendor_class,omitempty"`
	ParameterList string    `json:"parameter_list,omitempty"`
	Server        string    `json:"server,omitempty"`
	Router        string    `json:"router,omitempty"`
	LastSeen      time.Time `json:"last_seen"`
}

// ReconcileObservedDHCP adds the lab's observed DHCP exchanges to the
// inventory. A known MAC (or the device an administrator named the
// acknowledged address after, or the device a phone was before it rotated its
// private MAC) gains the evidence. A MAC seen only asking adds nothing new: a
// lab sees broadcasts from neighbouring networks too, so only an
// acknowledged lease creates a device.
func (s *Store) ReconcileObservedDHCP(clients []ObservedDHCPClient, scope ObservedDHCPScope) (Snapshot, error) {
	if len(clients) > MaxObservedDHCPClients {
		return Snapshot{}, errors.New("too many observed DHCP clients")
	}
	if !validAddressScope(scope.Interface, scope.VLANID, scope.ScopePlanSHA256) {
		return Snapshot{}, errors.New("observed DHCP scope is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	normalized := make([]ObservedDHCPClient, 0, len(clients))
	for _, client := range clients {
		value, err := normalizeObservedDHCPClient(client, now)
		if err != nil {
			return Snapshot{}, err
		}
		normalized = append(normalized, value)
	}
	// Oldest first, so a newer acknowledgement of an address ends the older
	// lease of another device.
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
	for _, client := range normalized {
		deviceIndex, known := macIndex[client.HardwareAddr]
		if !known && client.AssignedAddr.IsValid() {
			if index, ok := pinnedDevice(doc.Devices, client.AssignedAddr); ok {
				deviceIndex, known = index, true
			} else if index, ok := rotatedMACDevice(doc.Devices, NeighborObservation{Address: client.AssignedAddr, HardwareAddr: client.HardwareAddr, SeenAt: client.AssignedAt, Interface: scope.Interface, VLANID: scope.VLANID, ScopePlanSHA256: scope.ScopePlanSHA256}); ok {
				deviceIndex, known = index, true
			}
		}
		if !known {
			if !client.AssignedAddr.IsValid() {
				continue
			}
			if len(doc.Devices) >= MaxDevices {
				return Snapshot{}, errors.New("device inventory limit exceeded")
			}
			id, idErr := s.newUniqueDeviceID(doc.Devices)
			if idErr != nil {
				return Snapshot{}, idErr
			}
			doc.Devices = append(doc.Devices, Device{Schema: SchemaVersion, ID: id, FirstSeen: client.FirstSeen, LastSeen: client.LastSeen, LastReconciled: now})
			deviceIndex = len(doc.Devices) - 1
		}
		macIndex[client.HardwareAddr] = deviceIndex
		device := &doc.Devices[deviceIndex]
		upsertObservedIdentity(device, client)
		if client.HostName != "" {
			upsertObservedHostname(device, normalizeHostname(client.HostName), client.FirstSeen, client.LastSeen)
		}
		if client.AssignedAddr.IsValid() {
			endObservedLeases(doc.Devices, deviceIndex, client.AssignedAddr, client.AssignedAt)
			upsertObservedAddress(device, client, scope, now)
			if device.AttributionConfidence < ObservedDHCPConfidence {
				device.AttributionConfidence = ObservedDHCPConfidence
			}
		}
		if device.ObservedDHCP == nil || !client.LastSeen.Before(device.ObservedDHCP.LastSeen) {
			device.ObservedDHCP = observedDHCPIdentity(client)
		}
		if client.FirstSeen.Before(device.FirstSeen) {
			device.FirstSeen = client.FirstSeen
		}
		if client.LastSeen.After(device.LastSeen) {
			device.LastSeen = client.LastSeen
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
		// The same exchanges as last time: nothing to write.
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

func normalizeObservedDHCPClient(client ObservedDHCPClient, now time.Time) (ObservedDHCPClient, error) {
	if mac := normalizeMACIdentity(client.HardwareAddr); mac == "" || client.HardwareAddr != mac || !unicastMAC(mac) {
		return ObservedDHCPClient{}, errors.New("observed DHCP hardware address is invalid")
	}
	if client.FirstSeen.IsZero() || client.LastSeen.Before(client.FirstSeen) {
		return ObservedDHCPClient{}, errors.New("observed DHCP times are invalid")
	}
	if client.HostName != "" && (normalizeHostname(client.HostName) == "" || !validSingleLine(client.HostName, 1, 253)) ||
		client.ClientFQDN != "" && !validSingleLine(client.ClientFQDN, 1, 253) ||
		client.VendorClass != "" && !validSingleLine(client.VendorClass, 1, 255) ||
		client.ParameterList != "" && !dhcpParameterListPattern.MatchString(client.ParameterList) {
		return ObservedDHCPClient{}, errors.New("observed DHCP client text is invalid")
	}
	for _, address := range []netip.Addr{client.AssignedAddr, client.Server, client.Router} {
		if address.IsValid() && !observableDHCPAddress(address) {
			return ObservedDHCPClient{}, errors.New("observed DHCP address is invalid")
		}
	}
	if client.AssignedAddr.IsValid() == client.AssignedAt.IsZero() || !client.AssignedAddr.IsValid() && (client.LeaseTime != 0 || client.Server.IsValid() || client.Router.IsValid()) || client.LeaseTime < 0 {
		return ObservedDHCPClient{}, errors.New("observed DHCP lease is invalid")
	}
	client.FirstSeen, client.LastSeen = client.FirstSeen.UTC(), client.LastSeen.UTC()
	if client.LastSeen.After(now) {
		client.LastSeen = now
	}
	if client.FirstSeen.After(client.LastSeen) {
		client.FirstSeen = client.LastSeen
	}
	if client.AssignedAddr.IsValid() {
		client.AssignedAt = client.AssignedAt.UTC()
		if client.AssignedAt.After(now) {
			client.AssignedAt = now
		}
		if client.LeaseTime == 0 {
			client.LeaseTime = DefaultObservedDHCPLease
		}
		client.LeaseTime = min(client.LeaseTime, MaxObservedDHCPLease)
	}
	return client, nil
}

func unicastMAC(value string) bool {
	hardware, err := net.ParseMAC(value)
	return err == nil && len(hardware) == 6 && usableHardwareAddress(hardware)
}

func observableDHCPAddress(address netip.Addr) bool {
	return address.Is4() && !address.IsUnspecified() && !address.IsMulticast() && !address.IsLoopback() && address != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

func observedDHCPIdentity(client ObservedDHCPClient) *ObservedDHCPIdentity {
	identity := &ObservedDHCPIdentity{HardwareAddr: client.HardwareAddr, HostName: client.HostName, ClientFQDN: client.ClientFQDN, VendorClass: client.VendorClass, ParameterList: client.ParameterList, LastSeen: client.LastSeen}
	if client.Server.IsValid() {
		identity.Server = client.Server.String()
	}
	if client.Router.IsValid() {
		identity.Router = client.Router.String()
	}
	return identity
}

func upsertObservedIdentity(device *Device, client ObservedDHCPClient) {
	for index := range device.Identities {
		identity := &device.Identities[index]
		if identity.Kind != IdentityMAC || identity.Value != client.HardwareAddr {
			continue
		}
		identity.FirstSeen = earlier(identity.FirstSeen, client.FirstSeen)
		identity.LastSeen = later(identity.LastSeen, client.LastSeen)
		if client.AssignedAddr.IsValid() && identity.Source != SourceDHCP4Lease && identity.Confidence < ObservedDHCPConfidence {
			// A router's acknowledgement is stronger evidence for this MAC
			// than the neighbor table it may have come from.
			identity.Source, identity.Confidence = SourceObservedDHCP, ObservedDHCPConfidence
		}
		return
	}
	if len(device.Identities) >= MaxIdentities && locallyAdministeredMAC(client.HardwareAddr) {
		dropOldestRandomizedMAC(device)
	}
	if len(device.Identities) < MaxIdentities {
		device.Identities = append(device.Identities, Identity{Kind: IdentityMAC, Value: client.HardwareAddr, Source: SourceObservedDHCP, Confidence: ObservedDHCPConfidence, FirstSeen: client.FirstSeen, LastSeen: client.LastSeen})
	}
}

func upsertObservedHostname(device *Device, hostname string, firstSeen, lastSeen time.Time) {
	for index := range device.Hostnames {
		item := &device.Hostnames[index]
		if item.Hostname == hostname && item.Source == SourceObservedDHCP {
			item.FirstSeen = earlier(item.FirstSeen, firstSeen)
			item.LastSeen = later(item.LastSeen, lastSeen)
			return
		}
	}
	if len(device.Hostnames) >= MaxHostnames {
		sort.Slice(device.Hostnames, func(i, j int) bool { return device.Hostnames[i].LastSeen.After(device.Hostnames[j].LastSeen) })
		device.Hostnames = device.Hostnames[:MaxHostnames-1]
	}
	device.Hostnames = append(device.Hostnames, HostnameObservation{Hostname: hostname, Source: SourceObservedDHCP, Confidence: ObservedDHCPHostnameConfidence, FirstSeen: firstSeen, LastSeen: lastSeen})
}

// upsertObservedAddress records the acknowledged lease window [assigned,
// assigned + lease).
func upsertObservedAddress(device *Device, client ObservedDHCPClient, scope ObservedDHCPScope, now time.Time) {
	address := client.AssignedAddr.String()
	from, until := client.AssignedAt, client.AssignedAt.Add(client.LeaseTime)
	key := addressScopeKey(scope.Interface, scope.VLANID, scope.ScopePlanSHA256)
	for index := range device.Addresses {
		item := &device.Addresses[index]
		if item.Source == SourceObservedDHCP && item.Address == address && item.ValidFrom.Equal(from) && addressScopeKey(item.Interface, item.VLANID, item.ScopePlanSHA256) == key {
			item.ValidUntil = later(item.ValidUntil, until)
			item.ObservedAt = now
			item.Active = item.ValidUntil.After(now)
			return
		}
	}
	if len(device.Addresses) >= MaxAddresses {
		sortDeviceEvidence(device)
		device.Addresses = append([]AddressObservation(nil), device.Addresses[len(device.Addresses)-MaxAddresses+1:]...)
	}
	device.Addresses = append(device.Addresses, AddressObservation{
		Address: address, Family: "IPv4", Source: SourceObservedDHCP, Confidence: ObservedDHCPConfidence,
		ValidFrom: from, ValidUntil: until, ObservedAt: now, Active: until.After(now),
		Interface: scope.Interface, VLANID: cloneInt(scope.VLANID), ScopePlanSHA256: scope.ScopePlanSHA256,
	})
}

// endObservedLeases ends other devices' observed leases of an address when a
// newer acknowledgement gives it to this device: the router reassigned it,
// and two live windows would make every packet from it ambiguous.
func endObservedLeases(devices []Device, owner int, address netip.Addr, at time.Time) {
	text := address.String()
	for index := range devices {
		if index == owner {
			continue
		}
		kept := devices[index].Addresses[:0]
		for _, item := range devices[index].Addresses {
			if item.Source == SourceObservedDHCP && item.Address == text && item.ValidFrom.Before(at) && item.ValidUntil.After(at) {
				item.ValidUntil = at
			}
			if item.Source == SourceObservedDHCP && item.Address == text && !item.ValidUntil.After(item.ValidFrom) {
				continue
			}
			kept = append(kept, item)
		}
		devices[index].Addresses = kept
	}
}

func validObservedDHCPIdentity(identity ObservedDHCPIdentity) bool {
	if normalizeMACIdentity(identity.HardwareAddr) != identity.HardwareAddr || identity.HardwareAddr == "" || identity.LastSeen.IsZero() {
		return false
	}
	if identity.HostName != "" && !validSingleLine(identity.HostName, 1, 253) || identity.ClientFQDN != "" && !validSingleLine(identity.ClientFQDN, 1, 253) ||
		identity.VendorClass != "" && !validSingleLine(identity.VendorClass, 1, 255) || identity.ParameterList != "" && !dhcpParameterListPattern.MatchString(identity.ParameterList) {
		return false
	}
	for _, value := range []string{identity.Server, identity.Router} {
		if value == "" {
			continue
		}
		address, err := netip.ParseAddr(value)
		if err != nil || address.String() != value || !observableDHCPAddress(address) {
			return false
		}
	}
	return true
}
