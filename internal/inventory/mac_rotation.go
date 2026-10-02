package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"time"
)

// Phones (GrapheneOS, Android, iOS) use a "private" Wi-Fi MAC and may pick a
// new one on every connection. With a static address, as single-arm labs
// use, the address is what stays the same, so a new randomized MAC taking over
// the address of a device known only by randomized MACs is that device
// reconnecting. DHCP evidence keeps devices apart: a lab DHCP server may hand
// a released address to a different device.

// MaxFormerIDs bounds the device IDs a merged device remembers so that
// traffic attributed before the merge can still be found.
const MaxFormerIDs = 16

const macRotationActor = "ShakerProxy (MAC rotation)"

// locallyAdministeredMAC reports a randomized ("private") MAC address: the
// locally administered bit of the first octet is set.
func locallyAdministeredMAC(value string) bool {
	mac, err := net.ParseMAC(value)
	return err == nil && len(mac) == 6 && mac[0]&0x02 != 0
}

// rotatingMACDevice reports a device known only by randomized MACs from the
// neighbor tables, never from a DHCP lease or client ID.
func rotatingMACDevice(device Device) bool {
	macs := 0
	for _, identity := range device.Identities {
		if identity.Kind != IdentityMAC || identity.Source == SourceDHCP4Lease || !locallyAdministeredMAC(identity.Value) {
			return false
		}
		macs++
	}
	for _, address := range device.Addresses {
		if address.Source == SourceDHCP4Lease {
			return false
		}
	}
	return macs > 0
}

func ipv4ScopeKey(address AddressObservation) (string, bool) {
	parsed, err := netip.ParseAddr(address.Address)
	if err != nil || !parsed.Is4() {
		return "", false
	}
	return address.Address + "|" + addressScopeKey(address.Interface, address.VLANID, address.ScopePlanSHA256), true
}

// rotatedMACDevice finds the device a phone that rotated its randomized MAC
// was before: the rotating-MAC device that last held the observed IPv4 address
// on the same interface, VLAN and plan scope. IPv4 only: the ARP table maps an
// address to one MAC at a time, while two MACs claiming one IPv6 address stay
// a conflict.
func rotatedMACDevice(devices []Device, observation NeighborObservation) (int, bool) {
	if !observation.Address.Is4() || !locallyAdministeredMAC(observation.HardwareAddr) {
		return 0, false
	}
	want := observation.Address.String() + "|" + addressScopeKey(observation.Interface, observation.VLANID, observation.ScopePlanSHA256)
	best, bestSeen := -1, time.Time{}
	for index, device := range devices {
		if !rotatingMACDevice(device) {
			continue
		}
		for _, held := range device.Addresses {
			if key, ok := ipv4ScopeKey(held); ok && key == want && (best < 0 || held.ObservedAt.After(bestSeen)) {
				best, bestSeen = index, held.ObservedAt
			}
		}
	}
	return best, best >= 0
}

// consolidateRotatedMACDevices folds devices that earlier versions recorded
// separately for each MAC a phone rotated through into the most recently seen
// of them, and returns the IDs of the devices that absorbed others. Each fold
// is audited like a manual merge, and the absorbed IDs are kept as former IDs.
func consolidateRotatedMACDevices(doc *document, now time.Time) ([]string, error) {
	parent := map[int]int{}
	var find func(int) int
	find = func(index int) int {
		if root, ok := parent[index]; ok && root != index {
			parent[index] = find(root)
			return parent[index]
		}
		return index
	}
	holders := map[string]int{}
	for index, device := range doc.Devices {
		if !rotatingMACDevice(device) {
			continue
		}
		for _, address := range device.Addresses {
			key, ok := ipv4ScopeKey(address)
			if !ok {
				continue
			}
			if other, seen := holders[key]; seen {
				parent[find(index)] = find(other)
			} else {
				holders[key] = index
			}
		}
	}
	groups := map[int][]int{}
	for index := range parent {
		root := find(index)
		groups[root] = appendUnique(groups[root], index)
		groups[root] = appendUnique(groups[root], root)
	}
	if len(groups) == 0 {
		return nil, nil
	}
	roots := make([]int, 0, len(groups))
	for root := range groups {
		roots = append(roots, root)
	}
	sort.Ints(roots)
	absorbed := map[string]bool{}
	var targets []string
	for _, root := range roots {
		members := groups[root]
		// A device the administrator named by its address survives; otherwise
		// the most recently seen record, the one testers are looking at now.
		sort.Slice(members, func(i, j int) bool {
			a, b := doc.Devices[members[i]], doc.Devices[members[j]]
			if (a.PinnedAddress != "") != (b.PinnedAddress != "") {
				return a.PinnedAddress != ""
			}
			if !a.LastSeen.Equal(b.LastSeen) {
				return a.LastSeen.After(b.LastSeen)
			}
			return a.ID < b.ID
		})
		target := &doc.Devices[members[0]]
		for _, member := range members[1:] {
			source := trimForMerge(*target, doc.Devices[member])
			previousFriendlyName := target.FriendlyName
			changes, err := mergeDeviceEvidence(target, source)
			if err != nil {
				return nil, err
			}
			if target.FriendlyName != previousFriendlyName {
				adopted := target.FriendlyName
				target.FriendlyName = previousFriendlyName
				if err := appendAliasChange(target, adopted, macRotationActor, "Adopted while merging records of a device that changed its private MAC", now); err != nil {
					return nil, err
				}
			}
			sources := []string{target.ID, source.ID}
			requestSHA256, err := mutationRequestDigest(AuditDevicesMerged, sources, nil)
			if err != nil {
				return nil, err
			}
			digest := sha256.Sum256([]byte(target.ID + "|" + source.ID + "|" + strconv.FormatInt(now.UnixNano(), 10)))
			audit := newAuditEvent("mac-rotation-"+hex.EncodeToString(digest[:16]), requestSHA256, AuditDevicesMerged, macRotationActor, now, sources, []string{target.ID}, append(changes, "same static address with a new private MAC"))
			if err := appendAudit(doc, &audit); err != nil {
				return nil, err
			}
			absorbed[source.ID] = true
		}
		target.LastReconciled = now
		targets = append(targets, target.ID)
	}
	devices := doc.Devices[:0]
	for _, device := range doc.Devices {
		if !absorbed[device.ID] {
			devices = append(devices, device)
		}
	}
	doc.Devices = devices
	return targets, nil
}

func appendUnique(values []int, value int) []int {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

// trimForMerge drops the absorbed record's oldest evidence so the merged
// device stays within the per-device bounds instead of failing the merge.
func trimForMerge(target, source Device) Device {
	source.Identities = append([]Identity(nil), source.Identities...)
	for len(target.Identities)+len(source.Identities) > MaxIdentities && dropOldestRandomizedMAC(&source) {
	}
	source.Addresses = append([]AddressObservation(nil), source.Addresses...)
	if excess := len(target.Addresses) + len(source.Addresses) - MaxAddresses; excess > 0 {
		sort.Slice(source.Addresses, func(i, j int) bool { return source.Addresses[i].ObservedAt.After(source.Addresses[j].ObservedAt) })
		source.Addresses = source.Addresses[:max(0, len(source.Addresses)-excess)]
	}
	source.Hostnames = append([]HostnameObservation(nil), source.Hostnames...)
	if excess := len(target.Hostnames) + len(source.Hostnames) - MaxHostnames; excess > 0 {
		sort.Slice(source.Hostnames, func(i, j int) bool { return source.Hostnames[i].LastSeen.After(source.Hostnames[j].LastSeen) })
		source.Hostnames = source.Hostnames[:max(0, len(source.Hostnames)-excess)]
	}
	return source
}

// dropOldestRandomizedMAC removes the least recently seen randomized MAC
// identity and reports whether one was removed. A device always keeps at
// least one identity.
func dropOldestRandomizedMAC(device *Device) bool {
	oldest := -1
	for index, identity := range device.Identities {
		if identity.Kind == IdentityMAC && locallyAdministeredMAC(identity.Value) && (oldest < 0 || identity.LastSeen.Before(device.Identities[oldest].LastSeen)) {
			oldest = index
		}
	}
	if oldest < 0 || len(device.Identities) <= 1 {
		return false
	}
	device.Identities = append(device.Identities[:oldest], device.Identities[oldest+1:]...)
	return true
}

// mergeFormerIDs records the absorbed device's ID, and the IDs it had
// absorbed, on the surviving device, keeping the most recent MaxFormerIDs.
func mergeFormerIDs(target *Device, source Device) {
	ids := append(append([]string{source.ID}, source.FormerIDs...), target.FormerIDs...)
	seen := map[string]bool{target.ID: true}
	kept := make([]string, 0, len(ids))
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		kept = append(kept, id)
	}
	if len(kept) > MaxFormerIDs {
		kept = kept[:MaxFormerIDs]
	}
	target.FormerIDs = kept
}
