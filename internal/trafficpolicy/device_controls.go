package trafficpolicy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

const (
	MaxDeviceControls          = 512
	MaxBlockedDomainsPerDevice = 256
	MaxBypassHostsPerDevice    = 256
	maxDeviceHardwareAddresses = 8
	maxDeviceAddresses         = 16
	maxNeighborAddressesPerMAC = 8
)

var hardwareAddressPattern = regexp.MustCompile(`^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$`)

// DeviceMatch is the render-time identity of one device: MAC addresses are
// preferred because lab clients are L2-adjacent; IPs are the fallback when no
// MAC is known and the evidence mitmproxy and the DNS forwarder use to map a
// client address back to a stable device ID.
type DeviceMatch struct {
	HardwareAddresses []string `json:"hardware_addresses,omitempty"`
	IPv4              []string `json:"ipv4,omitempty"`
	IPv6              []string `json:"ipv6,omitempty"`
}

// Empty reports whether no packet of the device can be matched.
func (m DeviceMatch) Empty() bool {
	return len(m.HardwareAddresses) == 0 && len(m.IPv4) == 0 && len(m.IPv6) == 0
}

// Effective reports whether the control changes packet or DNS handling.
// Identity-only entries exist to carry evidence for selected TLS devices.
func (c DeviceControl) Effective() bool {
	return c.BlockInternet || len(c.BlockedDomains) != 0 || len(c.BypassHosts) != 0
}

// FindDeviceControl returns the control for a device, if any.
func FindDeviceControl(policy Policy, deviceID string) (DeviceControl, bool) {
	for _, control := range policy.DeviceControls {
		if control.DeviceID == deviceID {
			return control, true
		}
	}
	return DeviceControl{}, false
}

// NormalizeHardwareAddress returns the canonical lower-case colon form of a
// unicast 48-bit MAC address.
func NormalizeHardwareAddress(value string) (string, error) {
	parsed, err := net.ParseMAC(strings.TrimSpace(value))
	if err != nil || len(parsed) != 6 {
		return "", fmt.Errorf("hardware address %q is not a 48-bit MAC address", value)
	}
	if parsed[0]&0x01 != 0 {
		return "", fmt.Errorf("hardware address %q is multicast or broadcast", value)
	}
	if parsed.String() == "00:00:00:00:00:00" {
		return "", fmt.Errorf("hardware address %q is empty", value)
	}
	return parsed.String(), nil
}

// NormalizeDomain turns user input such as "*.Example.COM." into the
// canonical registrable name "example.com". A blocked or bypassed domain
// always covers its subdomains.
func NormalizeDomain(value string) (string, error) {
	domain := strings.ToLower(strings.TrimSpace(value))
	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimSuffix(domain, ".")
	if !validHostPattern(domain) || strings.HasPrefix(domain, "*.") {
		return "", fmt.Errorf("%q is not a valid domain name", value)
	}
	return domain, nil
}

// DomainCovers reports whether name equals domain or is one of its subdomains.
func DomainCovers(domain, name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	return name == domain || strings.HasSuffix(name, "."+domain)
}

func normalizeDeviceControls(values []DeviceControl) []DeviceControl {
	if len(values) == 0 {
		return nil
	}
	result := make([]DeviceControl, 0, len(values))
	for _, value := range values {
		control := DeviceControl{
			DeviceID:      strings.TrimSpace(value.DeviceID),
			BlockInternet: value.BlockInternet,
		}
		control.HardwareAddresses = normalizeStringList(value.HardwareAddresses, func(raw string) string {
			if normalized, err := NormalizeHardwareAddress(raw); err == nil {
				return normalized
			}
			return raw
		})
		control.Addresses = normalizeStringList(value.Addresses, func(raw string) string {
			if address, err := netip.ParseAddr(raw); err == nil {
				return address.Unmap().String()
			}
			return raw
		})
		control.BlockedDomains = normalizeDomainList(value.BlockedDomains)
		control.BypassHosts = normalizeDomainList(value.BypassHosts)
		result = append(result, control)
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].DeviceID < result[j].DeviceID })
	return result
}

func normalizeDomainList(values []string) []string {
	return normalizeStringList(values, func(raw string) string {
		if normalized, err := NormalizeDomain(raw); err == nil {
			return normalized
		}
		return raw
	})
}

func validateDeviceControls(policy Policy) error {
	if len(policy.DeviceControls) > MaxDeviceControls {
		return fmt.Errorf("at most %d devices can have lab controls", MaxDeviceControls)
	}
	seen := make(map[string]bool, len(policy.DeviceControls))
	for _, control := range policy.DeviceControls {
		if !selectedDeviceIDPattern.MatchString(control.DeviceID) {
			return fmt.Errorf("device control has an invalid device ID %q", control.DeviceID)
		}
		if seen[control.DeviceID] {
			return fmt.Errorf("device %s has more than one control entry", control.DeviceID)
		}
		seen[control.DeviceID] = true
		if len(control.HardwareAddresses) > maxDeviceHardwareAddresses || len(control.Addresses) > maxDeviceAddresses {
			return fmt.Errorf("device %s has too many identity addresses", control.DeviceID)
		}
		for _, hardwareAddress := range control.HardwareAddresses {
			if !hardwareAddressPattern.MatchString(hardwareAddress) {
				return fmt.Errorf("device %s has an invalid hardware address %q", control.DeviceID, hardwareAddress)
			}
			if _, err := NormalizeHardwareAddress(hardwareAddress); err != nil {
				return fmt.Errorf("device %s: %w", control.DeviceID, err)
			}
		}
		for _, raw := range control.Addresses {
			address, err := netip.ParseAddr(raw)
			if err != nil || address.String() != raw || address.Zone() != "" || !address.IsGlobalUnicast() && !address.IsPrivate() && !address.IsLinkLocalUnicast() {
				return fmt.Errorf("device %s has an invalid address %q", control.DeviceID, raw)
			}
		}
		if len(control.BlockedDomains) > MaxBlockedDomainsPerDevice {
			return fmt.Errorf("device %s can block at most %d domains", control.DeviceID, MaxBlockedDomainsPerDevice)
		}
		if len(control.BypassHosts) > MaxBypassHostsPerDevice {
			return fmt.Errorf("device %s can bypass at most %d hosts", control.DeviceID, MaxBypassHostsPerDevice)
		}
		for _, domain := range append(append([]string(nil), control.BlockedDomains...), control.BypassHosts...) {
			if normalized, err := NormalizeDomain(domain); err != nil || normalized != domain {
				return fmt.Errorf("device %s has an invalid domain %q", control.DeviceID, domain)
			}
		}
	}
	return nil
}

// DeviceIdentityFromControl splits captured identity evidence by family.
func DeviceIdentityFromControl(control DeviceControl) DeviceMatch {
	match := DeviceMatch{HardwareAddresses: append([]string(nil), control.HardwareAddresses...)}
	for _, raw := range control.Addresses {
		address, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		if address.Is4() {
			match.IPv4 = append(match.IPv4, address.String())
		} else {
			match.IPv6 = append(match.IPv6, address.String())
		}
	}
	return match
}

// Neighbor is one entry of the kernel neighbor (ARP/NDP) table on the lab
// interface.
type Neighbor struct {
	Address         string
	HardwareAddress string
}

// ResolveDeviceMatches combines identity evidence captured in device controls
// with the current lab neighbor table. For a device with known MACs, only the
// neighbor table says which addresses it holds now; its saved addresses are
// used only when the neighbor table could not be read (neighborsKnown false),
// because a saved lease may since have been handed to another device. A MAC
// observed at several addresses contributes each address (bounded); an
// address claimed by two devices is dropped.
func ResolveDeviceMatches(policy Policy, neighbors []Neighbor, neighborsKnown bool) map[string]DeviceMatch {
	byMAC := make(map[string][]netip.Addr)
	for _, neighbor := range neighbors {
		mac, err := NormalizeHardwareAddress(neighbor.HardwareAddress)
		if err != nil {
			continue
		}
		address, err := netip.ParseAddr(neighbor.Address)
		if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() {
			continue
		}
		if len(byMAC[mac]) < maxNeighborAddressesPerMAC {
			byMAC[mac] = append(byMAC[mac], address.Unmap())
		}
	}
	owners := make(map[string]string)
	ambiguous := make(map[string]bool)
	claim := func(deviceID, address string) {
		if ambiguous[address] {
			return
		}
		if previous, exists := owners[address]; exists && previous != deviceID {
			delete(owners, address)
			ambiguous[address] = true
			return
		}
		owners[address] = deviceID
	}
	result := make(map[string]DeviceMatch, len(policy.DeviceControls))
	for _, control := range policy.DeviceControls {
		identity := DeviceIdentityFromControl(control)
		if len(identity.HardwareAddresses) == 0 || !neighborsKnown {
			for _, address := range append(append([]string(nil), identity.IPv4...), identity.IPv6...) {
				claim(control.DeviceID, address)
			}
		}
		for _, mac := range identity.HardwareAddresses {
			for _, address := range byMAC[mac] {
				claim(control.DeviceID, address.String())
			}
		}
		result[control.DeviceID] = DeviceMatch{HardwareAddresses: identity.HardwareAddresses}
	}
	for address, deviceID := range owners {
		match := result[deviceID]
		if parsed, err := netip.ParseAddr(address); err == nil && parsed.Is4() {
			match.IPv4 = append(match.IPv4, address)
		} else {
			match.IPv6 = append(match.IPv6, address)
		}
		result[deviceID] = match
	}
	for deviceID, match := range result {
		sort.Strings(match.IPv4)
		sort.Strings(match.IPv6)
		result[deviceID] = match
	}
	return result
}

func validateDeviceMatches(matches map[string]DeviceMatch) error {
	if len(matches) > MaxDeviceControls {
		return errors.New("device match set exceeds its bound")
	}
	for deviceID, match := range matches {
		if !selectedDeviceIDPattern.MatchString(deviceID) {
			return fmt.Errorf("device match has an invalid device ID %q", deviceID)
		}
		if len(match.HardwareAddresses) > maxDeviceHardwareAddresses || len(match.IPv4)+len(match.IPv6) > maxDeviceAddresses+maxDeviceHardwareAddresses*maxNeighborAddressesPerMAC {
			return fmt.Errorf("device %s match set exceeds its bound", deviceID)
		}
		for _, mac := range match.HardwareAddresses {
			if !hardwareAddressPattern.MatchString(mac) {
				return fmt.Errorf("device %s has an invalid hardware address", deviceID)
			}
		}
		for _, raw := range match.IPv4 {
			if address, err := netip.ParseAddr(raw); err != nil || !address.Is4() || address.String() != raw {
				return fmt.Errorf("device %s has an invalid IPv4 address", deviceID)
			}
		}
		for _, raw := range match.IPv6 {
			if address, err := netip.ParseAddr(raw); err != nil || !address.Is6() || address.Is4In6() || address.Zone() != "" || address.String() != raw {
				return fmt.Errorf("device %s has an invalid IPv6 address", deviceID)
			}
		}
	}
	return nil
}
