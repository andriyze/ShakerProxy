package trafficpolicy

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"time"
)

const DefaultStandaloneInventoryPath = "/var/lib/shakerproxy/inventory/inventory.json"

// StandaloneProxyRuntime is the compatibility projection written for mitmproxy
// and the local DNS forwarder when the local/standalone policy owns the packet
// path. Fleet already writes the compiled schema through ProxySnapshot.
// Keeping the same top-level schema removes a second active runtime format
// while preserving standalone-only settings until the local UI migrates to
// EnforcementDocument directly. Readers must tolerate unknown fields.
type StandaloneProxyRuntime struct {
	SchemaVersion int                `json:"schema_version"`
	Revision      uint64             `json:"revision"`
	Enabled       bool               `json:"enabled"`
	EncryptedDNS  StandaloneProxyDNS `json:"encrypted_dns"`
	TLS           StandaloneProxyTLS `json:"tls"`
	DeviceByIP    map[string]string  `json:"device_by_ip"`
	Platforms     map[string]string  `json:"device_platforms"`
	// LabSources lists the lab prefixes. The DNS forwarder and mitmproxy
	// accept clients only from loopback, private ranges and these prefixes,
	// so a missing firewall rule cannot turn them into open services.
	LabSources []string `json:"lab_sources,omitempty"`
}

// StandaloneProxyDNS carries everything shakerproxy-dnsd needs. Mode uses the
// compiled (Fleet) vocabulary: observe, block or strict (ENFORCE_LOCAL).
type StandaloneProxyDNS struct {
	BlockKnownDoH bool   `json:"block_known_doh"`
	Mode          string `json:"mode"`
	// RedirectPlainDNS is true whenever any lab client's plain DNS is
	// redirected to the local forwarder: ENFORCE_LOCAL for the whole lab, or
	// per device for domain blocking.
	RedirectPlainDNS bool `json:"redirect_plain_dns"`
	// UpstreamServers is empty when the forwarder should use the host's own
	// resolver configuration (domain blocking without ENFORCE_LOCAL).
	UpstreamServers []string `json:"upstream_servers"`
	// BlockedDomains maps device IDs to names the forwarder answers with
	// NXDOMAIN, including their subdomains.
	BlockedDomains map[string][]string `json:"blocked_domains,omitempty"`
}

type StandaloneProxyTLS struct {
	Mode                         string            `json:"mode"`
	ExcludeHosts                 []string          `json:"exclude_hosts"`
	ExcludeCIDRs                 []string          `json:"exclude_cidrs"`
	AutoBypassPinning            bool              `json:"auto_bypass_pinning"`
	PinningThreshold             int               `json:"pinning_threshold"`
	AutoBypassTTLSeconds         int               `json:"auto_bypass_ttl_seconds"`
	MaxDynamicBypasses           int               `json:"max_dynamic_bypasses"`
	MobileClients                []TLSMobileClient `json:"mobile_clients"`
	SelectedDeviceIDs            []string          `json:"selected_device_ids"`
	BypassRules                  []TLSBypassRule   `json:"bypass_rules"`
	InterceptHTTP                bool              `json:"intercept_http"`
	InterceptPrivateDestinations bool              `json:"intercept_private_destinations"`
}

// ProjectStandaloneProxyRuntime is the installed-host projection. Identity is
// derived from active inventory addresses only. Missing or invalid inventory
// becomes an empty device map; in selective mode this fails open to passthrough
// instead of guessing identity or decrypting the wrong client.
func ProjectStandaloneProxyRuntime(input Policy) (StandaloneProxyRuntime, error) {
	return ProjectStandaloneProxyRuntimeWithIdentity(input, LoadStandaloneDevicesBestEffort(), nil)
}

// LoadStandaloneDevicesBestEffort reads the inventory projection when the
// caller is allowed to; otherwise it returns an empty map.
func LoadStandaloneDevicesBestEffort() StandaloneDeviceRuntime {
	if loaded, err := LoadStandaloneDeviceRuntimeFromInventory(DefaultStandaloneInventoryPath, time.Now().UTC()); err == nil {
		return loaded
	}
	return EmptyStandaloneDeviceRuntime()
}

// ProjectStandaloneProxyRuntimeWithDevices publishes local policy in the same
// compiled schema consumed by Fleet. An empty selected-device list means all
// eligible clients; a non-empty list means selective interception by stable
// ShakerProxy device ID. DeviceByIP contains only the privacy-minimized current
// address map, never complete inventory metadata.
func ProjectStandaloneProxyRuntimeWithDevices(input Policy, devices StandaloneDeviceRuntime) (StandaloneProxyRuntime, error) {
	return ProjectStandaloneProxyRuntimeWithIdentity(input, devices, nil)
}

// ProjectStandaloneProxyRuntimeWithIdentity also merges the addresses the
// privileged gateway resolved for devices with lab controls (neighbor table
// by MAC). Those addresses are the freshest evidence and win over inventory;
// hardware addresses themselves never cross into the runtime document.
func ProjectStandaloneProxyRuntimeWithIdentity(input Policy, devices StandaloneDeviceRuntime, matches map[string]DeviceMatch) (StandaloneProxyRuntime, error) {
	policy, err := Normalize(input)
	if err != nil {
		return StandaloneProxyRuntime{}, err
	}
	if devices.DeviceByIP == nil {
		devices.DeviceByIP = map[string]string{}
	}
	tlsMode := "off"
	if policy.TLS.Enabled {
		tlsMode = "all"
		if len(policy.TLS.SelectedDeviceIDs) != 0 {
			tlsMode = "selective"
		}
	}
	deviceByIP := make(map[string]string, len(devices.DeviceByIP))
	for address, deviceID := range devices.DeviceByIP {
		deviceByIP[address] = deviceID
	}
	// Resolved control identities are fresher than the inventory, but an
	// address the inventory attributes to another device is ambiguous and is
	// dropped rather than guessed.
	for deviceID, match := range matches {
		for _, address := range append(append([]string(nil), match.IPv4...), match.IPv6...) {
			parsed, err := netip.ParseAddr(address)
			if err != nil || parsed.String() != address {
				continue
			}
			if previous, exists := deviceByIP[address]; exists && previous != deviceID {
				delete(deviceByIP, address)
				continue
			}
			deviceByIP[address] = deviceID
		}
	}
	if len(deviceByIP) > 8192 {
		return StandaloneProxyRuntime{}, fmt.Errorf("standalone device runtime exceeds its address bound")
	}

	dnsMode := "observe"
	switch policy.EncryptedDNS.Mode {
	case EncryptedDNSBlockKnown:
		dnsMode = "block"
	case EncryptedDNSEnforceLocal:
		dnsMode = "strict"
	}
	upstreams := []string{}
	if policy.EncryptedDNS.Mode == EncryptedDNSEnforceLocal {
		upstreams = append(upstreams, policy.EncryptedDNS.UpstreamServers...)
	}
	var blockedDomains map[string][]string
	bypassRules := []TLSBypassRule{}
	for _, control := range policy.DeviceControls {
		if len(control.BlockedDomains) != 0 && !control.BlockInternet {
			if blockedDomains == nil {
				blockedDomains = map[string][]string{}
			}
			blockedDomains[control.DeviceID] = append([]string(nil), control.BlockedDomains...)
		}
		for index, host := range control.BypassHosts {
			bypassRules = append(bypassRules, TLSBypassRule{
				ID:        fmt.Sprintf("device-bypass-%s-%d", control.DeviceID, index+1),
				Enabled:   true,
				Platform:  "any",
				DeviceID:  control.DeviceID,
				MatchType: "exact-host",
				Pattern:   host,
				Reason:    "Bypassed from the device controls",
				Source:    "device-controls",
			})
		}
	}
	sort.Slice(bypassRules, func(i, j int) bool { return bypassRules[i].ID < bypassRules[j].ID })

	return StandaloneProxyRuntime{
		SchemaVersion: SchemaVersion,
		Revision:      policy.Revision,
		Enabled:       policy.TLS.Enabled,
		EncryptedDNS: StandaloneProxyDNS{
			BlockKnownDoH:    policy.EncryptedDNS.BlockKnownDoH,
			Mode:             dnsMode,
			RedirectPlainDNS: (policy.EncryptedDNS.Mode == EncryptedDNSEnforceLocal && policy.EncryptedDNS.RedirectPlainDNS) || len(blockedDomains) != 0,
			UpstreamServers:  upstreams,
			BlockedDomains:   blockedDomains,
		},
		TLS: StandaloneProxyTLS{
			Mode:                         tlsMode,
			ExcludeHosts:                 append([]string{}, policy.TLS.ExcludeHosts...),
			ExcludeCIDRs:                 append([]string{}, policy.TLS.ExcludeCIDRs...),
			AutoBypassPinning:            policy.TLS.AutoBypassPinned,
			PinningThreshold:             3,
			AutoBypassTTLSeconds:         policy.TLS.AutoBypassTTLSeconds,
			MaxDynamicBypasses:           policy.TLS.MaxDynamicBypasses,
			MobileClients:                append([]TLSMobileClient{}, policy.TLS.MobileClients...),
			SelectedDeviceIDs:            append([]string{}, policy.TLS.SelectedDeviceIDs...),
			BypassRules:                  bypassRules,
			InterceptHTTP:                policy.TLS.Enabled && policy.TLS.InterceptHTTP,
			InterceptPrivateDestinations: policy.TLS.InterceptPrivateDestinations,
		},
		DeviceByIP: deviceByIP,
		Platforms:  map[string]string{},
	}, nil
}

// EncodeStandaloneProxyRuntime is the exact byte encoding the gateway writes.
// Tests of every runtime reader use it so writer and readers cannot drift.
func EncodeStandaloneProxyRuntime(runtime StandaloneProxyRuntime) ([]byte, error) {
	encoded, err := json.MarshalIndent(runtime, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}
