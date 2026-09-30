package trafficpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	enforcementIDPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	enforcementInterfacePattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
	enforcementPlatformPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
)

type EnforcementDocument struct {
	SchemaVersion int                    `json:"schema_version"`
	Enabled       bool                   `json:"enabled"`
	EncryptedDNS  EnforcementDNSPolicy   `json:"encrypted_dns"`
	TLS           TLSInterceptionPolicy  `json:"tls"`
	Resolvers     []ResolverPolicyTarget `json:"resolvers,omitempty"`
}

type EnforcementDNSPolicy struct {
	Mode              string   `json:"mode"`
	RedirectPlainDNS  bool     `json:"redirect_plain_dns"`
	BlockDoT          bool     `json:"block_dot"`
	BlockDoQ          bool     `json:"block_doq"`
	BlockKnownDoH     bool     `json:"block_known_doh"`
	BlockQUICForScope bool     `json:"block_quic_for_scope"`
	FailMode          string   `json:"fail_mode"`
	SelectedDeviceIDs []string `json:"selected_device_ids,omitempty"`
}

type TLSInterceptionPolicy struct {
	Mode              string          `json:"mode"`
	FailMode          string          `json:"fail_mode"`
	AutoBypassPinning bool            `json:"auto_bypass_pinning"`
	PinningThreshold  int             `json:"pinning_threshold"`
	SelectedDeviceIDs []string        `json:"selected_device_ids,omitempty"`
	BypassRules       []TLSBypassRule `json:"bypass_rules,omitempty"`
}

type TLSBypassRule struct {
	ID        string     `json:"id"`
	Enabled   bool       `json:"enabled"`
	Platform  string     `json:"platform"`
	DeviceID  string     `json:"device_id,omitempty"`
	MatchType string     `json:"match_type"`
	Pattern   string     `json:"pattern"`
	Reason    string     `json:"reason"`
	Source    string     `json:"source"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type ResolverPolicyTarget struct {
	Provider        string   `json:"provider"`
	Hostnames       []string `json:"hostnames,omitempty"`
	IPv4            []string `json:"ipv4,omitempty"`
	IPv6            []string `json:"ipv6,omitempty"`
	Transports      []string `json:"transports"`
	Dedicated       bool     `json:"dedicated"`
	SafeToBlockByIP bool     `json:"safe_to_block_by_ip"`
	Source          string   `json:"source,omitempty"`
}

type ApplyRequest struct {
	PolicyID string              `json:"policy_id"`
	Revision uint64              `json:"revision"`
	Digest   string              `json:"digest"`
	Policy   EnforcementDocument `json:"policy"`
	Runtime  Runtime             `json:"runtime"`
}

type Runtime struct {
	TestInterfaces    []string            `json:"test_interfaces"`
	ScopeIPv4         []string            `json:"scope_ipv4,omitempty"`
	ScopeIPv6         []string            `json:"scope_ipv6,omitempty"`
	DevicePlatforms   map[string]string   `json:"device_platforms,omitempty"`
	DeviceIPv4        map[string][]string `json:"device_ipv4,omitempty"`
	DeviceIPv6        map[string][]string `json:"device_ipv6,omitempty"`
	LocalDNSPort      int                 `json:"local_dns_port"`
	MITMPort          int                 `json:"mitm_port"`
	TLSInterceptPorts []int               `json:"tls_intercept_ports,omitempty"`
}

type Status struct {
	SchemaVersion    int       `json:"schema_version"`
	PolicyID         string    `json:"policy_id,omitempty"`
	Revision         uint64    `json:"revision,omitempty"`
	Digest           string    `json:"digest,omitempty"`
	Enabled          bool      `json:"enabled"`
	EncryptedDNSMode string    `json:"encrypted_dns_mode,omitempty"`
	TLSMode          string    `json:"tls_mode,omitempty"`
	EmergencyBypass  bool      `json:"emergency_bypass,omitempty"`
	AppliedAt        time.Time `json:"applied_at,omitempty"`
	LastError        string    `json:"last_error,omitempty"`
}

func (document *EnforcementDocument) NormalizeAndValidate(now time.Time) error {
	if document == nil {
		return errors.New("traffic enforcement policy is required")
	}
	if document.SchemaVersion != SchemaVersion {
		return fmt.Errorf("traffic enforcement schema must be %d", SchemaVersion)
	}
	document.EncryptedDNS.Mode = strings.ToLower(strings.TrimSpace(document.EncryptedDNS.Mode))
	document.EncryptedDNS.FailMode = strings.ToLower(strings.TrimSpace(document.EncryptedDNS.FailMode))
	if document.EncryptedDNS.FailMode == "" {
		document.EncryptedDNS.FailMode = "passthrough"
	}
	switch document.EncryptedDNS.Mode {
	case "observe", "block", "strict":
	default:
		return errors.New("encrypted DNS mode must be observe, block, or strict")
	}
	if document.EncryptedDNS.FailMode != "passthrough" && document.EncryptedDNS.FailMode != "block" {
		return errors.New("encrypted DNS fail mode must be passthrough or block")
	}
	document.EncryptedDNS.SelectedDeviceIDs = enforcementValues(document.EncryptedDNS.SelectedDeviceIDs, strings.TrimSpace)
	if err := validateSelectedDeviceIDs(document.EncryptedDNS.SelectedDeviceIDs); err != nil {
		return fmt.Errorf("encrypted DNS device scope: %w", err)
	}
	document.TLS.Mode = strings.ToLower(strings.TrimSpace(document.TLS.Mode))
	document.TLS.FailMode = strings.ToLower(strings.TrimSpace(document.TLS.FailMode))
	if document.TLS.FailMode == "" {
		document.TLS.FailMode = "passthrough"
	}
	if document.TLS.PinningThreshold == 0 {
		document.TLS.PinningThreshold = 3
	}
	switch document.TLS.Mode {
	case "off", "all", "selective":
	default:
		return errors.New("TLS interception mode must be off, all, or selective")
	}
	if document.TLS.FailMode != "passthrough" && document.TLS.FailMode != "block" {
		return errors.New("TLS interception fail mode must be passthrough or block")
	}
	if document.TLS.PinningThreshold < 1 || document.TLS.PinningThreshold > 20 {
		return errors.New("TLS pinning threshold must be between 1 and 20")
	}
	document.TLS.SelectedDeviceIDs = enforcementValues(document.TLS.SelectedDeviceIDs, strings.TrimSpace)
	if err := validateSelectedDeviceIDs(document.TLS.SelectedDeviceIDs); err != nil {
		return fmt.Errorf("TLS device scope: %w", err)
	}
	if document.TLS.Mode == "selective" && len(document.TLS.SelectedDeviceIDs) == 0 {
		return errors.New("selective TLS interception requires at least one selected device")
	}
	if document.TLS.Mode != "selective" && len(document.TLS.SelectedDeviceIDs) != 0 {
		return errors.New("TLS selected devices require selective mode")
	}
	if len(document.TLS.BypassRules) > 2048 || len(document.Resolvers) > 1024 {
		return errors.New("traffic enforcement policy list exceeds its bound")
	}
	seenBypass := make(map[string]bool, len(document.TLS.BypassRules))
	for index := range document.TLS.BypassRules {
		rule := &document.TLS.BypassRules[index]
		rule.ID = strings.TrimSpace(rule.ID)
		rule.Platform = strings.ToLower(strings.TrimSpace(rule.Platform))
		rule.DeviceID = strings.TrimSpace(rule.DeviceID)
		rule.MatchType = strings.ToLower(strings.TrimSpace(rule.MatchType))
		rule.Pattern = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rule.Pattern), "."))
		rule.Reason = strings.TrimSpace(rule.Reason)
		rule.Source = strings.TrimSpace(rule.Source)
		if !enforcementIDPattern.MatchString(rule.ID) || seenBypass[rule.ID] {
			return fmt.Errorf("TLS bypass rule %d has an invalid or duplicate ID", index)
		}
		seenBypass[rule.ID] = true
		if rule.Platform == "" {
			rule.Platform = "any"
		}
		if !enforcementPlatformPattern.MatchString(rule.Platform) || rule.DeviceID != "" && !enforcementIDPattern.MatchString(rule.DeviceID) {
			return fmt.Errorf("TLS bypass rule %q has invalid scope", rule.ID)
		}
		if len(rule.Reason) == 0 || len(rule.Reason) > 256 || len(rule.Source) > 128 {
			return fmt.Errorf("TLS bypass rule %q has invalid provenance", rule.ID)
		}
		if rule.ExpiresAt != nil {
			expires := rule.ExpiresAt.UTC()
			rule.ExpiresAt = &expires
		}
		switch rule.MatchType {
		case "exact-host", "host-suffix":
			if !validHostPattern(rule.Pattern) {
				return fmt.Errorf("TLS bypass rule %q has an invalid host pattern", rule.ID)
			}
		case "ip":
			address, err := netip.ParseAddr(rule.Pattern)
			if err != nil || address.IsUnspecified() || address.IsMulticast() {
				return fmt.Errorf("TLS bypass rule %q has an invalid IP address", rule.ID)
			}
			rule.Pattern = address.String()
		case "cidr":
			prefix, err := netip.ParsePrefix(rule.Pattern)
			if err != nil || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
				return fmt.Errorf("TLS bypass rule %q has an invalid CIDR", rule.ID)
			}
			rule.Pattern = prefix.Masked().String()
		default:
			return fmt.Errorf("TLS bypass rule %q has an unsupported matcher", rule.ID)
		}
	}
	sort.Slice(document.TLS.BypassRules, func(i, j int) bool { return document.TLS.BypassRules[i].ID < document.TLS.BypassRules[j].ID })
	for index := range document.Resolvers {
		resolver := &document.Resolvers[index]
		resolver.Provider = strings.TrimSpace(resolver.Provider)
		resolver.Source = strings.TrimSpace(resolver.Source)
		if len(resolver.Provider) == 0 || len(resolver.Provider) > 128 || len(resolver.Source) > 128 {
			return fmt.Errorf("resolver target %d has invalid provenance", index)
		}
		resolver.Hostnames = enforcementHostnames(resolver.Hostnames)
		resolver.IPv4 = enforcementAddresses(resolver.IPv4)
		resolver.IPv6 = enforcementAddresses(resolver.IPv6)
		resolver.Transports = enforcementValues(resolver.Transports, strings.ToLower)
		if len(resolver.Hostnames)+len(resolver.IPv4)+len(resolver.IPv6) == 0 || len(resolver.Hostnames) > 128 || len(resolver.IPv4) > 128 || len(resolver.IPv6) > 128 || len(resolver.Transports) == 0 || len(resolver.Transports) > 4 {
			return fmt.Errorf("resolver target %q has invalid target counts", resolver.Provider)
		}
		for _, hostname := range resolver.Hostnames {
			if !validHostPattern(hostname) {
				return fmt.Errorf("resolver target %q has invalid hostname %q", resolver.Provider, hostname)
			}
		}
		for _, raw := range resolver.IPv4 {
			address, err := netip.ParseAddr(raw)
			if err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
				return fmt.Errorf("resolver target %q has invalid IPv4 address", resolver.Provider)
			}
		}
		for _, raw := range resolver.IPv6 {
			address, err := netip.ParseAddr(raw)
			if err != nil || !address.Is6() || address.IsUnspecified() || address.IsMulticast() {
				return fmt.Errorf("resolver target %q has invalid IPv6 address", resolver.Provider)
			}
		}
		for _, transport := range resolver.Transports {
			if transport != "doh" && transport != "doh3" && transport != "dot" && transport != "doq" {
				return fmt.Errorf("resolver target %q has unsupported transport %q", resolver.Provider, transport)
			}
		}
		if resolver.SafeToBlockByIP && !resolver.Dedicated {
			return fmt.Errorf("resolver target %q cannot block a shared address", resolver.Provider)
		}
	}
	sort.Slice(document.Resolvers, func(i, j int) bool { return document.Resolvers[i].Provider < document.Resolvers[j].Provider })
	_ = now
	return nil
}

func (document EnforcementDocument) Digest() (string, error) {
	if err := document.NormalizeAndValidate(time.Time{}); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (request *ApplyRequest) NormalizeAndValidate(now time.Time) error {
	if request == nil {
		return errors.New("traffic policy apply request is required")
	}
	request.PolicyID = strings.TrimSpace(request.PolicyID)
	request.Digest = strings.ToLower(strings.TrimSpace(request.Digest))
	if !enforcementIDPattern.MatchString(request.PolicyID) || request.Revision == 0 {
		return errors.New("traffic policy identity is invalid")
	}
	if err := request.Policy.NormalizeAndValidate(now); err != nil {
		return err
	}
	request.Runtime.TestInterfaces = enforcementValues(request.Runtime.TestInterfaces, strings.TrimSpace)
	if !request.Policy.Enabled && len(request.Runtime.TestInterfaces) == 0 {
		// A disabled policy can remove an existing owned table without a packet scope.
	} else if len(request.Runtime.TestInterfaces) == 0 || len(request.Runtime.TestInterfaces) > 64 {
		return errors.New("traffic policy requires between 1 and 64 test interfaces")
	}
	for _, interfaceName := range request.Runtime.TestInterfaces {
		if !enforcementInterfacePattern.MatchString(interfaceName) {
			return fmt.Errorf("invalid traffic policy interface %q", interfaceName)
		}
	}
	var err error
	request.Runtime.ScopeIPv4, err = normalizeRuntimePrefixes(request.Runtime.ScopeIPv4, true)
	if err != nil {
		return err
	}
	request.Runtime.ScopeIPv6, err = normalizeRuntimePrefixes(request.Runtime.ScopeIPv6, false)
	if err != nil {
		return err
	}
	if request.Policy.EncryptedDNS.RedirectPlainDNS && !validPort(request.Runtime.LocalDNSPort) {
		if request.Runtime.LocalDNSPort == 0 {
			request.Runtime.LocalDNSPort = DefaultDNSListenPort
		} else {
			return errors.New("plain DNS redirection requires a valid local DNS port")
		}
	}
	if request.Policy.TLS.Mode != "off" {
		if request.Runtime.MITMPort == 0 {
			request.Runtime.MITMPort = DefaultTLSListenPort
		}
		if !validPort(request.Runtime.MITMPort) {
			return errors.New("TLS interception requires a valid MITM port")
		}
		if len(request.Runtime.TLSInterceptPorts) == 0 {
			request.Runtime.TLSInterceptPorts = []int{443}
		}
	}
	request.Runtime.TLSInterceptPorts = normalizePorts(request.Runtime.TLSInterceptPorts)
	if len(request.Runtime.TLSInterceptPorts) > 16 {
		return errors.New("too many TLS interception ports")
	}
	for _, port := range request.Runtime.TLSInterceptPorts {
		if !validPort(port) || port == request.Runtime.MITMPort {
			return errors.New("TLS interception port is invalid or collides with the MITM listener")
		}
	}
	if request.Runtime.LocalDNSPort != 0 && request.Runtime.LocalDNSPort == request.Runtime.MITMPort {
		return errors.New("DNS and MITM listener ports must differ")
	}
	if err := normalizeRuntimeDevices(&request.Runtime); err != nil {
		return err
	}
	digest, err := request.Policy.Digest()
	if err != nil {
		return err
	}
	if len(request.Digest) != 64 {
		return errors.New("traffic policy digest is invalid")
	}
	if _, err := hex.DecodeString(request.Digest); err != nil || request.Digest != digest {
		return errors.New("traffic policy digest does not match the normalized policy")
	}
	return nil
}

func validPort(port int) bool { return port >= 1 && port <= 65535 }

func validateSelectedDeviceIDs(values []string) error {
	if len(values) > 4096 {
		return errors.New("selected device list exceeds its bound")
	}
	for _, value := range values {
		if !enforcementIDPattern.MatchString(value) {
			return fmt.Errorf("selected device ID %q is invalid", value)
		}
	}
	return nil
}

func normalizePorts(values []int) []int {
	seen := make(map[int]bool, len(values))
	result := make([]int, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Ints(result)
	return result
}

func normalizeRuntimePrefixes(values []string, ipv4 bool) ([]string, error) {
	result := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, raw := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil || prefix.Addr().Is4() != ipv4 || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
			return nil, fmt.Errorf("invalid traffic policy scope %q", raw)
		}
		value := prefix.Masked().String()
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result, nil
}

func normalizeRuntimeDevices(runtime *Runtime) error {
	if len(runtime.DevicePlatforms) > 4096 || len(runtime.DeviceIPv4) > 4096 || len(runtime.DeviceIPv6) > 4096 {
		return errors.New("traffic policy device scope exceeds its bound")
	}
	for deviceID, platform := range runtime.DevicePlatforms {
		if !enforcementIDPattern.MatchString(deviceID) {
			return errors.New("traffic policy device ID is invalid")
		}
		platform = strings.ToLower(strings.TrimSpace(platform))
		if !enforcementPlatformPattern.MatchString(platform) {
			return errors.New("traffic policy device platform is invalid")
		}
		runtime.DevicePlatforms[deviceID] = platform
	}
	for deviceID, addresses := range runtime.DeviceIPv4 {
		if !enforcementIDPattern.MatchString(deviceID) {
			return errors.New("traffic policy device ID is invalid")
		}
		normalized, err := normalizeRuntimeAddresses(addresses, true)
		if err != nil {
			return err
		}
		runtime.DeviceIPv4[deviceID] = normalized
	}
	for deviceID, addresses := range runtime.DeviceIPv6 {
		if !enforcementIDPattern.MatchString(deviceID) {
			return errors.New("traffic policy device ID is invalid")
		}
		normalized, err := normalizeRuntimeAddresses(addresses, false)
		if err != nil {
			return err
		}
		runtime.DeviceIPv6[deviceID] = normalized
	}
	return nil
}

func normalizeRuntimeAddresses(values []string, ipv4 bool) ([]string, error) {
	result := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, raw := range values {
		address, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil || address.Is4() != ipv4 || address.IsUnspecified() || address.IsMulticast() {
			return nil, fmt.Errorf("invalid traffic policy device address %q", raw)
		}
		value := address.String()
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result, nil
}

func enforcementHostnames(values []string) []string {
	return enforcementValues(values, func(value string) string {
		return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	})
}

func enforcementAddresses(values []string) []string {
	return enforcementValues(values, func(value string) string {
		address, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil {
			return strings.TrimSpace(value)
		}
		return address.String()
	})
}

func enforcementValues(values []string, transform func(string) string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, raw := range values {
		value := transform(raw)
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}
