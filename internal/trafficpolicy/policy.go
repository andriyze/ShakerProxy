package trafficpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	policyNamePattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._/-]{0,118}[A-Za-z0-9]$|^[A-Za-z0-9]$`)
	resolverIDPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)
	hostLabelPattern        = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	selectedDeviceIDPattern = regexp.MustCompile(`^device-[a-f0-9]{32}$`)
)

const (
	DefaultDNSListenPort    = 1053
	DefaultTLSListenPort    = 8085
	DefaultPinnedBypassTTL  = 86400
	DefaultMaxDynamicBypass = 1024
	maxListItems            = 512
)

func DefaultPolicy() Policy {
	return Policy{
		Schema:   SchemaVersion,
		Revision: 1,
		Name:     "Default observe-only policy",
		EncryptedDNS: EncryptedDNSPolicy{
			Mode:            EncryptedDNSObserve,
			LocalListenPort: DefaultDNSListenPort,
		},
		TLS: TLSInterception{
			TransparentPort:      DefaultTLSListenPort,
			AutoBypassTTLSeconds: DefaultPinnedBypassTTL,
			MaxDynamicBypasses:   DefaultMaxDynamicBypass,
		},
	}
}

func Normalize(input Policy) (Policy, error) {
	policy := input
	policy.Name = strings.TrimSpace(policy.Name)
	if policy.EncryptedDNS.LocalListenPort == 0 {
		policy.EncryptedDNS.LocalListenPort = DefaultDNSListenPort
	}
	if policy.TLS.TransparentPort == 0 {
		policy.TLS.TransparentPort = DefaultTLSListenPort
	}
	if policy.TLS.AutoBypassTTLSeconds == 0 {
		policy.TLS.AutoBypassTTLSeconds = DefaultPinnedBypassTTL
	}
	if policy.TLS.MaxDynamicBypasses == 0 {
		policy.TLS.MaxDynamicBypasses = DefaultMaxDynamicBypass
	}
	policy.EncryptedDNS.UpstreamServers = normalizeStringList(policy.EncryptedDNS.UpstreamServers, strings.ToLower)
	policy.EncryptedDNS.ResolverExclusions = normalizeStringList(policy.EncryptedDNS.ResolverExclusions, strings.ToLower)
	policy.TLS.ExcludeHosts = normalizeStringList(policy.TLS.ExcludeHosts, strings.ToLower)
	policy.TLS.ExcludeCIDRs = normalizeCIDRs(policy.TLS.ExcludeCIDRs)
	policy.TLS.MobileClients = normalizeMobileClients(policy.TLS.MobileClients)
	policy.TLS.SelectedDeviceIDs = normalizeStringList(policy.TLS.SelectedDeviceIDs, func(value string) string { return value })
	policy.DeviceControls = normalizeDeviceControls(policy.DeviceControls)
	if err := Validate(policy); err != nil {
		return Policy{}, err
	}
	return policy, nil
}

func Validate(policy Policy) error {
	if policy.Schema != SchemaVersion {
		return fmt.Errorf("traffic policy schema must be %d", SchemaVersion)
	}
	if policy.Revision == 0 {
		return errors.New("traffic policy revision must be positive")
	}
	if !policyNamePattern.MatchString(policy.Name) {
		return errors.New("traffic policy name is invalid")
	}
	switch policy.EncryptedDNS.Mode {
	case EncryptedDNSObserve, EncryptedDNSBlockKnown, EncryptedDNSEnforceLocal:
	default:
		return errors.New("encrypted DNS mode is invalid")
	}
	if !validUnprivilegedPort(policy.EncryptedDNS.LocalListenPort) {
		return errors.New("local DNS listener port must be between 1024 and 65535")
	}
	if policy.EncryptedDNS.Mode == EncryptedDNSEnforceLocal {
		if !policy.EncryptedDNS.RedirectPlainDNS {
			return errors.New("ENFORCE_LOCAL requires plain DNS redirection")
		}
		if len(policy.EncryptedDNS.UpstreamServers) == 0 {
			return errors.New("ENFORCE_LOCAL requires at least one upstream DNS server")
		}
	}
	if len(policy.EncryptedDNS.UpstreamServers) > 16 {
		return errors.New("too many upstream DNS servers")
	}
	for _, upstream := range policy.EncryptedDNS.UpstreamServers {
		if err := validateDNSEndpoint(upstream); err != nil {
			return fmt.Errorf("invalid upstream DNS server %q: %w", upstream, err)
		}
	}
	if len(policy.EncryptedDNS.ResolverExclusions) > maxListItems {
		return errors.New("too many resolver exclusions")
	}
	catalogIDs := resolverIDSet(BuiltinCatalog())
	for _, resolverID := range policy.EncryptedDNS.ResolverExclusions {
		if !resolverIDPattern.MatchString(resolverID) || !catalogIDs[resolverID] {
			return fmt.Errorf("resolver exclusion %q is not in the built-in catalog", resolverID)
		}
	}
	if !validUnprivilegedPort(policy.TLS.TransparentPort) {
		return errors.New("TLS transparent listener port must be between 1024 and 65535")
	}
	if policy.TLS.Enabled && policy.TLS.TransparentPort == policy.EncryptedDNS.LocalListenPort {
		return errors.New("DNS and TLS listener ports must differ")
	}
	if policy.TLS.AutoBypassTTLSeconds < 300 || policy.TLS.AutoBypassTTLSeconds > 30*86400 {
		return errors.New("pinned TLS bypass TTL must be between 300 and 2592000 seconds")
	}
	if policy.TLS.MaxDynamicBypasses < 16 || policy.TLS.MaxDynamicBypasses > 10000 {
		return errors.New("maximum dynamic pinned bypasses must be between 16 and 10000")
	}
	if len(policy.TLS.ExcludeHosts) > maxListItems || len(policy.TLS.ExcludeCIDRs) > maxListItems {
		return errors.New("TLS exclusion list is too large")
	}
	for _, host := range policy.TLS.ExcludeHosts {
		if !validHostPattern(host) {
			return fmt.Errorf("invalid TLS host exclusion %q", host)
		}
	}
	for _, raw := range policy.TLS.ExcludeCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix.String() != raw {
			return fmt.Errorf("invalid or non-canonical TLS CIDR exclusion %q", raw)
		}
	}
	if len(policy.TLS.MobileClients) > maxListItems {
		return errors.New("TLS mobile client list is too large")
	}
	for _, client := range policy.TLS.MobileClients {
		prefix, err := netip.ParsePrefix(client.CIDR)
		if err != nil || !prefix.Addr().Is4() || prefix.Masked().String() != client.CIDR {
			return fmt.Errorf("invalid or non-canonical mobile client CIDR %q", client.CIDR)
		}
		switch client.Platform {
		case "android", "android-tv", "ios", "tvos":
		default:
			return fmt.Errorf("unsupported mobile client platform %q", client.Platform)
		}
	}
	if len(policy.TLS.SelectedDeviceIDs) > maxListItems {
		return errors.New("TLS selected device list is too large")
	}
	for _, deviceID := range policy.TLS.SelectedDeviceIDs {
		if !selectedDeviceIDPattern.MatchString(deviceID) {
			return fmt.Errorf("invalid TLS selected device ID %q", deviceID)
		}
	}
	if !policy.TLS.Enabled && len(policy.TLS.SelectedDeviceIDs) != 0 {
		return errors.New("TLS selected devices require interception to be enabled")
	}
	return validateDeviceControls(policy)
}

func Digest(policy Policy) (string, error) {
	normalized, err := Normalize(policy)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func validateDNSEndpoint(value string) error {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return errors.New("endpoint must use IP:port syntax")
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() {
		return errors.New("endpoint host must be a non-loopback unicast IP address")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port != 53 {
		return errors.New("upstream DNS port must be 53")
	}
	return nil
}

func validUnprivilegedPort(port int) bool { return port >= 1024 && port <= 65535 }

func validHostPattern(value string) bool {
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "/:@ ") {
		return false
	}
	if strings.HasPrefix(value, "*.") {
		value = strings.TrimPrefix(value, "*.")
	}
	if strings.Contains(value, "*") || strings.HasSuffix(value, ".") {
		return false
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !hostLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func normalizeStringList(values []string, transform func(string) string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, raw := range values {
		value := transform(strings.TrimSpace(raw))
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func normalizeCIDRs(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, raw := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			value := strings.TrimSpace(raw)
			if value != "" && !seen[value] {
				seen[value] = true
				result = append(result, value)
			}
			continue
		}
		value := prefix.Masked().String()
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func normalizeMobileClients(values []TLSMobileClient) []TLSMobileClient {
	byCIDR := make(map[string]string, len(values))
	for _, client := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(client.CIDR))
		cidr := strings.TrimSpace(client.CIDR)
		if err == nil {
			cidr = prefix.Masked().String()
		}
		platform := strings.ToLower(strings.TrimSpace(client.Platform))
		if cidr != "" {
			byCIDR[cidr] = platform
		}
	}
	result := make([]TLSMobileClient, 0, len(byCIDR))
	for cidr, platform := range byCIDR {
		result = append(result, TLSMobileClient{CIDR: cidr, Platform: platform})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CIDR < result[j].CIDR })
	return result
}
