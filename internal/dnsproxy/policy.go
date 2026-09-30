package dnsproxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

// maxRuntimePolicyBytes bounds the shared runtime document. Fleet snapshots
// with thousands of device mappings and bypass rules stay well below it.
const maxRuntimePolicyBytes = 4 << 20

const (
	maxBlockedDevices     = trafficpolicy.MaxDeviceControls
	maxRuntimeDeviceByIP  = 8192
	hostResolverCacheTime = 30 * time.Second
)

// DefaultResolvConfPaths lists the host resolver files used when the runtime
// document names no upstream. systemd-resolved's non-stub file lists the real
// upstreams; /etc/resolv.conf usually points at the 127.0.0.53 stub, which is
// also acceptable because the forwarder runs on the host.
var DefaultResolvConfPaths = []string{"/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"}

var runtimeDeviceIDPattern = regexp.MustCompile(`^device-[a-f0-9]{32}$`)

// Runtime is one validated view of the shared traffic runtime document.
type Runtime struct {
	Revision  uint64
	Upstreams []string
	// HostResolver is true when Upstreams came from the host resolver
	// configuration instead of the policy.
	HostResolver bool
	deviceByIP   map[netip.Addr]string
	blocked      map[string][]string
	labSources   []netip.Prefix
}

var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// AllowedClient reports whether a query may be answered. Loopback, private
// (RFC 1918, ULA), CGNAT and link-local clients are always accepted, plus the
// lab prefixes the gateway publishes (a routed lab may use global space). This
// keeps the forwarder from becoming an open resolver even if a firewall rule
// protecting its port is missing.
func (r *Runtime) AllowedClient(client netip.Addr) bool {
	client = client.Unmap()
	if client.IsLoopback() || client.IsPrivate() || client.IsLinkLocalUnicast() || sharedAddressSpace.Contains(client) {
		return true
	}
	if r == nil {
		return false
	}
	for _, prefix := range r.labSources {
		if prefix.Contains(client) {
			return true
		}
	}
	return false
}

// Blocked reports whether name must be answered with NXDOMAIN for the client
// and returns the device and blocked domain that matched.
func (r *Runtime) Blocked(client netip.Addr, name string) (string, string, bool) {
	if r == nil || len(r.blocked) == 0 {
		return "", "", false
	}
	deviceID, ok := r.deviceByIP[client.Unmap()]
	if !ok {
		return "", "", false
	}
	for _, domain := range r.blocked[deviceID] {
		if trafficpolicy.DomainCovers(domain, name) {
			return deviceID, domain, true
		}
	}
	return "", "", false
}

// RuntimeProvider supplies the current runtime for each query.
type RuntimeProvider interface {
	Runtime() (*Runtime, error)
}

// FilePolicyProvider reads the runtime document the gateway (standalone
// policy) or shakerproxy-traffic-policy (Fleet) publishes for mitmproxy and the
// DNS forwarder. It accepts the compiled runtime schema (schema_version 1,
// both writers) and the legacy standalone policy (schema 1), and ignores
// fields it does not use so the two writers can evolve independently.
type FilePolicyProvider struct {
	Path string
	// FallbackUpstreams are used when the runtime names no upstream. When
	// empty, the host resolver configuration is read.
	FallbackUpstreams []string
	// ResolvConfPaths defaults to DefaultResolvConfPaths.
	ResolvConfPaths []string
	Now             func() time.Time

	mu            sync.Mutex
	seen          fileVersion
	cached        *Runtime
	hostUpstreams []string
	hostReadAt    time.Time
}

type fileVersion struct {
	Size    int64
	ModTime time.Time
}

type runtimeDocument struct {
	Schema        *int                `json:"schema"`
	SchemaVersion *int                `json:"schema_version"`
	Revision      uint64              `json:"revision"`
	EncryptedDNS  *runtimeDNSDocument `json:"encrypted_dns"`
	DeviceByIP    map[string]string   `json:"device_by_ip"`
	LabSources    []string            `json:"lab_sources"`
}

type runtimeDNSDocument struct {
	Mode             string              `json:"mode"`
	RedirectPlainDNS bool                `json:"redirect_plain_dns"`
	UpstreamServers  []string            `json:"upstream_servers"`
	BlockedDomains   map[string][]string `json:"blocked_domains"`
}

// Upstreams is retained for callers that only need forwarding targets.
func (p *FilePolicyProvider) Upstreams() ([]string, error) {
	runtime, err := p.Runtime()
	if err != nil {
		return nil, err
	}
	return append([]string(nil), runtime.Upstreams...), nil
}

func (p *FilePolicyProvider) Runtime() (*Runtime, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Path == "" {
		return nil, errors.New("DNS runtime policy path is required")
	}
	info, err := os.Lstat(p.Path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxRuntimePolicyBytes {
		return nil, errors.New("DNS runtime policy is not a bounded regular file")
	}
	version := fileVersion{Size: info.Size(), ModTime: info.ModTime()}
	if version == p.seen && p.cached != nil && (!p.cached.HostResolver || p.now().Sub(p.hostReadAt) < hostResolverCacheTime) {
		return p.cached, nil
	}
	data, err := os.ReadFile(p.Path)
	if err != nil {
		return nil, err
	}
	runtime, err := ParseRuntime(data)
	if err != nil {
		return nil, err
	}
	if len(runtime.Upstreams) == 0 {
		upstreams, err := p.hostResolverUpstreams()
		if err != nil {
			return nil, err
		}
		runtime.Upstreams = upstreams
		runtime.HostResolver = true
	}
	p.seen = version
	p.cached = runtime
	return runtime, nil
}

// ParseRuntime validates a runtime document without requiring upstreams.
func ParseRuntime(data []byte) (*Runtime, error) {
	var document runtimeDocument
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&document); err != nil {
		return nil, errors.New("DNS runtime policy is not valid JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("DNS runtime policy contains trailing data")
	}
	compiled := document.SchemaVersion != nil && *document.SchemaVersion == trafficpolicy.SchemaVersion
	legacy := document.Schema != nil && *document.Schema == trafficpolicy.SchemaVersion
	if compiled == legacy {
		return nil, errors.New("DNS runtime policy schema is unsupported")
	}
	if document.EncryptedDNS == nil {
		return nil, errors.New("DNS runtime policy has no encrypted_dns section")
	}
	dns := document.EncryptedDNS
	runtime := &Runtime{Revision: document.Revision, deviceByIP: map[netip.Addr]string{}, blocked: map[string][]string{}}
	mode := strings.ToLower(strings.TrimSpace(dns.Mode))
	// The legacy standalone policy lists upstreams even while observe-only;
	// they only apply when that policy enforces local DNS.
	if compiled || mode == "enforce_local" {
		if len(dns.UpstreamServers) > 16 {
			return nil, errors.New("DNS runtime policy lists too many upstream servers")
		}
		for _, upstream := range dns.UpstreamServers {
			normalized, err := normalizeUpstream(strings.TrimSpace(upstream), false)
			if err != nil {
				return nil, fmt.Errorf("DNS runtime policy upstream %q is invalid: %w", upstream, err)
			}
			runtime.Upstreams = append(runtime.Upstreams, normalized)
		}
	}
	if len(dns.BlockedDomains) > maxBlockedDevices {
		return nil, errors.New("DNS runtime policy blocks domains for too many devices")
	}
	for deviceID, domains := range dns.BlockedDomains {
		if !runtimeDeviceIDPattern.MatchString(deviceID) || len(domains) > trafficpolicy.MaxBlockedDomainsPerDevice {
			return nil, errors.New("DNS runtime policy contains an invalid domain block")
		}
		for _, raw := range domains {
			domain, err := trafficpolicy.NormalizeDomain(raw)
			if err != nil {
				return nil, errors.New("DNS runtime policy contains an invalid blocked domain")
			}
			runtime.blocked[deviceID] = append(runtime.blocked[deviceID], domain)
		}
	}
	if len(document.LabSources) > 16 {
		return nil, errors.New("DNS runtime policy lists too many lab prefixes")
	}
	for _, raw := range document.LabSources {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix.Bits() < 8 {
			return nil, errors.New("DNS runtime policy contains an invalid lab prefix")
		}
		runtime.labSources = append(runtime.labSources, prefix.Masked())
	}
	if len(document.DeviceByIP) > maxRuntimeDeviceByIP {
		return nil, errors.New("DNS runtime policy device map exceeds its bound")
	}
	for rawAddress, deviceID := range document.DeviceByIP {
		address, err := netip.ParseAddr(rawAddress)
		if err != nil || !runtimeDeviceIDPattern.MatchString(deviceID) {
			// Fleet snapshots may carry non-inventory identities; they are
			// irrelevant to domain blocking and are skipped.
			continue
		}
		runtime.deviceByIP[address.Unmap()] = deviceID
	}
	return runtime, nil
}

func (p *FilePolicyProvider) hostResolverUpstreams() ([]string, error) {
	if len(p.FallbackUpstreams) != 0 {
		result := make([]string, 0, len(p.FallbackUpstreams))
		for _, raw := range p.FallbackUpstreams {
			normalized, err := normalizeUpstream(strings.TrimSpace(raw), true)
			if err != nil {
				return nil, fmt.Errorf("fallback DNS upstream %q is invalid: %w", raw, err)
			}
			result = append(result, normalized)
		}
		p.hostReadAt = p.now()
		return result, nil
	}
	if p.hostUpstreams != nil && p.now().Sub(p.hostReadAt) < hostResolverCacheTime {
		return append([]string(nil), p.hostUpstreams...), nil
	}
	paths := p.ResolvConfPaths
	if len(paths) == 0 {
		paths = DefaultResolvConfPaths
	}
	for _, path := range paths {
		upstreams, err := readResolvConf(path)
		if err != nil || len(upstreams) == 0 {
			continue
		}
		p.hostUpstreams = upstreams
		p.hostReadAt = p.now()
		return append([]string(nil), upstreams...), nil
	}
	return nil, errors.New("no DNS upstream is configured and the host resolver configuration lists no nameserver")
}

func (p *FilePolicyProvider) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// readResolvConf returns up to 4 literal nameserver addresses as host:53.
func readResolvConf(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(io.LimitReader(file, 64<<10))
	result := []string{}
	for scanner.Scan() && len(result) < 4 {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		address, err := netip.ParseAddr(fields[1])
		if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
			continue
		}
		result = append(result, net.JoinHostPort(address.Unmap().String(), "53"))
	}
	return result, scanner.Err()
}

// normalizeUpstream accepts IP:53. Loopback is only acceptable for the host
// resolver fallback (for example the systemd-resolved stub).
func normalizeUpstream(value string, allowLoopback bool) (string, error) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return "", errors.New("endpoint must use IP:port syntax")
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || (!allowLoopback && address.IsLoopback()) {
		return "", errors.New("endpoint host must be a unicast IP address")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port != 53 {
		return "", errors.New("upstream DNS port must be 53")
	}
	return net.JoinHostPort(address.Unmap().String(), "53"), nil
}
