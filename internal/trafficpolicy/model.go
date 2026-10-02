package trafficpolicy

import "time"

const SchemaVersion = 1

const BuiltinCatalogRevision = "2026-10-02.1"

// EncryptedDNSLogGroup is the NFLOG group the encrypted DNS block rules log
// to; the gateway turns each logged attempt into a Traffic event.
const EncryptedDNSLogGroup = 853

type EncryptedDNSMode string

const (
	EncryptedDNSObserve      EncryptedDNSMode = "OBSERVE"
	EncryptedDNSBlockKnown   EncryptedDNSMode = "BLOCK_KNOWN"
	EncryptedDNSEnforceLocal EncryptedDNSMode = "ENFORCE_LOCAL"
)

type Policy struct {
	Schema       int                `json:"schema"`
	Revision     uint64             `json:"revision"`
	Name         string             `json:"name"`
	EncryptedDNS EncryptedDNSPolicy `json:"encrypted_dns"`
	TLS          TLSInterception    `json:"tls_interception"`
	// DeviceControls holds per-device lab controls (internet block, DNS
	// domain blocks, host bypasses) and the identity evidence used to match
	// the device's packets. It is omitted when empty so documents written
	// before device controls existed keep their digest.
	DeviceControls []DeviceControl `json:"device_controls,omitempty"`
}

// DeviceControl is the durable per-device lab state owned by the device
// controls API. HardwareAddresses and Addresses are identity evidence captured
// from the inventory when the control was saved; the privileged gateway
// refreshes current IPs from the lab neighbor table by MAC at render time.
type DeviceControl struct {
	DeviceID          string   `json:"device_id"`
	HardwareAddresses []string `json:"hardware_addresses,omitempty"`
	Addresses         []string `json:"addresses,omitempty"`
	BlockInternet     bool     `json:"block_internet,omitempty"`
	BlockedDomains    []string `json:"blocked_domains,omitempty"`
	BypassHosts       []string `json:"bypass_hosts,omitempty"`
}

type EncryptedDNSPolicy struct {
	Mode           EncryptedDNSMode `json:"mode"`
	BlockDoT       bool             `json:"block_dot"`
	BlockDoQ       bool             `json:"block_doq"`
	BlockKnownDoH  bool             `json:"block_known_doh"`
	BlockKnownDoH3 bool             `json:"block_known_doh3"`
	// RedirectPlainDNS is the "Force plain DNS through ShakerProxy" switch:
	// every lab client's port-53 DNS, to any resolver, is answered by the
	// local forwarder. It applies in any mode once a lab is confirmed.
	RedirectPlainDNS bool `json:"redirect_plain_dns"`
	// BlockDoHNames makes the forwarder answer NXDOMAIN for the catalog's
	// DNS-over-HTTPS hostnames and the encrypted-DNS canary names, so
	// browsers and phones fall back to plain DNS. Omitted when false so
	// documents written before it existed keep their digest.
	BlockDoHNames      bool     `json:"block_doh_names,omitempty"`
	LocalListenPort    int      `json:"local_listen_port"`
	UpstreamServers    []string `json:"upstream_servers"`
	ResolverExclusions []string `json:"resolver_exclusions,omitempty"`
}

type TLSInterception struct {
	Enabled              bool              `json:"enabled"`
	TransparentPort      int               `json:"transparent_port"`
	ExcludeHosts         []string          `json:"exclude_hosts,omitempty"`
	ExcludeCIDRs         []string          `json:"exclude_cidrs,omitempty"`
	AutoBypassPinned     bool              `json:"auto_bypass_pinned"`
	AutoBypassTTLSeconds int               `json:"auto_bypass_ttl_seconds"`
	MaxDynamicBypasses   int               `json:"max_dynamic_bypasses"`
	MobileClients        []TLSMobileClient `json:"mobile_clients,omitempty"`
	// SelectedDeviceIDs is empty for all-client interception. When non-empty,
	// the transparent packet path still reaches mitmproxy, but only these stable
	// ShakerProxy device identities are decrypted; other clients are passed through.
	SelectedDeviceIDs []string `json:"selected_device_ids,omitempty"`
	// AllowQUIC keeps UDP/443 open for intercepted clients. By default QUIC
	// is rejected for the interception scope so HTTP/3 clients fall back to
	// TCP, which ShakerProxy can decrypt.
	AllowQUIC bool `json:"allow_quic,omitempty"`
	// InterceptHTTP also redirects plain HTTP (TCP/80) from the interception
	// scope to the interception listener so cleartext requests are recorded.
	InterceptHTTP bool `json:"intercept_http,omitempty"`
	// InterceptPrivateDestinations also intercepts traffic to RFC 1918,
	// CGNAT, link-local and IPv6 ULA destinations. It is off by default
	// because LAN and IoT backends commonly use self-signed or mutually
	// authenticated TLS that interception would break.
	InterceptPrivateDestinations bool `json:"intercept_private_destinations,omitempty"`
}

type TLSMobileClient struct {
	CIDR     string `json:"cidr"`
	Platform string `json:"platform"`
}

type ResolverTransport string

const (
	TransportDoH  ResolverTransport = "DOH"
	TransportDoH3 ResolverTransport = "DOH3"
	TransportDoT  ResolverTransport = "DOT"
	TransportDoQ  ResolverTransport = "DOQ"
)

type Resolver struct {
	ID             string              `json:"id"`
	Provider       string              `json:"provider"`
	Hostnames      []string            `json:"hostnames"`
	IPv4           []string            `json:"ipv4,omitempty"`
	IPv6           []string            `json:"ipv6,omitempty"`
	DoHPaths       []string            `json:"doh_paths,omitempty"`
	Transports     []ResolverTransport `json:"transports"`
	DedicatedIPs   bool                `json:"dedicated_ips"`
	SafeForIPBlock bool                `json:"safe_for_ip_block"`
	Source         string              `json:"source"`
}

type Catalog struct {
	Schema      int        `json:"schema"`
	Revision    string     `json:"revision"`
	GeneratedAt time.Time  `json:"generated_at"`
	Resolvers   []Resolver `json:"resolvers"`
}

type Classification struct {
	Detected   bool              `json:"detected"`
	ResolverID string            `json:"resolver_id,omitempty"`
	Provider   string            `json:"provider,omitempty"`
	Transport  ResolverTransport `json:"transport,omitempty"`
	Confidence int               `json:"confidence"`
	Evidence   []string          `json:"evidence,omitempty"`
	BlockSafe  bool              `json:"block_safe"`
}

type RuntimeStatus struct {
	Schema                 int       `json:"schema"`
	PolicyRevision         uint64    `json:"policy_revision"`
	PolicyDigest           string    `json:"policy_digest"`
	AppliedAt              time.Time `json:"applied_at"`
	EncryptedDNSMode       string    `json:"encrypted_dns_mode"`
	TLSInterceptionEnabled bool      `json:"tls_interception_enabled"`
	DynamicBypasses        int       `json:"dynamic_bypasses"`
	LastError              string    `json:"last_error,omitempty"`
}
