// Package coverage proves, one traffic type at a time, whether ShakerProxy
// actually sees a device's connections. Probes run from the virtual test
// lab's client namespaces through the production path (capture, Zeek and
// Suricata, the DNS forwarder, ingestd and PostgreSQL); the evaluator reads
// the stored events back and reports what is visible, how fast, and what is
// missing. It never creates events of its own.
package coverage

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

const SchemaVersion = 1

type Status string

const (
	StatusPass Status = "PASS"
	StatusFail Status = "FAIL"
	StatusSkip Status = "SKIP"
)

type State string

const (
	StateRunning   State = "RUNNING"
	StateCompleted State = "COMPLETED"
	StateFailed    State = "FAILED"
)

// The virtual test lab's fixed addressing (internal/testlab).
const (
	ClientCIDR   = "198.18.240.0/24"
	GatewayIPv4  = "198.18.240.1"
	NormalClient = "198.18.240.10"
	DNSClient    = "198.18.240.30"
	TargetIPv4   = "198.18.241.254"

	// The lab's IPv6 is a unique-local prefix that never leaves the
	// appliance: subnet f0 is the client bridge and f1 the target side,
	// mirroring 198.18.240.0/24 and 198.18.241.0/24.
	ClientIPv6CIDR   = "fd8a:6c1e:4b37:f0::/64"
	GatewayIPv6      = "fd8a:6c1e:4b37:f0::1"
	NormalClientIPv6 = "fd8a:6c1e:4b37:f0::10"
	TargetIPv6       = "fd8a:6c1e:4b37:f1::fe"

	// Ports the virtual target serves for the probes.
	PortHTTP       = 8080
	PortHTTPS      = 8443
	PortDoH        = 443
	PortDoT        = 853
	PortSSH        = 22
	PortNTP        = 123
	PortTCPOdd     = 9998
	PortUDPOdd     = 9997
	MDNSGroup      = "224.0.0.251"
	MDNSPort       = 5353
	SSDPGroup      = "239.255.255.250"
	SSDPPort       = 1900
	QUICPort       = 443
	DoHResolverSNI = "cloudflare-dns.com"
)

// Probe IDs, in the order they run and are reported.
const (
	ProbeDNSGateway = "dns-gateway"
	ProbeDNSDirect  = "dns-direct"
	ProbeDoT        = "dot"
	ProbeDoH        = "doh"
	ProbeDoQ        = "doq"
	ProbeHTTP       = "http"
	ProbeHTTPS      = "https"
	ProbeQUIC       = "quic"
	ProbeTCP        = "tcp-unusual-port"
	ProbeUDP        = "udp-unusual-port"
	ProbeICMP       = "icmp"
	ProbeSSH        = "ssh"
	ProbeNTP        = "ntp"
	ProbeMDNS       = "mdns"
	ProbeSSDP       = "ssdp"
	ProbeDNSIPv6    = "dns-ipv6"
	ProbeHTTPIPv6   = "http-ipv6"
	ProbeHTTPSIPv6  = "https-ipv6"
	ProbeQUICIPv6   = "quic-ipv6"
	ProbeTCPIPv6    = "tcp-ipv6"
	ProbeUDPIPv6    = "udp-ipv6"
	ProbeICMPv6     = "icmpv6"
)

// CategoryIPv6 groups the probes sent over IPv6.
const CategoryIPv6 = "ipv6"

type Probe struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
}

// Probes is every traffic type the check proves, in report order.
var Probes = []Probe{
	{ProbeDNSGateway, "DNS via ShakerProxy", "dns", "A lookup sent to the gateway, answered by ShakerProxy's DNS forwarder"},
	{ProbeDNSDirect, "DNS to another resolver", "dns", "A lookup sent straight to an outside resolver on UDP 53"},
	{ProbeDoT, "DNS over TLS (DoT)", "encrypted-dns", "A TLS connection to TCP 853"},
	{ProbeDoH, "DNS over HTTPS (DoH)", "encrypted-dns", "An HTTPS lookup to a well-known DoH resolver name"},
	{ProbeDoQ, "DNS over QUIC (DoQ)", "encrypted-dns", "A datagram to UDP 853"},
	{ProbeHTTP, "HTTP (cleartext)", "web", "A cleartext HTTP GET"},
	{ProbeHTTPS, "HTTPS / TLS", "web", "A TLS handshake with a server name (SNI)"},
	{ProbeQUIC, "QUIC / HTTP/3", "web", "A QUIC v1 Initial packet with a server name"},
	{ProbeTCP, "TCP, unusual port", "transport", "A TCP connection to an unregistered port"},
	{ProbeUDP, "UDP, unusual port", "transport", "A UDP datagram to an unregistered port"},
	{ProbeICMP, "ICMP echo (ping)", "transport", "Two ICMP echo requests"},
	{ProbeSSH, "SSH", "remote-access", "An SSH version exchange"},
	{ProbeNTP, "NTP", "network", "An NTP time request"},
	{ProbeMDNS, "mDNS / Bonjour (AirPlay discovery)", "local-discovery", "An mDNS query for AirPlay receivers on the local network"},
	{ProbeSSDP, "SSDP / UPnP (casting discovery)", "local-discovery", "An SSDP M-SEARCH on the local network"},
	{ProbeDNSIPv6, "DNS over IPv6 (AAAA)", CategoryIPv6, "An AAAA lookup sent over IPv6 to the gateway, answered by ShakerProxy's DNS forwarder"},
	{ProbeHTTPIPv6, "HTTP over IPv6", CategoryIPv6, "A cleartext HTTP GET over IPv6"},
	{ProbeHTTPSIPv6, "HTTPS / TLS over IPv6", CategoryIPv6, "A TLS handshake with a server name (SNI) over IPv6"},
	{ProbeQUICIPv6, "QUIC over IPv6", CategoryIPv6, "A QUIC v1 Initial packet with a server name over IPv6"},
	{ProbeTCPIPv6, "TCP over IPv6, unusual port", CategoryIPv6, "A TCP connection to an unregistered port over IPv6"},
	{ProbeUDPIPv6, "UDP over IPv6, unusual port", CategoryIPv6, "A UDP datagram to an unregistered port over IPv6"},
	{ProbeICMPv6, "ICMPv6 echo (ping)", CategoryIPv6, "Two ICMPv6 echo requests"},
}

// IPv6Probe reports whether the probe with this ID is sent over IPv6.
func IPv6Probe(id string) bool {
	for _, probe := range Probes {
		if probe.ID == id {
			return probe.Category == CategoryIPv6
		}
	}
	return false
}

// Plan holds the markers that make one run's evidence unique, so a check
// never mistakes other traffic, or an earlier run, for a pass.
type Plan struct {
	RunID          string    `json:"run_id"`
	StartedAt      time.Time `json:"started_at"`
	DNSGatewayName string    `json:"dns_gateway_name"`
	DNSDirectName  string    `json:"dns_direct_name"`
	HTTPPath       string    `json:"http_path"`
	TLSServerName  string    `json:"tls_server_name"`
	DoTServerName  string    `json:"dot_server_name"`
	DoQServerName  string    `json:"doq_server_name"`
	QUICServerName string    `json:"quic_server_name"`
	MDNSService    string    `json:"mdns_service"`
	// The IPv6 probes carry their own markers, so neither family's
	// evidence can pass the other's probe.
	DNSIPv6Name        string `json:"dns_ipv6_name"`
	HTTPIPv6Path       string `json:"http_ipv6_path"`
	TLSIPv6ServerName  string `json:"tls_ipv6_server_name"`
	QUICIPv6ServerName string `json:"quic_ipv6_server_name"`
}

// NewPlan derives the run's markers from its ID. The names live under
// .test, which never resolves on the Internet.
func NewPlan(runID string, startedAt time.Time) Plan {
	digest := sha256.Sum256([]byte(runID))
	tag := hex.EncodeToString(digest[:5])
	return Plan{
		RunID:          runID,
		StartedAt:      startedAt.UTC(),
		DNSGatewayName: fmt.Sprintf("gw-%s.coverage.shakerproxy.test", tag),
		DNSDirectName:  fmt.Sprintf("direct-%s.coverage.shakerproxy.test", tag),
		HTTPPath:       "/coverage/" + tag,
		TLSServerName:  fmt.Sprintf("tls-%s.coverage.shakerproxy.test", tag),
		DoTServerName:  fmt.Sprintf("dot-%s.coverage.shakerproxy.test", tag),
		DoQServerName:  fmt.Sprintf("doq-%s.coverage.shakerproxy.test", tag),
		QUICServerName: fmt.Sprintf("quic-%s.coverage.shakerproxy.test", tag),
		MDNSService:    "_airplay._tcp.local",

		DNSIPv6Name:        fmt.Sprintf("aaaa-%s.coverage.shakerproxy.test", tag),
		HTTPIPv6Path:       "/coverage/ipv6-" + tag,
		TLSIPv6ServerName:  fmt.Sprintf("tls6-%s.coverage.shakerproxy.test", tag),
		QUICIPv6ServerName: fmt.Sprintf("quic6-%s.coverage.shakerproxy.test", tag),
	}
}

// ProbeOutcome is what the virtual client did for one probe.
type ProbeOutcome struct {
	ID     string    `json:"id"`
	SentAt time.Time `json:"sent_at"`
	Sent   bool      `json:"sent"`
	// Skipped probes could not run in this lab (for example, IPv6 on an
	// appliance with IPv6 turned off).
	Skipped bool   `json:"skipped,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// Event is the part of a stored event the evaluator reads.
type Event struct {
	RecordID        string    `json:"record_id"`
	Source          string    `json:"source"`
	Kind            string    `json:"kind"`
	OccurredAt      time.Time `json:"occurred_at"`
	ReceivedAt      time.Time `json:"received_at"`
	DeviceID        string    `json:"device_id,omitempty"`
	SourceIP        string    `json:"source_ip,omitempty"`
	DestinationIP   string    `json:"destination_ip,omitempty"`
	DestinationPort int       `json:"destination_port,omitempty"`
	Protocol        string    `json:"protocol,omitempty"`
	Service         string    `json:"service,omitempty"`
	AppProtocol     string    `json:"app_protocol,omitempty"`
	DNSQuery        string    `json:"dns_query,omitempty"`
	TLSServerName   string    `json:"tls_server_name,omitempty"`
	HTTPHost        string    `json:"http_host,omitempty"`
	HTTPPath        string    `json:"http_path,omitempty"`
}

type Result struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Status      Status   `json:"status"`
	Summary     string   `json:"summary"`
	EventKinds  []string `json:"event_kinds"`
	LatencyMS   int64    `json:"latency_ms,omitempty"`
	Attributed  bool     `json:"attributed"`
	Missing     string   `json:"missing,omitempty"`
	AppProtocol string   `json:"app_protocol,omitempty"`
}

type FindingStatus string

const (
	FindingGap     FindingStatus = "GAP"
	FindingOK      FindingStatus = "OK"
	FindingUnknown FindingStatus = "UNKNOWN"
)

// Finding is one way a real device could bypass ShakerProxy, judged from the
// live configuration and recorded evidence.
type Finding struct {
	ID     string        `json:"id"`
	Title  string        `json:"title"`
	Status FindingStatus `json:"status"`
	Detail string        `json:"detail"`
	Fix    string        `json:"fix,omitempty"`
}

type Report struct {
	Schema           int        `json:"schema"`
	RunID            string     `json:"run_id"`
	State            State      `json:"state"`
	Phase            string     `json:"phase,omitempty"`
	StartedAt        time.Time  `json:"started_at"`
	FinishedAt       *time.Time `json:"finished_at,omitempty"`
	CaptureSessionID string     `json:"capture_session_id,omitempty"`
	Results          []Result   `json:"results"`
	Routing          []Finding  `json:"routing"`
	PassCount        int        `json:"pass_count"`
	FailCount        int        `json:"fail_count"`
	SkipCount        int        `json:"skip_count"`
	GapCount         int        `json:"gap_count"`
	Error            string     `json:"error,omitempty"`
	Limitations      []string   `json:"limitations"`
}

// Overview is what GET /api/v1/coverage returns: the last run (if any) and a
// fresh routing inspection.
type Overview struct {
	Schema    int       `json:"schema"`
	LastRun   *Report   `json:"last_run"`
	Routing   []Finding `json:"routing"`
	GapCount  int       `json:"gap_count"`
	CheckedAt time.Time `json:"checked_at"`
}

// Count fills the report's totals.
func (r *Report) Count() {
	r.PassCount, r.FailCount, r.SkipCount, r.GapCount = 0, 0, 0, 0
	for _, item := range r.Results {
		switch item.Status {
		case StatusPass:
			r.PassCount++
		case StatusFail:
			r.FailCount++
		default:
			r.SkipCount++
		}
	}
	r.GapCount = CountGaps(r.Routing)
}

func CountGaps(findings []Finding) int {
	count := 0
	for _, finding := range findings {
		if finding.Status == FindingGap {
			count++
		}
	}
	return count
}

// Limitations are stated on every report so a PASS is not over-read.
func Limitations() []string {
	return []string{
		"Probes come from Linux network namespaces on the appliance, not from a phone or TV; they prove what ShakerProxy's pipeline records, not how a particular device behaves.",
		"Probes use the virtual test lab's own bridge and capture; the lab interface's automatic recording pauses for the few seconds the probes run.",
		"Virtual clients are not lab devices, so their traffic is not attributed to a device; attribution of real devices is covered by the Devices page.",
		"IPv6 probes use a private unique-local prefix inside the appliance: they prove ShakerProxy records IPv6, not that the lab network routes IPv6 through ShakerProxy; the IPv6 routing finding covers that.",
	}
}
