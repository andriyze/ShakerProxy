package testlab

import "time"

const (
	SchemaVersion       = 1
	DefaultSocketPath   = "/var/lib/shakerproxy/control-api/testlab/testlab.sock"
	MaxResults          = 32
	MaxOutputBytes      = 4096
	DefaultRunTimeout   = 90 * time.Second
	DefaultClientCIDR   = "198.18.240.0/24"
	DefaultGatewayIPv4  = "198.18.240.1"
	DefaultNormalClient = "198.18.240.10"
	DefaultBypassClient = "198.18.240.20"
	DefaultDNSClient    = "198.18.240.30"
)

type State string

const (
	StateIdle     State = "IDLE"
	StateRunning  State = "RUNNING"
	StatePassed   State = "PASSED"
	StateFailed   State = "FAILED"
	StateDegraded State = "DEGRADED"
)

type TestStatus string

const (
	TestPass TestStatus = "PASS"
	TestFail TestStatus = "FAIL"
	TestSkip TestStatus = "SKIP"
)

type Profile string

const (
	ProfileQuick Profile = "quick"
	ProfileFull  Profile = "full"
	ProfileDNS   Profile = "dns"
	ProfileTLS   Profile = "tls"
)

func ValidProfile(value Profile) bool {
	switch value {
	case ProfileQuick, ProfileFull, ProfileDNS, ProfileTLS:
		return true
	default:
		return false
	}
}

type RunRequest struct {
	Profile Profile `json:"profile"`
}

type Environment struct {
	Bridge              string `json:"bridge"`
	CIDR                string `json:"cidr"`
	GatewayIPv4         string `json:"gateway_ipv4"`
	NormalClientIPv4    string `json:"normal_client_ipv4"`
	BypassClientIPv4    string `json:"bypass_client_ipv4"`
	DNSClientIPv4       string `json:"dns_client_ipv4"`
	InternetReachable   bool   `json:"internet_reachable"`
	ShakerProxyDNSPort  int    `json:"shakerproxy_dns_port"`
	ShakerProxyMITMPort int    `json:"shakerproxy_mitm_port"`
	NamespaceIsolation  bool   `json:"namespace_isolation"`
}

type Result struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Category    string     `json:"category"`
	Status      TestStatus `json:"status"`
	Summary     string     `json:"summary"`
	Observed    string     `json:"observed,omitempty"`
	DurationMS  int64      `json:"duration_ms"`
	EvidenceRef string     `json:"evidence_ref,omitempty"`
}

type Run struct {
	Schema      int         `json:"schema"`
	RunID       string      `json:"run_id"`
	Profile     Profile     `json:"profile"`
	State       State       `json:"state"`
	StartedAt   time.Time   `json:"started_at"`
	FinishedAt  *time.Time  `json:"finished_at,omitempty"`
	Environment Environment `json:"environment"`
	Results     []Result    `json:"results"`
	PassCount   int         `json:"pass_count"`
	FailCount   int         `json:"fail_count"`
	SkipCount   int         `json:"skip_count"`
	Limitations []string    `json:"limitations,omitempty"`
}

type Status struct {
	Schema      int       `json:"schema"`
	State       State     `json:"state"`
	Available   bool      `json:"available"`
	Busy        bool      `json:"busy"`
	LastRun     *Run      `json:"last_run,omitempty"`
	Prereq      []Result  `json:"prerequisites,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
	Limitations []string  `json:"limitations,omitempty"`
}
