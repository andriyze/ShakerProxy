package networkplan

import (
	"time"

	"shakerproxy.dev/shakerproxy/internal/firewall"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

const SchemaVersion = 1

type Topology string

const (
	TopologyTwoNIC             Topology = "TWO_NIC"
	TopologySingleArm          Topology = "SINGLE_ARM"
	TopologyThreeInterface     Topology = "THREE_INTERFACE"
	TopologyVLANTrunk          Topology = "VLAN_TRUNK"
	TopologyExistingRoutedVLAN Topology = "EXISTING_ROUTED_VLAN"
	TopologyPassiveSensor      Topology = "PASSIVE_SENSOR"
	TopologyAdvancedCustom     Topology = "ADVANCED_CUSTOM"
)

type InterfaceRole string

const (
	RoleWAN        InterfaceRole = "WAN"
	RoleLab        InterfaceRole = "LAB"
	RoleWANLab     InterfaceRole = "WAN_LAB"
	RoleManagement InterfaceRole = "MANAGEMENT"
	RoleMirror     InterfaceRole = "MIRROR"
	RoleUnused     InterfaceRole = "UNUSED"
)

type IPv6Strategy string

const (
	IPv6NativeRouted     IPv6Strategy = "NATIVE_ROUTED_PREFIX"
	IPv6PrefixDelegation IPv6Strategy = "PREFIX_DELEGATION"
	IPv6ULANAT66Lab      IPv6Strategy = "ULA_NAT66_LAB"
	IPv6ObserveOnly      IPv6Strategy = "OBSERVE_ONLY"
	IPv6Disabled         IPv6Strategy = "DISABLED"
)

type WANIPv4Mode string

const (
	WANIPv4KeepExisting WANIPv4Mode = "KEEP_EXISTING"
	WANIPv4DHCP         WANIPv4Mode = "DHCP"
	WANIPv4Static       WANIPv4Mode = "STATIC"
)

type WANIPv6Mode string

const (
	WANIPv6KeepExisting     WANIPv6Mode = "KEEP_EXISTING"
	WANIPv6SLAAC            WANIPv6Mode = "SLAAC"
	WANIPv6DHCP             WANIPv6Mode = "DHCPV6"
	WANIPv6PrefixDelegation WANIPv6Mode = "PREFIX_DELEGATION"
	WANIPv6Static           WANIPv6Mode = "STATIC"
	WANIPv6None             WANIPv6Mode = "NONE"
)

type WANDNSMode string

const (
	WANDNSUseDHCP       WANDNSMode = "USE_DHCP"
	WANDNSIgnoreDHCP    WANDNSMode = "IGNORE_DHCP"
	WANDNSBootstrapOnly WANDNSMode = "BOOTSTRAP_ONLY"
)

type Plan struct {
	Schema     int               `json:"schema"`
	Name       string            `json:"name"`
	Topology   Topology          `json:"topology"`
	Interfaces []Interface       `json:"interfaces"`
	Management Management        `json:"management"`
	WAN        WANConfiguration  `json:"wan"`
	IPv4       IPv4Configuration `json:"ipv4"`
	IPv6       IPv6Configuration `json:"ipv6"`

	// WiFi is the optional lab access point; see wifi.go.
	WiFi *WiFiConfiguration `json:"wifi,omitempty"`
}

type Interface struct {
	StableID     string        `json:"stable_id"`
	CurrentName  string        `json:"current_name"`
	PermanentMAC string        `json:"permanent_mac,omitempty"`
	Role         InterfaceRole `json:"role"`
	VLANID       *int          `json:"vlan_id,omitempty"`
	MTU          int           `json:"mtu,omitempty"`
}

type WANConfiguration struct {
	IPv4Mode               WANIPv4Mode `json:"ipv4_mode,omitempty"`
	IPv4Address            string      `json:"ipv4_address,omitempty"`
	IPv4Gateway            string      `json:"ipv4_gateway,omitempty"`
	IPv6Mode               WANIPv6Mode `json:"ipv6_mode,omitempty"`
	IPv6Address            string      `json:"ipv6_address,omitempty"`
	IPv6Gateway            string      `json:"ipv6_gateway,omitempty"`
	RequestedPrefixLength  int         `json:"requested_prefix_length,omitempty"`
	DNSMode                WANDNSMode  `json:"dns_mode,omitempty"`
	UpstreamNAT            bool        `json:"upstream_nat"`
	ClampMSS               bool        `json:"clamp_mss"`
	AllowWorkingWANChange  bool        `json:"allow_working_wan_change"`
	AllowCloudInitOverride bool        `json:"allow_cloud_init_override"`
}

type Management struct {
	PreserveActiveSSH bool     `json:"preserve_active_ssh"`
	AllowedCIDRs      []string `json:"allowed_cidrs,omitempty"`
}

type ActiveSSHSession struct {
	SourceAddress        string `json:"source_address"`
	SourcePort           int    `json:"source_port"`
	DestinationAddress   string `json:"destination_address"`
	DestinationPort      int    `json:"destination_port"`
	DestinationInterface string `json:"destination_interface,omitempty"`
}

type IPv4Configuration struct {
	Enabled          bool              `json:"enabled"`
	LabCIDR          string            `json:"lab_cidr,omitempty"`
	GatewayAddress   string            `json:"gateway_address,omitempty"`
	DHCPStart        string            `json:"dhcp_start,omitempty"`
	DHCPEnd          string            `json:"dhcp_end,omitempty"`
	DHCPLeaseSeconds int               `json:"dhcp_lease_seconds,omitempty"`
	DNSAddresses     []string          `json:"dns_addresses,omitempty"`
	SearchDomain     string            `json:"search_domain,omitempty"`
	Reservations     []DHCPReservation `json:"reservations,omitempty"`
	NAT44            bool              `json:"nat44"`
	ClientIsolation  bool              `json:"client_isolation"`
}

type DHCPReservation struct {
	Hostname        string `json:"hostname,omitempty"`
	HardwareAddress string `json:"hardware_address"`
	IPAddress       string `json:"ip_address"`
}

type IPv6Configuration struct {
	Strategy       IPv6Strategy `json:"strategy"`
	LabPrefix      string       `json:"lab_prefix,omitempty"`
	GatewayAddress string       `json:"gateway_address,omitempty"`
	DNSAddresses   []string     `json:"dns_addresses,omitempty"`
}

type Issue struct {
	Code    string `json:"code"`
	Path    string `json:"path"`
	Message string `json:"message"`
}

type ValidationResult struct {
	Valid    bool    `json:"valid"`
	PlanHash string  `json:"plan_hash,omitempty"`
	Errors   []Issue `json:"errors"`
	Warnings []Issue `json:"warnings"`
}

type CommandPreview struct {
	Executable string   `json:"executable"`
	Arguments  []string `json:"arguments"`
}

type Preview struct {
	Validation          ValidationResult    `json:"validation"`
	GeneratedAt         time.Time           `json:"generated_at"`
	FirewallBackend     string              `json:"firewall_backend"`
	FirewallEnvironment firewall.Inspection `json:"firewall_environment"`
	ActiveSSH           []ActiveSSHSession  `json:"active_ssh"`
	FirewallRestoreIPv4 string              `json:"firewall_restore_ipv4,omitempty"`
	FirewallRestoreIPv6 string              `json:"firewall_restore_ipv6,omitempty"`
	RadvdConf           string              `json:"radvd_conf,omitempty"`
	AttachmentCommands  []CommandPreview    `json:"attachment_commands,omitempty"`
	NetplanYAML         string              `json:"netplan_yaml,omitempty"`
	KeaDHCP4JSON        string              `json:"kea_dhcp4_json,omitempty"`
	HostapdConf         string              `json:"hostapd_conf,omitempty"`
	ChangedObjects      []string            `json:"changed_objects"`
	Impact              []string            `json:"impact"`
}

type StagedPlan struct {
	ApplyID        string                     `json:"apply_id"`
	IdempotencyKey string                     `json:"idempotency_key"`
	PlanHash       string                     `json:"plan_hash"`
	Plan           Plan                       `json:"plan"`
	Preview        Preview                    `json:"preview"`
	StagedAt       time.Time                  `json:"staged_at"`
	ExpiresAt      time.Time                  `json:"expires_at"`
	Status         string                     `json:"status"`
	Transaction    *networktransaction.Record `json:"transaction,omitempty"`
}

type StageSummary struct {
	ApplyID   string     `json:"apply_id"`
	PlanHash  string     `json:"plan_hash"`
	StagedAt  time.Time  `json:"staged_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	Status    string     `json:"status"`
	ConfirmBy *time.Time `json:"confirm_by,omitempty"`
}
