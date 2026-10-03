package gatewayprotocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/configlock"
	"shakerproxy.dev/shakerproxy/internal/firewall"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/pcapng"
	"shakerproxy.dev/shakerproxy/internal/resourcepressure"
	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

const (
	Version          = "v1"
	JSONRPCVersion   = "2.0"
	MaxRequestBytes  = 64 << 10
	MaxResponseBytes = 1 << 20
	ModeSetupSafe    = "SETUP_SAFE"
	ModeRouted       = "ROUTED_PASSTHROUGH"
	ModeEmergency    = "EMERGENCY_BYPASS"
)

var ErrUnknownField = errors.New("unknown JSON field")

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      string    `json:"id"`
	Result  any       `json:"result,omitempty"`
	Error   *RPCError `json:"error,omitempty"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type EmptyParams struct{}

type SetOperatingModeParams struct {
	Mode string `json:"mode"`
}

type ValidateNetworkPlanParams struct {
	Plan networkplan.Plan `json:"plan"`
}

type PreviewNetworkPlanParams struct {
	Plan networkplan.Plan `json:"plan"`
}

type PreviewTrafficPolicyParams struct {
	Policy trafficpolicy.Policy `json:"policy"`
}

type ApplyTrafficPolicyParams struct {
	ExpectedRevision uint64               `json:"expected_revision"`
	Policy           trafficpolicy.Policy `json:"policy"`
}

type RollbackTrafficPolicyParams struct {
	ExpectedRevision uint64 `json:"expected_revision"`
}

type TrafficPolicyPreview struct {
	Policy         trafficpolicy.Policy        `json:"policy"`
	Digest         string                      `json:"digest"`
	Firewall       trafficpolicy.FirewallRules `json:"firewall"`
	ChangedObjects []string                    `json:"changed_objects"`
	Warnings       []string                    `json:"warnings"`
}

type StageNetworkPlanParams struct {
	Plan             networkplan.Plan `json:"plan"`
	ExpectedPlanHash string           `json:"expected_plan_hash"`
	IdempotencyKey   string           `json:"idempotency_key"`
	StageTTLSeconds  int              `json:"stage_ttl_seconds"`
}

type RollbackNetworkPlanParams struct {
	ApplyID string `json:"apply_id"`
}

type CommitNetworkPlanParams struct {
	ApplyID               string `json:"apply_id"`
	PlanHash              string `json:"plan_hash"`
	IdempotencyKey        string `json:"idempotency_key"`
	RollbackWindowSeconds int    `json:"rollback_window_seconds"`
}

type CommitNetworkPlanResult struct {
	ApplyID        string    `json:"apply_id"`
	PlanHash       string    `json:"plan_hash"`
	Status         string    `json:"status"`
	HealthToken    string    `json:"health_token"`
	HealthDeadline time.Time `json:"health_deadline"`
	Failure        string    `json:"failure,omitempty"`
}

type SignalNetworkHealthParams struct {
	ApplyID  string `json:"apply_id"`
	PlanHash string `json:"plan_hash"`
	Token    string `json:"token"`
}

type ConfirmNetworkPlanParams struct {
	ApplyID        string `json:"apply_id"`
	PlanHash       string `json:"plan_hash"`
	IdempotencyKey string `json:"idempotency_key"`
}

type StartCaptureParams struct {
	Request capture.StartRequest `json:"request"`
}

type StopCaptureParams struct {
	SessionID string `json:"session_id"`
}

// SetLabRecordingParams turns automatic lab recording on or off.
type SetLabRecordingParams struct {
	Enabled bool `json:"enabled"`
}

// LabRecordingStatus says whether lab traffic is being recorded and, when it
// is not, why, in words a tester can act on.
type LabRecordingStatus struct {
	// Enabled is the administrator setting; it is on unless turned off.
	Enabled bool `json:"enabled"`
	// Recording is true while any capture records the lab.
	Recording bool   `json:"recording"`
	SessionID string `json:"session_id,omitempty"`
	// Manual is true when a manual capture runs in place of the automatic one.
	Manual bool `json:"manual,omitempty"`
	// Reason explains a stopped recording, or that a manual capture replaced it.
	Reason    string    `json:"reason,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

type GetCaptureStatsParams struct {
	SessionID string `json:"session_id"`
}

type SetCaptureEvidenceHoldParams struct {
	Request capture.SetHoldRequest `json:"request"`
}

type PreviewCaptureDeletionParams struct {
	SessionID string `json:"session_id"`
}

type PreviewCaptureDeletionUntilParams struct {
	SessionID string    `json:"session_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type PreviewPCAPSelectionParams struct {
	Selection pcapng.SelectionRule `json:"selection_rule"`
}

type RewritePCAPParams struct {
	Request capture.PCAPRewriteRequest `json:"request"`
}

type DeletePCAPArtifactParams struct {
	Request capture.PCAPArtifactDeletionRequest `json:"request"`
}

type DeleteCaptureParams struct {
	Request capture.DeleteRequest `json:"request"`
}

type PreviewCaptureRetentionParams struct {
	Policy capture.RetentionPolicyInput `json:"policy"`
}

type ApplyCaptureRetentionPolicyParams struct {
	Request capture.ApplyRetentionPolicyRequest `json:"request"`
}

type StartCaptureRetentionRunParams struct {
	Request capture.StartRetentionRunRequest `json:"request"`
}

type RecordCaptureRetentionItemOutcomeParams struct {
	Request capture.RecordRetentionItemOutcomeRequest `json:"request"`
}

type ReadCaptureFlowParams struct {
	Request capture.FlowRequest `json:"request"`
}

type ReadCaptureArtifactParams struct {
	SessionID string `json:"session_id"`
	FileName  string `json:"file_name"`
	Offset    int64  `json:"offset"`
	Length    int    `json:"length"`
}

type Status struct {
	APIVersion             string                    `json:"api_version"`
	DaemonVersion          string                    `json:"daemon_version"`
	OperatingMode          string                    `json:"operating_mode"`
	EmergencyBypass        bool                      `json:"emergency_bypass"`
	NetworkActivation      bool                      `json:"network_activation_available"`
	CaptureAvailable       bool                      `json:"capture_available"`
	TrafficPolicyAvailable bool                      `json:"traffic_policy_available"`
	ActiveCaptureID        string                    `json:"active_capture_id,omitempty"`
	LabRecording           *LabRecordingStatus       `json:"lab_recording,omitempty"`
	StartedAt              string                    `json:"started_at"`
	StagedNetworkPlan      *networkplan.StageSummary `json:"staged_network_plan,omitempty"`
	// ConfirmedNetworkPlan is the plan the host is running when a different
	// candidate is staged; it is omitted when the staged plan is the active one.
	ConfirmedNetworkPlan *networkplan.StageSummary `json:"confirmed_network_plan,omitempty"`
	LabInterface         string                    `json:"lab_interface,omitempty"`
	LabVLANID            *int                      `json:"lab_vlan_id,omitempty"`
	LabScopePlanHash     string                    `json:"lab_scope_plan_hash,omitempty"`
	LabTopology          string                    `json:"lab_topology,omitempty"`
	LabWiFi              bool                      `json:"lab_wifi,omitempty"`
	// LabWiFiClientTraffic says how traffic between two Wi-Fi devices on
	// ShakerProxy's access point travels (networkplan.WiFiClientTraffic):
	// BRIDGED (through ShakerProxy, recorded), ISOLATED, or
	// INSIDE_ACCESS_POINT (switched by the adapter, not recorded).
	LabWiFiClientTraffic string `json:"lab_wifi_client_traffic,omitempty"`
	// LabIPv4Prefix and LabIPv4Gateway are the lab's IPv4 prefix and
	// ShakerProxy's address in it, the gateway lab devices should use.
	// LabIPv4Router is the network's own router on the lab, when the lab
	// interface has a default route through one (a single-arm lab, an
	// inline bridge): a device that takes the router's DHCP uses it as its
	// gateway instead.
	LabIPv4Prefix     string             `json:"lab_ipv4_prefix,omitempty"`
	LabIPv4Gateway    string             `json:"lab_ipv4_gateway,omitempty"`
	LabIPv4Router     string             `json:"lab_ipv4_router,omitempty"`
	LabIPv6Strategy   string             `json:"lab_ipv6_strategy,omitempty"`
	LabIPv6Prefix     string             `json:"lab_ipv6_prefix,omitempty"`
	LabIPv6Gateway    string             `json:"lab_ipv6_gateway,omitempty"`
	ConfigurationLock *configlock.Status `json:"configuration_lock,omitempty"`
	// Warnings explain, in plain language, parts of the managed state that
	// could not be read. The rest of the status is still valid.
	Warnings []string `json:"warnings,omitempty"`
	// Degraded lists the same problems as stable codes (Degraded* constants)
	// for callers that must branch on them. DegradedNetworkReconcile means the
	// network state is unproven; the lab scope fields are then omitted.
	Degraded []string `json:"degraded,omitempty"`
}

// Stable codes for Status.Degraded.
const (
	DegradedNetworkReconcile  = "network_reconcile"
	DegradedCaptureList       = "capture_list"
	DegradedConfigurationLock = "configuration_lock"
)

type HostInspection struct {
	Hostname        string                         `json:"hostname"`
	OperatingSystem string                         `json:"operating_system"`
	Architecture    string                         `json:"architecture"`
	Kernel          string                         `json:"kernel"`
	Interfaces      []Interface                    `json:"interfaces"`
	Firewall        firewall.Inspection            `json:"firewall"`
	ActiveSSH       []networkplan.ActiveSSHSession `json:"active_ssh"`
	NetworkConfig   NetworkConfiguration           `json:"network_configuration"`
}

type NetworkConfiguration struct {
	Owner            string   `json:"owner"`
	CloudInitManaged bool     `json:"cloud_init_managed"`
	NetplanFiles     []string `json:"netplan_files"`
}

type DiagnosticStatus string

const (
	DiagnosticPass    DiagnosticStatus = "PASS"
	DiagnosticWarning DiagnosticStatus = "WARNING"
	DiagnosticFail    DiagnosticStatus = "FAIL"
	DiagnosticUnknown DiagnosticStatus = "UNKNOWN"
)

type DiagnosticCheck struct {
	Name         string           `json:"name"`
	Status       DiagnosticStatus `json:"status"`
	Summary      string           `json:"summary"`
	Observations []string         `json:"observations"`
}

type DiagnosticReport struct {
	Schema      int                     `json:"schema"`
	GeneratedAt time.Time               `json:"generated_at"`
	Overall     DiagnosticStatus        `json:"overall"`
	Checks      []DiagnosticCheck       `json:"checks"`
	Pressure    resourcepressure.Report `json:"resource_pressure"`
}

type PortListener struct {
	Transport string `json:"transport"`
	Address   string `json:"address"`
	Port      int    `json:"port"`
	Process   string `json:"process,omitempty"`
}

type PortReservation struct {
	Transport       string         `json:"transport"`
	Port            int            `json:"port"`
	Purpose         string         `json:"purpose"`
	IntendedBinding string         `json:"intended_binding"`
	State           string         `json:"state"`
	Action          string         `json:"action"`
	Listeners       []PortListener `json:"listeners"`
}

type ServicePortPlan struct {
	Schema              int               `json:"schema"`
	GeneratedAt         time.Time         `json:"generated_at"`
	SystemdResolvedStub bool              `json:"systemd_resolved_stub"`
	ResolverHandling    string            `json:"resolver_handling"`
	Reservations        []PortReservation `json:"reservations"`
}

type ConnectivityProbe struct {
	Name          string           `json:"name"`
	Target        string           `json:"target"`
	Status        DiagnosticStatus `json:"status"`
	LatencyMillis int64            `json:"latency_millis,omitempty"`
	Detail        string           `json:"detail"`
}

type ConnectivityReport struct {
	Schema              int                 `json:"schema"`
	GeneratedAt         time.Time           `json:"generated_at"`
	DNSIndependentHTTPS bool                `json:"dns_independent_https"`
	PlainDNSPort53      bool                `json:"plain_dns_port_53"`
	RestrictedPort53    bool                `json:"restricted_port_53"`
	Probes              []ConnectivityProbe `json:"probes"`
}

type Interface struct {
	Name         string   `json:"name"`
	StableID     string   `json:"stable_id"`
	HardwareAddr string   `json:"hardware_address,omitempty"`
	Driver       string   `json:"driver,omitempty"`
	DevicePath   string   `json:"device_path,omitempty"`
	OperState    string   `json:"oper_state,omitempty"`
	Carrier      string   `json:"carrier,omitempty"`
	SpeedMbps    int      `json:"speed_mbps,omitempty"`
	MTU          int      `json:"mtu"`
	Flags        []string `json:"flags"`
	Addresses    []string `json:"addresses"`
	DefaultIPv4  bool     `json:"default_ipv4_route"`
	DefaultIPv6  bool     `json:"default_ipv6_route"`

	// Wireless reports a Wi-Fi adapter; APSupported is nil when AP mode
	// support could not be determined (for example, iw is not installed).
	Wireless      bool     `json:"wireless"`
	APSupported   *bool    `json:"ap_supported"`
	WirelessBands []string `json:"wireless_bands"`
}

func DecodeStrict(r io.Reader, dst any, maxBytes int64) error {
	limited := io.LimitReader(r, maxBytes+1)
	b, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if int64(len(b)) > maxBytes {
		return fmt.Errorf("request exceeds %d bytes", maxBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if bytes.Contains([]byte(err.Error()), []byte("unknown field")) {
			return fmt.Errorf("%w: %v", ErrUnknownField, err)
		}
		return err
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return errors.New("multiple JSON values are not allowed")
	}
	return nil
}

func DecodeParams(raw json.RawMessage, dst any) error {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	return DecodeStrict(bytes.NewReader(raw), dst, MaxRequestBytes)
}
