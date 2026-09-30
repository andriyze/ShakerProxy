package gatewayprotocol

// LabOnboarding is the read-only answer of GetLabOnboarding: where lab
// clients can reach ShakerProxy and whether the unauthenticated CA onboarding
// page is currently published on the lab side. It never contains secrets.
type LabOnboarding struct {
	Schema int `json:"schema"`
	// Routed is true when a routed or single-arm plan is confirmed.
	Routed       bool   `json:"routed"`
	LabInterface string `json:"lab_interface,omitempty"`
	GatewayIPv4  string `json:"gateway_ipv4,omitempty"`
	GatewayIPv6  string `json:"gateway_ipv6,omitempty"`
	// InterceptionConfigured is true when the local policy enables TLS
	// interception; the onboarding page is published only then.
	InterceptionConfigured bool `json:"interception_configured"`
	Published              bool `json:"published"`
	EmergencyBypass        bool `json:"emergency_bypass"`
	FleetManaged           bool `json:"fleet_managed"`
	Port                   int  `json:"port"`
}
