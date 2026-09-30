package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

// DefaultOnboardingEndpointsPath is read by shakerproxy-ca-onboarding to decide
// which lab-side addresses to serve the public CA on.
const DefaultOnboardingEndpointsPath = "/var/lib/shakerproxy/onboarding/lab-endpoints.json"

// OnboardingEndpoints is the world-readable, secret-free projection that
// tells the unprivileged onboarding service where to listen. Serve is true
// only while TLS interception is configured and the packet path is active.
type OnboardingEndpoints struct {
	Schema    int    `json:"schema"`
	Serve     bool   `json:"serve"`
	Interface string `json:"interface,omitempty"`
	IPv4      string `json:"ipv4,omitempty"`
	IPv6      string `json:"ipv6,omitempty"`
	Port      int    `json:"port"`
}

// confirmedLabPlan returns the lab interface of a confirmed routed or
// single-arm plan.
func confirmedLabPlan(store *StateStore) (networkplan.Interface, networkplan.Plan, bool) {
	if store == nil {
		return networkplan.Interface{}, networkplan.Plan{}, false
	}
	state := store.Get()
	staged := state.activeNetworkPlan()
	if state.OperatingMode != gatewayprotocol.ModeRouted || staged == nil {
		return networkplan.Interface{}, networkplan.Plan{}, false
	}
	lab, ok := networkplan.LabInterface(staged.Plan)
	if !ok || !staged.Plan.IPv4.Enabled || staged.Plan.IPv4.LabCIDR == "" {
		return networkplan.Interface{}, networkplan.Plan{}, false
	}
	return lab, staged.Plan, true
}

// labGatewayIPv4 returns the plan's lab gateway when it is a valid address
// inside the lab CIDR.
func labGatewayIPv4(plan networkplan.Plan) string {
	prefix, err := netip.ParsePrefix(plan.IPv4.LabCIDR)
	gateway, gatewayErr := netip.ParseAddr(plan.IPv4.GatewayAddress)
	if err != nil || gatewayErr != nil || !gateway.Is4() || !prefix.Masked().Contains(gateway) {
		return ""
	}
	return gateway.String()
}

// labIPv6Context returns the lab IPv6 prefix and gateway when the confirmed
// plan routes lab IPv6 (ULA_NAT66_LAB or NATIVE_ROUTED_PREFIX).
func labIPv6Context(plan networkplan.Plan) (string, string) {
	routing, ok := networkplan.LabIPv6Routing(plan)
	if !ok {
		return "", ""
	}
	return routing.Prefix.String(), routing.Gateway.String()
}

// deviceMatches resolves device-control identities against the current lab
// neighbor table. A neighbor lookup failure degrades to captured evidence.
func (m *TrafficPolicyManager) deviceMatches(ctx context.Context, policy trafficpolicy.Policy, labInterface string) map[string]trafficpolicy.DeviceMatch {
	if len(policy.DeviceControls) == 0 {
		return map[string]trafficpolicy.DeviceMatch{}
	}
	var neighbors []trafficpolicy.Neighbor
	known := false
	if m.Neighbors != nil {
		lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		result, err := m.Neighbors(lookupCtx, labInterface)
		cancel()
		if err != nil {
			m.warnOnce("neighbors", "lab neighbor table is unavailable; device controls use saved addresses only", err)
		} else {
			m.clearWarning("neighbors")
			neighbors, known = result, true
		}
	}
	return trafficpolicy.ResolveDeviceMatches(policy, neighbors, known)
}

// ipv6ListenersReady proves the listeners that IPv6 redirects would target
// accept IPv6 before any IPv6 client traffic is redirected to them.
func (m *TrafficPolicyManager) ipv6ListenersReady(ctx context.Context, policy trafficpolicy.Policy) bool {
	if m.ProbeIPv6 == nil || !m.ipv6Available() {
		return false
	}
	needsDNS := policy.EncryptedDNS.Mode == trafficpolicy.EncryptedDNSEnforceLocal && policy.EncryptedDNS.RedirectPlainDNS
	for _, control := range policy.DeviceControls {
		if len(control.BlockedDomains) != 0 {
			needsDNS = true
		}
	}
	if needsDNS && m.ProbeIPv6(ctx, policy.EncryptedDNS.LocalListenPort) != nil {
		return false
	}
	if policy.TLS.Enabled && m.ProbeIPv6(ctx, policy.TLS.TransparentPort) != nil {
		return false
	}
	return true
}

// publishOnboarding writes the onboarding endpoints projection when it
// changes. Failures are logged; the onboarding page is never on the critical
// packet path.
func (m *TrafficPolicyManager) publishOnboarding(context trafficpolicy.RenderContext, serve bool) {
	endpoints := OnboardingEndpoints{Schema: 1, Port: trafficpolicy.DefaultOnboardingPort}
	if serve {
		endpoints.Serve = true
		endpoints.Interface = context.LabInterface
		endpoints.IPv4 = context.LabGatewayIPv4
		endpoints.IPv6 = context.LabGatewayIPv6
	}
	encoded, err := json.MarshalIndent(endpoints, "", "  ")
	if err != nil {
		return
	}
	encoded = append(encoded, '\n')
	m.onboardingMu.Lock()
	defer m.onboardingMu.Unlock()
	if m.OnboardingPath == "" {
		m.onboardingPublished = serve
		return
	}
	if bytes.Equal(m.onboardingLast, encoded) {
		return
	}
	if current, err := os.ReadFile(m.OnboardingPath); err != nil || !bytes.Equal(current, encoded) {
		if err := writePublicFile(m.OnboardingPath, encoded, ".lab-endpoints-*"); err != nil {
			// Retried on the next reconcile; report the page as closed.
			m.onboardingPublished = false
			m.warnOnce("onboarding", "CA onboarding endpoints could not be published", err)
			return
		}
	}
	m.clearWarning("onboarding")
	m.onboardingLast = encoded
	m.onboardingPublished = serve
}

// LabOnboarding answers the read-only GetLabOnboarding RPC.
func (m *TrafficPolicyManager) LabOnboarding() gatewayprotocol.LabOnboarding {
	result := gatewayprotocol.LabOnboarding{Schema: 1, Port: trafficpolicy.DefaultOnboardingPort}
	if m.NetworkState != nil {
		result.EmergencyBypass = m.NetworkState.Get().EmergencyBypass
	}
	if lab, plan, ok := confirmedLabPlan(m.NetworkState); ok {
		result.Routed = true
		result.LabInterface = lab.CurrentName
		result.GatewayIPv4 = labGatewayIPv4(plan)
		_, result.GatewayIPv6 = labIPv6Context(plan)
	}
	if m.PolicyStore != nil {
		if document, err := m.PolicyStore.Load(); err == nil {
			result.InterceptionConfigured = document.Policy.TLS.Enabled
		}
	}
	result.FleetManaged, _ = m.cloudPolicyOwnership()
	m.onboardingMu.Lock()
	result.Published = m.onboardingPublished
	m.onboardingMu.Unlock()
	return result
}
