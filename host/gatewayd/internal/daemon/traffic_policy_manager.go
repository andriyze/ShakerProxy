package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/policycoordination"
	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

type TrafficPolicyManager struct {
	NetworkState          *StateStore
	PolicyStore           *trafficpolicy.Store
	RuntimePath           string
	CloudPolicyStatusPath string
	CoordinationLockPath  string
	Runner                trafficCommandRunner
	Logger                *slog.Logger
	Now                   func() time.Time
	Probe                 func(context.Context, int) error
	// ProbeIPv6 proves a listener accepts IPv6 on ::1; nil disables IPv6
	// redirects (IPv6 blocking and listener protection still apply).
	ProbeIPv6 func(context.Context, int) error
	// Neighbors reads the lab ARP/NDP table used to refresh the current
	// addresses of devices with lab controls.
	Neighbors func(context.Context, string) ([]trafficpolicy.Neighbor, error)
	// IPv6Available reports whether the host kernel has IPv6; nil means no.
	IPv6Available func() bool
	// OnboardingPath receives the lab-side CA onboarding endpoints.
	OnboardingPath string
	// BlockEvents reports blocked encrypted-DNS attempts in Traffic; nil
	// disables it.
	BlockEvents *EncryptedDNSBlockMonitor
	// VPN returns the running WireGuard VPN segment, or nil; its devices get
	// the same rules as lab devices.
	VPN                 func() *trafficpolicy.Segment
	onboardingMu        sync.Mutex
	onboardingPublished bool
	onboardingLast      []byte
	warningsMu          sync.Mutex
	warnings            map[string]string
	// installed remembers each security batch last loaded and the chains'
	// listing right after it, so an unchanged policy is not rewritten.
	installedMu sync.Mutex
	installed   map[string]installedSecurityBatch
	mu          sync.Mutex
	wake        chan struct{}
	wakeOnce    sync.Once
}

func NewProductionTrafficPolicyManager(networkState *StateStore, policyPath, runtimePath, cloudPolicyStatusPath, coordinationLockPath string, logger *slog.Logger) *TrafficPolicyManager {
	return &TrafficPolicyManager{
		NetworkState:          networkState,
		PolicyStore:           &trafficpolicy.Store{Path: policyPath},
		RuntimePath:           runtimePath,
		CloudPolicyStatusPath: cloudPolicyStatusPath,
		CoordinationLockPath:  coordinationLockPath,
		Runner:                execTrafficCommandRunner{},
		Logger:                logger,
		Probe:                 probeTrafficListener,
		ProbeIPv6:             probeTrafficListenerIPv6,
		Neighbors:             labNeighbors,
		IPv6Available:         hostIPv6Available,
		OnboardingPath:        DefaultOnboardingEndpointsPath,
		BlockEvents:           NewEncryptedDNSBlockMonitor(DefaultHostEventSpool, logger),
	}
}

func (m *TrafficPolicyManager) Ensure(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.NetworkState == nil || m.PolicyStore == nil || m.RuntimePath == "" || m.Runner == nil {
		return errors.New("traffic policy manager is incomplete")
	}
	coordination, err := policycoordination.Acquire(ctx, m.CoordinationLockPath)
	if err != nil {
		return err
	}
	defer coordination.Release()
	document, err := m.PolicyStore.Load()
	if errors.Is(err, os.ErrNotExist) {
		policy := trafficpolicy.DefaultPolicy()
		document, err = m.PolicyStore.Apply(policy, 0)
	}
	if err != nil {
		return err
	}
	// An installation nobody configured moves from the old observe-only
	// default to maximum visibility; an administrator's policy is kept.
	if migrated, ok := trafficpolicy.MigrateUntouchedDefault(document); ok {
		if next, migrateErr := m.PolicyStore.Apply(migrated, document.Policy.Revision); migrateErr != nil {
			m.warn("the untouched default DNS policy could not move to the visibility default", migrateErr)
		} else {
			document = next
			m.log("traffic policy moved to the visibility default: plain DNS forced through ShakerProxy; encrypted DNS identified, not blocked", document)
		}
	}
	cloudOwned, ownershipErr := m.cloudPolicyOwnership()
	if cloudOwned || ownershipErr != nil {
		if cleanupErr := m.cleanupFirewall(ctx); cleanupErr != nil {
			return errors.Join(ownershipErr, fmt.Errorf("fail-open local traffic policy cleanup: %w", cleanupErr))
		}
		if ownershipErr != nil {
			m.warn("local traffic policy disabled because Fleet ownership state is unsafe", ownershipErr)
		}
		return nil
	}
	if err := m.writeRuntimePolicy(ctx, document.Policy); err != nil {
		return err
	}
	// gatewayd starts before the containerized DNS and MITM services. Keep the
	// packet path fail-open until the reconciler proves every required listener.
	ipv4Err, ipv6Err := m.cleanupFirewallFamilies(ctx)
	if ipv6Err != nil {
		m.warn("IPv6 listener protection is not installed yet; the reconciler retries it", ipv6Err)
	}
	return ipv4Err
}

func (m *TrafficPolicyManager) reconcileLoop(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		m.reconcile(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-m.wakeChannel():
		}
	}
}

// Wake asks for a reconcile soon, for example when the VPN came up and its
// devices need the lab's DNS and TLS rules.
func (m *TrafficPolicyManager) Wake() {
	select {
	case m.wakeChannel() <- struct{}{}:
	default:
	}
}

func (m *TrafficPolicyManager) wakeChannel() chan struct{} {
	m.wakeOnce.Do(func() { m.wake = make(chan struct{}, 1) })
	return m.wake
}

func (m *TrafficPolicyManager) ownershipLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	suppressed := false
	lastError := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		current, err := m.reconcileOwnershipTransition(ctx, suppressed)
		suppressed = current
		if err != nil {
			if message := err.Error(); message != lastError {
				m.warn("traffic policy ownership reconciliation failed", err)
				lastError = message
			}
			continue
		}
		if lastError != "" {
			if m.Logger != nil {
				m.Logger.Info("traffic policy ownership reconciliation recovered", "fleet_owned", suppressed)
			}
			lastError = ""
		}
	}
}

func (m *TrafficPolicyManager) reconcile(ctx context.Context) {
	if err := m.ReconcileNow(ctx); err != nil {
		m.warn("traffic policy remains fail-open because reconciliation failed", err)
	}
}

// ReconcileNow synchronously restores the durable traffic policy after an
// emergency bypass is disabled. A failed restore always leaves client traffic
// fail-open and is retried by the regular reconciliation loop.
func (m *TrafficPolicyManager) ReconcileNow(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	coordination, err := policycoordination.Acquire(ctx, m.CoordinationLockPath)
	if err != nil {
		cleanupErr := m.cleanupFirewall(ctx)
		return errors.Join(err, cleanupErr)
	}
	defer coordination.Release()
	cloudOwned, ownershipErr := m.cloudPolicyOwnership()
	if cloudOwned || ownershipErr != nil {
		cleanupErr := m.cleanupFirewall(ctx)
		return errors.Join(ownershipErr, cleanupErr)
	}
	return m.reconcileLocalLocked(ctx)
}

func (m *TrafficPolicyManager) reconcileLocalLocked(ctx context.Context) error {
	document, err := m.PolicyStore.Load()
	if err != nil {
		return fmt.Errorf("load traffic policy: %w", err)
	}
	if err := m.writeRuntimePolicy(ctx, document.Policy); err != nil {
		return fmt.Errorf("publish runtime traffic policy: %w", err)
	}
	if err := m.applyFirewall(ctx, document.Policy, true); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if cleanupErr := m.cleanupFirewall(cleanupCtx); cleanupErr != nil {
			return errors.Join(err, fmt.Errorf("fail-open cleanup: %w", cleanupErr))
		}
		return err
	}
	return nil
}

// EnableEmergencyBypass immediately detaches every traffic-policy jump. The
// durable policy remains intact so DisableEmergencyBypass can restore it.
func (m *TrafficPolicyManager) EnableEmergencyBypass(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Runner == nil {
		return errors.New("traffic policy command runner is unavailable")
	}
	return m.cleanupFirewall(ctx)
}

func (m *TrafficPolicyManager) Apply(ctx context.Context, policy trafficpolicy.Policy, expectedRevision uint64) (trafficpolicy.Document, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	coordination, err := policycoordination.Acquire(ctx, m.CoordinationLockPath)
	if err != nil {
		return trafficpolicy.Document{}, errors.Join(err, m.cleanupFirewall(ctx))
	}
	defer coordination.Release()
	if err := m.requireLocalPolicyOwnership(ctx); err != nil {
		return trafficpolicy.Document{}, err
	}
	current, err := m.PolicyStore.Load()
	if err != nil {
		return trafficpolicy.Document{}, err
	}
	if current.Policy.Revision != expectedRevision {
		return trafficpolicy.Document{}, fmt.Errorf("traffic policy revision conflict: current %d, expected %d", current.Policy.Revision, expectedRevision)
	}
	normalized, err := trafficpolicy.Normalize(policy)
	if err != nil {
		return trafficpolicy.Document{}, err
	}
	if normalized.Revision <= expectedRevision {
		return trafficpolicy.Document{}, errors.New("traffic policy revision must increase")
	}
	if _, err := m.preview(normalized); err != nil {
		return trafficpolicy.Document{}, err
	}
	if err := m.writeRuntimePolicy(ctx, normalized); err != nil {
		return trafficpolicy.Document{}, err
	}
	if err := m.applyFirewall(ctx, normalized, true); err != nil {
		return trafficpolicy.Document{}, errors.Join(err, m.restoreRuntimeFailOpen(current.Policy))
	}
	document, err := m.PolicyStore.Apply(normalized, expectedRevision)
	if err != nil {
		return trafficpolicy.Document{}, errors.Join(err, m.restoreRuntimeFailOpen(current.Policy))
	}
	m.log("traffic policy applied", document)
	return document, nil
}

func (m *TrafficPolicyManager) Rollback(ctx context.Context, expectedRevision uint64) (trafficpolicy.Document, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	coordination, err := policycoordination.Acquire(ctx, m.CoordinationLockPath)
	if err != nil {
		return trafficpolicy.Document{}, errors.Join(err, m.cleanupFirewall(ctx))
	}
	defer coordination.Release()
	if err := m.requireLocalPolicyOwnership(ctx); err != nil {
		return trafficpolicy.Document{}, err
	}
	current, err := m.PolicyStore.Load()
	if err != nil {
		return trafficpolicy.Document{}, err
	}
	if current.Policy.Revision != expectedRevision || current.Previous == nil {
		return trafficpolicy.Document{}, errors.New("traffic policy rollback revision or history is invalid")
	}
	candidate := *current.Previous
	candidate.Revision = current.Policy.Revision + 1
	if _, err := m.preview(candidate); err != nil {
		return trafficpolicy.Document{}, err
	}
	if err := m.writeRuntimePolicy(ctx, candidate); err != nil {
		return trafficpolicy.Document{}, err
	}
	if err := m.applyFirewall(ctx, candidate, true); err != nil {
		return trafficpolicy.Document{}, errors.Join(err, m.restoreRuntimeFailOpen(current.Policy))
	}
	document, err := m.PolicyStore.Rollback(expectedRevision)
	if err != nil {
		return trafficpolicy.Document{}, errors.Join(err, m.restoreRuntimeFailOpen(current.Policy))
	}
	m.log("traffic policy rolled back", document)
	return document, nil
}

// restoreRuntimeFailOpen retains the last durable policy for reconciliation,
// but removes every client interception jump immediately. Reapplying a prior
// active policy without probing its dependencies could otherwise blackhole
// traffic after a failed policy change.
func (m *TrafficPolicyManager) restoreRuntimeFailOpen(policy trafficpolicy.Policy) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runtimeErr := m.writeRuntimePolicy(cleanupCtx, policy)
	cleanupErr := m.cleanupFirewall(cleanupCtx)
	return errors.Join(runtimeErr, cleanupErr)
}

func (m *TrafficPolicyManager) requireLocalPolicyOwnership(ctx context.Context) error {
	cloudOwned, ownershipErr := m.cloudPolicyOwnership()
	if !cloudOwned && ownershipErr == nil {
		return nil
	}
	cleanupErr := m.cleanupFirewall(ctx)
	if ownershipErr != nil {
		return errors.Join(fmt.Errorf("Fleet traffic policy ownership state is unsafe: %w", ownershipErr), cleanupErr)
	}
	return errors.Join(errors.New("traffic policy is managed by Fleet"), cleanupErr)
}

func (m *TrafficPolicyManager) reconcileOwnershipTransition(ctx context.Context, previouslySuppressed bool) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	coordination, err := policycoordination.Acquire(ctx, m.CoordinationLockPath)
	if err != nil {
		if previouslySuppressed {
			return true, err
		}
		return true, errors.Join(err, m.cleanupFirewall(ctx))
	}
	defer coordination.Release()
	cloudOwned, ownershipErr := m.cloudPolicyOwnership()
	suppressed := cloudOwned || ownershipErr != nil
	if suppressed == previouslySuppressed {
		return suppressed, ownershipErr
	}
	if suppressed {
		return true, errors.Join(ownershipErr, m.cleanupFirewall(ctx))
	}
	return false, m.reconcileLocalLocked(ctx)
}

func (m *TrafficPolicyManager) cloudPolicyOwnership() (bool, error) {
	if strings.TrimSpace(m.CloudPolicyStatusPath) == "" {
		return false, nil
	}
	data, err := readBoundedCloudPolicyStatus(m.CloudPolicyStatusPath, 64<<10)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var status trafficpolicy.Status
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&status); err != nil {
		return false, fmt.Errorf("decode Fleet traffic policy status: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return false, errors.New("Fleet traffic policy status must contain exactly one JSON value")
	}
	if status.SchemaVersion != trafficpolicy.SchemaVersion {
		return false, errors.New("unsupported Fleet traffic policy status schema")
	}
	return strings.TrimSpace(status.PolicyID) != "", nil
}

func readBoundedCloudPolicyStatus(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maximum {
		return nil, errors.New("Fleet traffic policy status is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, errors.New("Fleet traffic policy status changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, errors.New("Fleet traffic policy status exceeds size limit")
	}
	return data, nil
}

func (m *TrafficPolicyManager) preview(policy trafficpolicy.Policy) (gatewayprotocol.TrafficPolicyPreview, error) {
	normalized, err := trafficpolicy.Normalize(policy)
	if err != nil {
		return gatewayprotocol.TrafficPolicyPreview{}, err
	}
	digest, err := trafficpolicy.Digest(normalized)
	if err != nil {
		return gatewayprotocol.TrafficPolicyPreview{}, err
	}
	previewCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	context, required, err := m.activeRenderContext(previewCtx, normalized)
	if err != nil {
		return gatewayprotocol.TrafficPolicyPreview{}, err
	}
	rules := trafficpolicy.FirewallRules{FilterRules: []string{}, NATRules: []string{}}
	if required {
		rules, err = trafficpolicy.RenderFirewall(normalized, context)
		if err != nil {
			return gatewayprotocol.TrafficPolicyPreview{}, err
		}
	}
	changed := []string{"traffic policy state", m.RuntimePath}
	warnings := []string{
		"DoH blocking is catalog and evidence based; shared CDN, VPN, relay, ECH, and unknown endpoints may remain visible only as encrypted traffic.",
		"A failed pinned TLS handshake can only be bypassed on a subsequent client retry.",
	}
	if normalized.TLS.Enabled && !normalized.TLS.AllowQUIC {
		warnings = append(warnings, "QUIC (UDP 443) is blocked for decrypted clients so HTTP/3 apps fall back to HTTPS over TCP.")
	}
	if normalized.TLS.Enabled && !normalized.TLS.InterceptPrivateDestinations {
		warnings = append(warnings, "Connections to private, CGNAT and link-local destinations are not decrypted; LAN and IoT backends often use self-signed or mutual TLS.")
	}
	if len(rules.UnmatchedDevices) != 0 {
		warnings = append(warnings, fmt.Sprintf("%d device(s) with lab controls have no known MAC or IP address yet; their controls apply once they connect.", len(rules.UnmatchedDevices)))
	}
	if rules.NeedsNATHook || len(rules.FilterRules) != 0 {
		changed = append(changed, "iptables security chains")
	}
	if len(rules.FilterRulesIPv6) != 0 || len(rules.NATRulesIPv6) != 0 {
		changed = append(changed, "ip6tables security chains")
	}
	if rules.NeedsDNSService {
		changed = append(changed, "local DNS forwarder runtime policy")
	}
	if rules.NeedsMITMService {
		changed = append(changed, "mitmproxy runtime policy")
	}
	if rules.NeedsOnboarding {
		changed = append(changed, "lab-side CA onboarding page")
	}
	return gatewayprotocol.TrafficPolicyPreview{Policy: normalized, Digest: digest, Firewall: rules, ChangedObjects: changed, Warnings: warnings}, nil
}

func (m *TrafficPolicyManager) activeRenderContext(ctx context.Context, policy trafficpolicy.Policy) (trafficpolicy.RenderContext, bool, error) {
	needsLab := trafficpolicy.NeedsLabContext(policy)
	vpnSegment := m.vpnSegment()
	state := m.NetworkState.Get()
	lab, plan, ok := confirmedLabPlan(m.NetworkState)
	if !ok {
		// VPN devices get the same rules as lab devices, with or without a lab.
		if vpnSegment != nil {
			return trafficpolicy.RenderContext{VPN: vpnSegment, IPv6Listeners: m.ipv6ListenersReady(ctx, policy)}, true, nil
		}
		if !needsLab {
			return trafficpolicy.RenderContext{}, false, nil
		}
		if state.OperatingMode != gatewayprotocol.ModeRouted || state.activeNetworkPlan() == nil {
			return trafficpolicy.RenderContext{}, false, errors.New("active encrypted DNS, TLS or device controls require a confirmed routed network plan or VPN mode")
		}
		return trafficpolicy.RenderContext{}, false, errors.New("active traffic policy requires a configured IPv4 lab interface")
	}
	// A confirmed lab is always rendered, even for an observe-only policy,
	// so ShakerProxy answers DNS sent to its lab address.
	context := trafficpolicy.RenderContext{
		LabInterface:   lab.CurrentName,
		LabCIDR:        plan.IPv4.LabCIDR,
		LabGatewayIPv4: labGatewayIPv4(plan),
		Devices:        m.deviceMatches(ctx, policy, lab.CurrentName),
		VPN:            vpnSegment,
	}
	context.LabIPv6Prefix, context.LabGatewayIPv6 = labIPv6Context(plan)
	if _, device, bridged := networkplan.BridgePorts(plan); bridged {
		context.LabBridgePort = device.CurrentName
		context.LabBridgeIPv6 = networkplan.InlineBridgeIPv6Address(plan)
	}
	context.IPv6Listeners = m.ipv6ListenersReady(ctx, policy)
	return context, true, nil
}

// vpnSegment is the running VPN, or nil.
func (m *TrafficPolicyManager) vpnSegment() *trafficpolicy.Segment {
	if m.VPN == nil {
		return nil
	}
	return m.VPN()
}

func (m *TrafficPolicyManager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func (m *TrafficPolicyManager) warn(message string, err error) {
	if m.Logger != nil {
		m.Logger.Warn(message, "error", err)
	}
}

func (m *TrafficPolicyManager) log(message string, document trafficpolicy.Document) {
	if m.Logger != nil {
		m.Logger.Info(message, "revision", document.Policy.Revision, "digest", document.Digest, "encrypted_dns_mode", document.Policy.EncryptedDNS.Mode, "tls_interception", document.Policy.TLS.Enabled)
	}
}
