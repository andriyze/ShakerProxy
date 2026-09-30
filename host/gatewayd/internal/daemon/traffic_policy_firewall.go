package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

const (
	securityForwardChain    = "SHAKERPROXY-SEC-FORWARD"
	securityInputChain      = "SHAKERPROXY-SEC-INPUT"
	securityPreroutingChain = "SHAKERPROXY-SEC-PREROUTING"

	iptablesBinary         = "/usr/sbin/iptables"
	iptablesRestoreBinary  = "/usr/sbin/iptables-restore"
	ip6tablesBinary        = "/usr/sbin/ip6tables"
	ip6tablesRestoreBinary = "/usr/sbin/ip6tables-restore"
)

type trafficCommandRunner interface {
	Run(context.Context, string, []string, []byte) ([]byte, error)
}

type execTrafficCommandRunner struct{}

func (execTrafficCommandRunner) Run(ctx context.Context, executable string, arguments []string, stdin []byte) ([]byte, error) {
	switch executable {
	case iptablesBinary, iptablesRestoreBinary, ip6tablesBinary, ip6tablesRestoreBinary, "/usr/bin/ip6tables", "/usr/bin/ip6tables-restore":
	default:
		return nil, errors.New("traffic policy command is not allowlisted")
	}
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
	if len(stdin) != 0 {
		command.Stdin = bytes.NewReader(stdin)
	}
	output, err := command.CombinedOutput()
	if len(output) > 64<<10 {
		output = output[:64<<10]
	}
	if err != nil {
		return output, fmt.Errorf("fixed traffic policy command failed: %w", err)
	}
	return output, nil
}

type firewallFamily struct {
	ipv6    bool
	command string
	restore string
	// forwardParent is where the security forward chain hangs; "" means
	// "decide from the live ruleset" (IPv6 without a confirmed inspection).
	forwardParent string
}

var firewallIPv4 = firewallFamily{command: iptablesBinary, restore: iptablesRestoreBinary, forwardParent: "DOCKER-USER"}

// ipv6Family uses the ip6tables executable and forward parent the confirmed
// network plan recorded, so the security chain hangs where ShakerProxy's own IPv6
// forward chain does and can be kept in front of it.
func (m *TrafficPolicyManager) ipv6Family() firewallFamily {
	family := firewallFamily{ipv6: true, command: ip6tablesBinary, restore: ip6tablesRestoreBinary}
	if m.NetworkState == nil {
		return family
	}
	staged := m.NetworkState.Get().activeNetworkPlan()
	if staged == nil {
		return family
	}
	environment := staged.Preview.FirewallEnvironment
	switch environment.Ip6tablesPath {
	case "/usr/sbin/ip6tables", "/usr/bin/ip6tables":
		family.command = environment.Ip6tablesPath
		family.restore = environment.Ip6tablesPath + "-restore"
		family.forwardParent = networkplan.IPv6ForwardParent(environment)
	}
	return family
}

func (m *TrafficPolicyManager) applyFirewall(ctx context.Context, policy trafficpolicy.Policy, probe bool) error {
	renderContext, _, err := m.activeRenderContext(ctx, policy)
	if err != nil {
		return err
	}
	rules, err := trafficpolicy.RenderFirewall(policy, renderContext)
	if err != nil {
		return err
	}
	if probe {
		if rules.NeedsDNSService {
			if err := m.probe(ctx, policy.EncryptedDNS.LocalListenPort); err != nil {
				return fmt.Errorf("local DNS forwarder is not ready: %w", err)
			}
		}
		if rules.NeedsMITMService {
			if err := m.probe(ctx, policy.TLS.TransparentPort); err != nil {
				return fmt.Errorf("TLS interception service is not ready: %w", err)
			}
		}
	}
	if err := m.applyFamily(ctx, firewallIPv4, rules.FilterRules, rules.NATRules); err != nil {
		return err
	}
	if m.ipv6Available() {
		family := m.ipv6Family()
		if err := m.applyFamily(ctx, family, rules.FilterRulesIPv6, rules.NATRulesIPv6); err != nil {
			var natErr *natRedirectError
			if !errors.As(err, &natErr) {
				return fmt.Errorf("apply IPv6 traffic policy: %w", err)
			}
			// IPv6 blocks and listener protection are in place; only the
			// IPv6 redirects are missing, so IPv6 traffic is simply not
			// intercepted. That must not tear down the IPv4 policy.
			m.warnOnce("ipv6-nat", "IPv6 redirects could not be installed; IPv6 traffic is not intercepted", err)
			_ = m.setJumpWith(ctx, family.command, "nat", "PREROUTING", securityPreroutingChain, false)
		} else {
			m.clearWarning("ipv6-nat")
		}
	}
	m.publishOnboarding(renderContext, rules.NeedsOnboarding)
	return nil
}

// natRedirectError marks a failure confined to the NAT (redirect) half of a
// family's policy, after its filter rules and hooks were installed.
type natRedirectError struct{ err error }

func (e *natRedirectError) Error() string { return e.err.Error() }
func (e *natRedirectError) Unwrap() error { return e.err }

// applyFamily installs the filter half first (listener protection, blocks)
// and attaches its hooks ahead of ShakerProxy's own hooks, then the NAT half.
// A failure in the NAT half can therefore never leave the listeners exposed.
func (m *TrafficPolicyManager) applyFamily(ctx context.Context, family firewallFamily, filter, nat []string) error {
	if _, err := m.Runner.Run(ctx, family.restore, []string{"--noflush"}, []byte(renderFilterRestore(filter))); err != nil {
		return err
	}
	if err := m.setHook(ctx, family.command, "INPUT", securityInputChain, "SHAKERPROXY-INPUT", hasRuleForChain(filter, "SHAKERPROXY-INPUT")); err != nil {
		return err
	}
	if err := m.setForwardJump(ctx, family, hasRuleForChain(filter, "SHAKERPROXY-FORWARD")); err != nil {
		return err
	}
	if _, err := m.Runner.Run(ctx, family.restore, []string{"--noflush"}, []byte(renderNATRestore(nat))); err != nil {
		return &natRedirectError{err: err}
	}
	if err := m.setJumpWith(ctx, family.command, "nat", "PREROUTING", securityPreroutingChain, len(nat) != 0); err != nil {
		return &natRedirectError{err: err}
	}
	return nil
}

// setForwardJump attaches the security forward chain where Docker cannot
// reorder it and where ShakerProxy's forward chain hangs: DOCKER-USER for IPv4;
// for IPv6 the parent the confirmed plan recorded, else DOCKER-USER when
// Docker manages ip6tables, else FORWARD. It is detached from the other one.
func (m *TrafficPolicyManager) setForwardJump(ctx context.Context, family firewallFamily, enabled bool) error {
	parent := family.forwardParent
	if parent == "" {
		parent = "FORWARD"
		if m.chainExists(ctx, family.command, "filter", "DOCKER-USER") {
			parent = "DOCKER-USER"
		}
	}
	if family.ipv6 {
		other := "DOCKER-USER"
		if parent == "DOCKER-USER" {
			other = "FORWARD"
		}
		if other == "FORWARD" || m.chainExists(ctx, family.command, "filter", other) {
			if err := m.setJumpWith(ctx, family.command, "filter", other, securityForwardChain, false); err != nil {
				return err
			}
		}
	}
	return m.setHook(ctx, family.command, parent, securityForwardChain, "SHAKERPROXY-FORWARD", enabled)
}

// setHook attaches or detaches a security hook in a filter parent chain and
// keeps an attached hook above ShakerProxy's own hook there: the network restorer
// inserts ShakerProxy's hook directly below ours, but if ours ended up below it
// (for example after a restart order race), per-device blocks and
// encrypted-DNS drops would be bypassed by ShakerProxy's accept rules.
func (m *TrafficPolicyManager) setHook(ctx context.Context, command, parent, child, shakerproxyChain string, enabled bool) error {
	if err := m.setJumpWith(ctx, command, "filter", parent, child, enabled); err != nil || !enabled {
		return err
	}
	listing, err := m.Runner.Run(ctx, command, []string{"-w", "5", "-S", parent}, nil)
	if err != nil {
		return nil // hook present; ordering cannot be inspected, retried next reconcile
	}
	ours, theirs := hookPosition(string(listing), parent, child), hookPosition(string(listing), parent, shakerproxyChain)
	if ours == 0 || theirs == 0 || ours < theirs {
		return nil
	}
	if err := m.setJumpWith(ctx, command, "filter", parent, child, false); err != nil {
		return err
	}
	_, err = m.Runner.Run(ctx, command, []string{"-w", "5", "-I", parent, "1", "-j", child}, nil)
	return err
}

// hookPosition returns the 1-based position of "-A parent -j chain" in an
// iptables -S listing, or 0 when absent.
func hookPosition(listing, parent, chain string) int {
	position := 0
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "-A" || fields[1] != parent {
			continue
		}
		position++
		if strings.Join(fields, " ") == "-A "+parent+" -j "+chain {
			return position
		}
	}
	return 0
}

// cleanupFirewall removes interception and blocking from the packet path while
// retaining loopback-only access to, and global isolation of, the local DNS,
// MITM and onboarding listeners for both address families. This is the
// fail-open state for client traffic, not an invitation to expose proxy
// listeners on WAN or management interfaces.
func (m *TrafficPolicyManager) cleanupFirewall(ctx context.Context) error {
	ipv4Err, ipv6Err := m.cleanupFirewallFamilies(ctx)
	return errors.Join(ipv4Err, ipv6Err)
}

// cleanupFirewallFamilies reports each family separately so startup can
// survive an IPv6-only failure (retried by every reconcile) while emergency
// bypass and policy failures still surface it.
func (m *TrafficPolicyManager) cleanupFirewallFamilies(ctx context.Context) (error, error) {
	m.publishOnboarding(trafficpolicy.RenderContext{}, false)
	baseline := trafficpolicy.DefaultPolicy()
	rules, err := trafficpolicy.RenderFirewall(baseline, trafficpolicy.RenderContext{})
	if err != nil {
		return err, nil
	}
	ipv4Err := m.cleanupFamily(ctx, firewallIPv4, rules.FilterRules)
	var ipv6Err error
	if m.ipv6Available() {
		if err := m.cleanupFamily(ctx, m.ipv6Family(), rules.FilterRulesIPv6); err != nil {
			ipv6Err = fmt.Errorf("IPv6 traffic policy cleanup: %w", err)
		}
	}
	return ipv4Err, ipv6Err
}

// cleanupFamily installs the listener protection before anything else, then
// detaches every client hook. Flushing the detached redirect chain is only
// housekeeping.
func (m *TrafficPolicyManager) cleanupFamily(ctx context.Context, family firewallFamily, filter []string) error {
	if _, err := m.Runner.Run(ctx, family.restore, []string{"--noflush"}, []byte(renderFilterRestore(filter))); err != nil {
		return err
	}
	if err := m.setHook(ctx, family.command, "INPUT", securityInputChain, "SHAKERPROXY-INPUT", true); err != nil {
		return err
	}
	if err := m.setForwardJump(ctx, family, false); err != nil {
		return err
	}
	if err := m.setJumpWith(ctx, family.command, "nat", "PREROUTING", securityPreroutingChain, false); err != nil {
		return err
	}
	_, _ = m.Runner.Run(ctx, family.restore, []string{"--noflush"}, []byte(renderNATRestore(nil)))
	return nil
}

func renderSecurityRestore(rules trafficpolicy.FirewallRules) string {
	return renderSecurityRestoreBatch(rules.FilterRules, rules.NATRules)
}

func renderSecurityRestoreBatch(filter, nat []string) string {
	return renderFilterRestore(filter) + renderNATRestore(nat)
}

func renderFilterRestore(filter []string) string {
	var builder strings.Builder
	builder.WriteString("*filter\n:")
	builder.WriteString(securityForwardChain)
	builder.WriteString(" - [0:0]\n-F ")
	builder.WriteString(securityForwardChain)
	builder.WriteString("\n:")
	builder.WriteString(securityInputChain)
	builder.WriteString(" - [0:0]\n-F ")
	builder.WriteString(securityInputChain)
	builder.WriteByte('\n')
	for _, rule := range filter {
		rule = strings.ReplaceAll(rule, "SHAKERPROXY-FORWARD", securityForwardChain)
		rule = strings.ReplaceAll(rule, "SHAKERPROXY-INPUT", securityInputChain)
		builder.WriteString(rule)
		builder.WriteByte('\n')
	}
	fmt.Fprintf(&builder, "-A %s -j RETURN\n-A %s -j RETURN\nCOMMIT\n", securityForwardChain, securityInputChain)
	return builder.String()
}

func renderNATRestore(nat []string) string {
	var builder strings.Builder
	builder.WriteString("*nat\n:")
	builder.WriteString(securityPreroutingChain)
	builder.WriteString(" - [0:0]\n-F ")
	builder.WriteString(securityPreroutingChain)
	builder.WriteByte('\n')
	for _, rule := range nat {
		rule = strings.ReplaceAll(rule, "SHAKERPROXY-PREROUTING", securityPreroutingChain)
		builder.WriteString(rule)
		builder.WriteByte('\n')
	}
	fmt.Fprintf(&builder, "-A %s -j RETURN\nCOMMIT\n", securityPreroutingChain)
	return builder.String()
}

func hasRuleForChain(rules []string, chain string) bool {
	return trafficpolicy.HasRuleForChain(rules, chain)
}

func (m *TrafficPolicyManager) setJump(ctx context.Context, table, parent, child string, enabled bool) error {
	return m.setJumpWith(ctx, iptablesBinary, table, parent, child, enabled)
}

func (m *TrafficPolicyManager) setJumpWith(ctx context.Context, command, table, parent, child string, enabled bool) error {
	arguments := []string{"-w", "5"}
	if table != "filter" {
		arguments = append(arguments, "-t", table)
	}
	check := append(append([]string{}, arguments...), "-C", parent, "-j", child)
	_, checkErr := m.Runner.Run(ctx, command, check, nil)
	if enabled {
		if checkErr == nil {
			return nil
		}
		insert := append(append([]string{}, arguments...), "-I", parent, "1", "-j", child)
		_, err := m.Runner.Run(ctx, command, insert, nil)
		return err
	}
	for removed := 0; checkErr == nil; removed++ {
		if removed >= 64 {
			return errors.New("traffic policy contains too many duplicate jumps")
		}
		remove := append(append([]string{}, arguments...), "-D", parent, "-j", child)
		if _, err := m.Runner.Run(ctx, command, remove, nil); err != nil {
			return err
		}
		_, checkErr = m.Runner.Run(ctx, command, check, nil)
	}
	return nil
}

func (m *TrafficPolicyManager) chainExists(ctx context.Context, command, table, chain string) bool {
	arguments := []string{"-w", "5"}
	if table != "filter" {
		arguments = append(arguments, "-t", table)
	}
	_, err := m.Runner.Run(ctx, command, append(arguments, "-n", "-L", chain), nil)
	return err == nil
}

// ipv6Available is false on kernels booted with IPv6 disabled; there is then
// nothing to protect or redirect and ip6tables cannot run.
func (m *TrafficPolicyManager) ipv6Available() bool {
	if m.IPv6Available != nil {
		return m.IPv6Available()
	}
	return false
}

func hostIPv6Available() bool {
	_, err := os.Stat("/proc/net/if_inet6")
	return err == nil
}

func (m *TrafficPolicyManager) writeRuntimePolicy(ctx context.Context, policy trafficpolicy.Policy) error {
	matches := map[string]trafficpolicy.DeviceMatch{}
	var labSources []string
	if lab, plan, ok := confirmedLabPlan(m.NetworkState); ok {
		matches = m.deviceMatches(ctx, policy, lab.CurrentName)
		if prefix, err := netip.ParsePrefix(plan.IPv4.LabCIDR); err == nil {
			labSources = append(labSources, prefix.Masked().String())
		}
		if prefix, _ := labIPv6Context(plan); prefix != "" {
			labSources = append(labSources, prefix)
		}
	}
	runtimePolicy, err := trafficpolicy.ProjectStandaloneProxyRuntimeWithIdentity(policy, trafficpolicy.LoadStandaloneDevicesBestEffort(), matches)
	if err != nil {
		return err
	}
	runtimePolicy.LabSources = labSources
	encoded, err := trafficpolicy.EncodeStandaloneProxyRuntime(runtimePolicy)
	if err != nil {
		return err
	}
	return writePublicFile(m.RuntimePath, encoded, ".traffic-runtime-*")
}

// writePublicFile atomically replaces a world-readable, secret-free runtime
// projection.
func writePublicFile(path string, encoded []byte, pattern string) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, pattern)
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	if dir, err := os.Open(directory); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func (m *TrafficPolicyManager) probe(ctx context.Context, port int) error {
	if m.Probe == nil {
		return errors.New("traffic listener probe is unavailable")
	}
	return m.Probe(ctx, port)
}

func probeTrafficListener(ctx context.Context, port int) error {
	return probeListener(ctx, "127.0.0.1", port)
}

func probeTrafficListenerIPv6(ctx context.Context, port int) error {
	return probeListener(ctx, "::1", port)
}

func probeListener(ctx context.Context, host string, port int) error {
	dialer := net.Dialer{Timeout: 2 * time.Second}
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return err
	}
	return connection.Close()
}

// warnOnce logs a recurring condition once until clearWarning resets it, so
// the 15-second reconciler does not flood the journal.
func (m *TrafficPolicyManager) warnOnce(key, message string, err error) {
	m.warningsMu.Lock()
	defer m.warningsMu.Unlock()
	if m.warnings == nil {
		m.warnings = map[string]string{}
	}
	text := err.Error()
	if m.warnings[key] == text {
		return
	}
	m.warnings[key] = text
	m.warn(message, err)
}

func (m *TrafficPolicyManager) clearWarning(key string) {
	m.warningsMu.Lock()
	defer m.warningsMu.Unlock()
	delete(m.warnings, key)
}
