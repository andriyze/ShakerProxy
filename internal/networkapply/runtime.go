package networkapply

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

// Runtime state of a confirmed network plan.
//
// Netplan, Kea, hostapd and radvd configuration survive a reboot, but the
// forwarding, ICMP-redirect and router-advertisement sysctls and the ShakerProxy
// iptables/ip6tables chains and hooks are kernel state that a reboot erases.
// RuntimeRestorer re-establishes that state for a confirmed plan with the same
// fixed commands as the apply path. It is idempotent: ShakerProxy's chains are
// reloaded with restore (flush-and-refill semantics for ShakerProxy-owned chains
// only) and hooks are inserted only when missing.

// FirewallHook is one jump from a parent chain to a ShakerProxy-owned chain.
type FirewallHook struct {
	Table  string
	Parent string
	Chain  string
}

// RuntimeMachine performs the fixed runtime host operations. The OS
// implementation is OSRuntimeMachine.
type RuntimeMachine interface {
	LoadShakerProxyFirewall(context.Context, string, string) error
	LoadShakerProxyIPv6Firewall(context.Context, string, string) error
	EnsureOrderedHook(context.Context, string, FirewallHook) error
	SetIPv4Forwarding(context.Context, int) error
	SetIPv4SendRedirects(context.Context, string, int) error
	SetBridgeNFCallIPTables(context.Context, int) error
	SetIPv6AcceptRA(context.Context, string, int) error
	SetIPv6Forwarding(context.Context, int) error
	OwnedRuleCount(context.Context, string, string, string) (int, bool, error)
	HookPresent(context.Context, string, FirewallHook) (bool, error)
}

type RuntimeRestorer struct {
	Store    networktransaction.FileStore
	HostRoot string
	Machine  RuntimeMachine
}

// runtimeWork is the verified runtime state of one confirmed plan.
type runtimeWork struct {
	iptablesPath       string
	ipv4Restore        string
	ipv4Hooks          []FirewallHook
	redirectsInterface string
	bridgeNetfilter    bool
	ipv6               networktransaction.IPv6RollbackSpec
	ipv6Restore        string
	ipv6Hooks          []FirewallHook
}

// bind proves that the persisted preview still belongs to the confirmed plan
// before any of it is loaded: the plan hashes to its confirmed hash, and the
// preview, durable confirmation, watchdog manifest, and native syntax evidence
// all name that hash and those exact artifacts. Any mismatch fails closed.
func (r RuntimeRestorer) bind(staged networkplan.StagedPlan) (runtimeWork, error) {
	if r.Machine == nil || !filepath.IsAbs(r.HostRoot) {
		return runtimeWork{}, errors.New("runtime restore machine and absolute host root are required")
	}
	record := staged.Transaction
	if record == nil || record.Phase != networktransaction.PhaseConfirmed {
		return runtimeWork{}, errors.New("network plan is not confirmed")
	}
	if err := record.Validate(); err != nil {
		return runtimeWork{}, err
	}
	if staged.ApplyID != record.ApplyID || staged.PlanHash != record.PlanHash || !staged.Preview.Validation.Valid || staged.Preview.Validation.PlanHash != staged.PlanHash {
		return runtimeWork{}, errors.New("confirmed preview is not bound to the confirmed plan hash")
	}
	if networkplan.CanonicalPlanHash(staged.Plan) != staged.PlanHash {
		return runtimeWork{}, errors.New("persisted network plan no longer matches its confirmed hash")
	}
	manifest, err := r.Store.ReadManifest(staged.ApplyID)
	if err != nil {
		return runtimeWork{}, fmt.Errorf("read confirmed watchdog manifest: %w", err)
	}
	confirmation, err := r.Store.ReadConfirmation(staged.ApplyID)
	if err != nil {
		return runtimeWork{}, fmt.Errorf("read durable confirmation: %w", err)
	}
	if manifest.PlanHash != staged.PlanHash || confirmation.PlanHash != staged.PlanHash {
		return runtimeWork{}, errors.New("watchdog manifest or confirmation does not match the confirmed plan hash")
	}
	if manifest.Rollback.IptablesPath != staged.Preview.FirewallEnvironment.IptablesPath {
		return runtimeWork{}, errors.New("watchdog manifest does not match the confirmed firewall environment")
	}
	evidence, err := ReadEvidence(r.Store, staged.ApplyID)
	if err != nil {
		return runtimeWork{}, fmt.Errorf("read native syntax evidence: %w", err)
	}
	if staged.Preview.FirewallRestoreIPv4 == "" || evidence.FirewallSHA256 != digest(staged.Preview.FirewallRestoreIPv4) {
		return runtimeWork{}, errors.New("native syntax evidence does not match the confirmed IPv4 firewall")
	}
	if err := verifyIPv6Binding(staged, manifest, evidence); err != nil {
		return runtimeWork{}, err
	}
	work := runtimeWork{
		iptablesPath: manifest.Rollback.IptablesPath,
		ipv4Restore:  staged.Preview.FirewallRestoreIPv4,
		ipv4Hooks:    []FirewallHook{{Table: "filter", Parent: "DOCKER-USER", Chain: "SHAKERPROXY-FORWARD"}},
		ipv6:         manifest.Rollback.IPv6,
		ipv6Restore:  staged.Preview.FirewallRestoreIPv6,
	}
	if staged.Plan.IPv4.NAT44 {
		work.ipv4Hooks = append(work.ipv4Hooks, FirewallHook{Table: "nat", Parent: "POSTROUTING", Chain: "SHAKERPROXY-POSTROUTING"})
	}
	if staged.Plan.Topology == networkplan.TopologySingleArm {
		arm, ok := networkplan.WANInterface(staged.Plan)
		if !ok || !safeSysctlInterfaceName(arm.CurrentName) {
			return runtimeWork{}, errors.New("single-arm interface is unavailable for runtime restore")
		}
		work.redirectsInterface = arm.CurrentName
	}
	work.bridgeNetfilter = networkplan.InlineBridge(staged.Plan)
	if work.ipv6.Firewall != "" {
		work.ipv6Hooks = []FirewallHook{{Table: "filter", Parent: work.ipv6.ForwardParent, Chain: "SHAKERPROXY-FORWARD"}}
		if work.ipv6.Firewall == networktransaction.IPv6FirewallRoute {
			work.ipv6Hooks = append(work.ipv6Hooks, FirewallHook{Table: "filter", Parent: "INPUT", Chain: "SHAKERPROXY-INPUT"})
			if work.ipv6.NAT66 {
				work.ipv6Hooks = append(work.ipv6Hooks, FirewallHook{Table: "nat", Parent: "POSTROUTING", Chain: "SHAKERPROXY-POSTROUTING"})
			}
		}
	}
	return work, nil
}

// Restore re-establishes the runtime state of a confirmed plan. Each address
// family loads its ShakerProxy chains and hooks before its forwarding is enabled,
// so a failure leaves that family's forwarding off (fail closed). It stops at
// the first failure; callers retry.
func (r RuntimeRestorer) Restore(ctx context.Context, staged networkplan.StagedPlan) error {
	work, err := r.bind(staged)
	if err != nil {
		return err
	}
	if err := r.Machine.LoadShakerProxyFirewall(ctx, work.iptablesPath, work.ipv4Restore); err != nil {
		return fmt.Errorf("load ShakerProxy firewall batch: %w", err)
	}
	for _, hook := range work.ipv4Hooks {
		if err := r.Machine.EnsureOrderedHook(ctx, work.iptablesPath, hook); err != nil {
			return fmt.Errorf("attach ShakerProxy firewall chain %s: %w", hook.Chain, err)
		}
	}
	if work.bridgeNetfilter {
		if err := r.Machine.SetBridgeNFCallIPTables(ctx, 1); err != nil {
			return fmt.Errorf("enable bridge netfilter: %w", err)
		}
	}
	if err := r.Machine.SetIPv4Forwarding(ctx, 1); err != nil {
		return fmt.Errorf("enable IPv4 forwarding: %w", err)
	}
	if work.redirectsInterface != "" {
		if err := r.Machine.SetIPv4SendRedirects(ctx, work.redirectsInterface, 0); err != nil {
			return fmt.Errorf("disable IPv4 redirects on single-arm interface: %w", err)
		}
	}
	if work.ipv6.Firewall == "" {
		return nil
	}
	if err := r.Machine.LoadShakerProxyIPv6Firewall(ctx, work.ipv6.Ip6tablesPath, work.ipv6Restore); err != nil {
		return fmt.Errorf("load ShakerProxy IPv6 firewall batch: %w", err)
	}
	for _, hook := range work.ipv6Hooks {
		if err := r.Machine.EnsureOrderedHook(ctx, work.ipv6.Ip6tablesPath, hook); err != nil {
			return fmt.Errorf("attach ShakerProxy IPv6 firewall chain %s: %w", hook.Chain, err)
		}
	}
	if work.ipv6.Firewall != networktransaction.IPv6FirewallRoute {
		return nil
	}
	if work.ipv6.AcceptRAInterface != "" {
		if err := r.Machine.SetIPv6AcceptRA(ctx, work.ipv6.AcceptRAInterface, 2); err != nil {
			return fmt.Errorf("keep WAN router advertisements while forwarding: %w", err)
		}
	}
	if err := r.Machine.SetIPv6Forwarding(ctx, 1); err != nil {
		return fmt.Errorf("enable IPv6 forwarding: %w", err)
	}
	return nil
}

// Drift lists the runtime state of a confirmed plan that is missing, using
// only read-only commands and /proc. An empty list means the state is intact.
// Owned chains are compared by existence and rule count, which detects a
// reboot, a flushed table, or a lost hook without parsing iptables syntax.
func (r RuntimeRestorer) Drift(ctx context.Context, staged networkplan.StagedPlan) ([]string, error) {
	work, err := r.bind(staged)
	if err != nil {
		return nil, err
	}
	var drift []string
	checkFamily := func(binary, label, restore string, hooks []FirewallHook) error {
		for _, owned := range ownedChainRules(restore) {
			count, exists, err := r.Machine.OwnedRuleCount(ctx, binary, owned.table, owned.chain)
			if err != nil {
				return err
			}
			if !exists {
				drift = append(drift, fmt.Sprintf("%s chain %s is missing", label, owned.chain))
			} else if count != owned.rules {
				drift = append(drift, fmt.Sprintf("%s chain %s has %d of %d rules", label, owned.chain, count, owned.rules))
			}
		}
		for _, hook := range hooks {
			present, err := r.Machine.HookPresent(ctx, binary, hook)
			if err != nil {
				return err
			}
			if !present {
				drift = append(drift, fmt.Sprintf("%s hook %s -> %s is missing", label, hook.Parent, hook.Chain))
			}
		}
		return nil
	}
	if err := checkFamily(work.iptablesPath, "iptables", work.ipv4Restore, work.ipv4Hooks); err != nil {
		return nil, err
	}
	r.expectSysctl(&drift, "/proc/sys/net/ipv4/ip_forward", "1", "IPv4 forwarding is off")
	if work.bridgeNetfilter {
		r.expectSysctl(&drift, bridgeNFCallIPTablesPath, "1", "bridged traffic no longer passes through the firewall (bridge-nf-call-iptables is off)")
	}
	if work.redirectsInterface != "" {
		r.expectSysctl(&drift, "/proc/sys/net/ipv4/conf/"+work.redirectsInterface+"/send_redirects", "0", "IPv4 redirects are enabled on the single-arm interface")
	}
	if work.ipv6.Firewall != "" {
		if err := checkFamily(work.ipv6.Ip6tablesPath, "ip6tables", work.ipv6Restore, work.ipv6Hooks); err != nil {
			return nil, err
		}
	}
	if work.ipv6.Firewall == networktransaction.IPv6FirewallRoute {
		r.expectSysctl(&drift, "/proc/sys/net/ipv6/conf/all/forwarding", "1", "IPv6 forwarding is off")
		if work.ipv6.AcceptRAInterface != "" {
			r.expectSysctl(&drift, "/proc/sys/net/ipv6/conf/"+work.ipv6.AcceptRAInterface+"/accept_ra", "2", "the WAN no longer accepts router advertisements while forwarding")
		}
	}
	return drift, nil
}

func (r RuntimeRestorer) expectSysctl(drift *[]string, path, expected, message string) {
	raw, err := os.ReadFile(rootedPath(r.HostRoot, path))
	if err != nil || strings.TrimSpace(string(raw)) != expected {
		*drift = append(*drift, message)
	}
}

type ownedChain struct {
	table string
	chain string
	rules int
}

// ownedChainRules lists the ShakerProxy chains declared in a restore batch and how
// many rules each contains.
func ownedChainRules(restore string) []ownedChain {
	var chains []ownedChain
	index := map[string]int{}
	table := ""
	for _, line := range strings.Split(restore, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "*"):
			table = strings.TrimPrefix(line, "*")
		case strings.HasPrefix(line, ":"):
			fields := strings.Fields(strings.TrimPrefix(line, ":"))
			if len(fields) == 0 {
				continue
			}
			index[table+"\x00"+fields[0]] = len(chains)
			chains = append(chains, ownedChain{table: table, chain: fields[0]})
		case strings.HasPrefix(line, "-A "):
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			if position, ok := index[table+"\x00"+fields[1]]; ok {
				chains[position].rules++
			}
		}
	}
	return chains
}

// maxHookPosition bounds the ordered insert position of a ShakerProxy hook.
const maxHookPosition = 64

// securityChainFor names the traffic-policy chain that must stay in front of
// ShakerProxy's hook in a parent chain, so per-device blocks and encrypted-DNS
// drops are evaluated before ShakerProxy's lab-to-WAN accept rules.
func securityChainFor(parent string) string {
	switch parent {
	case "DOCKER-USER", "FORWARD":
		return "SHAKERPROXY-SEC-FORWARD"
	case "INPUT":
		return "SHAKERPROXY-SEC-INPUT"
	}
	return ""
}

// hookInsertPosition returns the 1-based position for a ShakerProxy hook in the
// parent listing (iptables -S output): directly below the traffic-policy
// security hook when it is present, otherwise first.
func hookInsertPosition(listing, parent string) int {
	security := securityChainFor(parent)
	if security == "" {
		return 1
	}
	position := 0
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "-A" || fields[1] != parent {
			continue
		}
		position++
		if strings.Join(fields, " ") == "-A "+parent+" -j "+security {
			return position + 1
		}
	}
	return 1
}

// OSRuntimeMachine runs the runtime restore through the apply path's fixed
// commands; hook inspection and ordered insertion use allowedRuntimeCommand.
type OSRuntimeMachine struct {
	run func(context.Context, string, []string) (string, rollbackCommandResult, error)
}

func (m OSRuntimeMachine) command(ctx context.Context, path string, arguments []string) (string, rollbackCommandResult, error) {
	if !allowedRuntimeCommand(path, arguments) {
		return "", rollbackCommandResult{}, errors.New("runtime firewall command is not allowlisted")
	}
	if m.run != nil {
		return m.run(ctx, path, arguments)
	}
	return execFixedCommand(ctx, path, arguments, "")
}

func (OSRuntimeMachine) LoadShakerProxyFirewall(ctx context.Context, iptablesPath, restore string) error {
	return (OSApplyMachine{}).LoadShakerProxyFirewall(ctx, iptablesPath, restore)
}

func (OSRuntimeMachine) LoadShakerProxyIPv6Firewall(ctx context.Context, ip6tablesPath, restore string) error {
	return (OSIPv6Machine{}).LoadShakerProxyIPv6Firewall(ctx, ip6tablesPath, restore)
}

func (OSRuntimeMachine) SetIPv4Forwarding(ctx context.Context, value int) error {
	return (OSRollbackMachine{}).SetIPv4Forwarding(ctx, value)
}

func (OSRuntimeMachine) SetIPv4SendRedirects(ctx context.Context, interfaceName string, value int) error {
	return (OSRollbackMachine{}).SetIPv4SendRedirects(ctx, interfaceName, value)
}

func (OSRuntimeMachine) SetBridgeNFCallIPTables(ctx context.Context, value int) error {
	return (OSRollbackMachine{}).SetBridgeNFCallIPTables(ctx, value)
}

func (OSRuntimeMachine) SetIPv6AcceptRA(ctx context.Context, interfaceName string, value int) error {
	return (OSIPv6Machine{}).SetIPv6AcceptRA(ctx, interfaceName, value)
}

func (OSRuntimeMachine) SetIPv6Forwarding(ctx context.Context, value int) error {
	return (OSIPv6Machine{}).SetIPv6Forwarding(ctx, value)
}

func (m OSRuntimeMachine) OwnedRuleCount(ctx context.Context, binary, table, chain string) (int, bool, error) {
	stdout, result, err := m.command(ctx, binary, tableArguments(table, "-S", chain))
	if err != nil {
		return 0, false, err
	}
	switch result.exitCode {
	case 0:
	case 1:
		return 0, false, nil
	default:
		return 0, false, commandResultError("inspect owned firewall chain", result, nil)
	}
	count := 0
	for _, line := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "-A "+chain+" ") {
			count++
		}
	}
	return count, true, nil
}

func (m OSRuntimeMachine) HookPresent(ctx context.Context, binary string, hook FirewallHook) (bool, error) {
	_, result, err := m.command(ctx, binary, tableArguments(hook.Table, "-C", hook.Parent, "-j", hook.Chain))
	if err != nil {
		return false, err
	}
	switch result.exitCode {
	case 0:
		return true, nil
	case 1:
		return false, nil
	default:
		return false, commandResultError("inspect firewall attachment", result, nil)
	}
}

// EnsureOrderedHook inserts a missing ShakerProxy hook directly below the
// traffic-policy security hook (or first when it is absent). An existing hook
// is left where it is, so repeated runs never duplicate or reorder hooks.
func (m OSRuntimeMachine) EnsureOrderedHook(ctx context.Context, binary string, hook FirewallHook) error {
	present, err := m.HookPresent(ctx, binary, hook)
	if err != nil || present {
		return err
	}
	listing, result, err := m.command(ctx, binary, tableArguments(hook.Table, "-S", hook.Parent))
	if err != nil || result.exitCode != 0 {
		return commandResultError("list firewall parent chain", result, err)
	}
	position := hookInsertPosition(listing, hook.Parent)
	if position > maxHookPosition {
		return errors.New("the traffic-policy hook is too far down the parent chain")
	}
	_, result, err = m.command(ctx, binary, tableArguments(hook.Table, "-I", hook.Parent, strconv.Itoa(position), "-j", hook.Chain))
	if err != nil || result.exitCode != 0 {
		return commandResultError("insert firewall attachment", result, err)
	}
	return nil
}

var runtimeHooks = []FirewallHook{
	{Table: "filter", Parent: "DOCKER-USER", Chain: "SHAKERPROXY-FORWARD"},
	{Table: "filter", Parent: "FORWARD", Chain: "SHAKERPROXY-FORWARD"},
	{Table: "filter", Parent: "INPUT", Chain: "SHAKERPROXY-INPUT"},
	{Table: "nat", Parent: "POSTROUTING", Chain: "SHAKERPROXY-POSTROUTING"},
}

// allowedRuntimeCommand permits read-only listings of ShakerProxy chains and of
// their parent chains, hook checks, and hook inserts at a bounded position.
// Nothing here can flush, delete, or change another owner's rules.
func allowedRuntimeCommand(path string, arguments []string) bool {
	switch path {
	case "/usr/sbin/iptables", "/usr/bin/iptables", "/usr/sbin/ip6tables", "/usr/bin/ip6tables":
	default:
		return false
	}
	joined := strings.Join(arguments, "\x00")
	for _, hook := range runtimeHooks {
		for _, allowed := range [][]string{
			tableArguments(hook.Table, "-S", hook.Chain),
			tableArguments(hook.Table, "-S", hook.Parent),
			tableArguments(hook.Table, "-C", hook.Parent, "-j", hook.Chain),
		} {
			if joined == strings.Join(allowed, "\x00") {
				return true
			}
		}
		for position := 1; position <= maxHookPosition; position++ {
			if joined == strings.Join(tableArguments(hook.Table, "-I", hook.Parent, strconv.Itoa(position), "-j", hook.Chain), "\x00") {
				return true
			}
		}
	}
	return false
}
