package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

type trafficCommandCall struct {
	executable string
	arguments  []string
	stdin      string
}

type fakeTrafficRunner struct {
	mu     sync.Mutex
	calls  []trafficCommandCall
	jumps  map[string]bool
	chains map[string]bool
	// order keeps each parent chain's jumps in position order ("6:" prefix
	// for ip6tables) so hook placement can be asserted.
	order map[string][]string
	// failRestore, when set, can fail a restore batch.
	failRestore func(executable, stdin string) error
	// contents holds the rules restore batches loaded into declared chains
	// ("6:" prefix for ip6tables), which -S lists like iptables does.
	contents map[string][]string
}

// loadLocked applies a restore batch's chain declarations, flushes and
// appends to contents.
func (r *fakeTrafficRunner) loadLocked(executable, batch string) {
	if r.contents == nil {
		r.contents = map[string][]string{}
	}
	prefix := ""
	if strings.Contains(executable, "ip6tables") {
		prefix = "6:"
	}
	for _, line := range strings.Split(batch, "\n") {
		fields := strings.Fields(line)
		switch {
		case len(fields) == 0:
		case strings.HasPrefix(fields[0], ":"):
			chain := strings.TrimPrefix(fields[0], ":")
			if _, exists := r.contents[prefix+chain]; !exists {
				r.contents[prefix+chain] = []string{}
			}
		case fields[0] == "-F" && len(fields) > 1:
			r.contents[prefix+fields[1]] = []string{}
		case fields[0] == "-A" && len(fields) > 1:
			r.contents[prefix+fields[1]] = append(r.contents[prefix+fields[1]], line)
		}
	}
}

// flush simulates another tool emptying a chain.
func (r *fakeTrafficRunner) flush(prefix, chain string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.contents[prefix+chain] = []string{}
}

// restores counts the restore batches sent so far.
func (r *fakeTrafficRunner) restores() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for _, call := range r.calls {
		if strings.HasSuffix(call.executable, "tables-restore") {
			count++
		}
	}
	return count
}

// lastRestore returns the most recent filter batch followed by the most
// recent NAT batch sent to executable.
func (r *fakeTrafficRunner) lastRestore(executable string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	filter, nat := "", ""
	for index := len(r.calls) - 1; index >= 0; index-- {
		call := r.calls[index]
		if call.executable != executable {
			continue
		}
		if filter == "" && strings.HasPrefix(call.stdin, "*filter") {
			filter = call.stdin
		}
		if nat == "" && strings.HasPrefix(call.stdin, "*nat") {
			nat = call.stdin
		}
	}
	return filter + nat
}

// attach simulates another owner inserting a jump at a position.
func (r *fakeTrafficRunner) attach(prefix, parent, child string, position int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.insertLocked(prefix, parent, child, position)
}

func (r *fakeTrafficRunner) insertLocked(prefix, parent, child string, position int) {
	if r.jumps == nil {
		r.jumps = map[string]bool{}
	}
	if r.order == nil {
		r.order = map[string][]string{}
	}
	list := r.order[prefix+parent]
	if position < 1 || position > len(list)+1 {
		position = len(list) + 1
	}
	list = append(list[:position-1], append([]string{child}, list[position-1:]...)...)
	r.order[prefix+parent] = list
	r.jumps[prefix+parent+"->"+child] = true
}

func (r *fakeTrafficRunner) positions(prefix, parent string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.order[prefix+parent]...)
}

func (r *fakeTrafficRunner) Run(_ context.Context, executable string, arguments []string, stdin []byte) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.jumps == nil {
		r.jumps = map[string]bool{}
	}
	call := trafficCommandCall{executable: executable, arguments: append([]string(nil), arguments...), stdin: string(stdin)}
	r.calls = append(r.calls, call)
	if strings.HasSuffix(executable, "tables-restore") {
		if r.failRestore != nil {
			if err := r.failRestore(executable, string(stdin)); err != nil {
				return nil, err
			}
		}
		r.loadLocked(executable, string(stdin))
		return nil, nil
	}
	prefix := ""
	switch executable {
	case "/usr/sbin/iptables":
	case "/usr/sbin/ip6tables", "/usr/bin/ip6tables":
		prefix = "6:"
	default:
		return nil, errors.New("unexpected executable")
	}
	for index, value := range arguments {
		if value == "-L" && index+1 < len(arguments) {
			if r.chains[prefix+arguments[index+1]] {
				return nil, nil
			}
			return nil, errors.New("chain absent")
		}
		if value == "-S" && index+1 < len(arguments) {
			parent := arguments[index+1]
			if rules, loaded := r.contents[prefix+parent]; loaded {
				return []byte(strings.Join(append([]string{"-N " + parent}, rules...), "\n") + "\n"), nil
			}
			var listing strings.Builder
			for _, child := range r.order[prefix+parent] {
				fmt.Fprintf(&listing, "-A %s -j %s\n", parent, child)
			}
			return []byte(listing.String()), nil
		}
	}
	operation, parent, child := trafficJump(arguments)
	if operation == "" {
		return nil, errors.New("unexpected iptables arguments")
	}
	key := prefix + parent + "->" + child
	switch operation {
	case "-C":
		if r.jumps[key] {
			return nil, nil
		}
		return nil, errors.New("rule absent")
	case "-I":
		position := 1
		for index, value := range arguments {
			if value == "-I" && index+2 < len(arguments) && arguments[index+2] != "-j" {
				fmt.Sscanf(arguments[index+2], "%d", &position)
			}
		}
		r.insertLocked(prefix, parent, child, position)
		return nil, nil
	case "-D":
		if !r.jumps[key] {
			return nil, errors.New("rule absent")
		}
		delete(r.jumps, key)
		list := r.order[prefix+parent]
		for index, existing := range list {
			if existing == child {
				r.order[prefix+parent] = append(list[:index], list[index+1:]...)
				break
			}
		}
		return nil, nil
	default:
		return nil, errors.New("unexpected operation")
	}
}

func trafficJump(arguments []string) (string, string, string) {
	for index, value := range arguments {
		if value != "-C" && value != "-I" && value != "-D" {
			continue
		}
		if index+1 >= len(arguments) {
			return "", "", ""
		}
		parent := arguments[index+1]
		for next := index + 2; next+1 < len(arguments); next++ {
			if arguments[next] == "-j" {
				return value, parent, arguments[next+1]
			}
		}
	}
	return "", "", ""
}

func routedTrafficState() *StateStore {
	record := &networktransaction.Record{Phase: networktransaction.PhaseConfirmed}
	return &StateStore{state: persistedState{
		OperatingMode: gatewayprotocol.ModeRouted,
		StagedNetworkPlan: &networkplan.StagedPlan{
			Plan: networkplan.Plan{
				IPv4:       networkplan.IPv4Configuration{Enabled: true, LabCIDR: "10.77.0.0/24"},
				Interfaces: []networkplan.Interface{{CurrentName: "lab0", Role: networkplan.RoleLab}},
			},
			Transaction: record,
		},
	}}
}

func TestTrafficPolicyManagerAppliesOnlyFixedFirewallCommands(t *testing.T) {
	root := t.TempDir()
	runner := &fakeTrafficRunner{}
	manager := &TrafficPolicyManager{
		NetworkState: routedTrafficState(),
		PolicyStore:  &trafficpolicy.Store{Path: filepath.Join(root, "policy.json")},
		RuntimePath:  filepath.Join(root, "runtime", "policy.json"),
		Runner:       runner,
		Probe:        func(context.Context, int) error { return nil },
	}
	if err := manager.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	policy := trafficpolicy.DefaultPolicy()
	policy.Revision = 2
	policy.Name = "Encrypted DNS and TLS"
	policy.EncryptedDNS.Mode = trafficpolicy.EncryptedDNSEnforceLocal
	policy.EncryptedDNS.RedirectPlainDNS = true
	policy.EncryptedDNS.UpstreamServers = []string{"1.1.1.1:53"}
	policy.EncryptedDNS.BlockDoT = true
	policy.EncryptedDNS.BlockDoQ = true
	policy.EncryptedDNS.BlockKnownDoH = true
	policy.EncryptedDNS.BlockKnownDoH3 = true
	policy.TLS.Enabled = true
	policy.TLS.ExcludeCIDRs = []string{"192.0.2.0/24"}
	if _, err := manager.Apply(t.Context(), policy, 1); err != nil {
		t.Fatal(err)
	}

	runner.mu.Lock()
	defer runner.mu.Unlock()
	var restore string
	for _, call := range runner.calls {
		if call.executable != "/usr/sbin/iptables" && call.executable != "/usr/sbin/iptables-restore" {
			t.Fatalf("unexpected executable %q", call.executable)
		}
		if call.executable == "/usr/sbin/iptables-restore" {
			restore += call.stdin
		}
	}
	for _, expected := range []string{
		"-F SHAKERPROXY-SEC-FORWARD",
		"--dport 853",
		"--dport 53 -j REDIRECT --to-ports 1053",
		"--dport 443 -j REDIRECT --to-ports 8085",
		"-d 192.0.2.0/24",
	} {
		if !strings.Contains(restore, expected) {
			t.Fatalf("restore batch lacks %q:\n%s", expected, restore)
		}
	}
	if !runner.jumps["DOCKER-USER->"+securityForwardChain] || !runner.jumps["INPUT->"+securityInputChain] || !runner.jumps["PREROUTING->"+securityPreroutingChain] {
		t.Fatalf("expected security jumps were not attached: %#v", runner.jumps)
	}
}

func dnsRedirectPolicyManager(t *testing.T) (*TrafficPolicyManager, *fakeTrafficRunner) {
	t.Helper()
	root := t.TempDir()
	runner := &fakeTrafficRunner{}
	manager := &TrafficPolicyManager{
		NetworkState: routedTrafficState(),
		PolicyStore:  &trafficpolicy.Store{Path: filepath.Join(root, "policy.json")},
		RuntimePath:  filepath.Join(root, "runtime", "policy.json"),
		Runner:       runner,
		Probe:        func(context.Context, int) error { return nil },
	}
	if err := manager.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	policy := trafficpolicy.DefaultPolicy()
	policy.Revision = 2
	policy.EncryptedDNS.Mode = trafficpolicy.EncryptedDNSEnforceLocal
	policy.EncryptedDNS.RedirectPlainDNS = true
	policy.EncryptedDNS.UpstreamServers = []string{"1.1.1.1:53"}
	if _, err := manager.Apply(t.Context(), policy, 1); err != nil {
		t.Fatal(err)
	}
	return manager, runner
}

// The reconciler runs every 15 s. Reloading unchanged chains zeroed their
// packet counters each time, so counters on the lab's DNS redirect and
// listener protection never showed real traffic.
func TestTrafficPolicyReconcileLeavesUnchangedChainsAlone(t *testing.T) {
	manager, runner := dnsRedirectPolicyManager(t)
	if err := manager.ReconcileNow(t.Context()); err != nil {
		t.Fatal(err)
	}
	before := runner.restores()
	for range 3 {
		if err := manager.ReconcileNow(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if after := runner.restores(); after != before {
		t.Fatalf("unchanged policy was reloaded %d times by 3 reconciles", after-before)
	}
	if !runner.jumps["PREROUTING->"+securityPreroutingChain] || !runner.jumps["INPUT->"+securityInputChain] {
		t.Fatalf("security hooks were detached: %#v", runner.jumps)
	}
}

func TestTrafficPolicyReconcileRestoresAFlushedChainInOneBatch(t *testing.T) {
	manager, runner := dnsRedirectPolicyManager(t)
	if err := manager.ReconcileNow(t.Context()); err != nil {
		t.Fatal(err)
	}
	runner.flush("", securityPreroutingChain)
	before := runner.restores()
	if err := manager.ReconcileNow(t.Context()); err != nil {
		t.Fatal(err)
	}
	if after := runner.restores(); after != before+1 {
		t.Fatalf("a flushed redirect chain took %d restores, want exactly 1", after-before)
	}
	batch := runner.lastRestore("/usr/sbin/iptables-restore")
	nat := batch[strings.Index(batch, "*nat"):]
	// One transaction declares, flushes and refills the chain, so the
	// redirect is never missing while it is replaced.
	for _, expected := range []string{":" + securityPreroutingChain, "-F " + securityPreroutingChain, "--dport 53 -j REDIRECT --to-ports 1053", "COMMIT"} {
		if !strings.Contains(nat, expected) {
			t.Fatalf("NAT restore batch lacks %q:\n%s", expected, nat)
		}
	}
	runner.mu.Lock()
	restored := strings.Join(runner.contents[securityPreroutingChain], "\n")
	runner.mu.Unlock()
	if !strings.Contains(restored, "--dport 53 -j REDIRECT --to-ports 1053") {
		t.Fatalf("DNS redirect was not restored: %q", restored)
	}
}

func TestTrafficPolicyReconcileReloadsAfterAFailedRestore(t *testing.T) {
	manager, runner := dnsRedirectPolicyManager(t)
	runner.flush("", securityInputChain)
	runner.mu.Lock()
	runner.failRestore = func(_, stdin string) error {
		if strings.HasPrefix(stdin, "*filter") {
			return errors.New("iptables-restore: resource busy")
		}
		return nil
	}
	runner.mu.Unlock()
	if err := manager.ReconcileNow(t.Context()); err == nil {
		t.Fatal("a failed filter restore was not reported")
	}
	runner.mu.Lock()
	runner.failRestore = nil
	runner.mu.Unlock()
	if err := manager.ReconcileNow(t.Context()); err != nil {
		t.Fatal(err)
	}
	runner.mu.Lock()
	protected := len(runner.contents[securityInputChain])
	runner.mu.Unlock()
	if protected == 0 {
		t.Fatal("listener protection was not reloaded after the failed restore")
	}
}

func TestTrafficPolicyManagerRejectsActivePolicyWithoutConfirmedRoute(t *testing.T) {
	root := t.TempDir()
	manager := &TrafficPolicyManager{
		NetworkState: &StateStore{state: persistedState{OperatingMode: gatewayprotocol.ModeSetupSafe}},
		PolicyStore:  &trafficpolicy.Store{Path: filepath.Join(root, "policy.json")},
		RuntimePath:  filepath.Join(root, "runtime.json"),
		Runner:       &fakeTrafficRunner{},
		Probe:        func(context.Context, int) error { return nil },
	}
	if err := manager.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	policy := trafficpolicy.DefaultPolicy()
	policy.Revision = 2
	policy.Name = "Block DoT"
	policy.EncryptedDNS.BlockDoT = true
	if _, err := manager.Apply(t.Context(), policy, 1); err == nil {
		t.Fatal("active traffic policy was accepted without a confirmed routed plan")
	}
}

func TestTrafficPolicyManagerFailedChangeRemovesPreviouslyActiveInterception(t *testing.T) {
	root := t.TempDir()
	runner := &fakeTrafficRunner{}
	probeErr := error(nil)
	manager := &TrafficPolicyManager{
		NetworkState: routedTrafficState(),
		PolicyStore:  &trafficpolicy.Store{Path: filepath.Join(root, "policy.json")},
		RuntimePath:  filepath.Join(root, "runtime.json"),
		Runner:       runner,
		Probe:        func(context.Context, int) error { return probeErr },
	}
	if err := manager.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	policy := trafficpolicy.DefaultPolicy()
	policy.Revision = 2
	policy.Name = "Active local DNS"
	policy.EncryptedDNS.Mode = trafficpolicy.EncryptedDNSEnforceLocal
	policy.EncryptedDNS.RedirectPlainDNS = true
	policy.EncryptedDNS.UpstreamServers = []string{"1.1.1.1:53"}
	if _, err := manager.Apply(t.Context(), policy, 1); err != nil {
		t.Fatal(err)
	}

	probeErr = errors.New("listener unavailable")
	policy.Revision = 3
	policy.Name = "Changed active local DNS"
	if _, err := manager.Apply(t.Context(), policy, 2); err == nil {
		t.Fatal("policy change unexpectedly succeeded with an unavailable listener")
	}

	runner.mu.Lock()
	defer runner.mu.Unlock()
	if runner.jumps["DOCKER-USER->"+securityForwardChain] || runner.jumps["PREROUTING->"+securityPreroutingChain] {
		t.Fatalf("failed change left client interception attached: %#v", runner.jumps)
	}
	if !runner.jumps["INPUT->"+securityInputChain] {
		t.Fatalf("failed change removed local listener isolation: %#v", runner.jumps)
	}

	data, err := os.ReadFile(manager.RuntimePath)
	if err != nil {
		t.Fatal(err)
	}
	var restored trafficpolicy.Policy
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Revision != 2 {
		t.Fatalf("runtime policy revision = %d, want last durable revision 2", restored.Revision)
	}
}

func TestTrafficPolicyManagerEmergencyBypassImmediatelyDetachesInterception(t *testing.T) {
	root := t.TempDir()
	runner := &fakeTrafficRunner{}
	manager := &TrafficPolicyManager{
		NetworkState: routedTrafficState(),
		PolicyStore:  &trafficpolicy.Store{Path: filepath.Join(root, "policy.json")},
		RuntimePath:  filepath.Join(root, "runtime.json"),
		Runner:       runner,
		Probe:        func(context.Context, int) error { return nil },
	}
	if err := manager.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	policy := trafficpolicy.DefaultPolicy()
	policy.Revision = 2
	policy.Name = "Active local DNS"
	policy.EncryptedDNS.Mode = trafficpolicy.EncryptedDNSEnforceLocal
	policy.EncryptedDNS.RedirectPlainDNS = true
	policy.EncryptedDNS.UpstreamServers = []string{"1.1.1.1:53"}
	if _, err := manager.Apply(t.Context(), policy, 1); err != nil {
		t.Fatal(err)
	}
	if err := manager.EnableEmergencyBypass(t.Context()); err != nil {
		t.Fatal(err)
	}

	runner.mu.Lock()
	defer runner.mu.Unlock()
	if runner.jumps["DOCKER-USER->"+securityForwardChain] || runner.jumps["PREROUTING->"+securityPreroutingChain] {
		t.Fatalf("emergency bypass left client interception attached: %#v", runner.jumps)
	}
	if !runner.jumps["INPUT->"+securityInputChain] {
		t.Fatalf("emergency bypass removed listener isolation: %#v", runner.jumps)
	}
}

func TestTrafficPolicyManagerYieldsRuntimeAndFirewallToFleet(t *testing.T) {
	root := t.TempDir()
	runner := &fakeTrafficRunner{}
	statusPath := filepath.Join(root, "fleet", "status.json")
	manager := &TrafficPolicyManager{
		NetworkState:          routedTrafficState(),
		PolicyStore:           &trafficpolicy.Store{Path: filepath.Join(root, "local-policy.json")},
		RuntimePath:           filepath.Join(root, "runtime", "policy.json"),
		CloudPolicyStatusPath: statusPath,
		CoordinationLockPath:  filepath.Join(root, "traffic-policy.lock"),
		Runner:                runner,
		Probe:                 func(context.Context, int) error { return nil },
	}
	if err := manager.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	policy := trafficpolicy.DefaultPolicy()
	policy.Revision = 2
	policy.Name = "Local DNS before Fleet"
	policy.EncryptedDNS.Mode = trafficpolicy.EncryptedDNSEnforceLocal
	policy.EncryptedDNS.RedirectPlainDNS = true
	policy.EncryptedDNS.UpstreamServers = []string{"1.1.1.1:53"}
	if _, err := manager.Apply(t.Context(), policy, 1); err != nil {
		t.Fatal(err)
	}

	fleetRuntime := []byte("{\"schema_version\":1,\"policy_id\":\"fleet-policy\"}\n")
	if err := os.WriteFile(manager.RuntimePath, fleetRuntime, 0o640); err != nil {
		t.Fatal(err)
	}
	writeFleetPolicyStatus(t, statusPath, "fleet-policy")
	if err := manager.ReconcileNow(t.Context()); err != nil {
		t.Fatal(err)
	}
	actualRuntime, err := os.ReadFile(manager.RuntimePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actualRuntime, fleetRuntime) {
		t.Fatalf("local reconciliation replaced Fleet runtime: %s", actualRuntime)
	}
	runner.mu.Lock()
	forwardAttached := runner.jumps["DOCKER-USER->"+securityForwardChain]
	preroutingAttached := runner.jumps["PREROUTING->"+securityPreroutingChain]
	runner.mu.Unlock()
	if forwardAttached || preroutingAttached {
		t.Fatalf("local enforcement remained attached after Fleet ownership: %#v", runner.jumps)
	}

	policy.Revision = 3
	if _, err := manager.Apply(t.Context(), policy, 2); err == nil || !strings.Contains(err.Error(), "managed by Fleet") {
		t.Fatalf("local apply was not rejected during Fleet ownership: %v", err)
	}
	if _, err := manager.Rollback(t.Context(), 2); err == nil || !strings.Contains(err.Error(), "managed by Fleet") {
		t.Fatalf("local rollback was not rejected during Fleet ownership: %v", err)
	}

	writeFleetPolicyStatus(t, statusPath, "")
	if _, err := manager.reconcileOwnershipTransition(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	restoredRuntime, err := os.ReadFile(manager.RuntimePath)
	if err != nil {
		t.Fatal(err)
	}
	var restored trafficpolicy.Policy
	if err := json.Unmarshal(restoredRuntime, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Revision != 2 {
		t.Fatalf("local durable policy was not restored after Fleet release: %#v", restored)
	}
}

func TestTrafficPolicyManagerFailsOpenForUnsafeFleetStatus(t *testing.T) {
	root := t.TempDir()
	runner := &fakeTrafficRunner{}
	statusPath := filepath.Join(root, "fleet-status.json")
	manager := &TrafficPolicyManager{
		NetworkState:          routedTrafficState(),
		PolicyStore:           &trafficpolicy.Store{Path: filepath.Join(root, "local-policy.json")},
		RuntimePath:           filepath.Join(root, "runtime.json"),
		CloudPolicyStatusPath: statusPath,
		CoordinationLockPath:  filepath.Join(root, "traffic-policy.lock"),
		Runner:                runner,
		Probe:                 func(context.Context, int) error { return nil },
	}
	if err := manager.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	policy := trafficpolicy.DefaultPolicy()
	policy.Revision = 2
	policy.Name = "Local DNS before unsafe status"
	policy.EncryptedDNS.Mode = trafficpolicy.EncryptedDNSEnforceLocal
	policy.EncryptedDNS.RedirectPlainDNS = true
	policy.EncryptedDNS.UpstreamServers = []string{"1.1.1.1:53"}
	if _, err := manager.Apply(t.Context(), policy, 1); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "real-status.json")
	writeFleetPolicyStatus(t, target, "fleet-policy")
	if err := os.Symlink(target, statusPath); err != nil {
		t.Fatal(err)
	}
	if err := manager.ReconcileNow(t.Context()); err == nil {
		t.Fatal("symlinked Fleet ownership status was accepted")
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if runner.jumps["DOCKER-USER->"+securityForwardChain] || runner.jumps["PREROUTING->"+securityPreroutingChain] {
		t.Fatalf("unsafe Fleet ownership state did not fail open: %#v", runner.jumps)
	}
}

func writeFleetPolicyStatus(t *testing.T, path, policyID string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(trafficpolicy.Status{SchemaVersion: trafficpolicy.SchemaVersion, PolicyID: policyID})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestGatewayEmergencyBypassRPCDetachesAndRestoresTrafficPolicy(t *testing.T) {
	root := t.TempDir()
	state, err := OpenStateStore(filepath.Join(root, "gateway-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	routed := routedTrafficState().Get()
	state.mu.Lock()
	if err := state.persistLocked(routed); err != nil {
		state.mu.Unlock()
		t.Fatal(err)
	}
	state.mu.Unlock()
	runner := &fakeTrafficRunner{}
	manager := &TrafficPolicyManager{
		NetworkState: state,
		PolicyStore:  &trafficpolicy.Store{Path: filepath.Join(root, "policy.json")},
		RuntimePath:  filepath.Join(root, "runtime.json"),
		Runner:       runner,
		Probe:        func(context.Context, int) error { return nil },
	}
	if err := manager.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	policy := trafficpolicy.DefaultPolicy()
	policy.Revision = 2
	policy.Name = "Active local DNS"
	policy.EncryptedDNS.Mode = trafficpolicy.EncryptedDNSEnforceLocal
	policy.EncryptedDNS.RedirectPlainDNS = true
	policy.EncryptedDNS.UpstreamServers = []string{"1.1.1.1:53"}
	if _, err := manager.Apply(t.Context(), policy, 1); err != nil {
		t.Fatal(err)
	}
	server := NewServer(state, slog.New(slog.NewTextHandler(io.Discard, nil)))
	server.SetTrafficPolicyManager(manager)
	if _, rpcErr := server.dispatch(t.Context(), trafficRPCRequest(t, "EnableEmergencyBypass", gatewayprotocol.EmptyParams{})); rpcErr != nil {
		t.Fatal(rpcErr)
	}
	if current := state.Get(); !current.EmergencyBypass || current.OperatingMode != gatewayprotocol.ModeEmergency {
		t.Fatalf("gateway state did not enter emergency bypass: %#v", current)
	}
	runner.mu.Lock()
	attachedDuringBypass := runner.jumps["DOCKER-USER->"+securityForwardChain] || runner.jumps["PREROUTING->"+securityPreroutingChain]
	runner.mu.Unlock()
	if attachedDuringBypass {
		t.Fatal("RPC returned before interception jumps were detached")
	}
	if _, rpcErr := server.dispatch(t.Context(), trafficRPCRequest(t, "DisableEmergencyBypass", gatewayprotocol.EmptyParams{})); rpcErr != nil {
		t.Fatal(rpcErr)
	}
	if current := state.Get(); current.EmergencyBypass || current.OperatingMode != gatewayprotocol.ModeRouted {
		t.Fatalf("gateway state did not leave emergency bypass: %#v", current)
	}
	runner.mu.Lock()
	restored := runner.jumps["PREROUTING->"+securityPreroutingChain] && runner.jumps["INPUT->"+securityInputChain]
	runner.mu.Unlock()
	if !restored {
		t.Fatal("RPC returned before the durable traffic policy was restored")
	}
}

func TestTrafficPolicyHTTPRejectsUnknownFields(t *testing.T) {
	root := t.TempDir()
	manager := &TrafficPolicyManager{
		NetworkState: routedTrafficState(),
		PolicyStore:  &trafficpolicy.Store{Path: filepath.Join(root, "policy.json")},
		RuntimePath:  filepath.Join(root, "runtime.json"),
		Runner:       &fakeTrafficRunner{},
		Probe:        func(context.Context, int) error { return nil },
	}
	if err := manager.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/apply", bytes.NewBufferString(`{"expected_revision":1,"policy":{},"shell":"id"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	manager.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid_request") {
		t.Fatalf("unexpected response: %d %s", response.Code, response.Body.String())
	}
}

func TestTrafficPolicyRollbackRestoresPreviousBehaviorAtNewRevision(t *testing.T) {
	root := t.TempDir()
	manager := &TrafficPolicyManager{
		NetworkState: routedTrafficState(),
		PolicyStore:  &trafficpolicy.Store{Path: filepath.Join(root, "policy.json"), Now: func() time.Time { return time.Date(2026, 9, 2, 1, 0, 0, 0, time.UTC) }},
		RuntimePath:  filepath.Join(root, "runtime.json"),
		Runner:       &fakeTrafficRunner{},
		Probe:        func(context.Context, int) error { return nil },
	}
	if err := manager.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	policy := trafficpolicy.DefaultPolicy()
	policy.Revision = 2
	policy.Name = "Block DoT"
	policy.EncryptedDNS.BlockDoT = true
	if _, err := manager.Apply(t.Context(), policy, 1); err != nil {
		t.Fatal(err)
	}
	document, err := manager.Rollback(t.Context(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if document.Policy.Revision != 3 || document.Policy.EncryptedDNS.BlockDoT {
		t.Fatalf("unexpected rollback: %#v", document)
	}
}

func TestGatewayRPCExposesTrafficPolicyLifecycle(t *testing.T) {
	root := t.TempDir()
	state := routedTrafficState()
	manager := &TrafficPolicyManager{
		NetworkState: state,
		PolicyStore:  &trafficpolicy.Store{Path: filepath.Join(root, "policy.json")},
		RuntimePath:  filepath.Join(root, "runtime.json"),
		Runner:       &fakeTrafficRunner{},
		Probe:        func(context.Context, int) error { return nil },
	}
	if err := manager.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	server := NewServer(state, slog.New(slog.NewTextHandler(io.Discard, nil)))
	server.SetTrafficPolicyManager(manager)

	result, rpcErr := server.dispatch(t.Context(), trafficRPCRequest(t, "GetTrafficPolicy", gatewayprotocol.EmptyParams{}))
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	document, ok := result.(trafficpolicy.Document)
	if !ok || document.Policy.Revision != 1 {
		t.Fatalf("unexpected initial document: %#v", result)
	}
	result, rpcErr = server.dispatch(t.Context(), trafficRPCRequest(t, "PreviewTrafficPolicy", gatewayprotocol.PreviewTrafficPolicyParams{Policy: document.Policy}))
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	observePreview, ok := result.(gatewayprotocol.TrafficPolicyPreview)
	if !ok || observePreview.Firewall.FilterRules == nil || observePreview.Firewall.NATRules == nil {
		t.Fatalf("observe-only preview must expose JSON arrays: %#v", result)
	}

	policy := document.Policy
	policy.Revision = 2
	policy.Name = "Local DNS enforcement"
	policy.EncryptedDNS.Mode = trafficpolicy.EncryptedDNSEnforceLocal
	policy.EncryptedDNS.RedirectPlainDNS = true
	policy.EncryptedDNS.UpstreamServers = []string{"1.1.1.1:53"}
	result, rpcErr = server.dispatch(t.Context(), trafficRPCRequest(t, "PreviewTrafficPolicy", gatewayprotocol.PreviewTrafficPolicyParams{Policy: policy}))
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	preview, ok := result.(gatewayprotocol.TrafficPolicyPreview)
	if !ok || !preview.Firewall.NeedsDNSService || preview.Digest == "" {
		t.Fatalf("unexpected preview: %#v", result)
	}

	result, rpcErr = server.dispatch(t.Context(), trafficRPCRequest(t, "ApplyTrafficPolicy", gatewayprotocol.ApplyTrafficPolicyParams{ExpectedRevision: 1, Policy: policy}))
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	document, ok = result.(trafficpolicy.Document)
	if !ok || document.Policy.Revision != 2 || document.Policy.EncryptedDNS.Mode != trafficpolicy.EncryptedDNSEnforceLocal {
		t.Fatalf("unexpected applied document: %#v", result)
	}

	result, rpcErr = server.dispatch(t.Context(), trafficRPCRequest(t, "RollbackTrafficPolicy", gatewayprotocol.RollbackTrafficPolicyParams{ExpectedRevision: 2}))
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	document, ok = result.(trafficpolicy.Document)
	if !ok || document.Policy.Revision != 3 || document.Policy.EncryptedDNS.Mode != trafficpolicy.EncryptedDNSObserve {
		t.Fatalf("unexpected rollback document: %#v", result)
	}

	if category, mutating := hostMutationCategory("ApplyTrafficPolicy"); !mutating || category != "dns" {
		t.Fatalf("traffic policy apply must use the DNS configuration lock: %q %t", category, mutating)
	}
}

func trafficRPCRequest(t *testing.T, method string, params any) gatewayprotocol.Request {
	t.Helper()
	encoded, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	return gatewayprotocol.Request{JSONRPC: gatewayprotocol.JSONRPCVersion, ID: "traffic-policy-test", Method: method, Params: encoded}
}
