package networkapply

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

// fakeRuntimeMachine models the kernel state the restorer manages: owned
// chain rule counts, hooks, and sysctl files under the test host root.
type fakeRuntimeMachine struct {
	hostRoot string
	calls    []string
	chains   map[string]int
	hooks    map[string]bool
	failOn   string
}

func newFakeRuntimeMachine(hostRoot string) *fakeRuntimeMachine {
	return &fakeRuntimeMachine{hostRoot: hostRoot, chains: map[string]int{}, hooks: map[string]bool{}}
}

func (m *fakeRuntimeMachine) record(call string) error {
	m.calls = append(m.calls, call)
	if m.failOn != "" && strings.HasPrefix(call, m.failOn) {
		return errors.New(call + " failed")
	}
	return nil
}

func (m *fakeRuntimeMachine) load(binary, restore string) {
	for _, owned := range ownedChainRules(restore) {
		m.chains[binary+" "+owned.table+" "+owned.chain] = owned.rules
	}
}

func (m *fakeRuntimeMachine) writeSysctl(path, value string) {
	target := filepath.Join(m.hostRoot, path)
	_ = os.MkdirAll(filepath.Dir(target), 0o755)
	_ = os.WriteFile(target, []byte(value+"\n"), 0o644)
}

func (m *fakeRuntimeMachine) LoadShakerProxyFirewall(_ context.Context, path, restore string) error {
	if err := m.record("firewall4:" + path + ":" + digest(restore)); err != nil {
		return err
	}
	m.load(path, restore)
	return nil
}

func (m *fakeRuntimeMachine) LoadShakerProxyIPv6Firewall(_ context.Context, path, restore string) error {
	if err := m.record("firewall6:" + path + ":" + digest(restore)); err != nil {
		return err
	}
	m.load(path, restore)
	return nil
}

func (m *fakeRuntimeMachine) EnsureOrderedHook(_ context.Context, binary string, hook FirewallHook) error {
	key := binary + " " + hook.Table + " " + hook.Parent + " " + hook.Chain
	if m.hooks[key] {
		return m.record("hook-present:" + key)
	}
	if err := m.record("hook-insert:" + key); err != nil {
		return err
	}
	m.hooks[key] = true
	return nil
}

func (m *fakeRuntimeMachine) SetIPv4Forwarding(_ context.Context, value int) error {
	if err := m.record(fmt.Sprintf("forwarding4:%d", value)); err != nil {
		return err
	}
	m.writeSysctl("proc/sys/net/ipv4/ip_forward", fmt.Sprint(value))
	return nil
}

func (m *fakeRuntimeMachine) SetBridgeNFCallIPTables(_ context.Context, value int) error {
	if err := m.record(fmt.Sprintf("bridge-nf:%d", value)); err != nil {
		return err
	}
	m.writeSysctl("proc/sys/net/bridge/bridge-nf-call-iptables", fmt.Sprint(value))
	return nil
}

func (m *fakeRuntimeMachine) SetIPv4SendRedirects(_ context.Context, name string, value int) error {
	if err := m.record(fmt.Sprintf("redirects:%s:%d", name, value)); err != nil {
		return err
	}
	m.writeSysctl("proc/sys/net/ipv4/conf/"+name+"/send_redirects", fmt.Sprint(value))
	return nil
}

func (m *fakeRuntimeMachine) SetIPv6AcceptRA(_ context.Context, name string, value int) error {
	if err := m.record(fmt.Sprintf("accept_ra:%s:%d", name, value)); err != nil {
		return err
	}
	m.writeSysctl("proc/sys/net/ipv6/conf/"+name+"/accept_ra", fmt.Sprint(value))
	return nil
}

func (m *fakeRuntimeMachine) SetIPv6Forwarding(_ context.Context, value int) error {
	if err := m.record(fmt.Sprintf("forwarding6:%d", value)); err != nil {
		return err
	}
	m.writeSysctl("proc/sys/net/ipv6/conf/all/forwarding", fmt.Sprint(value))
	return nil
}

func (m *fakeRuntimeMachine) OwnedRuleCount(_ context.Context, binary, table, chain string) (int, bool, error) {
	count, ok := m.chains[binary+" "+table+" "+chain]
	return count, ok, nil
}

func (m *fakeRuntimeMachine) HookPresent(_ context.Context, binary string, hook FirewallHook) (bool, error) {
	return m.hooks[binary+" "+hook.Table+" "+hook.Parent+" "+hook.Chain], nil
}

// reboot erases every piece of runtime state, as a host reboot does.
func (m *fakeRuntimeMachine) reboot() {
	m.chains, m.hooks, m.calls = map[string]int{}, map[string]bool{}, nil
	m.writeSysctl("proc/sys/net/ipv4/ip_forward", "0")
	m.writeSysctl("proc/sys/net/ipv6/conf/all/forwarding", "0")
	m.writeSysctl("proc/sys/net/ipv6/conf/eth0/accept_ra", "1")
}

type runtimeFixture struct {
	restorer RuntimeRestorer
	staged   networkplan.StagedPlan
	machine  *fakeRuntimeMachine
	hostRoot string
}

// confirmedRuntimeFixture drives a real plan through snapshot, native syntax
// evidence, the watchdog manifest, health and durable confirmation, exactly
// as a confirmed apply leaves it on disk.
func confirmedRuntimeFixture(t *testing.T, edit func(*networkplan.StagedPlan)) runtimeFixture {
	t.Helper()
	now := time.Unix(9000, 0)
	hostRoot := prepareHostRoot(t, "0\n")
	prepareIPv6HostState(t, hostRoot, "0\n", "1\n")
	prepareRedirectState(t, hostRoot, "eth0", "1\n")
	staged := validStagedPlan(t, now)
	staged.Plan.IPv6 = ulaConfiguration()
	if edit != nil {
		edit(&staged)
	}
	hash := networkplan.CanonicalPlanHash(staged.Plan)
	record, err := networktransaction.New(applyID, hash, now)
	if err != nil {
		t.Fatal(err)
	}
	staged.PlanHash, staged.Transaction = hash, &record
	preview := networkplan.BuildPreview(staged.Plan, now)
	if !preview.Validation.Valid || preview.Validation.PlanHash != hash {
		t.Fatalf("runtime fixture plan is invalid: %+v", preview.Validation)
	}
	preview.FirewallBackend = "iptables-nft"
	preview.FirewallEnvironment = ipv6ReadyInspection()
	networkplan.BindIPv6HostEvidence(&preview)
	staged.Preview = preview
	store := networktransaction.FileStore{Root: filepath.Join(t.TempDir(), "transactions")}
	spec, err := (Snapshotter{Store: store, HostRoot: hostRoot}).Capture(staged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (Validator{Store: store, Runner: &recordingRunner{}, Now: func() time.Time { return now.Add(time.Second) }}).Validate(context.Background(), staged); err != nil {
		t.Fatal(err)
	}
	manifest, err := networktransaction.NewWatchdogManifest(record, now.Add(2*time.Second), 2*time.Minute, spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteManifest(manifest); err != nil {
		t.Fatal(err)
	}
	record, err = record.ArmWatchdog(manifest.CreatedAt, manifest.ConfirmBy.Sub(manifest.CreatedAt))
	if err == nil {
		record, err = record.BeginApply(now.Add(3 * time.Second))
	}
	if err == nil {
		record, err = record.MarkApplied(now.Add(4 * time.Second))
	}
	if err == nil {
		checks := []networktransaction.HealthCheck{}
		for _, name := range []networktransaction.CheckName{networktransaction.CheckManagement, networktransaction.CheckWAN, networktransaction.CheckDNS, networktransaction.CheckIPv4Forwarding, networktransaction.CheckDHCP4, networktransaction.CheckIPv6} {
			checks = append(checks, networktransaction.HealthCheck{Name: name, Status: networktransaction.CheckPass})
		}
		record, err = record.RecordHealth(networktransaction.HealthReport{CheckedAt: now.Add(5 * time.Second), Checks: checks})
	}
	confirmation, confirmErr := store.Confirm(applyID, hash, now.Add(6*time.Second))
	if err == nil && confirmErr == nil {
		record, err = record.Confirm(confirmation.ConfirmedAt)
	}
	if err != nil || confirmErr != nil {
		t.Fatalf("confirm runtime fixture: %v %v", err, confirmErr)
	}
	staged.Transaction = &record
	staged.Status = string(record.Phase)
	machine := newFakeRuntimeMachine(hostRoot)
	return runtimeFixture{restorer: RuntimeRestorer{Store: store, HostRoot: hostRoot, Machine: machine}, staged: staged, machine: machine, hostRoot: hostRoot}
}

func TestRuntimeRestoreReappliesConfirmedStateInFailClosedOrder(t *testing.T) {
	fixture := confirmedRuntimeFixture(t, nil)
	fixture.machine.reboot()
	drift, err := fixture.restorer.Drift(context.Background(), fixture.staged)
	if err != nil || len(drift) == 0 {
		t.Fatalf("reboot was not detected as drift: %v %v", drift, err)
	}
	if err := fixture.restorer.Restore(context.Background(), fixture.staged); err != nil {
		t.Fatal(err)
	}
	preview := fixture.staged.Preview
	expected := []string{
		"firewall4:/usr/sbin/iptables:" + digest(preview.FirewallRestoreIPv4),
		"hook-insert:/usr/sbin/iptables filter DOCKER-USER SHAKERPROXY-FORWARD",
		"hook-insert:/usr/sbin/iptables nat POSTROUTING SHAKERPROXY-POSTROUTING",
		"forwarding4:1",
		"firewall6:/usr/sbin/ip6tables:" + digest(preview.FirewallRestoreIPv6),
		"hook-insert:/usr/sbin/ip6tables filter DOCKER-USER SHAKERPROXY-FORWARD",
		"hook-insert:/usr/sbin/ip6tables filter INPUT SHAKERPROXY-INPUT",
		"hook-insert:/usr/sbin/ip6tables nat POSTROUTING SHAKERPROXY-POSTROUTING",
		"accept_ra:eth0:2",
		"forwarding6:1",
	}
	if strings.Join(fixture.machine.calls, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("unexpected runtime restore order:\n%s", strings.Join(fixture.machine.calls, "\n"))
	}
	if drift, err := fixture.restorer.Drift(context.Background(), fixture.staged); err != nil || len(drift) != 0 {
		t.Fatalf("restored state still drifts: %v %v", drift, err)
	}
}

func TestRuntimeRestoreIsIdempotent(t *testing.T) {
	fixture := confirmedRuntimeFixture(t, nil)
	fixture.machine.reboot()
	for run := 0; run < 2; run++ {
		fixture.machine.calls = nil
		if err := fixture.restorer.Restore(context.Background(), fixture.staged); err != nil {
			t.Fatal(err)
		}
	}
	for _, call := range fixture.machine.calls {
		if strings.HasPrefix(call, "hook-insert:") {
			t.Fatalf("second restore inserted a duplicate hook: %v", fixture.machine.calls)
		}
	}
	if len(fixture.machine.hooks) != 5 {
		t.Fatalf("unexpected hook set after repeated restores: %v", fixture.machine.hooks)
	}
	if drift, err := fixture.restorer.Drift(context.Background(), fixture.staged); err != nil || len(drift) != 0 {
		t.Fatalf("repeated restore left drift: %v %v", drift, err)
	}
}

func TestRuntimeDriftNamesLostHooksFlushedChainsAndSysctls(t *testing.T) {
	fixture := confirmedRuntimeFixture(t, nil)
	if err := fixture.restorer.Restore(context.Background(), fixture.staged); err != nil {
		t.Fatal(err)
	}
	delete(fixture.machine.hooks, "/usr/sbin/iptables filter DOCKER-USER SHAKERPROXY-FORWARD")
	fixture.machine.chains["/usr/sbin/ip6tables filter SHAKERPROXY-INPUT"] = 0
	fixture.machine.writeSysctl("proc/sys/net/ipv6/conf/eth0/accept_ra", "0")
	drift, err := fixture.restorer.Drift(context.Background(), fixture.staged)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(drift, "\n")
	for _, expected := range []string{"iptables hook DOCKER-USER -> SHAKERPROXY-FORWARD is missing", "ip6tables chain SHAKERPROXY-INPUT has 0 of", "router advertisements"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("drift is missing %q:\n%s", expected, joined)
		}
	}
	if len(drift) != 3 {
		t.Fatalf("unexpected drift items:\n%s", joined)
	}
}

func TestRuntimeRestoreStopsBeforeForwardingWhenHooksFail(t *testing.T) {
	fixture := confirmedRuntimeFixture(t, nil)
	fixture.machine.reboot()
	fixture.machine.failOn = "hook-insert:/usr/sbin/iptables filter DOCKER-USER"
	if err := fixture.restorer.Restore(context.Background(), fixture.staged); err == nil {
		t.Fatal("hook failure was not reported")
	}
	for _, call := range fixture.machine.calls {
		if strings.HasPrefix(call, "forwarding") || strings.HasPrefix(call, "firewall6") {
			t.Fatalf("forwarding or IPv6 continued after the IPv4 hook failed: %v", fixture.machine.calls)
		}
	}
	fixture.machine.failOn = "hook-insert:/usr/sbin/ip6tables"
	fixture.machine.calls = nil
	if err := fixture.restorer.Restore(context.Background(), fixture.staged); err == nil {
		t.Fatal("IPv6 hook failure was not reported")
	}
	for _, call := range fixture.machine.calls {
		if call == "forwarding6:1" {
			t.Fatalf("IPv6 forwarding was enabled without its firewall: %v", fixture.machine.calls)
		}
	}
}

func TestRuntimeRestoreCoversSingleArmRedirectsAndDisabledIPv6(t *testing.T) {
	single := confirmedRuntimeFixture(t, func(staged *networkplan.StagedPlan) {
		staged.Plan.Topology = networkplan.TopologySingleArm
		staged.Plan.Interfaces = []networkplan.Interface{{StableID: "arm", CurrentName: "eth0", Role: networkplan.RoleWANLab}}
		staged.Plan.WAN = networkplan.WANConfiguration{IPv4Mode: networkplan.WANIPv4KeepExisting, IPv6Mode: networkplan.WANIPv6KeepExisting, DNSMode: networkplan.WANDNSUseDHCP, UpstreamNAT: true}
		staged.Plan.IPv4 = networkplan.IPv4Configuration{Enabled: true, LabCIDR: "192.0.2.0/24", GatewayAddress: "192.0.2.20", NAT44: true}
		staged.Plan.IPv6 = networkplan.IPv6Configuration{Strategy: networkplan.IPv6Disabled}
	})
	single.machine.reboot()
	if err := single.restorer.Restore(context.Background(), single.staged); err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"firewall4:/usr/sbin/iptables:" + digest(single.staged.Preview.FirewallRestoreIPv4),
		"hook-insert:/usr/sbin/iptables filter DOCKER-USER SHAKERPROXY-FORWARD",
		"hook-insert:/usr/sbin/iptables nat POSTROUTING SHAKERPROXY-POSTROUTING",
		"forwarding4:1",
		"redirects:eth0:0",
	}
	if strings.Join(single.machine.calls, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("unexpected single-arm restore:\n%s", strings.Join(single.machine.calls, "\n"))
	}
	if drift, err := single.restorer.Drift(context.Background(), single.staged); err != nil || len(drift) != 0 {
		t.Fatalf("single-arm restore left drift: %v %v", drift, err)
	}

	disabled := confirmedRuntimeFixture(t, func(staged *networkplan.StagedPlan) {
		staged.Plan.IPv6 = networkplan.IPv6Configuration{Strategy: networkplan.IPv6Disabled}
	})
	disabled.machine.reboot()
	if err := disabled.restorer.Restore(context.Background(), disabled.staged); err != nil {
		t.Fatal(err)
	}
	expected = []string{
		"firewall4:/usr/sbin/iptables:" + digest(disabled.staged.Preview.FirewallRestoreIPv4),
		"hook-insert:/usr/sbin/iptables filter DOCKER-USER SHAKERPROXY-FORWARD",
		"hook-insert:/usr/sbin/iptables nat POSTROUTING SHAKERPROXY-POSTROUTING",
		"forwarding4:1",
		"firewall6:/usr/sbin/ip6tables:" + digest(disabled.staged.Preview.FirewallRestoreIPv6),
		"hook-insert:/usr/sbin/ip6tables filter DOCKER-USER SHAKERPROXY-FORWARD",
	}
	if strings.Join(disabled.machine.calls, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("unexpected DISABLED restore (IPv6 must stay unrouted):\n%s", strings.Join(disabled.machine.calls, "\n"))
	}
	if drift, err := disabled.restorer.Drift(context.Background(), disabled.staged); err != nil || len(drift) != 0 {
		t.Fatalf("DISABLED restore left drift: %v %v", drift, err)
	}
}

func TestRuntimeRestoreFailsClosedWhenThePreviewIsNotBound(t *testing.T) {
	cases := map[string]func(*runtimeFixture){
		"plan edited after confirmation": func(fixture *runtimeFixture) { fixture.staged.Plan.IPv4.DHCPEnd = "10.77.0.199" },
		"IPv4 firewall changed":          func(fixture *runtimeFixture) { fixture.staged.Preview.FirewallRestoreIPv4 += "# changed\n" },
		"IPv6 firewall changed":          func(fixture *runtimeFixture) { fixture.staged.Preview.FirewallRestoreIPv6 += "# changed\n" },
		"preview hash changed": func(fixture *runtimeFixture) {
			fixture.staged.Preview.Validation.PlanHash = strings.Repeat("f", 64)
		},
		"not confirmed": func(fixture *runtimeFixture) {
			record := *fixture.staged.Transaction
			record.Phase = networktransaction.PhaseAwaitingConfirmation
			fixture.staged.Transaction = &record
		},
		"confirmation missing": func(fixture *runtimeFixture) {
			directory, _ := fixture.restorer.Store.TransactionDirectory(applyID)
			_ = os.Remove(filepath.Join(directory, "confirmed.json"))
		},
		"evidence missing": func(fixture *runtimeFixture) {
			directory, _ := fixture.restorer.Store.TransactionDirectory(applyID)
			_ = os.Remove(filepath.Join(directory, "syntax-evidence.json"))
		},
		"firewall environment changed": func(fixture *runtimeFixture) {
			fixture.staged.Preview.FirewallEnvironment.IPv6DockerUserChain = false
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := confirmedRuntimeFixture(t, nil)
			fixture.machine.reboot()
			edit(&fixture)
			if err := fixture.restorer.Restore(context.Background(), fixture.staged); err == nil {
				t.Fatal("unbound preview was restored")
			}
			if _, err := fixture.restorer.Drift(context.Background(), fixture.staged); err == nil {
				t.Fatal("unbound preview was inspected")
			}
			if len(fixture.machine.calls) != 0 {
				t.Fatalf("host state changed for an unbound preview: %v", fixture.machine.calls)
			}
		})
	}
}

func TestHookInsertPositionKeepsTheTrafficPolicyHookFirst(t *testing.T) {
	cases := []struct {
		listing, parent string
		expected        int
	}{
		{"-N DOCKER-USER\n-A DOCKER-USER -j RETURN\n", "DOCKER-USER", 1},
		{"-N DOCKER-USER\n-A DOCKER-USER -j SHAKERPROXY-SEC-FORWARD\n-A DOCKER-USER -j RETURN\n", "DOCKER-USER", 2},
		{"-N DOCKER-USER\n-A DOCKER-USER -j ADMIN\n-A DOCKER-USER -j SHAKERPROXY-SEC-FORWARD\n", "DOCKER-USER", 3},
		{"-P FORWARD DROP\n-A FORWARD -j DOCKER-USER\n-A FORWARD -j SHAKERPROXY-SEC-FORWARD\n", "FORWARD", 3},
		{"-P INPUT ACCEPT\n-A INPUT -j SHAKERPROXY-SEC-INPUT\n", "INPUT", 2},
		{"-P POSTROUTING ACCEPT\n-A POSTROUTING -j SHAKERPROXY-SEC-FORWARD\n", "POSTROUTING", 1},
		{"-A DOCKER-USER -s 10.0.0.1/32 -j SHAKERPROXY-SEC-FORWARD\n", "DOCKER-USER", 1},
	}
	for _, test := range cases {
		if position := hookInsertPosition(test.listing, test.parent); position != test.expected {
			t.Fatalf("position %d, expected %d for:\n%s", position, test.expected, test.listing)
		}
	}
}

func TestOSRuntimeMachineInsertsMissingHooksBelowTheTrafficPolicyHook(t *testing.T) {
	var calls []string
	present := false
	machine := OSRuntimeMachine{run: func(_ context.Context, path string, arguments []string) (string, rollbackCommandResult, error) {
		joined := strings.Join(arguments, " ")
		calls = append(calls, path+" "+joined)
		switch {
		case strings.Contains(joined, "-C DOCKER-USER"):
			if present {
				return "", rollbackCommandResult{}, nil
			}
			return "", rollbackCommandResult{exitCode: 1}, nil
		case strings.HasSuffix(joined, "-S DOCKER-USER"):
			return "-N DOCKER-USER\n-A DOCKER-USER -j SHAKERPROXY-SEC-FORWARD\n-A DOCKER-USER -j RETURN\n", rollbackCommandResult{}, nil
		case strings.HasSuffix(joined, "-S SHAKERPROXY-FORWARD"):
			return "-N SHAKERPROXY-FORWARD\n-A SHAKERPROXY-FORWARD -j ACCEPT\n-A SHAKERPROXY-FORWARD -j DROP\n", rollbackCommandResult{}, nil
		}
		present = true
		return "", rollbackCommandResult{}, nil
	}}
	hook := FirewallHook{Table: "filter", Parent: "DOCKER-USER", Chain: "SHAKERPROXY-FORWARD"}
	if err := machine.EnsureOrderedHook(context.Background(), "/usr/sbin/iptables", hook); err != nil {
		t.Fatal(err)
	}
	if err := machine.EnsureOrderedHook(context.Background(), "/usr/sbin/iptables", hook); err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"/usr/sbin/iptables -w 5 -C DOCKER-USER -j SHAKERPROXY-FORWARD",
		"/usr/sbin/iptables -w 5 -S DOCKER-USER",
		"/usr/sbin/iptables -w 5 -I DOCKER-USER 2 -j SHAKERPROXY-FORWARD",
		"/usr/sbin/iptables -w 5 -C DOCKER-USER -j SHAKERPROXY-FORWARD",
	}
	if strings.Join(calls, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("unexpected ordered hook commands:\n%s", strings.Join(calls, "\n"))
	}
	if count, exists, err := machine.OwnedRuleCount(context.Background(), "/usr/sbin/iptables", "filter", "SHAKERPROXY-FORWARD"); err != nil || !exists || count != 2 {
		t.Fatalf("owned rule count is wrong: %d %v %v", count, exists, err)
	}
	for _, rejected := range [][]string{
		{"-w", "5", "-F", "DOCKER-USER"},
		{"-w", "5", "-D", "DOCKER-USER", "-j", "SHAKERPROXY-FORWARD"},
		{"-w", "5", "-I", "DOCKER-USER", "65", "-j", "SHAKERPROXY-FORWARD"},
		{"-w", "5", "-I", "DOCKER-USER", "1", "-j", "ACCEPT"},
		{"-w", "5", "-S", "DOCKER"},
		{"-w", "5", "-t", "nat", "-S", "PREROUTING"},
	} {
		if allowedRuntimeCommand("/usr/sbin/iptables", rejected) {
			t.Fatalf("runtime allowlist accepted %v", rejected)
		}
	}
	if allowedRuntimeCommand("/bin/sh", []string{"-c", "iptables -S"}) {
		t.Fatal("shell accepted by the runtime allowlist")
	}
}
