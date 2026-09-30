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

	"shakerproxy.dev/shakerproxy/internal/firewall"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

type fakeIPv6Machine struct {
	calls  []string
	failOn string
}

func (m *fakeIPv6Machine) record(call string) error {
	m.calls = append(m.calls, call)
	if m.failOn != "" && strings.HasPrefix(call, m.failOn) {
		return errors.New(call + " failed")
	}
	return nil
}

func (m *fakeIPv6Machine) SetIPv6Forwarding(_ context.Context, value int) error {
	return m.record(fmt.Sprintf("forwarding:%d", value))
}
func (m *fakeIPv6Machine) SetIPv6AcceptRA(_ context.Context, name string, value int) error {
	return m.record(fmt.Sprintf("accept_ra:%s:%d", name, value))
}
func (m *fakeIPv6Machine) LoadShakerProxyIPv6Firewall(_ context.Context, path, restore string) error {
	return m.record("firewall:" + path + ":" + digest(restore))
}
func (m *fakeIPv6Machine) EnsureShakerProxyIPv6Attachments(_ context.Context, attachments IPv6Attachments) error {
	return m.record(fmt.Sprintf("attach:%s:%s:input=%t:nat=%t", attachments.Ip6tablesPath, attachments.ForwardParent, attachments.Input, attachments.NAT))
}
func (m *fakeIPv6Machine) RemoveShakerProxyIPv6Firewall(_ context.Context, path, parent string) error {
	return m.record("remove-firewall:" + path + ":" + parent)
}
func (m *fakeIPv6Machine) RestartRadvd(context.Context) error { return m.record("restart-radvd") }
func (m *fakeIPv6Machine) DisableRadvd(context.Context) error { return m.record("disable-radvd") }

func ipv6ReadyInspection() firewall.Inspection {
	return firewall.Inspection{SelectedBackend: "iptables-nft", DockerFirewallBackend: "iptables", IptablesPath: "/usr/sbin/iptables", ApplyReady: true, IPv6Available: true, Ip6tablesPath: "/usr/sbin/ip6tables", IPv6DockerUserChain: true, IPv6FirewallReady: true}
}

// ipv6StagedPlan renders a real preview for the IPv6 configuration so the
// tests exercise the same artifacts as a staged apply.
func ipv6StagedPlan(t *testing.T, now time.Time, ipv6 networkplan.IPv6Configuration, inspection firewall.Inspection) networkplan.StagedPlan {
	t.Helper()
	staged := validStagedPlan(t, now)
	staged.Plan.IPv6 = ipv6
	preview := networkplan.BuildPreview(staged.Plan, now)
	if !preview.Validation.Valid {
		t.Fatalf("IPv6 test plan is invalid: %+v", preview.Validation.Errors)
	}
	preview.Validation.PlanHash = planHash
	preview.FirewallBackend = "iptables-nft"
	preview.FirewallEnvironment = inspection
	networkplan.BindIPv6HostEvidence(&preview)
	staged.Preview = preview
	return staged
}

func ulaConfiguration() networkplan.IPv6Configuration {
	return networkplan.IPv6Configuration{Strategy: networkplan.IPv6ULANAT66Lab, LabPrefix: "fd12:3456:789a:1::/64"}
}

func prepareIPv6HostState(t *testing.T, root, forwarding, wanAcceptRA string) {
	t.Helper()
	for path, value := range map[string]string{
		"proc/sys/net/ipv6/conf/all/forwarding": forwarding,
		"proc/sys/net/ipv6/conf/eth0/accept_ra": wanAcceptRA,
	} {
		if value == "" {
			continue
		}
		target := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(value), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func writeRadvdConfig(t *testing.T, root string, contents []byte, mode os.FileMode) string {
	t.Helper()
	target := rootedPath(root, networkplan.RadvdConfigPath)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, contents, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, mode); err != nil {
		t.Fatal(err)
	}
	return target
}

type ipv6ApplyFixture struct {
	applier  Applier
	staged   networkplan.StagedPlan
	manifest networktransaction.WatchdogManifest
	hostRoot string
	machine  *fakeApplyMachine
	dhcp4    *fakeDHCP4Service
	ipv6     *fakeIPv6Machine
}

func newIPv6ApplyFixture(t *testing.T, staged networkplan.StagedPlan, hostRoot string) ipv6ApplyFixture {
	t.Helper()
	now := staged.Transaction.CreatedAt
	store := networktransaction.FileStore{Root: filepath.Join(t.TempDir(), "transactions")}
	spec, err := (Snapshotter{Store: store, HostRoot: hostRoot}).Capture(staged)
	if err != nil {
		t.Fatal(err)
	}
	validator := Validator{Store: store, Runner: &recordingRunner{}, Now: func() time.Time { return now.Add(time.Second) }}
	if _, err := validator.Validate(context.Background(), staged); err != nil {
		t.Fatal(err)
	}
	manifest, err := networktransaction.NewWatchdogManifest(*staged.Transaction, now.Add(2*time.Second), 2*time.Minute, spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteManifest(manifest); err != nil {
		t.Fatal(err)
	}
	record, err := staged.Transaction.ArmWatchdog(manifest.CreatedAt, manifest.ConfirmBy.Sub(manifest.CreatedAt))
	if err != nil {
		t.Fatal(err)
	}
	record, err = record.BeginApply(now.Add(3 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	staged.Transaction = &record
	staged.Status = string(record.Phase)
	fixture := ipv6ApplyFixture{staged: staged, manifest: manifest, hostRoot: hostRoot, machine: &fakeApplyMachine{}, dhcp4: &fakeDHCP4Service{}, ipv6: &fakeIPv6Machine{}}
	fixture.applier = Applier{Store: store, HostRoot: hostRoot, Machine: fixture.machine, DHCP4: fixture.dhcp4, IPv6: fixture.ipv6}
	return fixture
}

func TestSnapshotterCapturesRoutedIPv6State(t *testing.T) {
	now := time.Unix(4000, 0)
	hostRoot := prepareHostRoot(t, "0\n")
	prepareIPv6HostState(t, hostRoot, "0\n", "1\n")
	original := []byte("interface old { AdvSendAdvert off; };\n")
	writeRadvdConfig(t, hostRoot, original, 0o640)
	transactionRoot := filepath.Join(t.TempDir(), "transactions")
	staged := ipv6StagedPlan(t, now, ulaConfiguration(), ipv6ReadyInspection())
	spec, err := (Snapshotter{Store: networktransaction.FileStore{Root: transactionRoot}, HostRoot: hostRoot}).Capture(staged)
	if err != nil {
		t.Fatal(err)
	}
	ipv6 := spec.IPv6
	if ipv6.Firewall != "ROUTE" || ipv6.Ip6tablesPath != "/usr/sbin/ip6tables" || ipv6.ForwardParent != "DOCKER-USER" || !ipv6.NAT66 || ipv6.Forwarding != 0 || ipv6.AcceptRAInterface != "eth0" || ipv6.AcceptRA != 1 || !ipv6.RadvdConfigExisted || ipv6.RadvdConfigMode != 0o640 || ipv6.RadvdConfigSHA256 != digest(string(original)) {
		t.Fatalf("unexpected IPv6 rollback snapshot: %+v", ipv6)
	}
	backup, err := os.ReadFile(filepath.Join(transactionRoot, applyID, radvdBackupName))
	if err != nil || string(backup) != string(original) {
		t.Fatalf("radvd backup mismatch: %q err=%v", backup, err)
	}

	for _, acceptRA := range []string{"0\n", "2\n", ""} {
		hostRoot := prepareHostRoot(t, "1\n")
		prepareIPv6HostState(t, hostRoot, "1\n", acceptRA)
		spec, err := (Snapshotter{Store: networktransaction.FileStore{Root: filepath.Join(t.TempDir(), "transactions")}, HostRoot: hostRoot}).Capture(ipv6StagedPlan(t, now, ulaConfiguration(), ipv6ReadyInspection()))
		if err != nil {
			t.Fatal(err)
		}
		if spec.IPv6.Forwarding != 1 || spec.IPv6.AcceptRAInterface != "" || spec.IPv6.RadvdConfigExisted {
			t.Fatalf("accept_ra %q must not be managed: %+v", acceptRA, spec.IPv6)
		}
	}
}

func TestSnapshotterRecordsBlockedIPv6AndRefusesUnsafeIPv6Hosts(t *testing.T) {
	now := time.Unix(4000, 0)
	hostRoot := prepareHostRoot(t, "0\n")
	noDocker := ipv6ReadyInspection()
	noDocker.IPv6DockerUserChain = false
	staged := ipv6StagedPlan(t, now, networkplan.IPv6Configuration{Strategy: networkplan.IPv6Disabled}, noDocker)
	spec, err := (Snapshotter{Store: networktransaction.FileStore{Root: filepath.Join(t.TempDir(), "transactions")}, HostRoot: hostRoot}).Capture(staged)
	if err != nil {
		t.Fatal(err)
	}
	if spec.IPv6 != (networktransaction.IPv6RollbackSpec{Firewall: "BLOCK", Ip6tablesPath: "/usr/sbin/ip6tables", ForwardParent: "FORWARD"}) {
		t.Fatalf("unexpected blocked IPv6 snapshot: %+v", spec.IPv6)
	}

	cases := map[string]func(*networkplan.StagedPlan){
		"unreadable ip6tables": func(staged *networkplan.StagedPlan) { staged.Preview.FirewallEnvironment.IPv6FirewallReady = false },
		"kernel without IPv6":  func(staged *networkplan.StagedPlan) { staged.Preview.FirewallEnvironment.IPv6Available = false },
		"missing radvd":        func(staged *networkplan.StagedPlan) { staged.Preview.RadvdConf = "" },
		"stale IPv6 chains":    func(staged *networkplan.StagedPlan) { staged.Preview.FirewallEnvironment.ShakerProxyIPv6Chains = true },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			hostRoot := prepareHostRoot(t, "0\n")
			prepareIPv6HostState(t, hostRoot, "0\n", "1\n")
			staged := ipv6StagedPlan(t, now, ulaConfiguration(), ipv6ReadyInspection())
			edit(&staged)
			if _, err := (Snapshotter{Store: networktransaction.FileStore{Root: filepath.Join(t.TempDir(), "transactions")}, HostRoot: hostRoot}).Capture(staged); err == nil {
				t.Fatal("unsafe IPv6 host state reached the watchdog manifest")
			}
		})
	}
}

func TestValidatorRunsNativeIPv6SyntaxChecks(t *testing.T) {
	now := time.Unix(3000, 0)
	runner := &recordingRunner{}
	staged := ipv6StagedPlan(t, now, ulaConfiguration(), ipv6ReadyInspection())
	evidence, err := (Validator{Store: networktransaction.FileStore{Root: filepath.Join(t.TempDir(), "transactions")}, Runner: runner, Now: func() time.Time { return now }}).Validate(context.Background(), staged)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.FirewallIPv6SHA256 != digest(staged.Preview.FirewallRestoreIPv6) || !evidence.FirewallIPv6RestoreOK || evidence.RadvdSHA256 != digest(staged.Preview.RadvdConf) || !evidence.RadvdConfigOK {
		t.Fatalf("IPv6 syntax evidence is incomplete: %+v", evidence)
	}
	var ip6tables, radvd *runnerCall
	for index := range runner.calls {
		call := &runner.calls[index]
		switch call.path {
		case "/usr/sbin/ip6tables-restore":
			ip6tables = call
		case "/usr/sbin/radvd":
			radvd = call
		}
	}
	if ip6tables == nil || strings.Join(ip6tables.args, " ") != "--test" || ip6tables.input != staged.Preview.FirewallRestoreIPv6 {
		t.Fatalf("ip6tables-restore --test was not run on the rendered batch: %+v", runner.calls)
	}
	if radvd == nil || strings.Join(radvd.args, " ") != "--configtest --config /dev/stdin --logmethod stderr" || radvd.input != staged.Preview.RadvdConf {
		t.Fatalf("radvd --configtest was not run on the rendered configuration: %+v", runner.calls)
	}
	osRunner := OSRunner{TransactionRoot: "/var/lib/shakerproxy/gatewayd/transactions"}
	if !osRunner.allowed("/usr/sbin/ip6tables-restore", []string{"--test"}, "*filter\nCOMMIT\n") || !osRunner.allowed("/usr/sbin/radvd", radvdConfigTestArguments(), "interface x {};") {
		t.Fatal("native IPv6 syntax checks were not allowlisted")
	}
	if osRunner.allowed("/usr/sbin/ip6tables-restore", []string{"--noflush"}, "*filter\nCOMMIT\n") || osRunner.allowed("/usr/sbin/radvd", []string{"--config", "/etc/radvd.conf"}, "x") {
		t.Fatal("IPv6 syntax runner allowlisted a state-changing command")
	}
	tampered := evidence
	tampered.RadvdConfigOK = false
	if tampered.Validate() == nil {
		t.Fatal("radvd digest without a passed test was accepted")
	}
}

func TestApplierRoutesIPv6AfterIPv4AndBeforeDHCP(t *testing.T) {
	now := time.Unix(7000, 0)
	hostRoot := prepareHostRoot(t, "0\n")
	prepareIPv6HostState(t, hostRoot, "0\n", "1\n")
	fixture := newIPv6ApplyFixture(t, ipv6StagedPlan(t, now, ulaConfiguration(), ipv6ReadyInspection()), hostRoot)
	fixture.dhcp4.failAt = "start"
	if err := fixture.applier.Apply(context.Background(), fixture.staged); err == nil || !strings.Contains(err.Error(), "DHCPv4") {
		t.Fatalf("expected the DHCPv4 start (last step) to be reached: %v", err)
	}
	expected := []string{
		"firewall:/usr/sbin/ip6tables:" + digest(fixture.staged.Preview.FirewallRestoreIPv6),
		"attach:/usr/sbin/ip6tables:DOCKER-USER:input=true:nat=true",
		"accept_ra:eth0:2",
		"forwarding:1",
		"restart-radvd",
	}
	if strings.Join(fixture.ipv6.calls, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected IPv6 apply order: %v", fixture.ipv6.calls)
	}
	if len(fixture.machine.calls) != 5 {
		t.Fatalf("IPv6 must follow the IPv4 attachments: %v", fixture.machine.calls)
	}
	target := rootedPath(hostRoot, networkplan.RadvdConfigPath)
	contents, err := os.ReadFile(target)
	if err != nil || string(contents) != fixture.staged.Preview.RadvdConf {
		t.Fatalf("radvd configuration was not written: %q err=%v", contents, err)
	}
	if info, err := os.Stat(target); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("radvd configuration mode is wrong: %v %v", info, err)
	}
}

func TestApplierStopsBeforeForwardingWhenIPv6FirewallFails(t *testing.T) {
	hostRoot := prepareHostRoot(t, "0\n")
	prepareIPv6HostState(t, hostRoot, "0\n", "1\n")
	fixture := newIPv6ApplyFixture(t, ipv6StagedPlan(t, time.Unix(7000, 0), ulaConfiguration(), ipv6ReadyInspection()), hostRoot)
	fixture.ipv6.failOn = "attach:"
	if err := fixture.applier.Apply(context.Background(), fixture.staged); err == nil || !strings.Contains(err.Error(), "IPv6 firewall") {
		t.Fatalf("IPv6 attachment failure was not returned: %v", err)
	}
	for _, call := range fixture.ipv6.calls {
		if strings.HasPrefix(call, "forwarding") || call == "restart-radvd" {
			t.Fatalf("IPv6 forwarding or radvd started without the firewall: %v", fixture.ipv6.calls)
		}
	}
	if len(fixture.dhcp4.calls) != 0 {
		t.Fatalf("DHCPv4 started after an IPv6 failure: %v", fixture.dhcp4.calls)
	}
}

func TestApplierDisabledIPv6LoadsDropChainAndStopsRadvd(t *testing.T) {
	hostRoot := prepareHostRoot(t, "0\n")
	stale := writeRadvdConfig(t, hostRoot, []byte("stale\n"), 0o644)
	fixture := newIPv6ApplyFixture(t, ipv6StagedPlan(t, time.Unix(7000, 0), networkplan.IPv6Configuration{Strategy: networkplan.IPv6Disabled}, ipv6ReadyInspection()), hostRoot)
	if err := fixture.applier.Apply(context.Background(), fixture.staged); err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"firewall:/usr/sbin/ip6tables:" + digest(fixture.staged.Preview.FirewallRestoreIPv6),
		"attach:/usr/sbin/ip6tables:DOCKER-USER:input=false:nat=false",
		"disable-radvd",
	}
	if strings.Join(fixture.ipv6.calls, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected DISABLED IPv6 apply: %v", fixture.ipv6.calls)
	}
	if _, err := os.Lstat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale radvd configuration survived a DISABLED apply: %v", err)
	}
}

func TestApplierWithoutKernelIPv6OnlyEnsuresRadvdIsOff(t *testing.T) {
	applier, staged, _, _, _ := applyingFixture(t)
	if err := applier.Apply(context.Background(), staged); err != nil {
		t.Fatal(err)
	}
	if calls := applier.IPv6.(*fakeIPv6Machine).calls; strings.Join(calls, ",") != "disable-radvd" {
		t.Fatalf("IPv6-less host received IPv6 mutations: %v", calls)
	}
}

func TestApplierRejectsIPv6MismatchBeforeHostMutation(t *testing.T) {
	cases := map[string]func(*ipv6ApplyFixture){
		"changed firewall": func(fixture *ipv6ApplyFixture) { fixture.staged.Preview.FirewallRestoreIPv6 += "# changed\n" },
		"changed radvd":    func(fixture *ipv6ApplyFixture) { fixture.staged.Preview.RadvdConf += "# changed\n" },
		"missing machine":  func(fixture *ipv6ApplyFixture) { fixture.applier.IPv6 = nil },
		"changed parent": func(fixture *ipv6ApplyFixture) {
			fixture.staged.Preview.FirewallEnvironment.IPv6DockerUserChain = false
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			hostRoot := prepareHostRoot(t, "0\n")
			prepareIPv6HostState(t, hostRoot, "0\n", "1\n")
			fixture := newIPv6ApplyFixture(t, ipv6StagedPlan(t, time.Unix(7000, 0), ulaConfiguration(), ipv6ReadyInspection()), hostRoot)
			edit(&fixture)
			if err := fixture.applier.Apply(context.Background(), fixture.staged); err == nil {
				t.Fatal("IPv6 mismatch was not rejected")
			}
			if len(fixture.machine.calls) != 0 || len(fixture.ipv6.calls) != 0 || len(fixture.dhcp4.calls) != 0 {
				t.Fatalf("host mutated before IPv6 rejection: %v %v %v", fixture.machine.calls, fixture.ipv6.calls, fixture.dhcp4.calls)
			}
		})
	}
}

func TestRollbackRestoresPriorIPv6StateExactly(t *testing.T) {
	now := time.Unix(5000, 0)
	hostRoot := prepareHostRoot(t, "0\n")
	prepareIPv6HostState(t, hostRoot, "0\n", "1\n")
	original := []byte("# administrator radvd file kept by ShakerProxy\n")
	target := writeRadvdConfig(t, hostRoot, original, 0o640)
	fixture := newIPv6ApplyFixture(t, ipv6StagedPlan(t, now, ulaConfiguration(), ipv6ReadyInspection()), hostRoot)
	if err := fixture.applier.Apply(context.Background(), fixture.staged); err != nil {
		t.Fatal(err)
	}
	if contents, _ := os.ReadFile(target); string(contents) != fixture.staged.Preview.RadvdConf {
		t.Fatal("apply did not install the rendered radvd configuration")
	}
	machine, ipv6 := &fakeRollbackMachine{}, &fakeIPv6Machine{}
	executor := RollbackExecutor{Store: fixture.applier.Store, HostRoot: hostRoot, Machine: machine, DHCP4: &fakeDHCP4Service{}, IPv6: ipv6}
	if err := executor.Execute(context.Background(), fixture.manifest); err != nil {
		t.Fatal(err)
	}
	expected := []string{"disable-radvd", "forwarding:0", "accept_ra:eth0:1", "remove-firewall:/usr/sbin/ip6tables:DOCKER-USER"}
	if strings.Join(ipv6.calls, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected IPv6 rollback: %v", ipv6.calls)
	}
	contents, err := os.ReadFile(target)
	if err != nil || string(contents) != string(original) {
		t.Fatalf("radvd configuration was not restored: %q err=%v", contents, err)
	}
	if info, err := os.Stat(target); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("radvd configuration mode was not restored: %v %v", info, err)
	}
	if strings.Join(machine.calls, ",") != "firewall:/usr/sbin/iptables,netplan,forwarding:0" {
		t.Fatalf("IPv4 rollback changed: %v", machine.calls)
	}
}

func TestRollbackRemovesNewRadvdConfigAndContinuesAfterFailures(t *testing.T) {
	hostRoot := prepareHostRoot(t, "0\n")
	prepareIPv6HostState(t, hostRoot, "1\n", "0\n")
	fixture := newIPv6ApplyFixture(t, ipv6StagedPlan(t, time.Unix(5000, 0), ulaConfiguration(), ipv6ReadyInspection()), hostRoot)
	if err := fixture.applier.Apply(context.Background(), fixture.staged); err != nil {
		t.Fatal(err)
	}
	ipv6 := &fakeIPv6Machine{failOn: "disable-radvd"}
	executor := RollbackExecutor{Store: fixture.applier.Store, HostRoot: hostRoot, Machine: &fakeRollbackMachine{}, DHCP4: &fakeDHCP4Service{}, IPv6: ipv6}
	err := executor.Execute(context.Background(), fixture.manifest)
	if err == nil || !strings.Contains(err.Error(), "router advertisements") {
		t.Fatalf("radvd rollback failure was not reported: %v", err)
	}
	if strings.Join(ipv6.calls, ",") != "disable-radvd,forwarding:1,remove-firewall:/usr/sbin/ip6tables:DOCKER-USER" {
		t.Fatalf("independent IPv6 recovery steps did not all run: %v", ipv6.calls)
	}
	if _, err := os.Lstat(rootedPath(hostRoot, networkplan.RadvdConfigPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("new radvd configuration survived rollback: %v", err)
	}
}

func TestRollbackRejectsTamperedRadvdBackupButRestoresTheRest(t *testing.T) {
	hostRoot := prepareHostRoot(t, "0\n")
	prepareIPv6HostState(t, hostRoot, "0\n", "1\n")
	writeRadvdConfig(t, hostRoot, []byte("original\n"), 0o644)
	fixture := newIPv6ApplyFixture(t, ipv6StagedPlan(t, time.Unix(5000, 0), ulaConfiguration(), ipv6ReadyInspection()), hostRoot)
	directory, _ := fixture.applier.Store.TransactionDirectory(fixture.manifest.ApplyID)
	if err := os.WriteFile(filepath.Join(directory, radvdBackupName), []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ipv6 := &fakeIPv6Machine{}
	executor := RollbackExecutor{Store: fixture.applier.Store, HostRoot: hostRoot, Machine: &fakeRollbackMachine{}, DHCP4: &fakeDHCP4Service{}, IPv6: ipv6}
	if err := executor.Execute(context.Background(), fixture.manifest); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("tampered radvd backup was not rejected: %v", err)
	}
	if len(ipv6.calls) != 4 {
		t.Fatalf("IPv6 recovery stopped at the tampered backup: %v", ipv6.calls)
	}
}

func TestRollbackOfPreIPv6ManifestDoesNotTouchIPv6(t *testing.T) {
	executor, manifest, _, _, _ := rollbackFixture(t, nil, "0\n")
	if manifest.Rollback.IPv6 != (networktransaction.IPv6RollbackSpec{}) {
		t.Fatalf("IPv4-only fixture recorded IPv6 state: %+v", manifest.Rollback.IPv6)
	}
	if err := executor.Execute(context.Background(), manifest); err != nil {
		t.Fatalf("IPv4-only manifest needs no IPv6 machine: %v", err)
	}
	manifest.Rollback.IPv6 = networktransaction.IPv6RollbackSpec{Firewall: "BLOCK", Ip6tablesPath: "/usr/sbin/ip6tables", ForwardParent: "FORWARD"}
	if err := executor.Execute(context.Background(), manifest); err == nil || !strings.Contains(err.Error(), "IPv6 rollback machine") {
		t.Fatalf("IPv6 manifest without an IPv6 machine did not fail closed: %v", err)
	}
}

func TestOSIPv6MachineRunsOnlyExactCommands(t *testing.T) {
	var calls []string
	machine := OSIPv6Machine{run: func(_ context.Context, path string, arguments []string, input string) (rollbackCommandResult, error) {
		calls = append(calls, path+" "+strings.Join(arguments, " "))
		for _, argument := range arguments {
			if argument == "-C" {
				return rollbackCommandResult{exitCode: 1}, nil
			}
		}
		return rollbackCommandResult{}, nil
	}}
	ctx := context.Background()
	for _, step := range []error{
		machine.SetIPv6Forwarding(ctx, 1),
		machine.SetIPv6AcceptRA(ctx, "enp1s0.10", 2),
		machine.LoadShakerProxyIPv6Firewall(ctx, "/usr/sbin/ip6tables", "*filter\nCOMMIT\n"),
		machine.EnsureShakerProxyIPv6Attachments(ctx, IPv6Attachments{Ip6tablesPath: "/usr/sbin/ip6tables", ForwardParent: "FORWARD", Input: true, NAT: true}),
		machine.RestartRadvd(ctx),
		machine.EnableRadvd(ctx),
		machine.DisableRadvd(ctx),
	} {
		if step != nil {
			t.Fatal(step)
		}
	}
	expected := []string{
		"/usr/sbin/sysctl -w net.ipv6.conf.all.forwarding=1",
		"/usr/sbin/sysctl -w net/ipv6/conf/enp1s0.10/accept_ra=2",
		"/usr/sbin/ip6tables-restore --noflush",
		"/usr/sbin/ip6tables -w 5 -C FORWARD -j SHAKERPROXY-FORWARD",
		"/usr/sbin/ip6tables -w 5 -I FORWARD 1 -j SHAKERPROXY-FORWARD",
		"/usr/sbin/ip6tables -w 5 -C INPUT -j SHAKERPROXY-INPUT",
		"/usr/sbin/ip6tables -w 5 -I INPUT 1 -j SHAKERPROXY-INPUT",
		"/usr/sbin/ip6tables -w 5 -t nat -C POSTROUTING -j SHAKERPROXY-POSTROUTING",
		"/usr/sbin/ip6tables -w 5 -t nat -I POSTROUTING 1 -j SHAKERPROXY-POSTROUTING",
		"/usr/bin/systemctl restart shakerproxy-radvd.service",
		"/usr/bin/systemctl enable shakerproxy-radvd.service",
		"/usr/bin/systemctl disable --now shakerproxy-radvd.service",
	}
	if strings.Join(calls, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("unexpected IPv6 host commands:\n%s", strings.Join(calls, "\n"))
	}
	for _, rejected := range []struct {
		path  string
		args  []string
		input string
	}{
		{"/usr/sbin/sysctl", []string{"-w", "net.ipv6.conf.all.accept_ra=2"}, ""},
		{"/usr/sbin/sysctl", []string{"-w", "net/ipv6/conf/all/accept_ra=2"}, ""},
		{"/usr/sbin/sysctl", []string{"-w", "net/ipv6/conf/eth0/../all/accept_ra=2"}, ""},
		{"/usr/sbin/sysctl", []string{"-w", "net.ipv6.conf.all.forwarding=2"}, ""},
		{"/usr/sbin/ip6tables", []string{"-w", "5", "-F", "FORWARD"}, ""},
		{"/usr/sbin/ip6tables", []string{"-w", "5", "-I", "FORWARD", "1", "-j", "ACCEPT"}, ""},
		{"/usr/sbin/ip6tables-restore", []string{}, "*filter\nCOMMIT\n"},
		{"/usr/bin/systemctl", []string{"restart", "radvd.service"}, ""},
		{"/bin/sh", []string{"-c", "ip6tables -F"}, ""},
	} {
		if allowedIPv6Command(rejected.path, rejected.args, rejected.input) {
			t.Fatalf("broad IPv6 command was allowlisted: %s %v", rejected.path, rejected.args)
		}
	}
}

func TestRemoveShakerProxyIPv6FirewallDeletesOnlyOwnedState(t *testing.T) {
	var calls []string
	machine := OSIPv6Machine{run: func(_ context.Context, path string, arguments []string, _ string) (rollbackCommandResult, error) {
		joined := strings.Join(arguments, " ")
		calls = append(calls, joined)
		switch {
		case strings.Contains(joined, "SHAKERPROXY-POSTROUTING"):
			return rollbackCommandResult{exitCode: 1}, nil // NAT66 chain absent (native prefix)
		case strings.Contains(joined, "-C") && strings.Count(strings.Join(calls, "\n"), joined) > 1:
			return rollbackCommandResult{exitCode: 1}, nil // no duplicate hook
		}
		return rollbackCommandResult{}, nil
	}}
	if err := machine.RemoveShakerProxyIPv6Firewall(context.Background(), "/usr/sbin/ip6tables", "DOCKER-USER"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(calls, "\n")
	for _, exact := range []string{"-w 5 -D DOCKER-USER -j SHAKERPROXY-FORWARD", "-w 5 -X SHAKERPROXY-FORWARD", "-w 5 -D INPUT -j SHAKERPROXY-INPUT", "-w 5 -X SHAKERPROXY-INPUT", "-w 5 -t nat -S SHAKERPROXY-POSTROUTING"} {
		if !strings.Contains(joined, exact) {
			t.Fatalf("missing owned IPv6 cleanup %q in:\n%s", exact, joined)
		}
	}
	if strings.Contains(joined, "-D POSTROUTING") || strings.Contains(joined, "-F DOCKER-USER") {
		t.Fatalf("IPv6 cleanup touched state ShakerProxy does not own:\n%s", joined)
	}
	if err := machine.RemoveShakerProxyIPv6Firewall(context.Background(), "/tmp/ip6tables", "DOCKER-USER"); err == nil {
		t.Fatal("unapproved ip6tables path was accepted")
	}
}
