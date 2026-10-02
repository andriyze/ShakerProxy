package networkapply

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

type fakeApplyMachine struct {
	calls  []string
	failAt int
}

type fakeDHCP4Service struct {
	calls  []string
	failAt string
}

func (s *fakeDHCP4Service) StartDHCP4(context.Context) error {
	s.calls = append(s.calls, "start")
	if s.failAt == "start" {
		return errors.New("DHCPv4 start failed")
	}
	return nil
}

func (s *fakeDHCP4Service) EnsureDHCP4Enabled(context.Context) error {
	s.calls = append(s.calls, "enable")
	if s.failAt == "enable" {
		return errors.New("DHCPv4 enable failed")
	}
	return nil
}

func (s *fakeDHCP4Service) DisableDHCP4(context.Context) error {
	s.calls = append(s.calls, "disable")
	if s.failAt == "disable" {
		return errors.New("DHCPv4 disable failed")
	}
	return nil
}

func (m *fakeApplyMachine) record(value string) error {
	m.calls = append(m.calls, value)
	if m.failAt > 0 && len(m.calls) == m.failAt {
		return errors.New("apply machine failed")
	}
	return nil
}

func (m *fakeApplyMachine) GenerateNetplan(context.Context) error {
	return m.record("netplan-generate")
}
func (m *fakeApplyMachine) SetIPv4Forwarding(_ context.Context, value int) error {
	return m.record("forwarding:" + string(rune('0'+value)))
}
func (m *fakeApplyMachine) SetIPv4SendRedirects(_ context.Context, interfaceName string, value int) error {
	return m.record("redirects:" + interfaceName + ":" + string(rune('0'+value)))
}
func (m *fakeApplyMachine) SetBridgeNFCallIPTables(_ context.Context, value int) error {
	return m.record("bridge-nf:" + string(rune('0'+value)))
}
func (m *fakeApplyMachine) ApplyNetplan(context.Context) error { return m.record("netplan-apply") }
func (m *fakeApplyMachine) LoadShakerProxyFirewall(_ context.Context, path, restore string) error {
	return m.record("firewall:" + path + ":" + digest(restore))
}
func (m *fakeApplyMachine) EnsureShakerProxyAttachments(_ context.Context, path string, nat bool) error {
	return m.record("attachments:" + path + ":" + map[bool]string{true: "nat", false: "filter"}[nat])
}

func applyingFixtureFor(t *testing.T, singleArm bool) (Applier, networkplan.StagedPlan, string, *fakeApplyMachine, *fakeDHCP4Service) {
	t.Helper()
	now := time.Unix(7000, 0)
	hostRoot := prepareHostRoot(t, "0\n")
	transactionRoot := filepath.Join(t.TempDir(), "transactions")
	store := networktransaction.FileStore{Root: transactionRoot}
	staged := validStagedPlan(t, now)
	if singleArm {
		staged = singleArmStagedPlan(t, now)
		prepareRedirectState(t, hostRoot, "eth0", "1\n")
	}
	staged.Plan.IPv4.NAT44 = true
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
	machine := &fakeApplyMachine{}
	dhcp4 := &fakeDHCP4Service{}
	return Applier{Store: store, HostRoot: hostRoot, Machine: machine, DHCP4: dhcp4, IPv6: &fakeIPv6Machine{}}, staged, hostRoot, machine, dhcp4
}

func applyingFixture(t *testing.T) (Applier, networkplan.StagedPlan, string, *fakeApplyMachine, *fakeDHCP4Service) {
	return applyingFixtureFor(t, false)
}

func TestApplierRequiresEvidenceThenExecutesFixedOrder(t *testing.T) {
	applier, staged, hostRoot, machine, dhcp4 := applyingFixture(t)
	if err := applier.Apply(context.Background(), staged); err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"netplan-generate", "forwarding:1", "netplan-apply",
		"firewall:/usr/sbin/iptables:" + digest(staged.Preview.FirewallRestoreIPv4),
		"attachments:/usr/sbin/iptables:nat",
	}
	if strings.Join(machine.calls, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected apply order: %v", machine.calls)
	}
	if strings.Join(dhcp4.calls, ",") != "start" {
		t.Fatalf("DHCPv4 was not started after network attachment: %v", dhcp4.calls)
	}
	contents, err := os.ReadFile(rootedPath(hostRoot, managedNetplanPath))
	if err != nil || string(contents) != staged.Preview.NetplanYAML {
		t.Fatalf("managed Netplan was not written: contents=%q err=%v", contents, err)
	}
	contents, err = os.ReadFile(rootedPath(hostRoot, managedDHCP4Path))
	if err != nil || string(contents) != staged.Preview.KeaDHCP4JSON {
		t.Fatalf("managed Kea DHCPv4 file was not written: contents=%q err=%v", contents, err)
	}
}

func TestApplierSingleArmDisablesDHCPAndRedirectsWithoutNICRewrite(t *testing.T) {
	applier, staged, hostRoot, machine, dhcp4 := applyingFixtureFor(t, true)
	dhcp4Target := rootedPath(hostRoot, managedDHCP4Path)
	if err := os.MkdirAll(filepath.Dir(dhcp4Target), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dhcp4Target, []byte("old managed DHCP configuration"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := applier.Apply(context.Background(), staged); err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"netplan-generate", "forwarding:1", "redirects:eth0:0", "netplan-apply",
		"firewall:/usr/sbin/iptables:" + digest(staged.Preview.FirewallRestoreIPv4),
		"attachments:/usr/sbin/iptables:nat",
	}
	if strings.Join(machine.calls, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected single-arm apply order: %v", machine.calls)
	}
	if strings.Join(dhcp4.calls, ",") != "disable" {
		t.Fatalf("single-arm DHCP service was not disabled: %v", dhcp4.calls)
	}
	if _, err := os.Lstat(dhcp4Target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("single-arm left a managed DHCP configuration behind: %v", err)
	}
	contents, err := os.ReadFile(rootedPath(hostRoot, managedNetplanPath))
	if err != nil || string(contents) != "network:\n  version: 2\n" {
		t.Fatalf("single-arm Netplan artifact was not inert: %q %v", contents, err)
	}
}

func TestApplierRejectsChangedArtifactBeforeHostMutation(t *testing.T) {
	applier, staged, hostRoot, machine, dhcp4 := applyingFixture(t)
	staged.Preview.NetplanYAML += "# changed after syntax validation\n"
	if err := applier.Apply(context.Background(), staged); err == nil || !strings.Contains(err.Error(), "evidence") {
		t.Fatalf("changed artifact was not rejected: %v", err)
	}
	if len(machine.calls) != 0 {
		t.Fatalf("host commands ran after evidence mismatch: %v", machine.calls)
	}
	if len(dhcp4.calls) != 0 {
		t.Fatalf("DHCPv4 ran after evidence mismatch: %v", dhcp4.calls)
	}
	if _, err := os.Lstat(rootedPath(hostRoot, managedNetplanPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("managed Netplan was written before evidence rejection: %v", err)
	}
}

func TestApplierStopsAtFirstMachineFailureForImmediateRollback(t *testing.T) {
	applier, staged, _, machine, dhcp4 := applyingFixture(t)
	machine.failAt = 2
	if err := applier.Apply(context.Background(), staged); err == nil || !strings.Contains(err.Error(), "IPv4 forwarding") {
		t.Fatalf("machine failure was not returned: %v", err)
	}
	if strings.Join(machine.calls, ",") != "netplan-generate,forwarding:1" {
		t.Fatalf("apply continued after failure: %v", machine.calls)
	}
	if len(dhcp4.calls) != 0 {
		t.Fatalf("DHCPv4 started after earlier apply failure: %v", dhcp4.calls)
	}
}

func TestApplierReturnsDHCP4StartFailureForImmediateRollback(t *testing.T) {
	applier, staged, _, machine, dhcp4 := applyingFixture(t)
	dhcp4.failAt = "start"
	err := applier.Apply(context.Background(), staged)
	if err == nil || !strings.Contains(err.Error(), "DHCPv4") {
		t.Fatalf("DHCPv4 start failure was not returned: %v", err)
	}
	if len(machine.calls) != 5 || strings.Join(dhcp4.calls, ",") != "start" {
		t.Fatalf("unexpected final apply ordering: machine=%v dhcp=%v", machine.calls, dhcp4.calls)
	}
}

func TestApplyCommandAllowlistRejectsBroadMutation(t *testing.T) {
	if !allowedApplyCommand("/usr/sbin/iptables-restore", []string{"--noflush"}, "*filter\nCOMMIT\n") {
		t.Fatal("owned restore load was rejected")
	}
	if allowedApplyCommand("/usr/sbin/iptables-restore", []string{}, "*filter\nCOMMIT\n") {
		t.Fatal("flushing restore invocation was allowlisted")
	}
	if !allowedApplyCommand("/usr/sbin/iptables", []string{"-w", "5", "-I", "DOCKER-USER", "1", "-j", "SHAKERPROXY-FORWARD"}, "") {
		t.Fatal("exact filter attachment was rejected")
	}
	if allowedApplyCommand("/usr/sbin/iptables", []string{"-w", "5", "-I", "FORWARD", "1", "-j", "ACCEPT"}, "") {
		t.Fatal("broad forwarding mutation was allowlisted")
	}
	if allowedApplyCommand("/bin/sh", []string{"-c", "iptables-restore"}, "rules") {
		t.Fatal("shell command was allowlisted")
	}
	if !allowedApplyCommand("/usr/bin/systemctl", []string{"start", "shakerproxy-dhcp4.service"}, "") || !allowedApplyCommand("/usr/bin/systemctl", []string{"enable", "shakerproxy-dhcp4.service"}, "") {
		t.Fatal("exact DHCPv4 service operations were rejected")
	}
	if allowedApplyCommand("/usr/bin/systemctl", []string{"start", "kea-dhcp4-server.service"}, "") {
		t.Fatal("distribution DHCP service operation was allowlisted")
	}
}
