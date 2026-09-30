package networkapply

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

type fakeRollbackMachine struct {
	calls         []string
	firewallError error
	netplanError  error
	sysctlError   error
}

func (m *fakeRollbackMachine) RemoveShakerProxyFirewall(_ context.Context, path string) error {
	m.calls = append(m.calls, "firewall:"+path)
	return m.firewallError
}

func (m *fakeRollbackMachine) ReloadNetplan(context.Context) error {
	m.calls = append(m.calls, "netplan")
	return m.netplanError
}

func (m *fakeRollbackMachine) SetIPv4Forwarding(_ context.Context, value int) error {
	m.calls = append(m.calls, "forwarding:"+string(rune('0'+value)))
	return m.sysctlError
}
func (m *fakeRollbackMachine) SetIPv4SendRedirects(_ context.Context, interfaceName string, value int) error {
	m.calls = append(m.calls, "redirects:"+interfaceName+":"+string(rune('0'+value)))
	return m.sysctlError
}

func rollbackFixture(t *testing.T, original []byte, forwarding string) (RollbackExecutor, networktransaction.WatchdogManifest, string, *fakeRollbackMachine, *fakeDHCP4Service) {
	t.Helper()
	now := time.Unix(5000, 0)
	hostRoot := prepareHostRoot(t, forwarding)
	if original != nil {
		if err := os.WriteFile(rootedPath(hostRoot, managedNetplanPath), original, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	transactionRoot := filepath.Join(t.TempDir(), "transactions")
	store := networktransaction.FileStore{Root: transactionRoot}
	staged := validStagedPlan(t, now)
	spec, err := (Snapshotter{Store: store, HostRoot: hostRoot}).Capture(staged)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := networktransaction.NewWatchdogManifest(*staged.Transaction, now.Add(time.Second), 2*time.Minute, spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteManifest(manifest); err != nil {
		t.Fatal(err)
	}
	machine := &fakeRollbackMachine{}
	dhcp4 := &fakeDHCP4Service{}
	return RollbackExecutor{Store: store, HostRoot: hostRoot, Machine: machine, DHCP4: dhcp4}, manifest, hostRoot, machine, dhcp4
}

func TestRollbackExecutorRestoresExactOwnedState(t *testing.T) {
	original := []byte("network:\n  version: 2\n")
	executor, manifest, hostRoot, machine, dhcp4 := rollbackFixture(t, original, "0\n")
	target := rootedPath(hostRoot, managedNetplanPath)
	if err := os.WriteFile(target, []byte("network:\n  broken: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dhcp4Target := rootedPath(hostRoot, managedDHCP4Path)
	if err := os.MkdirAll(filepath.Dir(dhcp4Target), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dhcp4Target, []byte("applied"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := executor.Execute(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(target)
	if err != nil || string(contents) != string(original) {
		t.Fatalf("Netplan was not restored: contents=%q err=%v", contents, err)
	}
	if info, err := os.Stat(target); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("Netplan mode was not restored: info=%v err=%v", info, err)
	}
	if _, err := os.Lstat(dhcp4Target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("new managed DHCPv4 configuration remained: %v", err)
	}
	expected := []string{"firewall:/usr/sbin/iptables", "netplan", "forwarding:0"}
	if strings.Join(machine.calls, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected rollback order: %v", machine.calls)
	}
	if strings.Join(dhcp4.calls, ",") != "disable" {
		t.Fatalf("DHCPv4 was not disabled before rollback: %v", dhcp4.calls)
	}
}

func TestRollbackExecutorRemovesNewOwnedNetplanFile(t *testing.T) {
	executor, manifest, hostRoot, _, _ := rollbackFixture(t, nil, "1\n")
	target := rootedPath(hostRoot, managedNetplanPath)
	if err := os.WriteFile(target, []byte("network:\n  version: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := executor.Execute(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("new owned Netplan file remained: %v", err)
	}
}

func TestRollbackExecutorRestoresSingleArmRedirectState(t *testing.T) {
	executor, manifest, _, machine, _ := rollbackFixture(t, nil, "1\n")
	manifest.Rollback.IPv4SendRedirectsInterface = "eth0"
	manifest.Rollback.IPv4SendRedirects = 1
	if err := executor.Execute(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	expected := []string{"firewall:/usr/sbin/iptables", "netplan", "forwarding:1", "redirects:eth0:1"}
	if strings.Join(machine.calls, ",") != strings.Join(expected, ",") {
		t.Fatalf("single-arm redirect state was not restored: %v", machine.calls)
	}
}

func TestRollbackExecutorRestoresExactPriorDHCP4Configuration(t *testing.T) {
	now := time.Unix(5000, 0)
	hostRoot := prepareHostRoot(t, "0\n")
	target := rootedPath(hostRoot, managedDHCP4Path)
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		t.Fatal(err)
	}
	original := []byte("{\"Dhcp4\":{\"valid-lifetime\":60}}\n")
	if err := os.WriteFile(target, original, 0o640); err != nil {
		t.Fatal(err)
	}
	store := networktransaction.FileStore{Root: filepath.Join(t.TempDir(), "transactions")}
	staged := validStagedPlan(t, now)
	spec, err := (Snapshotter{Store: store, HostRoot: hostRoot}).Capture(staged)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := networktransaction.NewWatchdogManifest(*staged.Transaction, now.Add(time.Second), 2*time.Minute, spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteManifest(manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("applied"), 0o600); err != nil {
		t.Fatal(err)
	}
	executor := RollbackExecutor{Store: store, HostRoot: hostRoot, Machine: &fakeRollbackMachine{}, DHCP4: &fakeDHCP4Service{}}
	if err := executor.Execute(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(target)
	if err != nil || string(contents) != string(original) {
		t.Fatalf("DHCPv4 configuration was not restored: contents=%q err=%v", contents, err)
	}
	if info, err := os.Stat(target); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("DHCPv4 configuration mode was not restored: info=%v err=%v", info, err)
	}
}

func TestRollbackExecutorSkipsTamperedBackupButContinuesIndependentRecovery(t *testing.T) {
	executor, manifest, _, machine, _ := rollbackFixture(t, []byte("original"), "0\n")
	directory, _ := executor.Store.TransactionDirectory(manifest.ApplyID)
	if err := os.WriteFile(filepath.Join(directory, "netplan.before"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := executor.Execute(context.Background(), manifest); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("tampered backup was not rejected: %v", err)
	}
	expected := []string{"firewall:/usr/sbin/iptables", "forwarding:0"}
	if strings.Join(machine.calls, ",") != strings.Join(expected, ",") {
		t.Fatalf("independent recovery did not continue safely: %v", machine.calls)
	}
}

func TestRollbackExecutorContinuesIndependentRecoverySteps(t *testing.T) {
	executor, manifest, _, machine, dhcp4 := rollbackFixture(t, []byte("original"), "0\n")
	machine.firewallError = errors.New("firewall failed")
	machine.netplanError = errors.New("netplan failed")
	machine.sysctlError = errors.New("sysctl failed")
	dhcp4.failAt = "disable"
	err := executor.Execute(context.Background(), manifest)
	if err == nil || !strings.Contains(err.Error(), "firewall failed") || !strings.Contains(err.Error(), "netplan failed") || !strings.Contains(err.Error(), "sysctl failed") || !strings.Contains(err.Error(), "DHCPv4 disable failed") {
		t.Fatalf("rollback failures were not joined: %v", err)
	}
	if len(machine.calls) != 3 {
		t.Fatalf("rollback stopped before independent recovery steps: %v", machine.calls)
	}
}

func TestRollbackCommandAllowlistIsExact(t *testing.T) {
	if !allowedRollbackCommand("/usr/sbin/netplan", []string{"generate"}) || !allowedRollbackCommand("/usr/sbin/netplan", []string{"apply"}) {
		t.Fatal("fixed Netplan rollback commands were rejected")
	}
	if allowedRollbackCommand("/usr/sbin/netplan", []string{"try"}) {
		t.Fatal("unapproved Netplan command was allowlisted")
	}
	if !allowedRollbackCommand("/usr/sbin/sysctl", []string{"-w", "net.ipv4.ip_forward=0"}) || allowedRollbackCommand("/usr/sbin/sysctl", []string{"-w", "net.ipv4.conf.all.forwarding=0"}) {
		t.Fatal("sysctl allowlist is incorrect")
	}
	if !allowedRollbackCommand("/usr/sbin/sysctl", []string{"-w", "net.ipv4.conf.eth0.send_redirects=0"}) || allowedRollbackCommand("/usr/sbin/sysctl", []string{"-w", "net.ipv4.conf.eth0.send_redirects=2"}) || allowedRollbackCommand("/usr/sbin/sysctl", []string{"-w", "net.ipv4.conf.eth0;reboot.send_redirects=0"}) {
		t.Fatal("single-arm redirect sysctl allowlist is incorrect")
	}
	if !allowedRollbackCommand("/usr/sbin/iptables", []string{"-w", "5", "-D", "DOCKER-USER", "-j", "SHAKERPROXY-FORWARD"}) {
		t.Fatal("exact ShakerProxy detach was rejected")
	}
	if allowedRollbackCommand("/usr/sbin/iptables", []string{"-w", "5", "-F", "DOCKER-USER"}) {
		t.Fatal("Docker chain flush was allowlisted")
	}
	if allowedRollbackCommand("/bin/sh", []string{"-c", "iptables -F"}) {
		t.Fatal("shell command was allowlisted")
	}
	if !allowedRollbackCommand("/usr/bin/systemctl", []string{"disable", "--now", "shakerproxy-dhcp4.service"}) || allowedRollbackCommand("/usr/bin/systemctl", []string{"stop", "kea-dhcp4-server.service"}) {
		t.Fatal("DHCPv4 rollback service allowlist is incorrect")
	}
}

func TestRemoveShakerProxyFirewallAcceptsAlreadyAbsentOwnedChains(t *testing.T) {
	var calls []string
	run := func(_ context.Context, path string, arguments []string) (rollbackCommandResult, error) {
		calls = append(calls, path+":"+strings.Join(arguments, " "))
		return rollbackCommandResult{exitCode: 1, stderr: "chain does not exist"}, nil
	}
	if err := (OSRollbackMachine{run: run}).RemoveShakerProxyFirewall(context.Background(), "/usr/sbin/iptables"); err != nil {
		t.Fatalf("already absent firewall state must be idempotent: %v", err)
	}
	expected := []string{
		"/usr/sbin/iptables:-w 5 -S SHAKERPROXY-FORWARD",
		"/usr/sbin/iptables:-w 5 -t nat -S SHAKERPROXY-POSTROUTING",
	}
	if strings.Join(calls, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("unexpected commands for absent state:\n%s", strings.Join(calls, "\n"))
	}
}

func TestRemoveShakerProxyFirewallRejectsUnexpectedInspectionFailure(t *testing.T) {
	call := 0
	run := func(_ context.Context, _ string, _ []string) (rollbackCommandResult, error) {
		call++
		if call == 1 {
			return rollbackCommandResult{exitCode: 2, stderr: "permission denied"}, nil
		}
		return rollbackCommandResult{exitCode: 1}, nil
	}
	err := (OSRollbackMachine{run: run}).RemoveShakerProxyFirewall(context.Background(), "/usr/sbin/iptables")
	if err == nil || !strings.Contains(err.Error(), "status 2") || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("unexpected inspection failure was masked: %v", err)
	}
}

func TestRemoveShakerProxyFirewallDeletesOnlyOwnedState(t *testing.T) {
	results := []rollbackCommandResult{
		{exitCode: 0}, // owned filter chain exists
		{exitCode: 0}, // attachment exists
		{exitCode: 0}, // attachment deleted
		{exitCode: 1}, // no duplicate attachment
		{exitCode: 0}, // owned chain still exists
		{exitCode: 0}, // chain flushed
		{exitCode: 0}, // chain deleted
		{exitCode: 1}, // owned NAT chain absent
	}
	var calls []string
	run := func(_ context.Context, path string, arguments []string) (rollbackCommandResult, error) {
		calls = append(calls, path+":"+strings.Join(arguments, " "))
		if len(calls) > len(results) {
			t.Fatalf("unexpected extra rollback command: %v", arguments)
		}
		return results[len(calls)-1], nil
	}
	if err := (OSRollbackMachine{run: run}).RemoveShakerProxyFirewall(context.Background(), "/usr/sbin/iptables"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(calls, "\n")
	for _, exact := range []string{
		"-C DOCKER-USER -j SHAKERPROXY-FORWARD",
		"-D DOCKER-USER -j SHAKERPROXY-FORWARD",
		"-F SHAKERPROXY-FORWARD",
		"-X SHAKERPROXY-FORWARD",
	} {
		if !strings.Contains(joined, exact) {
			t.Fatalf("missing exact owned-state command %q in:\n%s", exact, joined)
		}
	}
}
