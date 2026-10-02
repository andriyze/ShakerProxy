package networkapply

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

func inlineBridgeStagedPlan(t *testing.T, now time.Time) networkplan.StagedPlan {
	t.Helper()
	staged := validStagedPlan(t, now)
	staged.Plan.Topology = networkplan.TopologyTransparentBridge
	staged.Plan.Interfaces = []networkplan.Interface{
		{StableID: "up", CurrentName: "eth0", Role: networkplan.RoleWAN},
		{StableID: "dev", CurrentName: "eth1", Role: networkplan.RoleLab},
	}
	staged.Plan.WAN = networkplan.WANConfiguration{IPv4Mode: networkplan.WANIPv4Static, IPv4Address: "192.0.2.20/24", IPv4Gateway: "192.0.2.1", IPv6Mode: networkplan.WANIPv6None, DNSMode: networkplan.WANDNSUseDHCP, AllowWorkingWANChange: true}
	staged.Plan.IPv4 = networkplan.IPv4Configuration{Enabled: true, LabCIDR: "192.0.2.0/24", GatewayAddress: "192.0.2.20"}
	staged.Plan.IPv6 = networkplan.IPv6Configuration{Strategy: networkplan.IPv6ObserveOnly}
	preview := networkplan.BuildPreview(staged.Plan, now)
	if !preview.Validation.Valid {
		t.Fatalf("bridge fixture is invalid: %+v", preview.Validation.Errors)
	}
	staged.Preview.NetplanYAML, staged.Preview.FirewallRestoreIPv4, staged.Preview.KeaDHCP4JSON = preview.NetplanYAML, preview.FirewallRestoreIPv4, ""
	staged.Preview.FirewallRestoreIPv6, staged.Preview.RadvdConf = "", ""
	return staged
}

func prepareBridgeNetfilter(t *testing.T, root, value string) {
	t.Helper()
	directory := filepath.Join(root, "proc", "sys", "net", "bridge")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "bridge-nf-call-iptables"), []byte(value), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestInlineBridgeSnapshotNeedsBrNetfilterAndRecordsItsState(t *testing.T) {
	now := time.Unix(8000, 0)
	hostRoot := prepareHostRoot(t, "1\n")
	store := networktransaction.FileStore{Root: filepath.Join(t.TempDir(), "transactions")}
	staged := inlineBridgeStagedPlan(t, now)
	if _, err := (Snapshotter{Store: store, HostRoot: hostRoot}).Capture(staged); err == nil || !strings.Contains(err.Error(), "br_netfilter") {
		t.Fatalf("a host without br_netfilter was not refused clearly: %v", err)
	}
	prepareBridgeNetfilter(t, hostRoot, "0\n")
	spec, err := (Snapshotter{Store: store, HostRoot: hostRoot}).Capture(staged)
	if err != nil {
		t.Fatal(err)
	}
	if !spec.BridgeNetfilter || spec.BridgeNFCallIPTables != 0 {
		t.Fatalf("bridge netfilter state not recorded: %+v", spec)
	}
}

func TestInlineBridgeApplyTurnsOnBridgeNetfilterBeforeTheBridgeExists(t *testing.T) {
	now := time.Unix(9000, 0)
	hostRoot := prepareHostRoot(t, "0\n")
	prepareBridgeNetfilter(t, hostRoot, "0\n")
	store := networktransaction.FileStore{Root: filepath.Join(t.TempDir(), "transactions")}
	staged := inlineBridgeStagedPlan(t, now)
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
	if record, err = record.BeginApply(now.Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	staged.Transaction = &record
	machine, dhcp4 := &fakeApplyMachine{}, &fakeDHCP4Service{}
	applier := Applier{Store: store, HostRoot: hostRoot, Machine: machine, DHCP4: dhcp4, IPv6: &fakeIPv6Machine{}}
	if err := applier.Apply(context.Background(), staged); err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"netplan-generate", "forwarding:1", "bridge-nf:1", "netplan-apply",
		"firewall:/usr/sbin/iptables:" + digest(staged.Preview.FirewallRestoreIPv4),
		"attachments:/usr/sbin/iptables:filter",
	}
	if strings.Join(machine.calls, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected bridge apply order: %v", machine.calls)
	}
	if strings.Join(dhcp4.calls, ",") != "disable" {
		t.Fatalf("an inline bridge must not run ShakerProxy DHCP: %v", dhcp4.calls)
	}

	executor := RollbackExecutor{Store: store, HostRoot: hostRoot, Machine: &fakeRollbackMachine{}, DHCP4: &fakeDHCP4Service{}, IPv6: &fakeIPv6Machine{}}
	if err := executor.Execute(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	calls := strings.Join(executor.Machine.(*fakeRollbackMachine).calls, ",")
	if !strings.Contains(calls, "netplan,forwarding:0,bridge-nf:0") {
		t.Fatalf("rollback did not restore the bridge netfilter state after the network: %s", calls)
	}
}

// On a host with IPv6 the bridge also sends bridged IPv6 through ip6tables,
// with its accept rule loaded, and rollback restores both switches.
func TestInlineBridgeWithIPv6ManagesBridgedIPv6(t *testing.T) {
	now := time.Unix(9500, 0)
	hostRoot := prepareHostRoot(t, "0\n")
	prepareBridgeNetfilter(t, hostRoot, "0\n")
	if err := os.WriteFile(filepath.Join(hostRoot, "proc", "sys", "net", "bridge", "bridge-nf-call-ip6tables"), []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	store := networktransaction.FileStore{Root: filepath.Join(t.TempDir(), "transactions")}
	staged := inlineBridgeStagedPlan(t, now)
	staged.Plan.WAN.IPv6Mode = networkplan.WANIPv6SLAAC
	preview := networkplan.BuildPreview(staged.Plan, now)
	preview.FirewallEnvironment = ipv6ReadyInspection()
	networkplan.BindIPv6HostEvidence(&preview)
	staged.Preview.NetplanYAML, staged.Preview.FirewallRestoreIPv6 = preview.NetplanYAML, preview.FirewallRestoreIPv6
	staged.Preview.FirewallEnvironment = preview.FirewallEnvironment
	spec, err := (Snapshotter{Store: store, HostRoot: hostRoot}).Capture(staged)
	if err != nil {
		t.Fatal(err)
	}
	if !spec.BridgeNetfilterIPv6 || spec.BridgeNFCallIP6Tables != 0 || spec.IPv6.Firewall != networktransaction.IPv6FirewallBlock || spec.IPv6.ForwardParent != networkplan.IPv6ForwardParentUser {
		t.Fatalf("bridged IPv6 state not recorded: %+v", spec)
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
	if record, err = record.BeginApply(now.Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	staged.Transaction = &record
	machine, ipv6 := &fakeApplyMachine{}, &fakeIPv6Machine{}
	applier := Applier{Store: store, HostRoot: hostRoot, Machine: machine, DHCP4: &fakeDHCP4Service{}, IPv6: ipv6}
	if err := applier.Apply(context.Background(), staged); err != nil {
		t.Fatal(err)
	}
	if calls := strings.Join(machine.calls, ","); !strings.Contains(calls, "bridge-nf:1,bridge-nf6:1,netplan-apply") {
		t.Fatalf("bridged IPv6 was not sent through ip6tables before the bridge exists: %s", calls)
	}
	wantIPv6 := "firewall:/usr/sbin/ip6tables:" + digest(staged.Preview.FirewallRestoreIPv6) + ",attach:/usr/sbin/ip6tables:DOCKER-USER:input=false:nat=false,disable-radvd"
	if calls := strings.Join(ipv6.calls, ","); calls != wantIPv6 {
		t.Fatalf("IPv6 bridge rule calls = %s, want %s", calls, wantIPv6)
	}

	executor := RollbackExecutor{Store: store, HostRoot: hostRoot, Machine: &fakeRollbackMachine{}, DHCP4: &fakeDHCP4Service{}, IPv6: &fakeIPv6Machine{}}
	if err := executor.Execute(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	if calls := strings.Join(executor.Machine.(*fakeRollbackMachine).calls, ","); !strings.Contains(calls, "bridge-nf:0,bridge-nf6:0") {
		t.Fatalf("rollback did not restore bridged IPv6 netfilter: %s", calls)
	}
}

func TestBridgeNetfilterRollbackSpecRejectsAValueWithoutCapture(t *testing.T) {
	spec := networktransaction.RollbackSpec{InitialMode: "SETUP_SAFE_NO_SHAKERPROXY", IptablesPath: "/usr/sbin/iptables", BridgeNFCallIPTables: 1}
	if err := spec.Validate(); err == nil {
		t.Fatal("a bridge netfilter value without a capture was accepted")
	}
	spec.BridgeNetfilter = true
	if err := spec.Validate(); err != nil {
		t.Fatal(err)
	}
	spec.BridgeNFCallIP6Tables = 1
	if err := spec.Validate(); err == nil {
		t.Fatal("a bridge IPv6 netfilter value without a capture was accepted")
	}
	spec.BridgeNetfilterIPv6 = true
	if err := spec.Validate(); err != nil {
		t.Fatal(err)
	}
	spec.BridgeNetfilter, spec.BridgeNFCallIPTables = false, 0
	if err := spec.Validate(); err == nil {
		t.Fatal("bridged IPv6 netfilter without the IPv4 capture was accepted")
	}
}
