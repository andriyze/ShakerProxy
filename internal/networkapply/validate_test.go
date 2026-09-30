package networkapply

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/firewall"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

const (
	applyID  = "apply-0123456789abcdef0123456789abcdef"
	planHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

type runnerCall struct {
	path  string
	args  []string
	input string
}

type recordingRunner struct {
	calls  []runnerCall
	failAt int
}

func (r *recordingRunner) Run(_ context.Context, path string, arguments []string, input string) error {
	r.calls = append(r.calls, runnerCall{path: path, args: append([]string(nil), arguments...), input: input})
	if r.failAt > 0 && len(r.calls) == r.failAt {
		return errors.New("native validation failed")
	}
	return nil
}

func validStagedPlan(t *testing.T, now time.Time) networkplan.StagedPlan {
	t.Helper()
	record, err := networktransaction.New(applyID, planHash, now)
	if err != nil {
		t.Fatal(err)
	}
	return networkplan.StagedPlan{
		ApplyID:  applyID,
		PlanHash: planHash,
		Status:   string(networktransaction.PhasePreparing),
		Plan: networkplan.Plan{
			Schema: networkplan.SchemaVersion, Name: "test", Topology: networkplan.TopologyTwoNIC,
			Interfaces: []networkplan.Interface{{StableID: "wan", CurrentName: "eth0", Role: networkplan.RoleWAN}, {StableID: "lab", CurrentName: "eth1", Role: networkplan.RoleLab}},
			Management: networkplan.Management{PreserveActiveSSH: true},
			IPv4:       networkplan.IPv4Configuration{Enabled: true, LabCIDR: "10.77.0.0/24", GatewayAddress: "10.77.0.1", DHCPStart: "10.77.0.100", DHCPEnd: "10.77.0.200", NAT44: true},
			IPv6:       networkplan.IPv6Configuration{Strategy: networkplan.IPv6Disabled},
		},
		Preview: networkplan.Preview{
			Validation:          networkplan.ValidationResult{Valid: true, PlanHash: planHash},
			FirewallBackend:     "iptables-nft",
			FirewallEnvironment: firewall.Inspection{SelectedBackend: "iptables-nft", DockerFirewallBackend: "iptables", IptablesPath: "/usr/sbin/iptables", ApplyReady: true},
			NetplanYAML:         "network:\n  version: 2\n",
			FirewallRestoreIPv4: "*filter\nCOMMIT\n",
			KeaDHCP4JSON:        "{\"Dhcp4\":{}}\n",
		},
		Transaction: &record,
	}
}

func singleArmStagedPlan(t *testing.T, now time.Time) networkplan.StagedPlan {
	t.Helper()
	staged := validStagedPlan(t, now)
	staged.Plan.Topology = networkplan.TopologySingleArm
	staged.Plan.Interfaces = []networkplan.Interface{{StableID: "arm", CurrentName: "eth0", Role: networkplan.RoleWANLab}}
	staged.Plan.WAN = networkplan.WANConfiguration{IPv4Mode: networkplan.WANIPv4KeepExisting, IPv6Mode: networkplan.WANIPv6KeepExisting, DNSMode: networkplan.WANDNSUseDHCP, UpstreamNAT: true}
	staged.Plan.IPv4 = networkplan.IPv4Configuration{Enabled: true, LabCIDR: "192.0.2.0/24", GatewayAddress: "192.0.2.20", NAT44: true}
	staged.Preview.KeaDHCP4JSON = ""
	return staged
}

func TestValidatorStagesArtifactsAndRunsOnlyNativeSyntaxChecks(t *testing.T) {
	now := time.Unix(3000, 0)
	root := filepath.Join(t.TempDir(), "transactions")
	runner := &recordingRunner{}
	validator := Validator{Store: networktransaction.FileStore{Root: root}, Runner: runner, Now: func() time.Time { return now.Add(time.Second) }}
	staged := validStagedPlan(t, now)

	evidence, err := validator.Validate(context.Background(), staged)
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("unexpected command count: %d", len(runner.calls))
	}
	if runner.calls[0].path != "/usr/sbin/netplan" || strings.Join(runner.calls[0].args[:2], " ") != "generate --root-dir" || runner.calls[0].input != "" {
		t.Fatalf("unexpected Netplan call: %+v", runner.calls[0])
	}
	if runner.calls[1].path != "/usr/sbin/iptables-restore" || strings.Join(runner.calls[1].args, " ") != "--test" || runner.calls[1].input != staged.Preview.FirewallRestoreIPv4 {
		t.Fatalf("unexpected firewall call: %+v", runner.calls[1])
	}
	if runner.calls[2].path != "/usr/sbin/kea-dhcp4" || strings.Join(runner.calls[2].args, " ") != "-t /dev/stdin" || runner.calls[2].input != staged.Preview.KeaDHCP4JSON {
		t.Fatalf("unexpected Kea call: %+v", runner.calls[2])
	}
	if evidence.Schema != 1 || !evidence.NetplanGenerated || !evidence.FirewallRestoreOK || !evidence.KeaDHCP4ConfigOK || len(evidence.NetplanSHA256) != 64 || len(evidence.FirewallSHA256) != 64 || len(evidence.KeaDHCP4SHA256) != 64 {
		t.Fatalf("invalid evidence: %+v", evidence)
	}
	netplanPath := filepath.Join(root, applyID, "syntax-root", "etc", "netplan", "90-shakerproxy.yaml")
	contents, err := os.ReadFile(netplanPath)
	if err != nil || string(contents) != staged.Preview.NetplanYAML {
		t.Fatalf("staged Netplan mismatch: contents=%q err=%v", contents, err)
	}
	info, err := os.Stat(netplanPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected staged Netplan mode: info=%v err=%v", info, err)
	}
	if info, err := os.Stat(filepath.Join(root, applyID, "syntax-evidence.json")); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("unexpected evidence mode: info=%v err=%v", info, err)
	}
}

func TestValidatorSingleArmSkipsKeaSyntaxCheck(t *testing.T) {
	now := time.Unix(3000, 0)
	runner := &recordingRunner{}
	validator := Validator{Store: networktransaction.FileStore{Root: filepath.Join(t.TempDir(), "transactions")}, Runner: runner, Now: func() time.Time { return now.Add(time.Second) }}
	evidence, err := validator.Validate(context.Background(), singleArmStagedPlan(t, now))
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 || runner.calls[0].path != "/usr/sbin/netplan" || runner.calls[1].path != "/usr/sbin/iptables-restore" {
		t.Fatalf("single-arm validation invoked an unexpected native command: %+v", runner.calls)
	}
	if !evidence.KeaDHCP4ConfigOK || evidence.KeaDHCP4SHA256 != digest("") {
		t.Fatalf("single-arm empty DHCP artifact was not represented deterministically: %+v", evidence)
	}
}

func TestValidatorFailsClosedBeforeNativeCommands(t *testing.T) {
	now := time.Unix(3000, 0)
	cases := []networkplan.StagedPlan{
		validStagedPlan(t, now),
		validStagedPlan(t, now),
		validStagedPlan(t, now),
	}
	cases[0].Preview.FirewallEnvironment.ApplyReady = false
	cases[1].Preview.FirewallBackend = "nftables"
	cases[2].Preview.NetplanYAML = strings.Repeat("x", maxArtifactBytes+1)
	for index, staged := range cases {
		runner := &recordingRunner{}
		validator := Validator{Store: networktransaction.FileStore{Root: filepath.Join(t.TempDir(), "transactions")}, Runner: runner}
		if _, err := validator.Validate(context.Background(), staged); err == nil {
			t.Fatalf("case %d was accepted", index)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("case %d executed native commands", index)
		}
	}
}

func TestValidatorStopsAfterFirstNativeFailure(t *testing.T) {
	now := time.Unix(3000, 0)
	runner := &recordingRunner{failAt: 1}
	validator := Validator{Store: networktransaction.FileStore{Root: filepath.Join(t.TempDir(), "transactions")}, Runner: runner}
	if _, err := validator.Validate(context.Background(), validStagedPlan(t, now)); err == nil {
		t.Fatal("native Netplan failure was ignored")
	}
	if len(runner.calls) != 1 {
		t.Fatalf("firewall validation ran after Netplan failed: %d calls", len(runner.calls))
	}
}

func TestOSRunnerAllowlistRejectsPathsAndCommands(t *testing.T) {
	root := filepath.Join(t.TempDir(), "transactions")
	runner := OSRunner{TransactionRoot: root}
	validRoot := filepath.Join(root, applyID, "syntax-root")
	if !runner.allowed("/usr/sbin/netplan", []string{"generate", "--root-dir", validRoot}, "") {
		t.Fatal("derived Netplan syntax root was rejected")
	}
	if runner.allowed("/usr/sbin/netplan", []string{"apply"}, "") {
		t.Fatal("Netplan apply was allowlisted")
	}
	if runner.allowed("/usr/sbin/netplan", []string{"generate", "--root-dir", "/etc"}, "") {
		t.Fatal("external root directory was allowlisted")
	}
	if runner.allowed("/bin/sh", []string{"-c", "netplan apply"}, "") {
		t.Fatal("shell command was allowlisted")
	}
	if !runner.allowed("/usr/sbin/iptables-restore", []string{"--test"}, "*filter\nCOMMIT\n") {
		t.Fatal("firewall test command was rejected")
	}
	if !runner.allowed("/usr/sbin/kea-dhcp4", []string{"-t", "/dev/stdin"}, "{\"Dhcp4\":{}}\n") {
		t.Fatal("Kea standard-input syntax check was rejected")
	}
	if runner.allowed("/usr/sbin/kea-dhcp4", []string{"-c", "/dev/stdin"}, "{\"Dhcp4\":{}}\n") || runner.allowed("/usr/sbin/kea-dhcp4", []string{"-t", "/etc/kea/kea-dhcp4.conf"}, "") || runner.allowed("/usr/sbin/kea-dhcp4", []string{"-t", "/dev/stdin"}, "") {
		t.Fatal("broad Kea invocation was allowlisted")
	}
	if runner.allowed("/usr/sbin/iptables-restore", []string{"--noflush"}, "*filter\nCOMMIT\n") {
		t.Fatal("firewall load command was allowlisted")
	}
}
