package networkapply

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

type ApplyMachine interface {
	GenerateNetplan(context.Context) error
	SetIPv4Forwarding(context.Context, int) error
	SetIPv4SendRedirects(context.Context, string, int) error
	ApplyNetplan(context.Context) error
	LoadShakerProxyFirewall(context.Context, string, string) error
	EnsureShakerProxyAttachments(context.Context, string, bool) error
}

type DHCP4Controller interface {
	StartDHCP4(context.Context) error
	DisableDHCP4(context.Context) error
}

type Applier struct {
	Store    networktransaction.FileStore
	HostRoot string
	Machine  ApplyMachine
	DHCP4    DHCP4Controller

	// AccessPoint is required only for plans with a Wi-Fi access point.
	AccessPoint AccessPointController

	// IPv6 performs the lab IPv6 host operations. It is always required,
	// because every apply also makes sure ShakerProxy router advertisements are off
	// unless the plan routes IPv6.
	IPv6 IPv6Machine
}

func (a Applier) Apply(ctx context.Context, staged networkplan.StagedPlan) error {
	if staged.Transaction == nil || staged.Transaction.Phase != networktransaction.PhaseApplying {
		return errors.New("native apply requires an APPLYING transaction")
	}
	if err := staged.Transaction.Validate(); err != nil {
		return err
	}
	if staged.ApplyID != staged.Transaction.ApplyID || staged.PlanHash != staged.Transaction.PlanHash || staged.Preview.Validation.PlanHash != staged.PlanHash {
		return errors.New("apply identities do not match")
	}
	if !staged.Preview.Validation.Valid || !staged.Preview.FirewallEnvironment.ApplyReady {
		return errors.New("staged preview is not apply-ready")
	}
	if !filepath.IsAbs(a.HostRoot) {
		return errors.New("host root must be absolute")
	}
	if a.Machine == nil || a.DHCP4 == nil {
		return errors.New("native apply machine is required")
	}
	manifest, err := a.Store.ReadManifest(staged.ApplyID)
	if err != nil {
		return err
	}
	if manifest.PlanHash != staged.PlanHash || manifest.Rollback.IptablesPath != staged.Preview.FirewallEnvironment.IptablesPath {
		return errors.New("watchdog manifest does not match the staged apply")
	}
	evidence, err := ReadEvidence(a.Store, staged.ApplyID)
	if err != nil {
		return err
	}
	if evidence.NetplanSHA256 != digest(staged.Preview.NetplanYAML) || evidence.FirewallSHA256 != digest(staged.Preview.FirewallRestoreIPv4) || evidence.KeaDHCP4SHA256 != digest(staged.Preview.KeaDHCP4JSON) {
		return errors.New("native syntax evidence does not match rendered apply artifacts")
	}
	if err := a.checkIPv6Apply(staged, manifest, evidence); err != nil {
		return err
	}
	if err := a.writeAccessPointConfig(staged); err != nil {
		return err
	}
	target := rootedPath(a.HostRoot, managedNetplanPath)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	if err := writeAtomicFile(filepath.Dir(target), filepath.Base(target), []byte(staged.Preview.NetplanYAML), 0o600); err != nil {
		return fmt.Errorf("write managed Netplan file: %w", err)
	}
	dhcp4Target := rootedPath(a.HostRoot, managedDHCP4Path)
	if networkplan.UsesManagedDHCP4(staged.Plan) {
		if err := os.MkdirAll(filepath.Dir(dhcp4Target), 0o750); err != nil {
			return err
		}
		if err := writeAtomicFile(filepath.Dir(dhcp4Target), filepath.Base(dhcp4Target), []byte(staged.Preview.KeaDHCP4JSON), 0o640); err != nil {
			return fmt.Errorf("write managed Kea DHCPv4 file: %w", err)
		}
	} else {
		if err := a.DHCP4.DisableDHCP4(ctx); err != nil {
			return fmt.Errorf("disable ShakerProxy DHCPv4 service: %w", err)
		}
		if err := os.Remove(dhcp4Target); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove managed Kea DHCPv4 file: %w", err)
		}
	}
	if err := a.Machine.GenerateNetplan(ctx); err != nil {
		return fmt.Errorf("generate Netplan backend: %w", err)
	}
	if err := a.Machine.SetIPv4Forwarding(ctx, 1); err != nil {
		return fmt.Errorf("enable IPv4 forwarding: %w", err)
	}
	if staged.Plan.Topology == networkplan.TopologySingleArm {
		arm, _ := networkplan.WANInterface(staged.Plan)
		if err := a.Machine.SetIPv4SendRedirects(ctx, arm.CurrentName, 0); err != nil {
			return fmt.Errorf("disable IPv4 redirects on single-arm interface: %w", err)
		}
	}
	if err := a.Machine.ApplyNetplan(ctx); err != nil {
		return fmt.Errorf("apply Netplan: %w", err)
	}
	if err := a.Machine.LoadShakerProxyFirewall(ctx, manifest.Rollback.IptablesPath, staged.Preview.FirewallRestoreIPv4); err != nil {
		return fmt.Errorf("load ShakerProxy firewall batch: %w", err)
	}
	if err := a.Machine.EnsureShakerProxyAttachments(ctx, manifest.Rollback.IptablesPath, staged.Plan.IPv4.NAT44); err != nil {
		return fmt.Errorf("attach ShakerProxy firewall chains: %w", err)
	}
	if err := a.startAccessPoint(ctx, staged); err != nil {
		return err
	}
	if err := a.applyIPv6(ctx, staged, manifest); err != nil {
		return err
	}
	if networkplan.UsesManagedDHCP4(staged.Plan) {
		if err := a.DHCP4.StartDHCP4(ctx); err != nil {
			return fmt.Errorf("start ShakerProxy DHCPv4 service: %w", err)
		}
	}
	return nil
}

type OSDHCP4Service struct{}

func (OSDHCP4Service) StartDHCP4(ctx context.Context) error {
	result, err := runApplyCommand(ctx, "/usr/bin/systemctl", []string{"start", "shakerproxy-dhcp4.service"})
	if err != nil || result.exitCode != 0 {
		return commandResultError("systemctl start shakerproxy-dhcp4", result, err)
	}
	return nil
}

func (OSDHCP4Service) EnsureDHCP4Enabled(ctx context.Context) error {
	result, err := runApplyCommand(ctx, "/usr/bin/systemctl", []string{"enable", "shakerproxy-dhcp4.service"})
	if err != nil || result.exitCode != 0 {
		return commandResultError("systemctl enable shakerproxy-dhcp4", result, err)
	}
	return nil
}

type OSApplyMachine struct{}

func (OSApplyMachine) GenerateNetplan(ctx context.Context) error {
	result, err := runRollbackCommand(ctx, "/usr/sbin/netplan", []string{"generate"})
	if err != nil || result.exitCode != 0 {
		return commandResultError("netplan generate", result, err)
	}
	return nil
}

func (OSApplyMachine) SetIPv4Forwarding(ctx context.Context, value int) error {
	return (OSRollbackMachine{}).SetIPv4Forwarding(ctx, value)
}

func (OSApplyMachine) SetIPv4SendRedirects(ctx context.Context, interfaceName string, value int) error {
	return (OSRollbackMachine{}).SetIPv4SendRedirects(ctx, interfaceName, value)
}

func (OSApplyMachine) ApplyNetplan(ctx context.Context) error {
	result, err := runRollbackCommand(ctx, "/usr/sbin/netplan", []string{"apply"})
	if err != nil || result.exitCode != 0 {
		return commandResultError("netplan apply", result, err)
	}
	return nil
}

func (OSApplyMachine) LoadShakerProxyFirewall(ctx context.Context, iptablesPath, restore string) error {
	restorePath := strings.TrimSuffix(iptablesPath, "iptables") + "iptables-restore"
	if (restorePath != "/usr/sbin/iptables-restore" && restorePath != "/usr/bin/iptables-restore") || restore == "" || len(restore) > maxArtifactBytes {
		return errors.New("firewall restore request is not approved")
	}
	result, err := runApplyInputCommand(ctx, restorePath, []string{"--noflush"}, restore)
	if err != nil || result.exitCode != 0 {
		return commandResultError("iptables-restore --noflush", result, err)
	}
	return nil
}

func (OSApplyMachine) EnsureShakerProxyAttachments(ctx context.Context, path string, nat bool) error {
	if err := ensureJump(ctx, path, "filter", "DOCKER-USER", "SHAKERPROXY-FORWARD"); err != nil {
		return err
	}
	if nat {
		if err := ensureJump(ctx, path, "nat", "POSTROUTING", "SHAKERPROXY-POSTROUTING"); err != nil {
			return err
		}
	}
	return nil
}

func ensureJump(ctx context.Context, path, table, chain, target string) error {
	check := tableArguments(table, "-C", chain, "-j", target)
	result, err := runRollbackCommand(ctx, path, check)
	if err != nil {
		return err
	}
	if result.exitCode == 0 {
		return nil
	}
	if result.exitCode != 1 {
		return commandResultError("inspect firewall attachment", result, nil)
	}
	insert := tableArguments(table, "-I", chain, "1", "-j", target)
	result, err = runApplyCommand(ctx, path, insert)
	if err != nil || result.exitCode != 0 {
		return commandResultError("insert firewall attachment", result, err)
	}
	return nil
}

func runApplyCommand(ctx context.Context, path string, arguments []string) (rollbackCommandResult, error) {
	return runApplyInputCommand(ctx, path, arguments, "")
}

func runApplyInputCommand(ctx context.Context, path string, arguments []string, input string) (rollbackCommandResult, error) {
	if !allowedApplyCommand(path, arguments, input) {
		return rollbackCommandResult{}, errors.New("apply command is not allowlisted")
	}
	command := exec.CommandContext(ctx, path, arguments...)
	command.Env = []string{"HOME=/nonexistent", "LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	command.Stdin = strings.NewReader(input)
	var stdout cappedBuffer
	var stderr cappedBuffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if stdout.exceeded || stderr.exceeded {
		return rollbackCommandResult{}, errors.New("apply command output exceeded limit")
	}
	result := rollbackCommandResult{stderr: strings.TrimSpace(stderr.String())}
	if err == nil {
		return result, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		result.exitCode = exitError.ExitCode()
		return result, nil
	}
	return result, err
}

func allowedApplyCommand(path string, arguments []string, input string) bool {
	joined := strings.Join(arguments, "\x00")
	if path == "/usr/bin/systemctl" {
		return input == "" && (joined == "start\x00shakerproxy-dhcp4.service" || joined == "enable\x00shakerproxy-dhcp4.service")
	}
	if path == "/usr/sbin/iptables-restore" || path == "/usr/bin/iptables-restore" {
		return joined == "--noflush" && input != "" && len(input) <= maxArtifactBytes
	}
	if path != "/usr/sbin/iptables" && path != "/usr/bin/iptables" || input != "" {
		return false
	}
	for _, table := range []string{"filter", "nat"} {
		chain := map[string]string{"filter": "DOCKER-USER", "nat": "POSTROUTING"}[table]
		target := map[string]string{"filter": "SHAKERPROXY-FORWARD", "nat": "SHAKERPROXY-POSTROUTING"}[table]
		if joined == strings.Join(tableArguments(table, "-I", chain, "1", "-j", target), "\x00") {
			return true
		}
	}
	return false
}
