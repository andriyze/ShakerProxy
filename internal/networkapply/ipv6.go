package networkapply

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

// IPv6Machine performs the fixed host operations for lab IPv6. The OS
// implementation (OSIPv6Machine) runs only allowlisted commands.
type IPv6Machine interface {
	SetIPv6Forwarding(context.Context, int) error
	SetIPv6AcceptRA(context.Context, string, int) error
	LoadShakerProxyIPv6Firewall(context.Context, string, string) error
	EnsureShakerProxyIPv6Attachments(context.Context, IPv6Attachments) error
	RemoveShakerProxyIPv6Firewall(context.Context, string, string) error
	RestartRadvd(context.Context) error
	DisableRadvd(context.Context) error
}

// IPv6Attachments describes which ShakerProxy ip6tables chains must be hooked.
type IPv6Attachments struct {
	Ip6tablesPath string
	ForwardParent string
	Input         bool
	NAT           bool
}

const radvdBackupName = "radvd.before"

// captureIPv6State snapshots everything an IPv6-aware apply may change. It
// runs inside the PREPARING phase, before the watchdog is armed, so any error
// leaves the host untouched.
func captureIPv6State(hostRoot string, staged networkplan.StagedPlan, directory string) (networktransaction.IPv6RollbackSpec, error) {
	var spec networktransaction.IPv6RollbackSpec
	if err := networkplan.CheckIPv6Artifacts(staged.Plan, staged.Preview); err != nil {
		return spec, err
	}
	inspection := staged.Preview.FirewallEnvironment
	if inspection.ShakerProxyIPv6Chains {
		return spec, errors.New("reserved ShakerProxy IPv6 firewall chains already exist")
	}
	radvd, err := captureManagedFile(hostRoot, networkplan.RadvdConfigPath, directory, radvdBackupName, "radvd configuration")
	if err != nil {
		return spec, err
	}
	spec.RadvdConfigExisted, spec.RadvdConfigSHA256, spec.RadvdConfigMode = radvd.existed, radvd.sha256, radvd.mode
	mode := networkplan.LabIPv6FirewallMode(staged.Preview)
	if mode == "" {
		return spec, nil
	}
	spec.Firewall = mode
	spec.Ip6tablesPath = inspection.Ip6tablesPath
	spec.ForwardParent = networkplan.IPv6ForwardParent(inspection)
	if mode == networktransaction.IPv6FirewallBlock {
		return spec, nil
	}
	labIPv6, ok := networkplan.LabIPv6Routing(staged.Plan)
	if !ok {
		return spec, errors.New("routed lab IPv6 addressing is unavailable for rollback capture")
	}
	spec.NAT66 = labIPv6.NAT66
	forwarding, err := readBinarySysctl(hostRoot, "/proc/sys/net/ipv6/conf/all/forwarding")
	if err != nil {
		return spec, fmt.Errorf("read IPv6 forwarding state: %w", err)
	}
	spec.Forwarding = forwarding
	wan, ok := networkplan.WANInterface(staged.Plan)
	if !ok || !safeSysctlInterfaceName(wan.CurrentName) {
		return spec, errors.New("WAN interface is unavailable for IPv6 rollback capture")
	}
	// Only a kernel that currently accepts router advertisements itself
	// (accept_ra=1) stops doing so once forwarding is on. Userspace network
	// managers (accept_ra=0) and already-forced hosts (accept_ra=2) are left
	// alone. A WAN VLAN that Netplan has not created yet is rendered with an
	// explicit accept-ra: true instead.
	raw, err := os.ReadFile(rootedPath(hostRoot, "/proc/sys/net/ipv6/conf/"+wan.CurrentName+"/accept_ra"))
	if errors.Is(err, os.ErrNotExist) {
		return spec, nil
	}
	if err != nil {
		return spec, fmt.Errorf("read WAN router advertisement state: %w", err)
	}
	if strings.TrimSpace(string(raw)) == "1" {
		spec.AcceptRAInterface, spec.AcceptRA = wan.CurrentName, 1
	}
	return spec, nil
}

func readBinarySysctl(hostRoot, path string) (int, error) {
	raw, err := os.ReadFile(rootedPath(hostRoot, path))
	if err != nil {
		return 0, err
	}
	switch strings.TrimSpace(string(raw)) {
	case "0":
		return 0, nil
	case "1":
		return 1, nil
	default:
		return 0, errors.New("value is not zero or one")
	}
}

type ipv6SyntaxEvidence struct {
	firewallSHA256 string
	radvdSHA256    string
}

func (e ipv6SyntaxEvidence) bind(evidence *Evidence) {
	evidence.FirewallIPv6SHA256 = e.firewallSHA256
	evidence.FirewallIPv6RestoreOK = e.firewallSHA256 != ""
	evidence.RadvdSHA256 = e.radvdSHA256
	evidence.RadvdConfigOK = e.radvdSHA256 != ""
}

// validateIPv6Syntax runs the native IPv6 syntax checks: ip6tables-restore
// --test and radvd --configtest, both fed on standard input.
func (v Validator) validateIPv6Syntax(ctx context.Context, staged networkplan.StagedPlan) (ipv6SyntaxEvidence, error) {
	if err := networkplan.CheckIPv6Artifacts(staged.Plan, staged.Preview); err != nil {
		return ipv6SyntaxEvidence{}, err
	}
	var evidence ipv6SyntaxEvidence
	if restore := staged.Preview.FirewallRestoreIPv6; restore != "" {
		if len(restore) > maxArtifactBytes {
			return evidence, errors.New("rendered IPv6 firewall exceeds size limit")
		}
		if err := v.Runner.Run(ctx, ip6tablesRestoreFor(staged.Preview.FirewallEnvironment.Ip6tablesPath), []string{"--test"}, restore); err != nil {
			return evidence, fmt.Errorf("ip6tables restore validation failed: %w", err)
		}
		evidence.firewallSHA256 = digest(restore)
	}
	if config := staged.Preview.RadvdConf; config != "" {
		if len(config) > maxArtifactBytes {
			return evidence, errors.New("rendered radvd configuration exceeds size limit")
		}
		if err := v.Runner.Run(ctx, radvdExecutable, radvdConfigTestArguments(), config); err != nil {
			return evidence, fmt.Errorf("radvd configuration validation failed (is the radvd package installed?): %w", err)
		}
		evidence.radvdSHA256 = digest(config)
	}
	return evidence, nil
}

func validateIPv6Evidence(e Evidence) error {
	for _, item := range []struct {
		digest string
		tested bool
		label  string
	}{{e.FirewallIPv6SHA256, e.FirewallIPv6RestoreOK, "IPv6 firewall"}, {e.RadvdSHA256, e.RadvdConfigOK, "radvd"}} {
		if item.digest == "" {
			if item.tested {
				return fmt.Errorf("%s evidence claims a test without a digest", item.label)
			}
			continue
		}
		if len(item.digest) != 64 || !item.tested {
			return fmt.Errorf("%s evidence is invalid", item.label)
		}
		if _, err := hex.DecodeString(item.digest); err != nil {
			return fmt.Errorf("%s evidence digest is invalid", item.label)
		}
	}
	return nil
}

func optionalDigest(value string) string {
	if value == "" {
		return ""
	}
	return digest(value)
}

// checkIPv6Apply verifies, before any host mutation, that the IPv6 artifacts,
// syntax evidence and immutable rollback manifest all describe the same apply.
func (a Applier) checkIPv6Apply(staged networkplan.StagedPlan, manifest networktransaction.WatchdogManifest, evidence Evidence) error {
	if err := verifyIPv6Binding(staged, manifest, evidence); err != nil {
		return err
	}
	if a.IPv6 == nil {
		return errors.New("IPv6 apply machine is required")
	}
	return nil
}

// verifyIPv6Binding proves that the preview's IPv6 artifacts, their native
// syntax evidence, and the immutable watchdog manifest describe one apply.
func verifyIPv6Binding(staged networkplan.StagedPlan, manifest networktransaction.WatchdogManifest, evidence Evidence) error {
	if err := networkplan.CheckIPv6Artifacts(staged.Plan, staged.Preview); err != nil {
		return err
	}
	if evidence.FirewallIPv6SHA256 != optionalDigest(staged.Preview.FirewallRestoreIPv6) || evidence.RadvdSHA256 != optionalDigest(staged.Preview.RadvdConf) {
		return errors.New("native IPv6 syntax evidence does not match rendered apply artifacts")
	}
	spec := manifest.Rollback.IPv6
	if spec.Firewall != networkplan.LabIPv6FirewallMode(staged.Preview) {
		return errors.New("watchdog manifest IPv6 state does not match the staged apply")
	}
	if spec.Firewall != "" && (spec.Ip6tablesPath != staged.Preview.FirewallEnvironment.Ip6tablesPath || spec.ForwardParent != networkplan.IPv6ForwardParent(staged.Preview.FirewallEnvironment)) {
		return errors.New("watchdog manifest IPv6 firewall does not match the staged apply")
	}
	return nil
}

// applyIPv6 runs after the IPv4 firewall is attached. Order matters: the
// IPv6 firewall is in place before forwarding is enabled, the WAN keeps
// accepting router advertisements before it becomes a router, and radvd
// starts only once the lab has its address and forwarding is on.
func (a Applier) applyIPv6(ctx context.Context, staged networkplan.StagedPlan, manifest networktransaction.WatchdogManifest) error {
	spec := manifest.Rollback.IPv6
	if spec.Firewall != "" {
		if err := a.IPv6.LoadShakerProxyIPv6Firewall(ctx, spec.Ip6tablesPath, staged.Preview.FirewallRestoreIPv6); err != nil {
			return fmt.Errorf("load ShakerProxy IPv6 firewall batch: %w", err)
		}
		route := spec.Firewall == networktransaction.IPv6FirewallRoute
		if err := a.IPv6.EnsureShakerProxyIPv6Attachments(ctx, IPv6Attachments{Ip6tablesPath: spec.Ip6tablesPath, ForwardParent: spec.ForwardParent, Input: route, NAT: route && spec.NAT66}); err != nil {
			return fmt.Errorf("attach ShakerProxy IPv6 firewall chains: %w", err)
		}
	}
	target := rootedPath(a.HostRoot, networkplan.RadvdConfigPath)
	if spec.Firewall != networktransaction.IPv6FirewallRoute {
		if err := a.IPv6.DisableRadvd(ctx); err != nil {
			return fmt.Errorf("disable ShakerProxy router advertisements: %w", err)
		}
		if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove managed radvd configuration: %w", err)
		}
		return nil
	}
	if spec.AcceptRAInterface != "" {
		if err := a.IPv6.SetIPv6AcceptRA(ctx, spec.AcceptRAInterface, 2); err != nil {
			return fmt.Errorf("keep WAN router advertisements while forwarding: %w", err)
		}
	}
	if err := a.IPv6.SetIPv6Forwarding(ctx, 1); err != nil {
		return fmt.Errorf("enable IPv6 forwarding: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	if err := writeAtomicFile(filepath.Dir(target), filepath.Base(target), []byte(staged.Preview.RadvdConf), 0o644); err != nil {
		return fmt.Errorf("write managed radvd configuration: %w", err)
	}
	if err := a.IPv6.RestartRadvd(ctx); err != nil {
		return fmt.Errorf("start ShakerProxy router advertisements: %w", err)
	}
	return nil
}

// rollbackIPv6 restores the recorded IPv6 state. Every step runs even when an
// earlier one fails; failures are returned for the joined rollback error.
func (e RollbackExecutor) rollbackIPv6(ctx context.Context, manifest networktransaction.WatchdogManifest, directory string) []error {
	spec := manifest.Rollback.IPv6
	if spec == (networktransaction.IPv6RollbackSpec{}) {
		return nil
	}
	if e.IPv6 == nil {
		return []error{errors.New("IPv6 rollback machine is required")}
	}
	var failures []error
	backup, err := verifyManagedBackup(directory, radvdBackupName, spec.RadvdConfigExisted, spec.RadvdConfigSHA256, "radvd configuration")
	backupValid := err == nil
	if err != nil {
		failures = append(failures, err)
	}
	if spec.Firewall == networktransaction.IPv6FirewallRoute {
		if err := e.IPv6.DisableRadvd(ctx); err != nil {
			failures = append(failures, fmt.Errorf("disable ShakerProxy router advertisements: %w", err))
		}
		if err := e.IPv6.SetIPv6Forwarding(ctx, spec.Forwarding); err != nil {
			failures = append(failures, fmt.Errorf("restore IPv6 forwarding state: %w", err))
		}
		if spec.AcceptRAInterface != "" {
			if err := e.IPv6.SetIPv6AcceptRA(ctx, spec.AcceptRAInterface, spec.AcceptRA); err != nil {
				failures = append(failures, fmt.Errorf("restore WAN router advertisement state: %w", err))
			}
		}
	}
	if spec.Firewall != "" {
		if err := e.IPv6.RemoveShakerProxyIPv6Firewall(ctx, spec.Ip6tablesPath, spec.ForwardParent); err != nil {
			failures = append(failures, fmt.Errorf("remove ShakerProxy IPv6 firewall state: %w", err))
		}
	}
	if backupValid {
		if err := restoreManagedFile(e.HostRoot, networkplan.RadvdConfigPath, spec.RadvdConfigExisted, spec.RadvdConfigMode, backup); err != nil {
			failures = append(failures, fmt.Errorf("restore managed radvd configuration: %w", err))
		}
	}
	return failures
}
