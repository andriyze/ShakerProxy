package networkapply

import (
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"

	"shakerproxy.dev/shakerproxy/internal/networkplan"
)

const (
	radvdExecutable = "/usr/sbin/radvd"
	systemctlPath   = "/usr/bin/systemctl"
	sysctlPath      = "/usr/sbin/sysctl"
)

func radvdConfigTestArguments() []string {
	return []string{"--configtest", "--config", "/dev/stdin", "--logmethod", "stderr"}
}

func ip6tablesRestoreFor(ip6tablesPath string) string {
	switch ip6tablesPath {
	case "/usr/bin/ip6tables":
		return "/usr/bin/ip6tables-restore"
	default:
		return "/usr/sbin/ip6tables-restore"
	}
}

// allowedIPv6Syntax extends the native syntax runner with the two read-only
// IPv6 checks. Neither loads state into the kernel.
func allowedIPv6Syntax(path string, arguments []string, input string) bool {
	if input == "" || len(input) > maxArtifactBytes {
		return false
	}
	switch path {
	case "/usr/sbin/ip6tables-restore", "/usr/bin/ip6tables-restore":
		return len(arguments) == 1 && arguments[0] == "--test"
	case radvdExecutable:
		return strings.Join(arguments, "\x00") == strings.Join(radvdConfigTestArguments(), "\x00")
	}
	return false
}

// OSIPv6Machine is the production IPv6Machine. Every command is checked
// against allowedIPv6Command before it runs; run replaces execution in tests.
type OSIPv6Machine struct {
	run func(context.Context, string, []string, string) (rollbackCommandResult, error)
}

func (m OSIPv6Machine) command(ctx context.Context, path string, arguments []string, input string) (rollbackCommandResult, error) {
	if !allowedIPv6Command(path, arguments, input) {
		return rollbackCommandResult{}, errors.New("IPv6 command is not allowlisted")
	}
	if m.run != nil {
		return m.run(ctx, path, arguments, input)
	}
	return runFixedCommand(ctx, path, arguments, input)
}

func (m OSIPv6Machine) mustSucceed(ctx context.Context, operation, path string, arguments []string, input string) error {
	result, err := m.command(ctx, path, arguments, input)
	if err != nil || result.exitCode != 0 {
		return commandResultError(operation, result, err)
	}
	return nil
}

func (m OSIPv6Machine) SetIPv6Forwarding(ctx context.Context, value int) error {
	if value != 0 && value != 1 {
		return errors.New("IPv6 forwarding value must be zero or one")
	}
	return m.mustSucceed(ctx, "sysctl", sysctlPath, []string{"-w", "net.ipv6.conf.all.forwarding=" + strconv.Itoa(value)}, "")
}

func (m OSIPv6Machine) SetIPv6AcceptRA(ctx context.Context, interfaceName string, value int) error {
	if !safeSysctlInterfaceName(interfaceName) || value < 0 || value > 2 {
		return errors.New("IPv6 router advertisement request is invalid")
	}
	// The slash form keeps dots in VLAN interface names (enp1s0.10) intact.
	return m.mustSucceed(ctx, "sysctl", sysctlPath, []string{"-w", "net/ipv6/conf/" + interfaceName + "/accept_ra=" + strconv.Itoa(value)}, "")
}

func (m OSIPv6Machine) LoadShakerProxyIPv6Firewall(ctx context.Context, ip6tablesPath, restore string) error {
	if ip6tablesPath != "/usr/sbin/ip6tables" && ip6tablesPath != "/usr/bin/ip6tables" || restore == "" || len(restore) > maxArtifactBytes {
		return errors.New("IPv6 firewall restore request is not approved")
	}
	return m.mustSucceed(ctx, "ip6tables-restore --noflush", ip6tablesRestoreFor(ip6tablesPath), []string{"--noflush"}, restore)
}

func (m OSIPv6Machine) EnsureShakerProxyIPv6Attachments(ctx context.Context, attachments IPv6Attachments) error {
	if err := m.ensureJump(ctx, attachments.Ip6tablesPath, "filter", attachments.ForwardParent, "SHAKERPROXY-FORWARD"); err != nil {
		return err
	}
	if attachments.Input {
		if err := m.ensureJump(ctx, attachments.Ip6tablesPath, "filter", "INPUT", "SHAKERPROXY-INPUT"); err != nil {
			return err
		}
	}
	if attachments.NAT {
		if err := m.ensureJump(ctx, attachments.Ip6tablesPath, "nat", "POSTROUTING", "SHAKERPROXY-POSTROUTING"); err != nil {
			return err
		}
	}
	return nil
}

func (m OSIPv6Machine) ensureJump(ctx context.Context, path, table, parent, target string) error {
	result, err := m.command(ctx, path, tableArguments(table, "-C", parent, "-j", target), "")
	if err != nil {
		return err
	}
	if result.exitCode == 0 {
		return nil
	}
	if result.exitCode != 1 {
		return commandResultError("inspect IPv6 firewall attachment", result, nil)
	}
	return m.mustSucceed(ctx, "insert IPv6 firewall attachment", path, tableArguments(table, "-I", parent, "1", "-j", target), "")
}

// RemoveShakerProxyIPv6Firewall removes only ShakerProxy's own ip6tables hooks and
// chains. Absent chains are treated as already removed.
func (m OSIPv6Machine) RemoveShakerProxyIPv6Firewall(ctx context.Context, ip6tablesPath, forwardParent string) error {
	if ip6tablesPath != "/usr/sbin/ip6tables" && ip6tablesPath != "/usr/bin/ip6tables" {
		return errors.New("ip6tables path is not approved")
	}
	run := func(ctx context.Context, path string, arguments []string) (rollbackCommandResult, error) {
		return m.command(ctx, path, arguments, "")
	}
	var failures []error
	for _, hook := range []struct{ table, parent, chain string }{
		{"filter", forwardParent, "SHAKERPROXY-FORWARD"},
		{"filter", "INPUT", "SHAKERPROXY-INPUT"},
		{"nat", "POSTROUTING", "SHAKERPROXY-POSTROUTING"},
	} {
		if err := removeFirewallTable(ctx, run, ip6tablesPath, hook.table, hook.parent, hook.chain); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (m OSIPv6Machine) RestartRadvd(ctx context.Context) error {
	return m.mustSucceed(ctx, "systemctl restart ShakerProxy radvd", systemctlPath, []string{"restart", networkplan.RadvdUnit}, "")
}

func (m OSIPv6Machine) DisableRadvd(ctx context.Context) error {
	return m.mustSucceed(ctx, "systemctl disable ShakerProxy radvd", systemctlPath, []string{"disable", "--now", networkplan.RadvdUnit}, "")
}

// EnableRadvd persists router advertisements across reboot. Like DHCPv4 it
// runs only after the administrator confirms the network plan.
func (m OSIPv6Machine) EnableRadvd(ctx context.Context) error {
	return m.mustSucceed(ctx, "systemctl enable ShakerProxy radvd", systemctlPath, []string{"enable", networkplan.RadvdUnit}, "")
}

// OSNetworkServices combines the DHCPv4 and radvd service controls used when a
// guarded network plan is confirmed or recovered after restart.
type OSNetworkServices struct {
	OSDHCP4Service
	OSIPv6Machine
}

func allowedIPv6Command(path string, arguments []string, input string) bool {
	joined := strings.Join(arguments, "\x00")
	switch path {
	case systemctlPath:
		return input == "" && (joined == "restart\x00"+networkplan.RadvdUnit || joined == "disable\x00--now\x00"+networkplan.RadvdUnit || joined == "enable\x00"+networkplan.RadvdUnit)
	case sysctlPath:
		if input != "" || len(arguments) != 2 || arguments[0] != "-w" {
			return false
		}
		key, value, ok := strings.Cut(arguments[1], "=")
		if !ok {
			return false
		}
		if key == "net.ipv6.conf.all.forwarding" {
			return value == "0" || value == "1"
		}
		const prefix, suffix = "net/ipv6/conf/", "/accept_ra"
		if strings.HasPrefix(key, prefix) && strings.HasSuffix(key, suffix) && (value == "0" || value == "1" || value == "2") {
			name := strings.TrimSuffix(strings.TrimPrefix(key, prefix), suffix)
			return safeSysctlInterfaceName(name) && name != "all" && name != "default"
		}
		return false
	case "/usr/sbin/ip6tables-restore", "/usr/bin/ip6tables-restore":
		return joined == "--noflush" && input != "" && len(input) <= maxArtifactBytes
	case "/usr/sbin/ip6tables", "/usr/bin/ip6tables":
		return input == "" && allowedIp6tablesArguments(joined)
	}
	return false
}

func allowedIp6tablesArguments(joined string) bool {
	hooks := []struct{ table, parent, chain string }{
		{"filter", "DOCKER-USER", "SHAKERPROXY-FORWARD"},
		{"filter", "FORWARD", "SHAKERPROXY-FORWARD"},
		{"filter", "INPUT", "SHAKERPROXY-INPUT"},
		{"nat", "POSTROUTING", "SHAKERPROXY-POSTROUTING"},
	}
	for _, hook := range hooks {
		for _, operation := range []string{"-C", "-D"} {
			if joined == strings.Join(tableArguments(hook.table, operation, hook.parent, "-j", hook.chain), "\x00") {
				return true
			}
		}
		if joined == strings.Join(tableArguments(hook.table, "-I", hook.parent, "1", "-j", hook.chain), "\x00") {
			return true
		}
		for _, operation := range []string{"-S", "-F", "-X"} {
			if joined == strings.Join(tableArguments(hook.table, operation, hook.chain), "\x00") {
				return true
			}
		}
	}
	return false
}

func runFixedCommand(ctx context.Context, path string, arguments []string, input string) (rollbackCommandResult, error) {
	_, result, err := execFixedCommand(ctx, path, arguments, input)
	return result, err
}

// execFixedCommand runs an already-allowlisted command with a minimal
// environment and bounded output, returning its standard output.
func execFixedCommand(ctx context.Context, path string, arguments []string, input string) (string, rollbackCommandResult, error) {
	command := exec.CommandContext(ctx, path, arguments...)
	command.Env = []string{"HOME=/nonexistent", "LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	command.Stdin = strings.NewReader(input)
	var stdout cappedBuffer
	var stderr cappedBuffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if stdout.exceeded || stderr.exceeded {
		return "", rollbackCommandResult{}, errors.New("fixed command output exceeded limit")
	}
	result := rollbackCommandResult{stderr: strings.TrimSpace(stderr.String())}
	if err == nil {
		return stdout.String(), result, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		result.exitCode = exitError.ExitCode()
		return stdout.String(), result, nil
	}
	return "", result, err
}
