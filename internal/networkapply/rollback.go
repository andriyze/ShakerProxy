package networkapply

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

const maxAttachmentCopies = 32

type RollbackMachine interface {
	RemoveShakerProxyFirewall(context.Context, string) error
	ReloadNetplan(context.Context) error
	SetIPv4Forwarding(context.Context, int) error
	SetIPv4SendRedirects(context.Context, string, int) error
	SetBridgeNFCallIPTables(context.Context, int) error
	SetBridgeNFCallIP6Tables(context.Context, int) error
}

// bridgeNFCallIPTablesPath decides whether bridged IPv4 traverses iptables,
// bridgeNFCallIP6TablesPath whether bridged IPv6 traverses ip6tables.
const (
	bridgeNFCallIPTablesPath  = "/proc/sys/net/bridge/bridge-nf-call-iptables"
	bridgeNFCallIP6TablesPath = "/proc/sys/net/bridge/bridge-nf-call-ip6tables"
)

type DHCP4Rollbacker interface {
	DisableDHCP4(context.Context) error
}

type RollbackExecutor struct {
	Store    networktransaction.FileStore
	HostRoot string
	Machine  RollbackMachine
	DHCP4    DHCP4Rollbacker

	// AccessPoint is required only when the manifest records a managed
	// Wi-Fi access point.
	AccessPoint AccessPointRollbacker

	// IPv6 is required only when the manifest records IPv6 state.
	IPv6 IPv6Machine
}

func (e RollbackExecutor) Execute(ctx context.Context, manifest networktransaction.WatchdogManifest) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	if !filepath.IsAbs(e.HostRoot) {
		return errors.New("host root must be absolute")
	}
	if e.Machine == nil || e.DHCP4 == nil {
		return errors.New("rollback machine is required")
	}
	directory, err := e.Store.TransactionDirectory(manifest.ApplyID)
	if err != nil {
		return err
	}
	netplanBackup, err := verifyManagedBackup(directory, "netplan.before", manifest.Rollback.NetplanExisted, manifest.Rollback.NetplanSHA256, "Netplan")
	var failures []error
	netplanBackupValid := err == nil
	if err != nil {
		failures = append(failures, err)
	}
	dhcp4Backup, err := verifyManagedBackup(directory, "dhcp4.before", manifest.Rollback.DHCP4ConfigExisted, manifest.Rollback.DHCP4ConfigSHA256, "DHCPv4 configuration")
	dhcp4BackupValid := err == nil
	if err != nil {
		failures = append(failures, err)
	}
	failures = append(failures, e.rollbackAccessPoint(ctx, manifest, directory)...)
	if err := e.DHCP4.DisableDHCP4(ctx); err != nil {
		failures = append(failures, fmt.Errorf("disable ShakerProxy DHCPv4 service: %w", err))
	}
	if err := e.Machine.RemoveShakerProxyFirewall(ctx, manifest.Rollback.IptablesPath); err != nil {
		failures = append(failures, fmt.Errorf("remove ShakerProxy firewall state: %w", err))
	}
	failures = append(failures, e.rollbackIPv6(ctx, manifest, directory)...)
	if netplanBackupValid {
		restored := true
		if err := restoreManagedFile(e.HostRoot, managedNetplanPath, manifest.Rollback.NetplanExisted, manifest.Rollback.NetplanMode, netplanBackup); err != nil {
			restored = false
			failures = append(failures, fmt.Errorf("restore managed Netplan file: %w", err))
		}
		if restored {
			if err := e.Machine.ReloadNetplan(ctx); err != nil {
				failures = append(failures, fmt.Errorf("reload restored Netplan state: %w", err))
			}
		}
	}
	if err := e.Machine.SetIPv4Forwarding(ctx, manifest.Rollback.IPv4Forwarding); err != nil {
		failures = append(failures, fmt.Errorf("restore IPv4 forwarding state: %w", err))
	}
	if manifest.Rollback.IPv4SendRedirectsInterface != "" {
		if err := e.Machine.SetIPv4SendRedirects(ctx, manifest.Rollback.IPv4SendRedirectsInterface, manifest.Rollback.IPv4SendRedirects); err != nil {
			failures = append(failures, fmt.Errorf("restore IPv4 redirect state: %w", err))
		}
	}
	if manifest.Rollback.BridgeNetfilter {
		if err := e.Machine.SetBridgeNFCallIPTables(ctx, manifest.Rollback.BridgeNFCallIPTables); err != nil {
			failures = append(failures, fmt.Errorf("restore bridge netfilter state: %w", err))
		}
	}
	if manifest.Rollback.BridgeNetfilterIPv6 {
		if err := e.Machine.SetBridgeNFCallIP6Tables(ctx, manifest.Rollback.BridgeNFCallIP6Tables); err != nil {
			failures = append(failures, fmt.Errorf("restore bridge IPv6 netfilter state: %w", err))
		}
	}
	if dhcp4BackupValid {
		if err := restoreManagedFile(e.HostRoot, managedDHCP4Path, manifest.Rollback.DHCP4ConfigExisted, manifest.Rollback.DHCP4ConfigMode, dhcp4Backup); err != nil {
			failures = append(failures, fmt.Errorf("restore managed DHCPv4 configuration: %w", err))
		}
	}
	return errors.Join(failures...)
}

func verifyManagedBackup(directory, backupName string, existed bool, expectedSHA256, label string) ([]byte, error) {
	backupPath := filepath.Join(directory, backupName)
	info, err := os.Lstat(backupPath)
	if !existed {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("unexpected %s backup exists for an absent original", label)
	}
	if err != nil {
		return nil, fmt.Errorf("inspect Netplan backup: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxArtifactBytes {
		return nil, fmt.Errorf("%s backup is not a bounded regular file", label)
	}
	contents, err := os.ReadFile(backupPath)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(contents)
	if hex.EncodeToString(sum[:]) != expectedSHA256 {
		return nil, fmt.Errorf("%s backup digest does not match watchdog manifest", label)
	}
	return contents, nil
}

func restoreManagedFile(hostRoot, managedPath string, existed bool, mode uint32, backup []byte) error {
	target := rootedPath(hostRoot, managedPath)
	if !existed {
		if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncDirectory(filepath.Dir(target))
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	return writeAtomicFile(filepath.Dir(target), filepath.Base(target), backup, os.FileMode(mode))
}

func syncDirectory(directory string) error {
	dir, err := os.Open(directory)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

type rollbackCommandRunner func(context.Context, string, []string) (rollbackCommandResult, error)

type OSRollbackMachine struct {
	run rollbackCommandRunner
}

func (OSDHCP4Service) DisableDHCP4(ctx context.Context) error {
	result, err := runRollbackCommand(ctx, "/usr/bin/systemctl", []string{"disable", "--now", "shakerproxy-dhcp4.service"})
	if err != nil || result.exitCode != 0 {
		return commandResultError("systemctl disable ShakerProxy DHCPv4", result, err)
	}
	return nil
}

func (m OSRollbackMachine) command(ctx context.Context, path string, arguments []string) (rollbackCommandResult, error) {
	if m.run != nil {
		return m.run(ctx, path, arguments)
	}
	return runRollbackCommand(ctx, path, arguments)
}

func (m OSRollbackMachine) RemoveShakerProxyFirewall(ctx context.Context, iptablesPath string) error {
	if iptablesPath != "/usr/sbin/iptables" && iptablesPath != "/usr/bin/iptables" {
		return errors.New("iptables path is not approved")
	}
	var failures []error
	if err := removeFirewallTable(ctx, m.command, iptablesPath, "filter", "DOCKER-USER", "SHAKERPROXY-FORWARD"); err != nil {
		failures = append(failures, err)
	}
	if err := removeFirewallTable(ctx, m.command, iptablesPath, "nat", "POSTROUTING", "SHAKERPROXY-POSTROUTING"); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func (OSRollbackMachine) ReloadNetplan(ctx context.Context) error {
	if err := runNetplanUnit(ctx, netplanGenerateUnit); err != nil {
		return err
	}
	return runNetplanUnit(ctx, netplanApplyUnit)
}

// Netplan runs through fixed oneshot units rather than inside the caller's
// sandbox. "netplan generate" gives the files it writes under /run to
// systemd-network; without CAP_CHOWN they stay unreadable to systemd-networkd,
// which then drops the interface (and its DHCP lease).
const (
	netplanGenerateUnit = "shakerproxy-netplan-generate.service"
	netplanApplyUnit    = "shakerproxy-netplan-apply.service"
)

func runNetplanUnit(ctx context.Context, unit string) error {
	result, err := runRollbackCommand(ctx, "/usr/bin/systemctl", []string{"start", unit})
	if err != nil || result.exitCode != 0 {
		return commandResultError("systemctl start "+unit+" (see journalctl -u "+unit+")", result, err)
	}
	return nil
}

func (OSRollbackMachine) SetIPv4Forwarding(ctx context.Context, value int) error {
	if value != 0 && value != 1 {
		return errors.New("IPv4 forwarding value must be zero or one")
	}
	result, err := runRollbackCommand(ctx, "/usr/sbin/sysctl", []string{"-w", "net.ipv4.ip_forward=" + strconv.Itoa(value)})
	if err != nil || result.exitCode != 0 {
		return commandResultError("sysctl", result, err)
	}
	return nil
}

func (OSRollbackMachine) SetIPv4SendRedirects(ctx context.Context, interfaceName string, value int) error {
	if !safeSysctlInterfaceName(interfaceName) || value != 0 && value != 1 {
		return errors.New("IPv4 redirect request is invalid")
	}
	key := "net.ipv4.conf." + interfaceName + ".send_redirects=" + strconv.Itoa(value)
	result, err := runRollbackCommand(ctx, "/usr/sbin/sysctl", []string{"-w", key})
	if err != nil || result.exitCode != 0 {
		return commandResultError("sysctl", result, err)
	}
	return nil
}

func (OSRollbackMachine) SetBridgeNFCallIPTables(ctx context.Context, value int) error {
	if value != 0 && value != 1 {
		return errors.New("bridge netfilter value must be zero or one")
	}
	result, err := runRollbackCommand(ctx, "/usr/sbin/sysctl", []string{"-w", "net.bridge.bridge-nf-call-iptables=" + strconv.Itoa(value)})
	if err != nil || result.exitCode != 0 {
		return commandResultError("sysctl", result, err)
	}
	return nil
}

func (OSRollbackMachine) SetBridgeNFCallIP6Tables(ctx context.Context, value int) error {
	if value != 0 && value != 1 {
		return errors.New("bridge IPv6 netfilter value must be zero or one")
	}
	result, err := runRollbackCommand(ctx, "/usr/sbin/sysctl", []string{"-w", "net.bridge.bridge-nf-call-ip6tables=" + strconv.Itoa(value)})
	if err != nil || result.exitCode != 0 {
		return commandResultError("sysctl", result, err)
	}
	return nil
}

func safeSysctlInterfaceName(name string) bool {
	if name == "" || len(name) > 15 || name == "." || name == ".." {
		return false
	}
	for _, character := range name {
		if !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') && !(character >= '0' && character <= '9') && character != '_' && character != '.' && character != ':' && character != '-' {
			return false
		}
	}
	return true
}

func removeFirewallTable(ctx context.Context, run rollbackCommandRunner, path, table, parent, target string) error {
	exists, err := ownedChainExists(ctx, run, path, table, target)
	if err != nil || !exists {
		return err
	}
	if err := deleteAllJumps(ctx, run, path, table, parent, target); err != nil {
		return err
	}
	return deleteOwnedChain(ctx, run, path, table, target)
}

func ownedChainExists(ctx context.Context, run rollbackCommandRunner, path, table, chain string) (bool, error) {
	result, err := run(ctx, path, tableArguments(table, "-S", chain))
	if err != nil {
		return false, err
	}
	switch result.exitCode {
	case 0:
		return true, nil
	case 1:
		return false, nil
	default:
		return false, commandResultError("inspect owned firewall chain", result, nil)
	}
}

func deleteAllJumps(ctx context.Context, run rollbackCommandRunner, path, table, chain, target string) error {
	check := tableArguments(table, "-C", chain, "-j", target)
	remove := tableArguments(table, "-D", chain, "-j", target)
	for attempt := 0; attempt < maxAttachmentCopies; attempt++ {
		result, err := run(ctx, path, check)
		if err != nil {
			return err
		}
		switch result.exitCode {
		case 0:
			deleted, err := run(ctx, path, remove)
			if err != nil || deleted.exitCode != 0 {
				return commandResultError("delete firewall attachment", deleted, err)
			}
		case 1:
			return nil
		default:
			return commandResultError("inspect firewall attachment", result, nil)
		}
	}
	return errors.New("too many duplicate ShakerProxy firewall attachments")
}

func deleteOwnedChain(ctx context.Context, run rollbackCommandRunner, path, table, chain string) error {
	exists, err := ownedChainExists(ctx, run, path, table, chain)
	if err != nil || !exists {
		return err
	}
	for _, operation := range []string{"-F", "-X"} {
		result, err := run(ctx, path, tableArguments(table, operation, chain))
		if err != nil || result.exitCode != 0 {
			return commandResultError("remove owned firewall chain", result, err)
		}
	}
	return nil
}

func tableArguments(table string, arguments ...string) []string {
	result := []string{"-w", "5"}
	if table == "nat" {
		result = append(result, "-t", "nat")
	}
	return append(result, arguments...)
}

type rollbackCommandResult struct {
	exitCode int
	stderr   string
}

func runRollbackCommand(ctx context.Context, path string, arguments []string) (rollbackCommandResult, error) {
	if !allowedRollbackCommand(path, arguments) {
		return rollbackCommandResult{}, errors.New("rollback command is not allowlisted")
	}
	command := exec.CommandContext(ctx, path, arguments...)
	command.Env = []string{"HOME=/nonexistent", "LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	var stdout cappedBuffer
	var stderr cappedBuffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if stdout.exceeded || stderr.exceeded {
		return rollbackCommandResult{}, errors.New("rollback command output exceeded limit")
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

func allowedRollbackCommand(path string, arguments []string) bool {
	joined := strings.Join(arguments, "\x00")
	if path == "/usr/bin/systemctl" {
		return joined == "disable\x00--now\x00shakerproxy-dhcp4.service" || joined == "start\x00"+netplanGenerateUnit || joined == "start\x00"+netplanApplyUnit
	}
	if path == "/usr/sbin/sysctl" {
		if joined == "-w\x00net.ipv4.ip_forward=0" || joined == "-w\x00net.ipv4.ip_forward=1" {
			return true
		}
		if joined == "-w\x00net.bridge.bridge-nf-call-iptables=0" || joined == "-w\x00net.bridge.bridge-nf-call-iptables=1" {
			return true
		}
		if joined == "-w\x00net.bridge.bridge-nf-call-ip6tables=0" || joined == "-w\x00net.bridge.bridge-nf-call-ip6tables=1" {
			return true
		}
		if len(arguments) == 2 && arguments[0] == "-w" {
			key, value, ok := strings.Cut(arguments[1], "=")
			const prefix = "net.ipv4.conf."
			const suffix = ".send_redirects"
			if ok && (value == "0" || value == "1") && strings.HasPrefix(key, prefix) && strings.HasSuffix(key, suffix) {
				return safeSysctlInterfaceName(strings.TrimSuffix(strings.TrimPrefix(key, prefix), suffix))
			}
		}
		return false
	}
	if path != "/usr/sbin/iptables" && path != "/usr/bin/iptables" {
		return false
	}
	approved := map[string]bool{}
	for _, table := range []string{"filter", "nat"} {
		for _, operation := range []string{"-C", "-D"} {
			approved[strings.Join(tableArguments(table, operation, map[string]string{"filter": "DOCKER-USER", "nat": "POSTROUTING"}[table], "-j", map[string]string{"filter": "SHAKERPROXY-FORWARD", "nat": "SHAKERPROXY-POSTROUTING"}[table]), "\x00")] = true
		}
		for _, operation := range []string{"-S", "-F", "-X"} {
			approved[strings.Join(tableArguments(table, operation, map[string]string{"filter": "SHAKERPROXY-FORWARD", "nat": "SHAKERPROXY-POSTROUTING"}[table]), "\x00")] = true
		}
	}
	return approved[joined]
}

func commandResultError(operation string, result rollbackCommandResult, err error) error {
	if err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	detail := result.stderr
	if len(detail) > 512 {
		detail = detail[:512]
	}
	if detail == "" {
		return fmt.Errorf("%s exited with status %d", operation, result.exitCode)
	}
	return fmt.Errorf("%s exited with status %d: %s", operation, result.exitCode, detail)
}
