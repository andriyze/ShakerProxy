package networkapply

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

const (
	hostapdBackupName          = "hostapd.before"
	hostapdLabel               = "Wi-Fi access point configuration"
	defaultAccessPointReady    = 20 * time.Second
	defaultAccessPointInterval = 250 * time.Millisecond
	maxSysfsValueBytes         = 4096
)

// AccessPointTarget identifies the adapter hostapd drives and, when bridged,
// the lab bridge hostapd must add it to.
type AccessPointTarget struct {
	Interface string
	Bridge    string
}

// AccessPointController starts the ShakerProxy access point during a guarded
// apply. It never receives configuration text: hostapd reads only the fixed,
// root-owned file written by the Applier.
type AccessPointController interface {
	StartAccessPoint(context.Context, AccessPointTarget) error
}

// AccessPointRollbacker stops and disables the ShakerProxy access point.
type AccessPointRollbacker interface {
	DisableAccessPoint(context.Context) error
}

// writeAccessPointConfig writes the full hostapd configuration for a Wi-Fi plan
// after binding it to the reviewed, redacted preview. It runs before Netplan is
// touched so a missing prerequisite fails before any network change.
func (a Applier) writeAccessPointConfig(staged networkplan.StagedPlan) error {
	if !networkplan.WiFiEnabled(staged.Plan) {
		return nil
	}
	if a.AccessPoint == nil {
		return errors.New("Wi-Fi access point controller is required")
	}
	if staged.Preview.HostapdConf == "" || len(staged.Preview.HostapdConf) > maxArtifactBytes {
		return errors.New("reviewed Wi-Fi access point configuration is missing")
	}
	config, err := networkplan.RenderHostapdConf(staged.Plan)
	if err != nil {
		return fmt.Errorf("render Wi-Fi access point configuration: %w", err)
	}
	if networkplan.RedactHostapdConf(config) != staged.Preview.HostapdConf {
		return errors.New("Wi-Fi access point configuration does not match the reviewed preview")
	}
	target := rootedPath(a.HostRoot, networkplan.ManagedHostapdPath)
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return fmt.Errorf("Wi-Fi configuration directory %s is unavailable; reinstall shakerproxy-host: %w", filepath.Dir(networkplan.ManagedHostapdPath), err)
	}
	if err := writeAtomicFile(filepath.Dir(target), filepath.Base(target), []byte(config), 0o600); err != nil {
		return fmt.Errorf("write Wi-Fi access point configuration: %w", err)
	}
	return nil
}

// startAccessPoint (re)starts hostapd after Netplan and the firewall are in
// place and before DHCP starts, so leases are offered only on a live network.
func (a Applier) startAccessPoint(ctx context.Context, staged networkplan.StagedPlan) error {
	ap, ok := networkplan.WiFiAccessPoint(staged.Plan)
	if !ok {
		return nil
	}
	target := AccessPointTarget{Interface: ap.CurrentName, Bridge: networkplan.AccessPointBridgeName(staged.Plan)}
	if err := a.AccessPoint.StartAccessPoint(ctx, target); err != nil {
		return fmt.Errorf("start ShakerProxy Wi-Fi access point: %w", err)
	}
	return nil
}

// captureAccessPoint records the prior ShakerProxy hostapd configuration for a
// Wi-Fi plan so rollback can stop the access point and restore the file.
func captureAccessPoint(hostRoot string, staged networkplan.StagedPlan, directory string, spec *networktransaction.RollbackSpec) error {
	if !networkplan.WiFiEnabled(staged.Plan) {
		return nil
	}
	snapshot, err := captureManagedFile(hostRoot, networkplan.ManagedHostapdPath, directory, hostapdBackupName, hostapdLabel)
	if err != nil {
		return err
	}
	spec.HostapdManaged = true
	spec.HostapdConfigExisted, spec.HostapdConfigSHA256, spec.HostapdConfigMode = snapshot.existed, snapshot.sha256, snapshot.mode
	return nil
}

// rollbackAccessPoint verifies the hostapd backup, stops and disables the
// access point, and restores the prior configuration file. Every step is
// attempted so one failure does not strand the others.
func (e RollbackExecutor) rollbackAccessPoint(ctx context.Context, manifest networktransaction.WatchdogManifest, directory string) []error {
	spec := manifest.Rollback
	if !spec.HostapdManaged {
		return nil
	}
	var failures []error
	backup, err := verifyManagedBackup(directory, hostapdBackupName, spec.HostapdConfigExisted, spec.HostapdConfigSHA256, hostapdLabel)
	backupValid := err == nil
	if err != nil {
		failures = append(failures, err)
	}
	if e.AccessPoint == nil {
		failures = append(failures, errors.New("Wi-Fi access point rollback controller is required"))
	} else if err := e.AccessPoint.DisableAccessPoint(ctx); err != nil {
		failures = append(failures, fmt.Errorf("stop ShakerProxy Wi-Fi access point: %w", err))
	}
	if backupValid {
		if err := restoreManagedFile(e.HostRoot, networkplan.ManagedHostapdPath, spec.HostapdConfigExisted, spec.HostapdConfigMode, backup); err != nil {
			failures = append(failures, fmt.Errorf("restore Wi-Fi access point configuration: %w", err))
		}
	}
	return failures
}

type accessPointCommandRunner func(context.Context, string, []string) (rollbackCommandResult, error)

// OSAccessPointService drives shakerproxy-hostapd.service through fixed systemctl
// argument arrays.
type OSAccessPointService struct {
	run          accessPointCommandRunner
	readFile     func(string) ([]byte, error)
	readyTimeout time.Duration
	pollInterval time.Duration
}

func (s OSAccessPointService) StartAccessPoint(ctx context.Context, target AccessPointTarget) error {
	if !safeSysctlInterfaceName(target.Interface) || strings.Contains(target.Interface, ":") || target.Bridge != "" && target.Bridge != networkplan.LabBridgeName && target.Bridge != networkplan.InlineBridgeName {
		return errors.New("Wi-Fi access point target is invalid")
	}
	if result, err := s.command(ctx, []string{"restart", networkplan.HostapdUnit}); err != nil || result.exitCode != 0 {
		return commandResultError("systemctl restart "+networkplan.HostapdUnit, result, err)
	}
	return s.waitReady(ctx, target)
}

func (s OSAccessPointService) waitReady(ctx context.Context, target AccessPointTarget) error {
	timeout := s.readyTimeout
	if timeout <= 0 {
		timeout = defaultAccessPointReady
	}
	interval := s.pollInterval
	if interval <= 0 {
		interval = defaultAccessPointInterval
	}
	waitContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if s.ready(target) {
			return nil
		}
		select {
		case <-waitContext.Done():
			if result, err := s.command(context.WithoutCancel(ctx), []string{"is-active", "--quiet", networkplan.HostapdUnit}); err == nil && result.exitCode != 0 {
				return fmt.Errorf("hostapd stopped while starting the access point on %s; see `journalctl -u %s` for the reason (often an adapter without AP mode, a channel not allowed in the selected country, or Wi-Fi blocked by rfkill)", target.Interface, networkplan.HostapdUnit)
			}
			return fmt.Errorf("the Wi-Fi access point on %s did not come up within %s; see `journalctl -u %s`", target.Interface, timeout, networkplan.HostapdUnit)
		case <-ticker.C:
		}
	}
}

func (s OSAccessPointService) ready(target AccessPointTarget) bool {
	operstate, err := s.read("/sys/class/net/" + target.Interface + "/operstate")
	if err != nil || strings.TrimSpace(string(operstate)) != "up" {
		return false
	}
	if target.Bridge == "" {
		return true
	}
	// The port state file exists only once hostapd has added the adapter to
	// the bridge; 3 is BR_STATE_FORWARDING.
	state, err := s.read("/sys/class/net/" + target.Bridge + "/brif/" + target.Interface + "/state")
	return err == nil && strings.TrimSpace(string(state)) == "3"
}

// EnsureAccessPointEnabled starts the access point at boot once a Wi-Fi plan
// is confirmed.
func (s OSAccessPointService) EnsureAccessPointEnabled(ctx context.Context) error {
	if result, err := s.command(ctx, []string{"enable", networkplan.HostapdUnit}); err != nil || result.exitCode != 0 {
		return commandResultError("systemctl enable "+networkplan.HostapdUnit, result, err)
	}
	return nil
}

// DisableAccessPoint stops the access point now and at boot.
func (s OSAccessPointService) DisableAccessPoint(ctx context.Context) error {
	if result, err := s.command(ctx, []string{"disable", "--now", networkplan.HostapdUnit}); err != nil || result.exitCode != 0 {
		return commandResultError("systemctl disable --now "+networkplan.HostapdUnit, result, err)
	}
	return nil
}

func (s OSAccessPointService) command(ctx context.Context, arguments []string) (rollbackCommandResult, error) {
	if !allowedAccessPointCommand("/usr/bin/systemctl", arguments) {
		return rollbackCommandResult{}, errors.New("access point command is not allowlisted")
	}
	if s.run != nil {
		return s.run(ctx, "/usr/bin/systemctl", arguments)
	}
	return runAccessPointCommand(ctx, "/usr/bin/systemctl", arguments)
}

func (s OSAccessPointService) read(path string) ([]byte, error) {
	if s.readFile != nil {
		return s.readFile(path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, maxSysfsValueBytes+1))
	if err != nil {
		return nil, err
	}
	if len(value) > maxSysfsValueBytes {
		return nil, errors.New("sysfs value exceeded limit")
	}
	return value, nil
}

// allowedAccessPointCommand is the complete command boundary for the access
// point: four exact systemctl argument arrays naming only the ShakerProxy unit.
func allowedAccessPointCommand(path string, arguments []string) bool {
	if path != "/usr/bin/systemctl" {
		return false
	}
	switch strings.Join(arguments, "\x00") {
	case "restart\x00" + networkplan.HostapdUnit,
		"enable\x00" + networkplan.HostapdUnit,
		"disable\x00--now\x00" + networkplan.HostapdUnit,
		"is-active\x00--quiet\x00" + networkplan.HostapdUnit:
		return true
	}
	return false
}

func runAccessPointCommand(ctx context.Context, path string, arguments []string) (rollbackCommandResult, error) {
	if !allowedAccessPointCommand(path, arguments) {
		return rollbackCommandResult{}, errors.New("access point command is not allowlisted")
	}
	command := exec.CommandContext(ctx, path, arguments...)
	command.Env = []string{"HOME=/nonexistent", "LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	var stdout cappedBuffer
	var stderr cappedBuffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if stdout.exceeded || stderr.exceeded {
		return rollbackCommandResult{}, errors.New("access point command output exceeded limit")
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
