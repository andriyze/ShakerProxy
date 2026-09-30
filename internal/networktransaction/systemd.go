package networktransaction

import (
	"context"
	"errors"
	"os/exec"
	"strings"
)

const watchdogExecutable = "/usr/libexec/shakerproxy/shakerproxy-network-watchdog"

type CommandRunner interface {
	Run(context.Context, string, ...string) error
}

type SystemdWatchdog struct{ Runner CommandRunner }

func (s SystemdWatchdog) EnsureArmed(ctx context.Context, manifest WatchdogManifest) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	if s.Runner == nil {
		return errors.New("watchdog command runner is required")
	}
	unit := watchdogUnit(manifest.ApplyID) + ".service"
	if err := s.Runner.Run(ctx, "/usr/bin/systemctl", "is-active", "--quiet", unit); err == nil {
		return nil
	}
	return s.Arm(ctx, manifest)
}

func (s SystemdWatchdog) Arm(ctx context.Context, manifest WatchdogManifest) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	if s.Runner == nil {
		return errors.New("watchdog command runner is required")
	}
	return s.Runner.Run(ctx, "/usr/bin/systemd-run",
		"--unit="+watchdogUnit(manifest.ApplyID),
		"--collect",
		"--service-type=exec",
		"--property=NoNewPrivileges=yes",
		"--property=ProtectSystem=strict",
		"--property=ProtectHome=yes",
		"--property=PrivateTmp=yes",
		"--property=CapabilityBoundingSet=CAP_NET_ADMIN",
		"--property=RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6",
		"--property=LockPersonality=yes",
		"--property=MemoryDenyWriteExecute=yes",
		"--property=RestrictSUIDSGID=yes",
		"--property=ReadWritePaths=/run/lock/shakerproxy "+DefaultTransactionRoot+" /etc/netplan /etc/kea /etc/systemd/system /run/systemd/system /run/systemd/network /run/udev/rules.d -/etc/shakerproxy/hostapd -/etc/shakerproxy/radvd",
		watchdogExecutable,
		"--apply-id", manifest.ApplyID,
	)
}

func (s SystemdWatchdog) Disarm(ctx context.Context, applyID string) error {
	if !applyIDPattern.MatchString(applyID) {
		return errors.New("invalid apply ID")
	}
	if s.Runner == nil {
		return errors.New("watchdog command runner is required")
	}
	return s.Runner.Run(ctx, "/usr/bin/systemctl", "stop", watchdogUnit(applyID)+".service")
}

func watchdogUnit(applyID string) string {
	return "shakerproxy-network-watchdog-" + strings.TrimPrefix(applyID, "apply-")
}

type OSCommandRunner struct{}

func (OSCommandRunner) Run(ctx context.Context, path string, arguments ...string) error {
	if !allowedWatchdogCommand(path, arguments) {
		return errors.New("watchdog command is not allowlisted")
	}
	command := exec.CommandContext(ctx, path, arguments...)
	return command.Run()
}

func allowedWatchdogCommand(path string, arguments []string) bool {
	if path == "/usr/bin/systemctl" {
		var unit string
		switch {
		case len(arguments) == 2 && arguments[0] == "stop":
			unit = strings.TrimSuffix(arguments[1], ".service")
		case len(arguments) == 3 && arguments[0] == "is-active" && arguments[1] == "--quiet":
			unit = strings.TrimSuffix(arguments[2], ".service")
		default:
			return false
		}
		id := strings.TrimPrefix(unit, "shakerproxy-network-watchdog-")
		return unit == "shakerproxy-network-watchdog-"+id && applyIDPattern.MatchString("apply-"+id) && strings.HasSuffix(arguments[len(arguments)-1], ".service")
	}
	if path != "/usr/bin/systemd-run" || len(arguments) != 16 {
		return false
	}
	return arguments[0] == "--unit="+watchdogUnit(arguments[15]) &&
		arguments[1] == "--collect" &&
		arguments[2] == "--service-type=exec" &&
		arguments[3] == "--property=NoNewPrivileges=yes" &&
		arguments[4] == "--property=ProtectSystem=strict" &&
		arguments[5] == "--property=ProtectHome=yes" &&
		arguments[6] == "--property=PrivateTmp=yes" &&
		arguments[7] == "--property=CapabilityBoundingSet=CAP_NET_ADMIN" &&
		arguments[8] == "--property=RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6" &&
		arguments[9] == "--property=LockPersonality=yes" &&
		arguments[10] == "--property=MemoryDenyWriteExecute=yes" &&
		arguments[11] == "--property=RestrictSUIDSGID=yes" &&
		arguments[12] == "--property=ReadWritePaths=/run/lock/shakerproxy "+DefaultTransactionRoot+" /etc/netplan /etc/kea /etc/systemd/system /run/systemd/system /run/systemd/network /run/udev/rules.d -/etc/shakerproxy/hostapd -/etc/shakerproxy/radvd" &&
		arguments[13] == watchdogExecutable && arguments[14] == "--apply-id" && applyIDPattern.MatchString(arguments[15])
}
