package daemon

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/configlock"
	"shakerproxy.dev/shakerproxy/internal/networkapply"
	"shakerproxy.dev/shakerproxy/internal/networkhealth"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

func NewProductionNetworkActivation(store *StateStore) (*NetworkActivation, error) {
	if store == nil {
		return nil, errors.New("network activation state store is required")
	}
	if err := validateProductionActivationHost(); err != nil {
		return nil, err
	}
	secret := make([]byte, activationSecretBytes)
	if _, err := rand.Read(secret); err != nil {
		return nil, errors.New("generate network activation secret")
	}
	files := networktransaction.FileStore{Root: networktransaction.DefaultTransactionRoot}
	heartbeats := &networkhealth.HeartbeatGate{}
	systemdWatchdog := networktransaction.SystemdWatchdog{Runner: networktransaction.OSCommandRunner{}}
	dhcp4 := networkapply.OSDHCP4Service{}
	accessPoint := networkapply.OSAccessPointService{}
	ipv6 := networkapply.OSIPv6Machine{}
	services := networkapply.OSNetworkServices{OSDHCP4Service: dhcp4, OSIPv6Machine: ipv6}
	rollback := networkapply.RollbackExecutor{Store: files, HostRoot: "/", Machine: networkapply.OSRollbackMachine{}, DHCP4: dhcp4, AccessPoint: accessPoint, IPv6: ipv6}
	base := NetworkCoordinator{
		Store:       store,
		Files:       files,
		Snapshotter: networkapply.Snapshotter{Store: files, HostRoot: "/"},
		Syntax: networkapply.Validator{
			Store:  files,
			Runner: networkapply.OSRunner{TransactionRoot: networktransaction.DefaultTransactionRoot},
		},
		Watchdog:  systemdWatchdog,
		Applier:   networkapply.Applier{Store: files, HostRoot: "/", Machine: networkapply.OSApplyMachine{}, DHCP4: dhcp4, AccessPoint: accessPoint, IPv6: ipv6},
		Health:    networkhealth.Checker{Probe: networkhealth.DefaultOSProbe(heartbeats)},
		Rollback:  rollback,
		Finalizer: services,

		AccessPoint: accessPoint,
	}
	configurationLock := &configlock.Manager{}
	activation := &NetworkActivation{
		Store:      store,
		Files:      files,
		Heartbeats: heartbeats,
		Secret:     secret,
		ConfigLock: configurationLock,
		Coordinator: func(window time.Duration) transactionCoordinator {
			coordinator := base
			coordinator.RollbackWindow = window
			return coordinator
		},
		Rollback: rollback.Execute,
		Runtime: &NetworkRuntimeKeeper{
			Store:      store,
			Restorer:   networkapply.RuntimeRestorer{Store: files, HostRoot: "/", Machine: networkapply.OSRuntimeMachine{}},
			ConfigLock: configurationLock,
		},
	}
	recovery := NetworkRecovery{Store: store, Files: files, Watchdog: systemdWatchdog, Rollback: rollback, Finalizer: services, AccessPoint: accessPoint}
	lockStatus, err := configurationLock.Inspect()
	if err != nil {
		return nil, fmt.Errorf("inspect appliance configuration lock: %w", err)
	}
	if lockStatus.Active {
		if staged := store.Get().StagedNetworkPlan; staged != nil && staged.Transaction != nil && staged.Transaction.Phase != networktransaction.PhaseConfirmed && staged.Transaction.Phase != networktransaction.PhaseRolledBack {
			return nil, errors.New("unresolved network recovery is blocked by another appliance configuration mutation")
		}
		return activation, nil
	}
	recoveryContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	guard, err := configurationLock.Acquire(recoveryContext, configlock.Request{OperationID: "network-startup-recovery", Category: configlock.CategoryNetwork, Actor: "gatewayd"})
	if err != nil {
		return nil, fmt.Errorf("acquire network recovery lock: %w", err)
	}
	defer guard.Release()
	if err := recovery.Recover(recoveryContext); err != nil {
		return nil, fmt.Errorf("recover guarded network transaction: %w", err)
	}
	return activation, nil
}

func validateProductionActivationHost() error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
		return errors.New("network activation requires root on Linux amd64")
	}
	release, err := os.ReadFile("/etc/os-release")
	if err != nil || len(release) > 64<<10 {
		return errors.New("network activation cannot validate the operating system")
	}
	id, version := parseOSRelease(string(release))
	if id != "ubuntu" || !supportedUbuntuVersion(version) {
		return fmt.Errorf("network activation requires Ubuntu 24.04 or 26.04, found %s %s", id, version)
	}
	if info, err := os.Stat("/run/systemd/system"); err != nil || !info.IsDir() {
		return errors.New("network activation requires a running systemd host")
	}
	for _, path := range []string{
		"/usr/sbin/netplan",
		"/usr/sbin/iptables-restore",
		"/usr/sbin/ip6tables-restore",
		"/usr/sbin/sysctl",
		"/usr/sbin/kea-dhcp4",
		"/usr/bin/systemd-run",
		"/usr/bin/systemctl",
		"/usr/bin/ss",
		"/usr/libexec/shakerproxy/shakerproxy-network-watchdog",
	} {
		if err := requireExecutable(path); err != nil {
			return err
		}
	}
	if err := requireExecutable("/usr/sbin/iptables"); err != nil {
		if fallbackErr := requireExecutable("/usr/bin/iptables"); fallbackErr != nil {
			return errors.New("network activation requires an approved iptables executable")
		}
	}
	return nil
}

func supportedUbuntuVersion(version string) bool {
	switch version {
	case "24.04", "26.04":
		return true
	default:
		return false
	}
}

func requireExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("network activation prerequisite is unavailable: %s", path)
	}
	return nil
}

func parseOSRelease(contents string) (string, string) {
	values := map[string]string{}
	for _, line := range strings.Split(contents, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || (key != "ID" && key != "VERSION_ID") {
			continue
		}
		values[key] = strings.Trim(strings.TrimSpace(value), "\"")
	}
	return values["ID"], values["VERSION_ID"]
}
