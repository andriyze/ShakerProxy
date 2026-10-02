package daemon

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/wifi"
)

const (
	systemctlExecutable = "/usr/bin/systemctl"
	wifiCommandTimeout  = 5 * time.Second
)

// productionWiFiHost runs a fixed, allowlisted set of commands: `iw phy
// <phyN> info`, `iw phy <phyN> interface add spmon0 type monitor`, `iw dev
// spmon0 set freq <MHz>`, `iw dev spmon0 del`, and `systemctl
// start|stop|is-active` of the two Wi-Fi units.
type productionWiFiHost struct {
	sysfsRoot string
}

// NewProductionWiFiMonitor manages Wi-Fi visibility on this host.
func NewProductionWiFiMonitor(server *Server, logger *slog.Logger) *WiFiMonitor {
	return &WiFiMonitor{
		SettingsPath: DefaultWiFiMonitorSettingsPath,
		ScopePath:    wifi.DefaultScopePath,
		Host:         productionWiFiHost{sysfsRoot: "/sys/class/net"},
		Plan: func() (networkplan.Plan, bool) {
			_, plan, ok := confirmedLabPlan(server.store)
			return plan, ok
		},
		LabMACs: server.labHardwareAddresses,
		Logger:  logger,
	}
}

// labHardwareAddresses lists lab devices' hardware addresses from the lab
// interface's IPv4 and IPv6 neighbor tables.
func (s *Server) labHardwareAddresses(ctx context.Context) []string {
	addresses := []string{}
	if table, err := s.ipv4NeighborTable(ctx); err == nil {
		for _, neighbor := range table.Neighbors {
			addresses = append(addresses, neighbor.HardwareAddress)
		}
	}
	if table, err := s.neighborTable(ctx); err == nil {
		for _, neighbor := range table.Neighbors {
			if !neighbor.Router {
				addresses = append(addresses, neighbor.HardwareAddress)
			}
		}
	}
	return addresses
}

func (h productionWiFiHost) Wireless(_ context.Context) ([]wifiInterface, error) {
	entries, err := os.ReadDir(h.sysfsRoot)
	if err != nil {
		return nil, err
	}
	routes := defaultRouteInterfaces()
	interfaces := []wifiInterface{}
	for _, entry := range entries {
		name := entry.Name()
		if !wirelessInterfacePattern.MatchString(name) || name == "." || name == ".." {
			continue
		}
		base := filepath.Join(h.sysfsRoot, name)
		if _, err := os.Stat(filepath.Join(base, "phy80211")); err != nil {
			continue
		}
		iface := wifiInterface{
			Name:    name,
			Phy:     strings.TrimSpace(readWirelessSysfs(filepath.Join(base, "phy80211", "name"))),
			Address: strings.TrimSpace(readWirelessSysfs(filepath.Join(base, "address"))),
			InUse:   routes[name] || hasGlobalAddress(name),
		}
		if !wirelessPhyPattern.MatchString(iface.Phy) {
			iface.Phy = ""
		}
		interfaces = append(interfaces, iface)
	}
	return interfaces, nil
}

func hasGlobalAddress(name string) bool {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return false
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, address := range addresses {
		prefix, ok := address.(*net.IPNet)
		if ok && !prefix.IP.IsLinkLocalUnicast() && !prefix.IP.IsLoopback() {
			return true
		}
	}
	return false
}

// defaultRouteInterfaces reads the interfaces holding an IPv4 or IPv6
// default route from /proc.
func defaultRouteInterfaces() map[string]bool {
	result := map[string]bool{}
	if file, err := os.Open("/proc/net/route"); err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) > 2 && fields[1] == "00000000" && fields[0] != "Iface" {
				result[fields[0]] = true
			}
		}
		file.Close()
	}
	if file, err := os.Open("/proc/net/ipv6_route"); err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) == 10 && fields[0] == strings.Repeat("0", 32) && fields[1] == "00" && fields[9] != "lo" {
				result[fields[9]] = true
			}
		}
		file.Close()
	}
	return result
}

func (productionWiFiHost) PhyInfo(ctx context.Context, phy string) (string, error) {
	return runIWPhyInfo(ctx, phy)
}

func (productionWiFiHost) AddMonitor(ctx context.Context, phy string) error {
	if !wirelessPhyPattern.MatchString(phy) {
		return errors.New("Wi-Fi radio name is invalid")
	}
	return runWiFiCommand(ctx, iwExecutable, "phy", phy, "interface", "add", WiFiMonitorInterface, "type", "monitor")
}

func (productionWiFiHost) DeleteMonitor(ctx context.Context) error {
	return runWiFiCommand(ctx, iwExecutable, "dev", WiFiMonitorInterface, "del")
}

func (h productionWiFiHost) MonitorExists() bool {
	_, err := os.Lstat(filepath.Join(h.sysfsRoot, WiFiMonitorInterface))
	return err == nil
}

func (productionWiFiHost) LinkUp(name string) (bool, error) { return linkUp(name) }

func (productionWiFiHost) SetLinkUp(name string, up bool) error { return setLinkUp(name, up) }

func (productionWiFiHost) SetFrequency(ctx context.Context, frequency int) error {
	if wifi.ChannelForFrequency(frequency) == 0 {
		return errors.New("frequency is not a Wi-Fi channel")
	}
	return runWiFiCommand(ctx, iwExecutable, "dev", WiFiMonitorInterface, "set", "freq", strconv.Itoa(frequency))
}

func (productionWiFiHost) StartUnit(ctx context.Context, unit string) error {
	return runWiFiCommand(ctx, systemctlExecutable, "start", unit)
}

func (productionWiFiHost) StopUnit(ctx context.Context, unit string) error {
	return runWiFiCommand(ctx, systemctlExecutable, "stop", unit)
}

func (productionWiFiHost) UnitActive(ctx context.Context, unit string) bool {
	return runWiFiCommand(ctx, systemctlExecutable, "is-active", "--quiet", unit) == nil
}

// WriteScope replaces the scope file atomically. Its directory is setgid
// shakerproxy-wifi, so the file is readable by the worker's group.
func (productionWiFiHost) WriteScope(path string, data []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".scope-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o640); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// allowedWiFiCommand admits only the monitor's fixed commands.
func allowedWiFiCommand(path string, arguments []string) bool {
	switch path {
	case iwExecutable:
		switch {
		case len(arguments) == 7 && arguments[0] == "phy" && wirelessPhyPattern.MatchString(arguments[1]) && strings.Join(arguments[2:], " ") == "interface add "+WiFiMonitorInterface+" type monitor":
			return true
		case len(arguments) == 3 && strings.Join(arguments, " ") == "dev "+WiFiMonitorInterface+" del":
			return true
		case len(arguments) == 5 && strings.Join(arguments[:4], " ") == "dev "+WiFiMonitorInterface+" set freq":
			frequency, err := strconv.Atoi(arguments[4])
			return err == nil && wifi.ChannelForFrequency(frequency) != 0
		}
	case systemctlExecutable:
		unit := arguments[len(arguments)-1]
		if unit != wifiCaptureUnit && unit != wifiWorkerUnit {
			return false
		}
		verb := strings.Join(arguments[:len(arguments)-1], " ")
		return verb == "start" || verb == "stop" || verb == "is-active --quiet"
	}
	return false
}

func runWiFiCommand(ctx context.Context, path string, arguments ...string) error {
	if len(arguments) == 0 || !allowedWiFiCommand(path, arguments) {
		return errors.New("Wi-Fi monitor command is not allowlisted")
	}
	if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
		if path == iwExecutable {
			return errors.New("the iw tool is not installed (apt install iw)")
		}
		return fmt.Errorf("%s is not installed", path)
	}
	commandContext, cancel := context.WithTimeout(ctx, wifiCommandTimeout)
	defer cancel()
	command := exec.CommandContext(commandContext, path, arguments...)
	command.Env = []string{"HOME=/nonexistent", "LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	var output wirelessOutput
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		message := strings.TrimSpace(string(output.bytes))
		if len(message) > 200 {
			message = message[:200]
		}
		if message != "" {
			return fmt.Errorf("%s: %s", filepath.Base(path), message)
		}
		return fmt.Errorf("%s failed: %w", filepath.Base(path), err)
	}
	return nil
}
