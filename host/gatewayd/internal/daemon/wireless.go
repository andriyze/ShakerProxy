package daemon

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
)

const (
	iwExecutable           = "/usr/sbin/iw"
	hostapdExecutable      = "/usr/sbin/hostapd"
	maxIWOutputBytes       = 256 << 10
	maxWirelessSysfsBytes  = 256
	wirelessCommandTimeout = 2 * time.Second
)

var (
	wirelessInterfacePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)
	wirelessPhyPattern       = regexp.MustCompile(`^phy[0-9]{1,4}$`)
)

// wirelessInspector gathers Wi-Fi evidence for preflight. Every host access is
// a bounded sysfs read or the single fixed command `iw phy <phyN> info`.
type wirelessInspector struct {
	sysfsRoot string
	runIW     func(context.Context, string) (string, error)
	phyCache  map[string]phyCapabilities
}

type phyCapabilities struct {
	known       bool
	apSupported bool
	bands       []string
}

func newWirelessInspector() *wirelessInspector {
	return &wirelessInspector{sysfsRoot: "/sys/class/net", runIW: runIWPhyInfo, phyCache: map[string]phyCapabilities{}}
}

// inspect returns the contract fields for one interface: wireless, AP support
// (nil when unknown), and the supported Wi-Fi bands.
func (w *wirelessInspector) inspect(ctx context.Context, name string) (bool, *bool, []string) {
	bands := []string{}
	if !wirelessInterfacePattern.MatchString(name) || name == "." || name == ".." {
		return false, nil, bands
	}
	base := filepath.Join(w.sysfsRoot, name)
	_, phyErr := os.Stat(filepath.Join(base, "phy80211"))
	_, wirelessErr := os.Stat(filepath.Join(base, "wireless"))
	if phyErr != nil && wirelessErr != nil {
		notSupported := false
		return false, &notSupported, bands
	}
	phy := strings.TrimSpace(readWirelessSysfs(filepath.Join(base, "phy80211", "name")))
	if !wirelessPhyPattern.MatchString(phy) {
		return true, nil, bands
	}
	capabilities, cached := w.phyCache[phy]
	if !cached {
		output, err := w.runIW(ctx, phy)
		if err == nil {
			capabilities = parseIWPhyInfo(output)
		}
		w.phyCache[phy] = capabilities
	}
	if !capabilities.known {
		return true, nil, bands
	}
	supported := capabilities.apSupported
	return true, &supported, append(bands, capabilities.bands...)
}

func readWirelessSysfs(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, maxWirelessSysfsBytes+1))
	if err != nil || len(value) > maxWirelessSysfsBytes {
		return ""
	}
	return string(value)
}

// parseIWPhyInfo reads the "Supported interface modes" list and the enabled
// channel frequencies from `iw phy <phy> info`.
func parseIWPhyInfo(output string) phyCapabilities {
	result := phyCapabilities{}
	bands := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 0, 4096), 4096)
	inModes, modesIndent := false, 0
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if trimmed == "Supported interface modes:" {
			inModes, modesIndent, result.known = true, indent, true
			continue
		}
		if inModes {
			if indent > modesIndent && strings.HasPrefix(trimmed, "* ") {
				if strings.TrimSpace(strings.TrimPrefix(trimmed, "* ")) == "AP" {
					result.apSupported = true
				}
				continue
			}
			inModes = false
		}
		if !strings.HasPrefix(trimmed, "* ") || !strings.Contains(trimmed, " MHz") || strings.Contains(trimmed, "(disabled)") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(trimmed, "* "))
		if len(fields) < 2 || fields[1] != "MHz" {
			continue
		}
		frequency, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			continue
		}
		switch {
		case frequency >= 2400 && frequency < 2500:
			bands[string(networkplan.WiFiBand24GHz)] = true
		case frequency >= 4900 && frequency < 5925:
			bands[string(networkplan.WiFiBand5GHz)] = true
		}
	}
	if scanner.Err() != nil {
		return phyCapabilities{}
	}
	for band := range bands {
		result.bands = append(result.bands, band)
	}
	sort.Strings(result.bands)
	return result
}

func runIWPhyInfo(ctx context.Context, phy string) (string, error) {
	arguments := []string{"phy", phy, "info"}
	if !allowedWirelessCommand(iwExecutable, arguments) {
		return "", errors.New("wireless inspection command is not allowlisted")
	}
	if info, err := os.Stat(iwExecutable); err != nil || !info.Mode().IsRegular() {
		return "", errors.New("iw is not installed")
	}
	commandContext, cancel := context.WithTimeout(ctx, wirelessCommandTimeout)
	defer cancel()
	return runWirelessCommand(commandContext, iwExecutable, arguments)
}

// networkManagerActive reports whether NetworkManager is running; only bridged
// Wi-Fi plans ask, because NetworkManager may reclaim the hostapd-owned adapter.
func networkManagerActive(ctx context.Context) bool {
	arguments := []string{"is-active", "NetworkManager.service"}
	commandContext, cancel := context.WithTimeout(ctx, wirelessCommandTimeout)
	defer cancel()
	output, err := runWirelessCommand(commandContext, "/usr/bin/systemctl", arguments)
	return err == nil && strings.TrimSpace(output) == "active"
}

func runWirelessCommand(ctx context.Context, path string, arguments []string) (string, error) {
	if !allowedWirelessCommand(path, arguments) {
		return "", errors.New("wireless inspection command is not allowlisted")
	}
	command := exec.CommandContext(ctx, path, arguments...)
	command.Env = []string{"HOME=/nonexistent", "LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	var stdout, stderr wirelessOutput
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return "", fmt.Errorf("fixed wireless inspection command failed: %w", err)
	}
	if stdout.truncated || stderr.truncated {
		return "", errors.New("wireless inspection output exceeded limit")
	}
	return string(stdout.bytes), nil
}

// allowedWirelessCommand admits exactly `iw phy <phyN> info` and
// `systemctl is-active NetworkManager.service`.
func allowedWirelessCommand(path string, arguments []string) bool {
	switch path {
	case iwExecutable:
		return len(arguments) == 3 && arguments[0] == "phy" && wirelessPhyPattern.MatchString(arguments[1]) && arguments[2] == "info"
	case "/usr/bin/systemctl":
		return strings.Join(arguments, "\x00") == "is-active\x00NetworkManager.service"
	}
	return false
}

type wirelessOutput struct {
	bytes     []byte
	truncated bool
}

func (w *wirelessOutput) Write(value []byte) (int, error) {
	original := len(value)
	remaining := maxIWOutputBytes - len(w.bytes)
	if remaining <= 0 {
		w.truncated = true
		return original, nil
	}
	if len(value) > remaining {
		value = value[:remaining]
		w.truncated = true
	}
	w.bytes = append(w.bytes, value...)
	return original, nil
}

// wifiHostEvidence converts preflight evidence into what host-aware Wi-Fi
// validation needs. Only Wi-Fi plans pay for the NetworkManager query.
func wifiHostEvidence(ctx context.Context, plan networkplan.Plan, host gatewayprotocol.HostInspection, hostapdInstalled func() bool, managerActive func(context.Context) bool) networkplan.WiFiHostEvidence {
	evidence := networkplan.WiFiHostEvidence{Interfaces: map[string]networkplan.WirelessInterfaceEvidence{}}
	if !networkplan.WiFiEnabled(plan) {
		return evidence
	}
	evidence.HostapdInstalled = hostapdInstalled()
	if networkplan.WiFiBridged(plan) {
		evidence.NetworkManagerActive = managerActive(ctx)
	}
	for _, iface := range host.Interfaces {
		item := networkplan.WirelessInterfaceEvidence{Wireless: iface.Wireless, APSupported: iface.APSupported, DefaultRoute: iface.DefaultIPv4 || iface.DefaultIPv6}
		for _, band := range iface.WirelessBands {
			item.Bands = append(item.Bands, networkplan.WiFiBand(band))
		}
		evidence.Interfaces[iface.Name] = item
	}
	return evidence
}

func hostapdInstalled() bool {
	info, err := os.Stat(hostapdExecutable)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}

// labIngressMatches finds the observed interface for the confirmed lab
// segment. The ShakerProxy bridge is virtual, so it is matched by its fixed name;
// physical interfaces keep matching by stable identity.
func labIngressMatches(planned networkplan.Interface, observed gatewayprotocol.Interface) bool {
	if networkplan.IsLabBridge(planned) {
		return observed.Name == planned.CurrentName
	}
	return observed.StableID == planned.StableID
}

type accessPointFinalizer interface {
	EnsureAccessPointEnabled(context.Context) error
}

// finalizeAccessPoint enables the access point at boot once a Wi-Fi plan is
// durably confirmed. Wired plans never touch the hostapd unit.
func finalizeAccessPoint(ctx context.Context, finalizer accessPointFinalizer, plan networkplan.Plan) error {
	if !networkplan.WiFiEnabled(plan) {
		return nil
	}
	if finalizer == nil {
		return errors.New("Wi-Fi access point finalizer is unavailable")
	}
	return finalizer.EnsureAccessPointEnabled(ctx)
}

// wirelessDiagnostic reports the access point service when the confirmed
// routed plan includes Wi-Fi.
func wirelessDiagnostic(ctx context.Context, state persistedState) (gatewayprotocol.DiagnosticCheck, bool) {
	staged := state.activeNetworkPlan()
	if state.OperatingMode != gatewayprotocol.ModeRouted || staged == nil {
		return gatewayprotocol.DiagnosticCheck{}, false
	}
	ap, ok := networkplan.WiFiAccessPoint(staged.Plan)
	if !ok {
		return gatewayprotocol.DiagnosticCheck{}, false
	}
	active, known := diagnosticServiceActive(ctx, networkplan.HostapdUnit)
	switch {
	case !known:
		return diagnosticCheck("wifi_ap", gatewayprotocol.DiagnosticUnknown, "Wi-Fi access point service state is unavailable"), true
	case !active:
		return diagnosticCheck("wifi_ap", gatewayprotocol.DiagnosticFail, "Wi-Fi access point is not running; check `journalctl -u "+networkplan.HostapdUnit+"`", "adapter: "+ap.CurrentName), true
	default:
		return diagnosticCheck("wifi_ap", gatewayprotocol.DiagnosticPass, fmt.Sprintf("Wi-Fi access point %q is broadcasting from %s", staged.Plan.WiFi.SSID, ap.CurrentName)), true
	}
}
