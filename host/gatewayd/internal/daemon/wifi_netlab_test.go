package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
)

// netlabWiFiHost is the production Wi-Fi host (sysfs, iw, interface flags)
// with the two systemd units left to tests/netlab/wifi-hwsim.sh, which runs
// dumpcap and the frame parser itself.
type netlabWiFiHost struct {
	productionWiFiHost
	units map[string]bool
}

func (h netlabWiFiHost) StartUnit(_ context.Context, unit string) error {
	h.units[unit] = true
	return nil
}

func (h netlabWiFiHost) StopUnit(_ context.Context, unit string) error {
	h.units[unit] = false
	return nil
}

func (h netlabWiFiHost) UnitActive(_ context.Context, unit string) bool { return h.units[unit] }

// TestWiFiNetlabRole runs gatewayd's real Wi-Fi monitor against
// mac80211_hwsim radios for tests/netlab/wifi-hwsim.sh: "start" turns
// monitoring on in automatic mode with the lab access point (in another
// namespace) on channel 6, "stop" turns it off.
func TestWiFiNetlabRole(t *testing.T) {
	role := os.Getenv("SHAKERPROXY_WIFILAB_ROLE")
	if role == "" {
		t.Skip("run by tests/netlab/wifi-hwsim.sh")
	}
	directory := os.Getenv("SHAKERPROXY_WIFILAB_DIR")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	plan := networkplan.Plan{
		Interfaces: []networkplan.Interface{{CurrentName: os.Getenv("SHAKERPROXY_WIFILAB_AP_INTERFACE"), Role: networkplan.RoleWiFiAP}},
		WiFi:       &networkplan.WiFiConfiguration{Enabled: true, SSID: os.Getenv("SHAKERPROXY_WIFILAB_SSID"), Channel: 6},
	}
	monitor := &WiFiMonitor{
		SettingsPath: filepath.Join(directory, "wifi-monitor.json"),
		ScopePath:    filepath.Join(directory, "scope.json"),
		Host:         netlabWiFiHost{productionWiFiHost: productionWiFiHost{sysfsRoot: "/sys/class/net"}, units: map[string]bool{}},
		Plan:         func() (networkplan.Plan, bool) { return plan, true },
		LabMACs:      func(context.Context) []string { return strings.Fields(os.Getenv("SHAKERPROXY_WIFILAB_LAB_MACS")) },
	}
	settings := gatewayprotocol.WiFiMonitorSettings{ChannelMode: gatewayprotocol.WiFiChannelAuto}
	switch role {
	case "start":
		settings.Enabled = true
		status, err := monitor.Set(ctx, gatewayprotocol.SetWiFiMonitorParams{Settings: settings})
		if err != nil {
			t.Fatalf("start: %v (%+v)", err, status)
		}
		encoded, _ := json.Marshal(status)
		t.Logf("status: %s", encoded)
		if !status.Active || status.Interface != WiFiMonitorInterface || status.Channel != 6 || status.ChannelMode != gatewayprotocol.WiFiChannelFixed {
			t.Fatalf("monitor is not listening on channel 6: %s", encoded)
		}
		if _, err := os.Stat("/sys/class/net/" + WiFiMonitorInterface); err != nil {
			t.Fatalf("no monitor interface: %v", err)
		}
	case "stop":
		// A fresh monitor, as after a restart, reads the saved settings.
		if status, err := monitor.Set(ctx, gatewayprotocol.SetWiFiMonitorParams{Settings: settings}); err != nil || status.Active {
			t.Fatalf("stop: %+v %v", status, err)
		}
		if _, err := os.Stat("/sys/class/net/" + WiFiMonitorInterface); !os.IsNotExist(err) {
			t.Fatalf("monitor interface left behind: %v", err)
		}
	default:
		t.Fatalf("unknown role %q", role)
	}
}
