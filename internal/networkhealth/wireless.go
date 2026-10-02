package networkhealth

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"shakerproxy.dev/shakerproxy/internal/networkplan"
)

// AccessPointProbe is implemented by probes that can verify the ShakerProxy Wi-Fi
// access point. It is separate from Probe so wired-only probes stay unchanged.
type AccessPointProbe interface {
	AccessPoint(context.Context, networkplan.StagedPlan) error
}

// AccessPointStatusProbe reports whether shakerproxy-hostapd.service is active.
type AccessPointStatusProbe interface {
	Active(context.Context) error
}

func (c Checker) accessPointProbe(ctx context.Context, staged networkplan.StagedPlan) error {
	probe, ok := c.Probe.(AccessPointProbe)
	if !ok {
		return errors.New("Wi-Fi access point health probe is unavailable")
	}
	return probe.AccessPoint(ctx, staged)
}

// AccessPoint passes when hostapd is active, the adapter is up, and, in
// bridged mode, the adapter is a forwarding port of the lab bridge.
func (p OSProbe) AccessPoint(ctx context.Context, staged networkplan.StagedPlan) error {
	ap, ok := networkplan.WiFiAccessPoint(staged.Plan)
	if !ok || !safeInterfaceName(ap.CurrentName) {
		return errors.New("validated Wi-Fi access point interface is unavailable")
	}
	status := p.AccessPointStatus
	if status == nil {
		status = OSAccessPointStatusProbe{}
	}
	if err := status.Active(ctx); err != nil {
		return fmt.Errorf("the Wi-Fi access point service is not running; see `journalctl -u %s`", networkplan.HostapdUnit)
	}
	operstate, err := p.readFile("/sys/class/net/" + ap.CurrentName + "/operstate")
	if err != nil {
		return fmt.Errorf("the state of Wi-Fi adapter %s is unreadable", ap.CurrentName)
	}
	if state := strings.TrimSpace(string(operstate)); state != "up" {
		return fmt.Errorf("Wi-Fi adapter %s is %s instead of broadcasting", ap.CurrentName, state)
	}
	if bridge := networkplan.AccessPointBridgeName(staged.Plan); bridge != "" {
		state, err := p.readFile("/sys/class/net/" + bridge + "/brif/" + ap.CurrentName + "/state")
		if err != nil || strings.TrimSpace(string(state)) != "3" {
			return fmt.Errorf("Wi-Fi adapter %s is not forwarding in bridge %s", ap.CurrentName, bridge)
		}
	}
	return nil
}

type OSAccessPointStatusProbe struct{}

func (OSAccessPointStatusProbe) Active(ctx context.Context) error {
	arguments := []string{"is-active", "--quiet", networkplan.HostapdUnit}
	if !allowedAccessPointStatusProbe("/usr/bin/systemctl", arguments) {
		return errors.New("access point health command is not allowlisted")
	}
	command := exec.CommandContext(ctx, "/usr/bin/systemctl", arguments...)
	command.Env = []string{"HOME=/nonexistent", "LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	if err := command.Run(); err != nil {
		return errors.New("fixed access point health command failed")
	}
	return nil
}

func allowedAccessPointStatusProbe(path string, arguments []string) bool {
	return path == "/usr/bin/systemctl" && strings.Join(arguments, "\x00") == "is-active\x00--quiet\x00"+networkplan.HostapdUnit
}
