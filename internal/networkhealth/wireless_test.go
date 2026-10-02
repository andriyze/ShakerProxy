package networkhealth

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

type fakeWiFiProbe struct {
	fakeProbe
	accessPointErr error
}

func (p *fakeWiFiProbe) AccessPoint(context.Context, networkplan.StagedPlan) error {
	p.run(networktransaction.CheckWiFiAP)
	return p.accessPointErr
}

type fakeAccessPointStatus struct{ err error }

func (f fakeAccessPointStatus) Active(context.Context) error { return f.err }

func wifiHealthStaged(t *testing.T, now time.Time, bridged bool) networkplan.StagedPlan {
	t.Helper()
	staged := healthStaged(t, now)
	staged.Plan.Interfaces = []networkplan.Interface{{CurrentName: "eth0", Role: networkplan.RoleWAN}, {CurrentName: "wlan0", Role: networkplan.RoleWiFiAP}}
	if bridged {
		staged.Plan.Interfaces = append(staged.Plan.Interfaces, networkplan.Interface{CurrentName: "eth1", Role: networkplan.RoleLab})
	}
	staged.Plan.WiFi = &networkplan.WiFiConfiguration{Enabled: true, BridgeWithLab: bridged}
	return staged
}

func findCheck(report networktransaction.HealthReport, name networktransaction.CheckName) (networktransaction.HealthCheck, bool) {
	for _, check := range report.Checks {
		if check.Name == name {
			return check, true
		}
	}
	return networktransaction.HealthCheck{}, false
}

func TestCheckerRequiresAccessPointHealthOnlyForWiFiPlans(t *testing.T) {
	now := time.Unix(10000, 0)
	clock := func() time.Time { return now.Add(4 * time.Second) }

	probe := &fakeWiFiProbe{}
	report, err := (Checker{Probe: probe, Now: clock}).Check(context.Background(), wifiHealthStaged(t, now, true))
	if err != nil {
		t.Fatal(err)
	}
	check, found := findCheck(report, networktransaction.CheckWiFiAP)
	if !report.Healthy() || !found || check.Status != networktransaction.CheckPass || probe.calls[networktransaction.CheckWiFiAP] != 1 {
		t.Fatalf("healthy access point was not verified: %+v", report)
	}

	probe = &fakeWiFiProbe{accessPointErr: errors.New("hostapd is not running")}
	report, err = (Checker{Probe: probe, Now: clock}).Check(context.Background(), wifiHealthStaged(t, now, false))
	if err != nil {
		t.Fatal(err)
	}
	if check, _ := findCheck(report, networktransaction.CheckWiFiAP); report.Healthy() || check.Status != networktransaction.CheckFail || check.Detail != "hostapd is not running" {
		t.Fatalf("failed access point was reported healthy: %+v", report)
	}

	report, err = (Checker{Probe: &fakeProbe{}, Now: clock}).Check(context.Background(), wifiHealthStaged(t, now, false))
	if err != nil {
		t.Fatal(err)
	}
	if check, _ := findCheck(report, networktransaction.CheckWiFiAP); report.Healthy() || check.Status != networktransaction.CheckFail || !strings.Contains(check.Detail, "unavailable") {
		t.Fatalf("a probe without access point support passed a Wi-Fi plan: %+v", report)
	}

	report, err = (Checker{Probe: &fakeWiFiProbe{}, Now: clock}).Check(context.Background(), healthStaged(t, now))
	if err != nil {
		t.Fatal(err)
	}
	if _, found := findCheck(report, networktransaction.CheckWiFiAP); found {
		t.Fatalf("wired plan gained a Wi-Fi health check: %+v", report.Checks)
	}
}

func TestHealthReportRejectsSkippedAccessPoint(t *testing.T) {
	report := networktransaction.HealthReport{CheckedAt: time.Unix(1, 0), Checks: []networktransaction.HealthCheck{
		{Name: networktransaction.CheckManagement, Status: networktransaction.CheckPass},
		{Name: networktransaction.CheckWAN, Status: networktransaction.CheckPass},
		{Name: networktransaction.CheckDNS, Status: networktransaction.CheckPass},
		{Name: networktransaction.CheckIPv4Forwarding, Status: networktransaction.CheckPass},
		{Name: networktransaction.CheckDHCP4, Status: networktransaction.CheckPass},
		{Name: networktransaction.CheckWiFiAP, Status: networktransaction.CheckSkip},
	}}
	if err := report.Validate(); err == nil {
		t.Fatal("a skipped access point check was accepted")
	}
	report.Checks[5].Status = networktransaction.CheckPass
	if err := report.Validate(); err != nil || !report.Healthy() {
		t.Fatalf("passing access point check was rejected: %v", err)
	}
}

func TestOSProbeAccessPoint(t *testing.T) {
	now := time.Unix(10000, 0)
	files := map[string]string{
		"/sys/class/net/wlan0/operstate":        "up\n",
		"/sys/class/net/lgbr0/brif/wlan0/state": "3\n",
	}
	probeWith := func(files map[string]string, status error) OSProbe {
		return OSProbe{
			AccessPointStatus: fakeAccessPointStatus{err: status},
			ReadFile: func(path string) ([]byte, error) {
				if value, ok := files[path]; ok {
					return []byte(value), nil
				}
				return nil, os.ErrNotExist
			},
		}
	}
	if err := probeWith(files, nil).AccessPoint(context.Background(), wifiHealthStaged(t, now, true)); err != nil {
		t.Fatalf("healthy bridged access point failed: %v", err)
	}
	if err := probeWith(map[string]string{"/sys/class/net/wlan0/operstate": "up\n"}, nil).AccessPoint(context.Background(), wifiHealthStaged(t, now, false)); err != nil {
		t.Fatalf("healthy access point failed: %v", err)
	}
	cases := map[string]struct {
		files  map[string]string
		status error
		want   string
	}{
		"service inactive":     {files: files, status: errors.New("inactive"), want: "journalctl -u shakerproxy-hostapd.service"},
		"adapter down":         {files: map[string]string{"/sys/class/net/wlan0/operstate": "down\n"}, want: "is down"},
		"adapter unreadable":   {files: map[string]string{}, want: "unreadable"},
		"not in bridge":        {files: map[string]string{"/sys/class/net/wlan0/operstate": "up\n"}, want: "not forwarding"},
		"bridge port learning": {files: map[string]string{"/sys/class/net/wlan0/operstate": "up\n", "/sys/class/net/lgbr0/brif/wlan0/state": "2\n"}, want: "not forwarding"},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			err := probeWith(test.files, test.status).AccessPoint(context.Background(), wifiHealthStaged(t, now, true))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected %q, got %v", test.want, err)
			}
		})
	}
	// On an inline bridge the access point must forward in spbr0.
	inline := wifiHealthStaged(t, now, true)
	inline.Plan.Topology = networkplan.TopologyTransparentBridge
	if err := probeWith(map[string]string{"/sys/class/net/wlan0/operstate": "up\n", "/sys/class/net/spbr0/brif/wlan0/state": "3\n"}, nil).AccessPoint(context.Background(), inline); err != nil {
		t.Fatalf("an access point forwarding in the inline bridge failed: %v", err)
	}
	if err := probeWith(files, nil).AccessPoint(context.Background(), inline); err == nil || !strings.Contains(err.Error(), "not forwarding in bridge spbr0") {
		t.Fatalf("an access point outside the inline bridge passed: %v", err)
	}
	unsafe := wifiHealthStaged(t, now, false)
	unsafe.Plan.Interfaces[1].CurrentName = "../../etc"
	if err := probeWith(files, nil).AccessPoint(context.Background(), unsafe); err == nil {
		t.Fatal("unsafe access point name reached sysfs")
	}
}

func TestAccessPointStatusProbeAllowlistIsExact(t *testing.T) {
	if !allowedAccessPointStatusProbe("/usr/bin/systemctl", []string{"is-active", "--quiet", "shakerproxy-hostapd.service"}) {
		t.Fatal("exact access point status probe rejected")
	}
	for _, arguments := range [][]string{
		{"is-active", "shakerproxy-hostapd.service"},
		{"is-active", "--quiet", "hostapd.service"},
		{"restart", "shakerproxy-hostapd.service"},
		{"is-active", "--quiet", "shakerproxy-hostapd.service", "shakerproxy-dhcp4.service"},
	} {
		if allowedAccessPointStatusProbe("/usr/bin/systemctl", arguments) {
			t.Fatalf("broad status probe allowlisted: %q", arguments)
		}
	}
	if allowedAccessPointStatusProbe("/bin/sh", []string{"-c", "systemctl is-active --quiet shakerproxy-hostapd.service"}) {
		t.Fatal("shell status probe allowlisted")
	}
}
