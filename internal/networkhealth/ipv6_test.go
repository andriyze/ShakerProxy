package networkhealth

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/firewall"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

type fakeIPv6Probe struct {
	fakeProbe
	ipv6Err   error
	ipv6Calls int
}

func (p *fakeIPv6Probe) IPv6(context.Context, networkplan.StagedPlan) error {
	p.ipv6Calls++
	return p.ipv6Err
}

func ipv6HealthStaged(t *testing.T, now time.Time, ipv6 networkplan.IPv6Configuration) networkplan.StagedPlan {
	t.Helper()
	staged := healthStaged(t, now)
	staged.Plan = networkplan.Plan{
		Schema: networkplan.SchemaVersion, Name: "ipv6 health", Topology: networkplan.TopologyTwoNIC,
		Interfaces: []networkplan.Interface{{StableID: "wan", CurrentName: "eth0", Role: networkplan.RoleWAN}, {StableID: "lab", CurrentName: "eth1", Role: networkplan.RoleLab}},
		Management: networkplan.Management{PreserveActiveSSH: true},
		IPv4:       networkplan.IPv4Configuration{Enabled: true, LabCIDR: "10.77.0.0/24", GatewayAddress: "10.77.0.1", DHCPStart: "10.77.0.100", DHCPEnd: "10.77.0.200", NAT44: true},
		IPv6:       ipv6,
	}
	preview := networkplan.BuildPreview(staged.Plan, now)
	if !preview.Validation.Valid {
		t.Fatalf("invalid IPv6 health plan: %+v", preview.Validation.Errors)
	}
	preview.FirewallEnvironment = firewall.Inspection{IptablesPath: "/usr/sbin/iptables", IPv6Available: true, Ip6tablesPath: "/usr/sbin/ip6tables", IPv6DockerUserChain: true, IPv6FirewallReady: true}
	networkplan.BindIPv6HostEvidence(&preview)
	staged.Preview = preview
	return staged
}

func ipv6CheckFrom(t *testing.T, report networktransaction.HealthReport) networktransaction.HealthCheck {
	t.Helper()
	for _, check := range report.Checks {
		if check.Name == networktransaction.CheckIPv6 {
			return check
		}
	}
	t.Fatalf("IPv6 check is missing: %+v", report.Checks)
	return networktransaction.HealthCheck{}
}

func TestCheckerVerifiesRoutedAndBlockedIPv6(t *testing.T) {
	now := time.Unix(10000, 0)
	ula := networkplan.IPv6Configuration{Strategy: networkplan.IPv6ULANAT66Lab, LabPrefix: "fd12:3456:789a:1::/64"}
	for _, ipv6 := range []networkplan.IPv6Configuration{ula, {Strategy: networkplan.IPv6Disabled}} {
		probe := &fakeIPv6Probe{fakeProbe: fakeProbe{errors: map[networktransaction.CheckName]error{}}}
		report, err := (Checker{Probe: probe, Now: func() time.Time { return now.Add(4 * time.Second) }}).Check(context.Background(), ipv6HealthStaged(t, now, ipv6))
		if err != nil {
			t.Fatal(err)
		}
		if check := ipv6CheckFrom(t, report); check.Status != networktransaction.CheckPass || probe.ipv6Calls != 1 || !report.Healthy() {
			t.Fatalf("%s IPv6 state was not verified: %+v calls=%d", ipv6.Strategy, check, probe.ipv6Calls)
		}
		probe.ipv6Err = errors.New("ShakerProxy router advertisements (radvd) are not running")
		report, err = (Checker{Probe: probe, Now: func() time.Time { return now.Add(4 * time.Second) }}).Check(context.Background(), ipv6HealthStaged(t, now, ipv6))
		if err != nil {
			t.Fatal(err)
		}
		if check := ipv6CheckFrom(t, report); check.Status != networktransaction.CheckFail || report.Healthy() {
			t.Fatalf("%s IPv6 failure was reported healthy: %+v", ipv6.Strategy, check)
		}
	}
	plain := &fakeProbe{errors: map[networktransaction.CheckName]error{}}
	report, err := (Checker{Probe: plain, Now: func() time.Time { return now.Add(4 * time.Second) }}).Check(context.Background(), ipv6HealthStaged(t, now, ula))
	if err != nil {
		t.Fatal(err)
	}
	if check := ipv6CheckFrom(t, report); check.Status != networktransaction.CheckFail || report.Healthy() {
		t.Fatalf("routed IPv6 without an IPv6 probe was reported healthy: %+v", check)
	}
	observe := ipv6HealthStaged(t, now, networkplan.IPv6Configuration{Strategy: networkplan.IPv6ObserveOnly})
	report, err = (Checker{Probe: plain, Now: func() time.Time { return now.Add(4 * time.Second) }}).Check(context.Background(), observe)
	if err != nil {
		t.Fatal(err)
	}
	if check := ipv6CheckFrom(t, report); check.Status != networktransaction.CheckSkip || !report.Healthy() {
		t.Fatalf("observe-only IPv6 was not skipped honestly: %+v", check)
	}
}

func ipv6ProbeFiles() map[string][]byte {
	return map[string][]byte{
		"/proc/sys/net/ipv6/conf/all/forwarding": []byte("1\n"),
		"/proc/net/if_inet6": []byte("fe80000000000000505400fffe123456 03 40 20 80     eth1\n" +
			"fd123456789a00010000000000000001 03 40 00 80     eth1\n"),
	}
}

func TestOSProbeVerifiesRoutedIPv6State(t *testing.T) {
	now := time.Unix(10000, 0)
	staged := ipv6HealthStaged(t, now, networkplan.IPv6Configuration{Strategy: networkplan.IPv6ULANAT66Lab, LabPrefix: "fd12:3456:789a:1::/64"})
	newProbe := func(files map[string][]byte, radvd error) (OSProbe, *fakeFirewallRunner) {
		runner := &fakeFirewallRunner{}
		return OSProbe{Firewall: runner, RadvdStatus: fakeDHCP4StatusProbe{err: radvd}, ReadFile: func(path string) ([]byte, error) {
			value, ok := files[path]
			if !ok {
				return nil, os.ErrNotExist
			}
			return value, nil
		}}, runner
	}
	probe, runner := newProbe(ipv6ProbeFiles(), nil)
	if err := probe.IPv6(context.Background(), staged); err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"/usr/sbin/ip6tables -w 2 -S SHAKERPROXY-FORWARD", "/usr/sbin/ip6tables -w 2 -C DOCKER-USER -j SHAKERPROXY-FORWARD",
		"/usr/sbin/ip6tables -w 2 -S SHAKERPROXY-INPUT", "/usr/sbin/ip6tables -w 2 -C INPUT -j SHAKERPROXY-INPUT",
		"/usr/sbin/ip6tables -w 2 -t nat -S SHAKERPROXY-POSTROUTING", "/usr/sbin/ip6tables -w 2 -t nat -C POSTROUTING -j SHAKERPROXY-POSTROUTING",
	}
	if strings.Join(runner.calls, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("unexpected IPv6 firewall probes:\n%s", strings.Join(runner.calls, "\n"))
	}
	for _, call := range expected {
		fields := strings.Fields(call)
		if !allowedIPv6FirewallProbe(fields[0], fields[1:]) {
			t.Fatalf("IPv6 health probe is not allowlisted: %s", call)
		}
	}
	failures := map[string]func(map[string][]byte) error{
		"forwarding": func(files map[string][]byte) error {
			files["/proc/sys/net/ipv6/conf/all/forwarding"] = []byte("0\n")
			return nil
		},
		"gateway address": func(files map[string][]byte) error {
			files["/proc/net/if_inet6"] = []byte("fd123456789a00010000000000000001 03 40 00 80     eth0\n")
			return nil
		},
		"duplicate address": func(files map[string][]byte) error {
			files["/proc/net/if_inet6"] = []byte("fd123456789a00010000000000000001 03 40 00 88     eth1\n")
			return nil
		},
		"radvd": func(map[string][]byte) error { return errors.New("inactive") },
	}
	for name, edit := range failures {
		files := ipv6ProbeFiles()
		probe, _ := newProbe(files, edit(files))
		if err := probe.IPv6(context.Background(), staged); err == nil {
			t.Fatalf("%s drift was reported healthy", name)
		}
	}
	probe, runner = newProbe(ipv6ProbeFiles(), nil)
	runner.errAt = 2
	if err := probe.IPv6(context.Background(), staged); err == nil || !strings.Contains(err.Error(), "IPv6 firewall") {
		t.Fatalf("missing IPv6 firewall hook was reported healthy: %v", err)
	}
}

func TestOSProbeVerifiesBlockedIPv6WithFallbackParent(t *testing.T) {
	staged := ipv6HealthStaged(t, time.Unix(10000, 0), networkplan.IPv6Configuration{Strategy: networkplan.IPv6Disabled})
	staged.Preview.FirewallEnvironment.IPv6DockerUserChain = false
	runner := &fakeFirewallRunner{}
	if err := (OSProbe{Firewall: runner}).IPv6(context.Background(), staged); err != nil {
		t.Fatal(err)
	}
	if strings.Join(runner.calls, "\n") != "/usr/sbin/ip6tables -w 2 -S SHAKERPROXY-FORWARD\n/usr/sbin/ip6tables -w 2 -C FORWARD -j SHAKERPROXY-FORWARD" {
		t.Fatalf("unexpected blocked IPv6 probes: %v", runner.calls)
	}
	if allowedIPv6FirewallProbe("/usr/sbin/ip6tables", []string{"-w", "2", "-F", "SHAKERPROXY-FORWARD"}) || allowedIPv6FirewallProbe("/usr/sbin/iptables", []string{"-w", "2", "-S", "SHAKERPROXY-INPUT"}) {
		t.Fatal("IPv6 health allowlist accepted a mutating or IPv4 command")
	}
}
