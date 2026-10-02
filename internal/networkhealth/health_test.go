package networkhealth

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/firewall"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

type fakeProbe struct {
	mu     sync.Mutex
	errors map[networktransaction.CheckName]error
	calls  map[networktransaction.CheckName]int
}

func (p *fakeProbe) run(name networktransaction.CheckName) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.calls == nil {
		p.calls = map[networktransaction.CheckName]int{}
	}
	p.calls[name]++
	return p.errors[name]
}

func (p *fakeProbe) Management(context.Context, networkplan.StagedPlan) error {
	return p.run(networktransaction.CheckManagement)
}
func (p *fakeProbe) WAN(context.Context, networkplan.StagedPlan) error {
	return p.run(networktransaction.CheckWAN)
}
func (p *fakeProbe) DNS(context.Context, networkplan.StagedPlan) error {
	return p.run(networktransaction.CheckDNS)
}
func (p *fakeProbe) IPv4Forwarding(context.Context, networkplan.StagedPlan) error {
	return p.run(networktransaction.CheckIPv4Forwarding)
}
func (p *fakeProbe) DHCP4(context.Context, networkplan.StagedPlan) error {
	return p.run(networktransaction.CheckDHCP4)
}

func healthStaged(t *testing.T, now time.Time) networkplan.StagedPlan {
	t.Helper()
	record, err := networktransaction.New(heartbeatApplyID, heartbeatPlanHash, now)
	if err != nil {
		t.Fatal(err)
	}
	record, err = record.ArmWatchdog(now.Add(time.Second), 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	record, err = record.BeginApply(now.Add(2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	record, err = record.MarkApplied(now.Add(3 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return networkplan.StagedPlan{
		ApplyID:  heartbeatApplyID,
		PlanHash: heartbeatPlanHash,
		Plan: networkplan.Plan{
			Interfaces: []networkplan.Interface{{CurrentName: "eth0", Role: networkplan.RoleWAN}, {CurrentName: "eth1", Role: networkplan.RoleLab}},
			IPv4:       networkplan.IPv4Configuration{NAT44: true},
			IPv6:       networkplan.IPv6Configuration{Strategy: networkplan.IPv6Disabled},
		},
		Preview:     networkplan.Preview{FirewallEnvironment: firewall.Inspection{IptablesPath: "/usr/sbin/iptables"}},
		Status:      string(record.Phase),
		Transaction: &record,
	}
}

func TestCheckerRunsAllRequiredProbesAndProducesHealthyReport(t *testing.T) {
	now := time.Unix(10000, 0)
	probe := &fakeProbe{errors: map[networktransaction.CheckName]error{}}
	report, err := (Checker{Probe: probe, Now: func() time.Time { return now.Add(4 * time.Second) }}).Check(context.Background(), healthStaged(t, now))
	if err != nil {
		t.Fatal(err)
	}
	if !report.Healthy() || len(report.Checks) != 6 {
		t.Fatalf("unexpected health report: %+v", report)
	}
	for _, name := range []networktransaction.CheckName{networktransaction.CheckManagement, networktransaction.CheckWAN, networktransaction.CheckDNS, networktransaction.CheckIPv4Forwarding, networktransaction.CheckDHCP4} {
		if probe.calls[name] != 1 {
			t.Fatalf("probe %s ran %d times", name, probe.calls[name])
		}
	}
	if report.Checks[5].Name != networktransaction.CheckIPv6 || report.Checks[5].Status != networktransaction.CheckSkip {
		t.Fatalf("IPv6 strategy was not represented honestly: %+v", report.Checks[5])
	}
}

func TestCheckerSingleArmSkipsDHCPProbe(t *testing.T) {
	now := time.Unix(10000, 0)
	probe := &fakeProbe{errors: map[networktransaction.CheckName]error{}}
	staged := healthStaged(t, now)
	staged.Plan.Topology = networkplan.TopologySingleArm
	staged.Plan.Interfaces = []networkplan.Interface{{CurrentName: "eth0", Role: networkplan.RoleWANLab}}
	report, err := (Checker{Probe: probe, Now: func() time.Time { return now.Add(4 * time.Second) }}).Check(context.Background(), staged)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Healthy() || probe.calls[networktransaction.CheckDHCP4] != 0 {
		t.Fatalf("single-arm health required managed DHCP: report=%+v calls=%+v", report, probe.calls)
	}
	foundSkip := false
	for _, check := range report.Checks {
		if check.Name == networktransaction.CheckDHCP4 && check.Status == networktransaction.CheckSkip {
			foundSkip = true
		}
	}
	if !foundSkip {
		t.Fatalf("single-arm DHCP omission was not explicit: %+v", report.Checks)
	}
}

func TestCheckerRetainsBoundedFailureEvidenceAndUnsupportedIPv6(t *testing.T) {
	now := time.Unix(10000, 0)
	probe := &fakeProbe{errors: map[networktransaction.CheckName]error{networktransaction.CheckDNS: errors.New(strings.Repeat("dns failure ", 100))}}
	staged := healthStaged(t, now)
	staged.Plan.IPv6.Strategy = networkplan.IPv6NativeRouted
	report, err := (Checker{Probe: probe, Now: func() time.Time { return now.Add(4 * time.Second) }}).Check(context.Background(), staged)
	if err != nil {
		t.Fatal(err)
	}
	if report.Healthy() {
		t.Fatal("failed DNS and unsupported IPv6 were reported healthy")
	}
	for _, check := range report.Checks {
		if len(check.Detail) > 256 {
			t.Fatalf("unbounded health detail: %d", len(check.Detail))
		}
	}
}

type deadlineProbe struct{}

func (deadlineProbe) wait(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
func (p deadlineProbe) Management(ctx context.Context, _ networkplan.StagedPlan) error {
	return p.wait(ctx)
}
func (p deadlineProbe) WAN(ctx context.Context, _ networkplan.StagedPlan) error { return p.wait(ctx) }
func (p deadlineProbe) DNS(ctx context.Context, _ networkplan.StagedPlan) error { return p.wait(ctx) }
func (p deadlineProbe) IPv4Forwarding(ctx context.Context, _ networkplan.StagedPlan) error {
	return p.wait(ctx)
}
func (p deadlineProbe) DHCP4(ctx context.Context, _ networkplan.StagedPlan) error {
	return p.wait(ctx)
}

func TestCheckerBoundsAllProbesByWatchdogDeadline(t *testing.T) {
	staged := healthStaged(t, time.Now().Add(-10*time.Minute))
	report, err := (Checker{Probe: deadlineProbe{}}).Check(context.Background(), staged)
	if err != nil {
		t.Fatal(err)
	}
	if report.Healthy() {
		t.Fatal("deadline-expired probes were reported healthy")
	}
	for _, check := range report.Checks[:5] {
		if check.Status != networktransaction.CheckFail || !strings.Contains(check.Detail, "deadline exceeded") {
			t.Fatalf("probe did not fail on the watchdog deadline: %+v", check)
		}
	}
}

type fakeResolver struct {
	addresses []net.IPAddr
	err       error
	name      string
}

func (r *fakeResolver) LookupIPAddr(_ context.Context, name string) ([]net.IPAddr, error) {
	r.name = name
	return r.addresses, r.err
}

type fakeFirewallRunner struct {
	calls []string
	errAt int
}

func (r *fakeFirewallRunner) Run(_ context.Context, path string, arguments ...string) (string, error) {
	r.calls = append(r.calls, path+" "+strings.Join(arguments, " "))
	if r.errAt > 0 && len(r.calls) == r.errAt {
		return "", errors.New("missing")
	}
	return "-N chain\n", nil
}

type immediateManagement struct{ err error }

func (m immediateManagement) Wait(context.Context, string, string) error { return m.err }

type fakeDHCP4StatusProbe struct{ err error }

func (p fakeDHCP4StatusProbe) Active(context.Context) error { return p.err }

func TestOSProbeChecksManagementWANRouteDNSAndFirewall(t *testing.T) {
	now := time.Unix(10000, 0)
	staged := healthStaged(t, now)
	files := map[string][]byte{
		"/sys/class/net/eth0/carrier":   []byte("1\n"),
		"/sys/class/net/eth0/operstate": []byte("up\n"),
		"/sys/class/net/eth1/carrier":   []byte("1\n"),
		"/sys/class/net/eth1/operstate": []byte("up\n"),
		"/proc/net/route":               []byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\neth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\n"),
		"/proc/sys/net/ipv4/ip_forward": []byte("1\n"),
	}
	resolver := &fakeResolver{addresses: []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}}}
	firewallRunner := &fakeFirewallRunner{}
	probe := OSProbe{
		ManagementChannel: immediateManagement{},
		Resolver:          resolver,
		Firewall:          firewallRunner,
		DHCP4Status:       fakeDHCP4StatusProbe{},
		ReadFile: func(path string) ([]byte, error) {
			value, ok := files[path]
			if !ok {
				return nil, os.ErrNotExist
			}
			return value, nil
		},
	}
	if err := probe.Management(context.Background(), staged); err != nil {
		t.Fatal(err)
	}
	if err := probe.WAN(context.Background(), staged); err != nil {
		t.Fatal(err)
	}
	if err := probe.DNS(context.Background(), staged); err != nil {
		t.Fatal(err)
	}
	if err := probe.IPv4Forwarding(context.Background(), staged); err != nil {
		t.Fatal(err)
	}
	if err := probe.DHCP4(context.Background(), staged); err != nil {
		t.Fatal(err)
	}
	if resolver.name != "example.com" || len(firewallRunner.calls) != 4 {
		t.Fatalf("unexpected probes: dns=%q firewall=%v", resolver.name, firewallRunner.calls)
	}
}

func TestOSProbeSingleArmRequiresRedirectsDisabled(t *testing.T) {
	staged := healthStaged(t, time.Unix(10000, 0))
	staged.Plan.Topology = networkplan.TopologySingleArm
	staged.Plan.Interfaces = []networkplan.Interface{{CurrentName: "eth0", Role: networkplan.RoleWANLab}}
	files := map[string][]byte{
		"/proc/sys/net/ipv4/ip_forward":               []byte("1\n"),
		"/proc/sys/net/ipv4/conf/eth0/send_redirects": []byte("0\n"),
	}
	probe := OSProbe{Firewall: &fakeFirewallRunner{}, ReadFile: func(path string) ([]byte, error) {
		value, ok := files[path]
		if !ok {
			return nil, os.ErrNotExist
		}
		return value, nil
	}}
	if err := probe.IPv4Forwarding(context.Background(), staged); err != nil {
		t.Fatal(err)
	}
	files["/proc/sys/net/ipv4/conf/eth0/send_redirects"] = []byte("1\n")
	if err := probe.IPv4Forwarding(context.Background(), staged); err == nil || !strings.Contains(err.Error(), "redirects") {
		t.Fatalf("enabled single-arm redirects were accepted: %v", err)
	}
}

func TestDHCP4ProbeFailsClosedWhenLabLinkIsDown(t *testing.T) {
	staged := healthStaged(t, time.Unix(10000, 0))
	probe := OSProbe{
		DHCP4Status: fakeDHCP4StatusProbe{},
		ReadFile: func(path string) ([]byte, error) {
			if path == "/sys/class/net/eth1/carrier" {
				return []byte("0\n"), nil
			}
			return nil, os.ErrNotExist
		},
	}
	if err := probe.DHCP4(context.Background(), staged); err == nil || !strings.Contains(err.Error(), "carrier") {
		t.Fatalf("down lab link was reported healthy: %v", err)
	}
}

func TestOSProbeFailsClosedOnRouteAndFirewallDrift(t *testing.T) {
	now := time.Unix(10000, 0)
	staged := healthStaged(t, now)
	probe := OSProbe{ReadFile: func(path string) ([]byte, error) {
		switch path {
		case "/sys/class/net/eth0/carrier":
			return []byte("1\n"), nil
		case "/sys/class/net/eth0/operstate":
			return []byte("up\n"), nil
		case "/proc/net/route":
			return []byte("Iface\tDestination\tGateway\tFlags\neth1\t00000000\t0\t0001\n"), nil
		case "/proc/sys/net/ipv4/ip_forward":
			return []byte("1\n"), nil
		default:
			return nil, os.ErrNotExist
		}
	}, Firewall: &fakeFirewallRunner{errAt: 2}}
	if err := probe.WAN(context.Background(), staged); err == nil {
		t.Fatal("WAN route drift was reported healthy")
	}
	if err := probe.IPv4Forwarding(context.Background(), staged); err == nil {
		t.Fatal("firewall attachment drift was reported healthy")
	}
}

func TestFirewallProbeAllowlistIsExact(t *testing.T) {
	if !allowedFirewallProbe("/usr/sbin/iptables", []string{"-w", "2", "-S", "SHAKERPROXY-FORWARD"}) {
		t.Fatal("owned chain probe was rejected")
	}
	if allowedFirewallProbe("/usr/sbin/iptables", []string{"-w", "2", "-S", "DOCKER-USER"}) {
		t.Fatal("unapproved Docker chain enumeration was allowlisted")
	}
	if allowedFirewallProbe("/bin/sh", []string{"-c", "iptables -S"}) {
		t.Fatal("shell probe was allowlisted")
	}
}

func TestDHCP4HealthProbeAllowlistIsExact(t *testing.T) {
	if !allowedDHCP4StatusProbe("/usr/bin/systemctl", []string{"is-active", "--quiet", "shakerproxy-dhcp4.service"}) {
		t.Fatal("exact DHCPv4 status probe was rejected")
	}
	if allowedDHCP4StatusProbe("/usr/bin/systemctl", []string{"restart", "shakerproxy-dhcp4.service"}) || allowedDHCP4StatusProbe("/bin/sh", []string{"-c", "systemctl is-active shakerproxy-dhcp4"}) {
		t.Fatal("mutating or shell DHCPv4 health command was allowlisted")
	}
}

func TestOSProbeRejectsOversizedHostEvidence(t *testing.T) {
	probe := OSProbe{ReadFile: func(string) ([]byte, error) {
		return make([]byte, maxProbeFileBytes+1), nil
	}}
	if _, err := probe.readFile("/proc/net/route"); err == nil {
		t.Fatal("oversized host evidence was accepted")
	}
}

func TestHealthChecksEndBeforeTheWatchdogDeadline(t *testing.T) {
	now := time.Unix(10_000, 0)
	cases := []struct {
		name      string
		confirmBy time.Time
		want      time.Time
	}{
		{"default three-minute window leaves the rollback margin", now.Add(3 * time.Minute), now.Add(3*time.Minute - rollbackMargin)},
		{"short window still gets the minimum check time", now.Add(30 * time.Second), now.Add(minimumCheckTime)},
		{"never past the watchdog deadline", now.Add(10 * time.Second), now.Add(10 * time.Second)},
	}
	for _, tc := range cases {
		if got := checkDeadline(now, tc.confirmBy); !got.Equal(tc.want) {
			t.Errorf("%s: checkDeadline = %s, want %s", tc.name, got.Sub(now), tc.want.Sub(now))
		}
	}
}

func TestOSProbeInlineBridgeChecksTheBridgeRouteAndBridgeNetfilter(t *testing.T) {
	staged := healthStaged(t, time.Unix(10000, 0))
	staged.Plan.Topology = networkplan.TopologyTransparentBridge
	staged.Plan.Interfaces = []networkplan.Interface{{CurrentName: "eth0", Role: networkplan.RoleWAN}, {CurrentName: "eth1", Role: networkplan.RoleLab}}
	files := map[string][]byte{
		"/proc/sys/net/ipv4/ip_forward":                []byte("1\n"),
		"/proc/sys/net/bridge/bridge-nf-call-iptables": []byte("1\n"),
		"/sys/class/net/spbr0/carrier":                 []byte("1\n"),
		"/sys/class/net/spbr0/operstate":               []byte("up\n"),
		"/proc/net/route":                              []byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\nspbr0\t00000000\t0102000A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"),
	}
	probe := OSProbe{Firewall: &fakeFirewallRunner{}, ReadFile: func(path string) ([]byte, error) {
		value, ok := files[path]
		if !ok {
			return nil, os.ErrNotExist
		}
		return value, nil
	}}
	if err := probe.WAN(context.Background(), staged); err != nil {
		t.Fatalf("the bridge's default route was not accepted as the uplink: %v", err)
	}
	if err := probe.IPv4Forwarding(context.Background(), staged); err != nil {
		t.Fatal(err)
	}
	files["/proc/sys/net/bridge/bridge-nf-call-iptables"] = []byte("0\n")
	if err := probe.IPv4Forwarding(context.Background(), staged); err == nil || !strings.Contains(err.Error(), "bridge-nf-call-iptables") {
		t.Fatalf("bridged traffic bypassing the firewall was accepted: %v", err)
	}
}
