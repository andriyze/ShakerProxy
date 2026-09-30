package networkhealth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

const (
	maxProbeFileBytes = 1 << 20
	maxProbeOutput    = 64 << 10
)

type Probe interface {
	Management(context.Context, networkplan.StagedPlan) error
	WAN(context.Context, networkplan.StagedPlan) error
	DNS(context.Context, networkplan.StagedPlan) error
	IPv4Forwarding(context.Context, networkplan.StagedPlan) error
	DHCP4(context.Context, networkplan.StagedPlan) error
}

type Checker struct {
	Probe Probe
	Now   func() time.Time
}

func (c Checker) Check(ctx context.Context, staged networkplan.StagedPlan) (networktransaction.HealthReport, error) {
	if c.Probe == nil {
		return networktransaction.HealthReport{}, errors.New("network health probe is required")
	}
	if staged.Transaction == nil || staged.Transaction.Phase != networktransaction.PhaseAwaitingHealth || staged.ApplyID != staged.Transaction.ApplyID || staged.PlanHash != staged.Transaction.PlanHash {
		return networktransaction.HealthReport{}, errors.New("health validation requires a matching AWAITING_HEALTH transaction")
	}
	if staged.Transaction.ConfirmBy == nil {
		return networktransaction.HealthReport{}, errors.New("health validation requires a watchdog deadline")
	}
	probeContext, cancel := context.WithDeadline(ctx, *staged.Transaction.ConfirmBy)
	defer cancel()
	type probeCase struct {
		name networktransaction.CheckName
		run  func(context.Context, networkplan.StagedPlan) error
	}
	probes := []probeCase{
		{name: networktransaction.CheckManagement, run: c.Probe.Management},
		{name: networktransaction.CheckWAN, run: c.Probe.WAN},
		{name: networktransaction.CheckDNS, run: c.Probe.DNS},
		{name: networktransaction.CheckIPv4Forwarding, run: c.Probe.IPv4Forwarding},
	}
	if networkplan.UsesManagedDHCP4(staged.Plan) {
		probes = append(probes, probeCase{name: networktransaction.CheckDHCP4, run: c.Probe.DHCP4})
	}
	if networkplan.WiFiEnabled(staged.Plan) {
		probes = append(probes, probeCase{name: networktransaction.CheckWiFiAP, run: c.accessPointProbe})
	}
	checks := make([]networktransaction.HealthCheck, len(probes))
	var wait sync.WaitGroup
	for index, probe := range probes {
		index, probe := index, probe
		wait.Add(1)
		go func() {
			defer wait.Done()
			err := probe.run(probeContext, staged)
			checks[index] = networktransaction.HealthCheck{Name: probe.name, Status: networktransaction.CheckPass}
			if err != nil {
				checks[index].Status = networktransaction.CheckFail
				checks[index].Detail = boundedDetail(err)
			}
		}()
	}
	wait.Wait()
	if !networkplan.UsesManagedDHCP4(staged.Plan) {
		checks = append(checks, networktransaction.HealthCheck{Name: networktransaction.CheckDHCP4, Status: networktransaction.CheckSkip, Detail: "managed DHCPv4 is intentionally disabled for this topology"})
	}
	checks = append(checks, c.ipv6Check(probeContext, staged))
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	report := networktransaction.HealthReport{CheckedAt: now().UTC(), Checks: checks}
	if err := report.Validate(); err != nil {
		return networktransaction.HealthReport{}, err
	}
	return report, nil
}

func boundedDetail(err error) string {
	detail := strings.TrimSpace(err.Error())
	if len(detail) > 256 {
		detail = detail[:256]
	}
	return detail
}

type ManagementProbe interface {
	Wait(context.Context, string, string) error
}

type DNSResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type FirewallRunner interface {
	Run(context.Context, string, ...string) (string, error)
}

type OSProbe struct {
	ManagementChannel ManagementProbe
	Resolver          DNSResolver
	Firewall          FirewallRunner
	ReadFile          func(string) ([]byte, error)
	DHCP4Status       DHCP4StatusProbe
	AccessPointStatus AccessPointStatusProbe
	RadvdStatus       RadvdStatusProbe
}

func DefaultOSProbe(management ManagementProbe) OSProbe {
	return OSProbe{ManagementChannel: management, Resolver: net.DefaultResolver, Firewall: OSFirewallRunner{}}
}

func (p OSProbe) Management(ctx context.Context, staged networkplan.StagedPlan) error {
	if p.ManagementChannel == nil {
		return errors.New("second management health channel is unavailable")
	}
	return p.ManagementChannel.Wait(ctx, staged.ApplyID, staged.PlanHash)
}

func (p OSProbe) WAN(_ context.Context, staged networkplan.StagedPlan) error {
	wan, ok := networkplan.WANInterface(staged.Plan)
	if !ok || !safeInterfaceName(wan.CurrentName) {
		return errors.New("validated WAN interface is unavailable")
	}
	carrier, err := p.readFile("/sys/class/net/" + wan.CurrentName + "/carrier")
	if err != nil || strings.TrimSpace(string(carrier)) != "1" {
		return errors.New("WAN carrier is not up")
	}
	operstate, err := p.readFile("/sys/class/net/" + wan.CurrentName + "/operstate")
	if err != nil {
		return errors.New("WAN operational state is unreadable")
	}
	state := strings.TrimSpace(string(operstate))
	if state != "up" && state != "unknown" {
		return fmt.Errorf("WAN operational state is %s", state)
	}
	routes, err := p.readFile("/proc/net/route")
	if err != nil {
		return errors.New("IPv4 route table is unavailable")
	}
	if !hasUsableDefaultRoute(routes, wan.CurrentName) {
		return errors.New("WAN default route was not preserved")
	}
	return nil
}

func (p OSProbe) DNS(ctx context.Context, _ networkplan.StagedPlan) error {
	resolver := p.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	addresses, err := resolver.LookupIPAddr(ctx, "example.com")
	if err != nil {
		return fmt.Errorf("DNS lookup failed: %w", err)
	}
	if len(addresses) == 0 {
		return errors.New("DNS lookup returned no addresses")
	}
	return nil
}

func (p OSProbe) IPv4Forwarding(ctx context.Context, staged networkplan.StagedPlan) error {
	forwarding, err := p.readFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil || strings.TrimSpace(string(forwarding)) != "1" {
		return errors.New("IPv4 forwarding is not enabled")
	}
	if staged.Plan.Topology == networkplan.TopologySingleArm {
		arm, ok := networkplan.WANInterface(staged.Plan)
		if !ok || !safeInterfaceName(arm.CurrentName) {
			return errors.New("validated single-arm interface is unavailable")
		}
		redirects, readErr := p.readFile("/proc/sys/net/ipv4/conf/" + arm.CurrentName + "/send_redirects")
		if readErr != nil || strings.TrimSpace(string(redirects)) != "0" {
			return errors.New("IPv4 redirects are not disabled on the single-arm interface")
		}
	}
	runner := p.Firewall
	if runner == nil {
		runner = OSFirewallRunner{}
	}
	path := staged.Preview.FirewallEnvironment.IptablesPath
	if path != "/usr/sbin/iptables" && path != "/usr/bin/iptables" {
		return errors.New("approved iptables path is unavailable")
	}
	commands := [][]string{
		{"-w", "2", "-S", "SHAKERPROXY-FORWARD"},
		{"-w", "2", "-C", "DOCKER-USER", "-j", "SHAKERPROXY-FORWARD"},
	}
	if staged.Plan.IPv4.NAT44 {
		commands = append(commands,
			[]string{"-w", "2", "-t", "nat", "-S", "SHAKERPROXY-POSTROUTING"},
			[]string{"-w", "2", "-t", "nat", "-C", "POSTROUTING", "-j", "SHAKERPROXY-POSTROUTING"},
		)
	}
	for _, arguments := range commands {
		if _, err := runner.Run(ctx, path, arguments...); err != nil {
			return errors.New("ShakerProxy firewall ownership or attachment is missing")
		}
	}
	return nil
}

type DHCP4StatusProbe interface {
	Active(context.Context) error
}

func (p OSProbe) DHCP4(ctx context.Context, staged networkplan.StagedPlan) error {
	lab, ok := networkplan.LabInterface(staged.Plan)
	if !ok || !safeInterfaceName(lab.CurrentName) {
		return errors.New("validated lab interface is unavailable")
	}
	carrier, err := p.readFile("/sys/class/net/" + lab.CurrentName + "/carrier")
	if err != nil || strings.TrimSpace(string(carrier)) != "1" {
		return errors.New("lab interface carrier is not up")
	}
	operstate, err := p.readFile("/sys/class/net/" + lab.CurrentName + "/operstate")
	if err != nil {
		return errors.New("lab interface operational state is unreadable")
	}
	state := strings.TrimSpace(string(operstate))
	if state != "up" && state != "unknown" {
		return fmt.Errorf("lab interface operational state is %s", state)
	}
	status := p.DHCP4Status
	if status == nil {
		status = OSDHCP4StatusProbe{}
	}
	if err := status.Active(ctx); err != nil {
		return errors.New("ShakerProxy DHCPv4 service is not active")
	}
	return nil
}

type OSDHCP4StatusProbe struct{}

func (OSDHCP4StatusProbe) Active(ctx context.Context) error {
	arguments := []string{"is-active", "--quiet", "shakerproxy-dhcp4.service"}
	if !allowedDHCP4StatusProbe("/usr/bin/systemctl", arguments) {
		return errors.New("DHCPv4 health command is not allowlisted")
	}
	command := exec.CommandContext(ctx, "/usr/bin/systemctl", arguments...)
	command.Env = []string{"HOME=/nonexistent", "LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	if err := command.Run(); err != nil {
		return errors.New("fixed DHCPv4 health command failed")
	}
	return nil
}

func allowedDHCP4StatusProbe(path string, arguments []string) bool {
	return path == "/usr/bin/systemctl" && strings.Join(arguments, "\x00") == "is-active\x00--quiet\x00shakerproxy-dhcp4.service"
}

func (p OSProbe) readFile(path string) ([]byte, error) {
	if p.ReadFile != nil {
		value, err := p.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if len(value) > maxProbeFileBytes {
			return nil, errors.New("health probe file exceeded limit")
		}
		return value, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, maxProbeFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(value) > maxProbeFileBytes {
		return nil, errors.New("health probe file exceeded limit")
	}
	return value, nil
}

func safeInterfaceName(name string) bool {
	if name == "" || len(name) > 15 || name == "." || name == ".." {
		return false
	}
	for _, char := range name {
		if !(char >= 'a' && char <= 'z') && !(char >= 'A' && char <= 'Z') && !(char >= '0' && char <= '9') && !strings.ContainsRune("_.:-", char) {
			return false
		}
	}
	return true
}

func hasUsableDefaultRoute(raw []byte, interfaceName string) bool {
	lines := strings.Split(string(raw), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != interfaceName || fields[1] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err == nil && flags&0x1 != 0 {
			return true
		}
	}
	return false
}

type OSFirewallRunner struct{}

func (OSFirewallRunner) Run(ctx context.Context, path string, arguments ...string) (string, error) {
	if !allowedFirewallProbe(path, arguments) && !allowedIPv6FirewallProbe(path, arguments) {
		return "", errors.New("firewall health command is not allowlisted")
	}
	command := exec.CommandContext(ctx, path, arguments...)
	command.Env = []string{"HOME=/nonexistent", "LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	var stdout healthCappedBuffer
	var stderr healthCappedBuffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return "", errors.New("fixed firewall health command failed")
	}
	if stdout.exceeded || stderr.exceeded {
		return "", errors.New("firewall health command output exceeded limit")
	}
	return stdout.String(), nil
}

func allowedFirewallProbe(path string, arguments []string) bool {
	if path != "/usr/sbin/iptables" && path != "/usr/bin/iptables" {
		return false
	}
	joined := strings.Join(arguments, "\x00")
	return joined == "-w\x002\x00-S\x00SHAKERPROXY-FORWARD" ||
		joined == "-w\x002\x00-C\x00DOCKER-USER\x00-j\x00SHAKERPROXY-FORWARD" ||
		joined == "-w\x002\x00-t\x00nat\x00-S\x00SHAKERPROXY-POSTROUTING" ||
		joined == "-w\x002\x00-t\x00nat\x00-C\x00POSTROUTING\x00-j\x00SHAKERPROXY-POSTROUTING"
}

type healthCappedBuffer struct {
	bytes.Buffer
	exceeded bool
}

func (b *healthCappedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	remaining := maxProbeOutput - b.Len()
	if remaining <= 0 {
		b.exceeded = true
		return original, nil
	}
	if len(value) > remaining {
		value = value[:remaining]
		b.exceeded = true
	}
	_, _ = b.Buffer.Write(value)
	return original, nil
}
