package networkhealth

import (
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"

	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

// IPv6Probe is implemented by probes that can verify the ShakerProxy IPv6 state.
// A plan that changes IPv6 fails health when its probe cannot check it.
type IPv6Probe interface {
	IPv6(context.Context, networkplan.StagedPlan) error
}

// RadvdStatusProbe reports whether shakerproxy-radvd.service is running.
type RadvdStatusProbe interface {
	Active(context.Context) error
}

func (c Checker) ipv6Check(ctx context.Context, staged networkplan.StagedPlan) networktransaction.HealthCheck {
	check := networktransaction.HealthCheck{Name: networktransaction.CheckIPv6, Status: networktransaction.CheckPass}
	if err := networkplan.CheckIPv6Artifacts(staged.Plan, staged.Preview); err != nil {
		check.Status, check.Detail = networktransaction.CheckFail, boundedDetail(err)
		return check
	}
	if networkplan.LabIPv6FirewallMode(staged.Preview) == "" {
		check.Status, check.Detail = networktransaction.CheckSkip, "IPv6 routing is not enabled by this plan"
		if networkplan.BlocksLabIPv6(staged.Plan) {
			check.Detail = "IPv6 is turned off in this host's kernel, so lab devices cannot use IPv6"
		}
		return check
	}
	probe, ok := c.Probe.(IPv6Probe)
	if !ok {
		check.Status, check.Detail = networktransaction.CheckFail, "IPv6 health probe is unavailable for the selected strategy"
		return check
	}
	if err := probe.IPv6(ctx, staged); err != nil {
		check.Status, check.Detail = networktransaction.CheckFail, boundedDetail(err)
	}
	return check
}

// IPv6 verifies the IPv6 state installed by the apply: ShakerProxy's ip6tables
// chains and hooks, and for a routed lab also forwarding, the lab gateway
// address and a running radvd.
func (p OSProbe) IPv6(ctx context.Context, staged networkplan.StagedPlan) error {
	env := staged.Preview.FirewallEnvironment
	if env.Ip6tablesPath != "/usr/sbin/ip6tables" && env.Ip6tablesPath != "/usr/bin/ip6tables" {
		return errors.New("approved ip6tables path is unavailable")
	}
	parent := networkplan.IPv6ForwardParent(env)
	commands := [][]string{
		{"-w", "2", "-S", "SHAKERPROXY-FORWARD"},
		{"-w", "2", "-C", parent, "-j", "SHAKERPROXY-FORWARD"},
	}
	if networkplan.LabIPv6FirewallMode(staged.Preview) == networktransaction.IPv6FirewallRoute {
		labIPv6, ok := networkplan.LabIPv6Routing(staged.Plan)
		if !ok || !safeInterfaceName(labIPv6.Interface) {
			return errors.New("validated lab IPv6 addressing is unavailable")
		}
		forwarding, err := p.readFile("/proc/sys/net/ipv6/conf/all/forwarding")
		if err != nil || strings.TrimSpace(string(forwarding)) != "1" {
			return errors.New("IPv6 forwarding is not enabled")
		}
		addresses, err := p.readFile("/proc/net/if_inet6")
		if err != nil {
			return errors.New("IPv6 address table is unavailable")
		}
		if err := labGatewayConfigured(addresses, labIPv6.Interface, labIPv6.Gateway); err != nil {
			return err
		}
		commands = append(commands, []string{"-w", "2", "-S", "SHAKERPROXY-INPUT"}, []string{"-w", "2", "-C", "INPUT", "-j", "SHAKERPROXY-INPUT"})
		if labIPv6.NAT66 {
			commands = append(commands, []string{"-w", "2", "-t", "nat", "-S", "SHAKERPROXY-POSTROUTING"}, []string{"-w", "2", "-t", "nat", "-C", "POSTROUTING", "-j", "SHAKERPROXY-POSTROUTING"})
		}
		status := p.RadvdStatus
		if status == nil {
			status = OSRadvdStatusProbe{}
		}
		if err := status.Active(ctx); err != nil {
			return errors.New("ShakerProxy router advertisements (radvd) are not running")
		}
	}
	runner := p.Firewall
	if runner == nil {
		runner = OSFirewallRunner{}
	}
	for _, arguments := range commands {
		if _, err := runner.Run(ctx, env.Ip6tablesPath, arguments...); err != nil {
			return errors.New("ShakerProxy IPv6 firewall ownership or attachment is missing")
		}
	}
	return nil
}

// labGatewayConfigured checks /proc/net/if_inet6 for the lab gateway address.
// Each line is: address(32 hex) ifindex prefixlen scope flags device.
func labGatewayConfigured(raw []byte, interfaceName string, gateway netip.Addr) error {
	const dadFailed = 0x08
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 6 || fields[5] != interfaceName || len(fields[0]) != 32 {
			continue
		}
		bytes, err := hex.DecodeString(fields[0])
		if err != nil {
			continue
		}
		if netip.AddrFrom16([16]byte(bytes)) != gateway {
			continue
		}
		flags, err := strconv.ParseUint(fields[4], 16, 32)
		if err == nil && flags&dadFailed != 0 {
			return errors.New("another lab device already uses the IPv6 gateway address (duplicate address detected)")
		}
		return nil
	}
	return errors.New("the lab interface does not have its IPv6 gateway address")
}

type OSRadvdStatusProbe struct{}

func (OSRadvdStatusProbe) Active(ctx context.Context) error {
	arguments := []string{"is-active", "--quiet", networkplan.RadvdUnit}
	command := exec.CommandContext(ctx, "/usr/bin/systemctl", arguments...)
	command.Env = []string{"HOME=/nonexistent", "LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	if err := command.Run(); err != nil {
		return errors.New("fixed radvd health command failed")
	}
	return nil
}

func allowedIPv6FirewallProbe(path string, arguments []string) bool {
	if path != "/usr/sbin/ip6tables" && path != "/usr/bin/ip6tables" {
		return false
	}
	joined := strings.Join(arguments, "\x00")
	for _, allowed := range []string{
		"-w\x002\x00-S\x00SHAKERPROXY-FORWARD",
		"-w\x002\x00-C\x00DOCKER-USER\x00-j\x00SHAKERPROXY-FORWARD",
		"-w\x002\x00-C\x00FORWARD\x00-j\x00SHAKERPROXY-FORWARD",
		"-w\x002\x00-S\x00SHAKERPROXY-INPUT",
		"-w\x002\x00-C\x00INPUT\x00-j\x00SHAKERPROXY-INPUT",
		"-w\x002\x00-t\x00nat\x00-S\x00SHAKERPROXY-POSTROUTING",
		"-w\x002\x00-t\x00nat\x00-C\x00POSTROUTING\x00-j\x00SHAKERPROXY-POSTROUTING",
	} {
		if joined == allowed {
			return true
		}
	}
	return false
}
