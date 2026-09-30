package firewall

import (
	"context"
	"errors"
	"os"
	"testing"
)

func ipv6InspectorFor(runner fakeRunner, kernelIPv6 bool) Inspector {
	inspector := inspectorFor(`{"firewall-backend":"iptables"}`, "", runner)
	base := inspector.ReadFile
	inspector.ReadFile = func(path string) ([]byte, error) {
		if path == "/proc/sys/net/ipv6/conf/all/forwarding" {
			if !kernelIPv6 {
				return nil, os.ErrNotExist
			}
			return []byte("0\n"), nil
		}
		return base(path)
	}
	return inspector
}

func readyIPv6Runner(filter, nat string) fakeRunner {
	runner := readyRunner()
	runner.outputs[commandKey("/usr/sbin/ip6tables", "-w", "2", "-S")] = filter
	runner.outputs[commandKey("/usr/sbin/ip6tables", "-w", "2", "-t", "nat", "-S")] = nat
	return runner
}

func TestInspectRecordsDockerManagedIPv6Firewall(t *testing.T) {
	inspection := ipv6InspectorFor(readyIPv6Runner("-P FORWARD DROP\n-N DOCKER-USER\n", "-P POSTROUTING ACCEPT\n"), true).Inspect(context.Background())
	if !inspection.ApplyReady || !inspection.IPv6Available || !inspection.IPv6FirewallReady || !inspection.IPv6DockerUserChain || inspection.Ip6tablesPath != "/usr/sbin/ip6tables" || inspection.ShakerProxyIPv6Chains {
		t.Fatalf("unexpected IPv6 inspection: %+v", inspection)
	}
}

func TestInspectAllowsIPv6WithoutDockerHook(t *testing.T) {
	inspection := ipv6InspectorFor(readyIPv6Runner("-P FORWARD ACCEPT\n", "-P POSTROUTING ACCEPT\n"), true).Inspect(context.Background())
	if !inspection.ApplyReady || !inspection.IPv6FirewallReady || inspection.IPv6DockerUserChain {
		t.Fatalf("missing Docker IPv6 hook must fall back rather than block: %+v", inspection)
	}
}

func TestInspectBlocksStaleShakerProxyIPv6Chains(t *testing.T) {
	for _, runner := range []fakeRunner{
		readyIPv6Runner("-N DOCKER-USER\n-N SHAKERPROXY-FORWARD\n", ""),
		readyIPv6Runner("-N DOCKER-USER\n-N SHAKERPROXY-INPUT\n", ""),
		readyIPv6Runner("-N DOCKER-USER\n", "-N SHAKERPROXY-POSTROUTING\n"),
	} {
		inspection := ipv6InspectorFor(runner, true).Inspect(context.Background())
		if inspection.ApplyReady || inspection.IPv6FirewallReady || !inspection.ShakerProxyIPv6Chains || !hasFirewallIssue(inspection, "SHAKERPROXY_IPV6_CHAIN_CONFLICT", true) {
			t.Fatalf("stale ShakerProxy IPv6 chains were not blocking: %+v", inspection)
		}
	}
}

func TestInspectIPv6FailuresOnlyBlockIPv6Plans(t *testing.T) {
	runner := readyIPv6Runner("", "")
	runner.errors[commandKey("/usr/sbin/ip6tables", "-w", "2", "-S")] = errors.New("permission denied")
	inspection := ipv6InspectorFor(runner, true).Inspect(context.Background())
	if !inspection.ApplyReady || inspection.IPv6FirewallReady || !hasFirewallIssue(inspection, "IP6TABLES_RULESET_UNREADABLE", false) {
		t.Fatalf("unreadable ip6tables must mark only IPv6 unavailable: %+v", inspection)
	}
	inspection = ipv6InspectorFor(readyRunner(), false).Inspect(context.Background())
	if !inspection.ApplyReady || inspection.IPv6Available || inspection.IPv6FirewallReady || !hasFirewallIssue(inspection, "IPV6_KERNEL_DISABLED", false) {
		t.Fatalf("kernel without IPv6 was not recorded: %+v", inspection)
	}
}

func TestIPv6InspectionCommandsAreAllowlisted(t *testing.T) {
	for _, args := range [][]string{{"-w", "2", "-S"}, {"-w", "2", "-t", "nat", "-S"}} {
		if !allowedCommand("/usr/sbin/ip6tables", args) || !allowedCommand("/usr/bin/ip6tables", args) {
			t.Fatalf("fixed ip6tables inspection was rejected: %v", args)
		}
	}
	for _, args := range [][]string{{"-F"}, {"-w", "2", "-t", "nat", "-F"}, {"-w", "2", "-S", "DOCKER-USER"}} {
		if allowedCommand("/usr/sbin/ip6tables", args) {
			t.Fatalf("mutating or unexpected ip6tables command was allowlisted: %v", args)
		}
	}
	if Ip6tablesPathFor("/usr/sbin/iptables") != "/usr/sbin/ip6tables" || Ip6tablesPathFor("/tmp/iptables") != "" {
		t.Fatal("ip6tables path derivation is not fixed")
	}
}
