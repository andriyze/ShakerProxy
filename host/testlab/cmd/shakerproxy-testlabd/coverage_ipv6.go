package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/coverage"
	"shakerproxy.dev/shakerproxy/internal/testlab"
)

// The coverage lab's IPv6. ShakerProxy's lab address on the client bridge
// (fd8a:…:f0::1) answers DNS, as the IPv4 gateway does, but IPv6 is routed
// by a router namespace of its own on both lab bridges. Turning on any
// net.ipv6.conf.*.forwarding on the host makes Linux drop every IPv6
// default route learned from router advertisements, so the host's IPv6
// forwarding is never touched and there is nothing to restore. The probes
// still cross the client bridge that the coverage capture records.

const (
	routerNS         = "lgtest-router"
	routerClientIPv6 = "fd8a:6c1e:4b37:f0::2"
	routerWANIPv6    = "fd8a:6c1e:4b37:f1::1"
	targetIPv6       = coverage.TargetIPv6
)

// Environment for the probe runner when the lab has no working IPv6: the
// IPv6 probes then report the reason instead of timing out one by one.
const (
	ipv6SkipEnv    = "SHAKERPROXY_COVERAGE_IPV6_SKIP"
	ipv6FailureEnv = "SHAKERPROXY_COVERAGE_IPV6_FAILURE"
)

// labIPv6 is how the coverage lab's IPv6 came up. Without it the IPv4
// probes still run.
type labIPv6 struct {
	// skip says why this appliance has no IPv6 to probe; the IPv6 rows
	// are skipped.
	skip string
	// failure says why the lab's IPv6 did not work although it should
	// have; the IPv6 rows fail with it.
	failure string
}

func (l labIPv6) probeEnvironment() []string {
	switch {
	case l.skip != "":
		return []string{ipv6SkipEnv + "=" + l.skip}
	case l.failure != "":
		return []string{ipv6FailureEnv + "=" + l.failure}
	}
	return nil
}

// setupCoverageIPv6 adds IPv6 to a lab that setupLab and setupCoverage
// built. It never fails the coverage run: a lab without IPv6 reports why
// in the IPv6 rows.
func setupCoverageIPv6(ctx context.Context) labIPv6 {
	for _, scope := range []string{"all", "default"} {
		if strings.TrimSpace(readFile("/proc/sys/net/ipv6/conf/"+scope+"/disable_ipv6")) != "0" {
			return labIPv6{skip: "IPv6 is turned off on this appliance, so it was not probed."}
		}
	}
	if err := configureLabIPv6(ctx); err != nil {
		return labIPv6{failure: "the virtual lab could not set up IPv6: " + bound(err.Error(), 300)}
	}
	if err := waitForTargetIPv6(ctx); err != nil {
		return labIPv6{failure: "the virtual lab could not route IPv6: " + bound(err.Error(), 300)}
	}
	return labIPv6{}
}

func configureLabIPv6(ctx context.Context) error {
	commands := [][]string{
		// nodad: the addresses are usable at once instead of after
		// duplicate address detection; nothing else uses this prefix.
		{"ip", "addr", "add", testlab.DefaultGatewayIPv6 + "/64", "dev", clientBridge, "nodad"},
		{"ip", "netns", "add", routerNS},
		{"ip", "-n", routerNS, "link", "set", "lo", "up"},
		{"ip", "netns", "exec", routerNS, "sysctl", "-w", "net.ipv6.conf.all.forwarding=1"},
	}
	for _, side := range []struct{ hostIf, peerIf, bridge, name, address string }{
		{"lgtr0", "lgtr1", clientBridge, "eth0", routerClientIPv6},
		{"lgtw0", "lgtw1", wanBridge, "eth1", routerWANIPv6},
	} {
		commands = append(commands,
			[]string{"ip", "link", "add", side.hostIf, "type", "veth", "peer", "name", side.peerIf},
			[]string{"ip", "link", "set", side.hostIf, "master", side.bridge},
			[]string{"ip", "link", "set", side.hostIf, "up"},
			[]string{"ip", "link", "set", side.peerIf, "netns", routerNS},
			[]string{"ip", "-n", routerNS, "link", "set", side.peerIf, "name", side.name},
			[]string{"ip", "-n", routerNS, "link", "set", side.name, "up"},
			[]string{"ip", "-n", routerNS, "addr", "add", side.address + "/64", "dev", side.name, "nodad"},
		)
	}
	for _, client := range []struct{ namespace, address string }{
		{normalNS, testlab.DefaultNormalClientIPv6},
		{bypassNS, testlab.DefaultBypassClientIPv6},
		{dnsNS, testlab.DefaultDNSClientIPv6},
	} {
		commands = append(commands,
			[]string{"ip", "-n", client.namespace, "addr", "add", client.address + "/64", "dev", "eth0", "nodad"},
			[]string{"ip", "-n", client.namespace, "-6", "route", "add", "default", "via", routerClientIPv6},
		)
	}
	commands = append(commands,
		[]string{"ip", "-n", targetNS, "addr", "add", targetIPv6 + "/64", "dev", "eth0", "nodad"},
		[]string{"ip", "-n", targetNS, "-6", "route", "add", "default", "via", routerWANIPv6},
	)
	// DNS to ShakerProxy's lab address goes to the real DNS forwarder, as
	// for IPv4 (setupCoverage made the chain).
	for _, protocol := range []string{"udp", "tcp"} {
		commands = append(commands, []string{"nft", "add", "rule", "inet", testTable, "prerouting", "iifname", clientBridge, "ip6", "daddr", testlab.DefaultGatewayIPv6, protocol, "dport", "53", "redirect", "to", ":" + dnsForwarderPort()})
	}
	for _, command := range commands {
		if _, err := runCommand(ctx, command[0], command[1:]...); err != nil {
			return err
		}
	}
	if _, err := exec.LookPath("ip6tables"); err != nil {
		return nil // no IPv6 packet filter, so nothing drops the lab's traffic
	}
	for _, rule := range coverageInputRules() {
		if _, err := runCommand(ctx, "ip6tables", append([]string{"-I", "INPUT", "1"}, rule...)...); err != nil {
			return err
		}
	}
	// With br_netfilter loaded (Docker loads it), frames bridged between the
	// clients and the router namespace cross the host's FORWARD chain, whose
	// policy Docker sets to DROP.
	for _, rule := range bridgedIPv6Rules() {
		if _, err := runCommand(ctx, "ip6tables", append([]string{"-I", "FORWARD", "1"}, rule...)...); err != nil {
			return err
		}
	}
	return nil
}

// bridgedIPv6Rules accept IPv6 bridged within each lab bridge.
func bridgedIPv6Rules() [][]string {
	return [][]string{
		{"-i", clientBridge, "-o", clientBridge, "-m", "comment", "--comment", testTable, "-j", "ACCEPT"},
		{"-i", wanBridge, "-o", wanBridge, "-m", "comment", "--comment", testTable, "-j", "ACCEPT"},
	}
}

func waitForTargetIPv6(ctx context.Context) error {
	url := "http://[" + targetIPv6 + "]:8080/health"
	deadline := time.Now().Add(3 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		probeCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		_, last = runCommand(probeCtx, "ip", "netns", "exec", normalNS, "curl", "--globoff", "--fail", "--silent", "--max-time", "1", url)
		cancel()
		if last == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("the virtual target did not answer at %s within 3 seconds (%v)", url, last)
}

// deleteTaggedRules removes every copy of the test lab's rules from chain,
// for example after an interrupted earlier run. tool is iptables or
// ip6tables; a missing ip6tables holds no rules.
func deleteTaggedRules(ctx context.Context, tool, chain string, rules [][]string) {
	if _, err := exec.LookPath(tool); err != nil {
		return
	}
	for _, rule := range rules {
		for attempt := 0; attempt < 8; attempt++ {
			if _, err := runCommand(ctx, tool, append([]string{"-D", chain}, rule...)...); err != nil {
				break
			}
		}
	}
}
