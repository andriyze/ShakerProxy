package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"shakerproxy.dev/shakerproxy/internal/testlab"
)

const (
	clientBridge = "lgtest-client"
	wanBridge    = "lgtest-wan"
	normalNS     = "lgtest-normal"
	bypassNS     = "lgtest-bypass"
	dnsNS        = "lgtest-dns"
	targetNS     = "lgtest-target"
	targetIPv4   = "198.18.241.254"
	wanIPv4      = "198.18.241.1"
	testTable    = "shakerproxy-testlab"
)

func setupLab(ctx context.Context) error {
	commands := [][]string{
		{"ip", "link", "add", clientBridge, "type", "bridge"},
		{"ip", "addr", "add", testlab.DefaultGatewayIPv4 + "/24", "dev", clientBridge},
		{"ip", "link", "set", clientBridge, "up"},
		{"ip", "link", "add", wanBridge, "type", "bridge"},
		{"ip", "addr", "add", wanIPv4 + "/24", "dev", wanBridge},
		{"ip", "link", "set", wanBridge, "up"},
		{"ip", "netns", "add", normalNS},
		{"ip", "netns", "add", bypassNS},
		{"ip", "netns", "add", dnsNS},
		{"ip", "netns", "add", targetNS},
	}
	for _, command := range commands {
		if _, err := runCommand(ctx, command[0], command[1:]...); err != nil {
			return err
		}
	}

	clients := []struct {
		namespace string
		hostIf    string
		peerIf    string
		address   string
	}{
		{normalNS, "lgtn0", "lgtn1", testlab.DefaultNormalClient},
		{bypassNS, "lgtb0", "lgtb1", testlab.DefaultBypassClient},
		{dnsNS, "lgtd0", "lgtd1", testlab.DefaultDNSClient},
	}
	for _, client := range clients {
		clientCommands := [][]string{
			{"ip", "link", "add", client.hostIf, "type", "veth", "peer", "name", client.peerIf},
			{"ip", "link", "set", client.hostIf, "master", clientBridge},
			{"ip", "link", "set", client.hostIf, "up"},
			{"ip", "link", "set", client.peerIf, "netns", client.namespace},
			{"ip", "-n", client.namespace, "link", "set", "lo", "up"},
			{"ip", "-n", client.namespace, "link", "set", client.peerIf, "name", "eth0"},
			{"ip", "-n", client.namespace, "link", "set", "eth0", "up"},
			{"ip", "-n", client.namespace, "addr", "add", client.address + "/24", "dev", "eth0"},
			{"ip", "-n", client.namespace, "route", "add", "default", "via", testlab.DefaultGatewayIPv4},
		}
		for _, command := range clientCommands {
			if _, err := runCommand(ctx, command[0], command[1:]...); err != nil {
				return err
			}
		}
	}

	targetCommands := [][]string{
		{"ip", "link", "add", "lgtt0", "type", "veth", "peer", "name", "lgtt1"},
		{"ip", "link", "set", "lgtt0", "master", wanBridge},
		{"ip", "link", "set", "lgtt0", "up"},
		{"ip", "link", "set", "lgtt1", "netns", targetNS},
		{"ip", "-n", targetNS, "link", "set", "lo", "up"},
		{"ip", "-n", targetNS, "link", "set", "lgtt1", "name", "eth0"},
		{"ip", "-n", targetNS, "link", "set", "eth0", "up"},
		{"ip", "-n", targetNS, "addr", "add", targetIPv4 + "/24", "dev", "eth0"},
		{"ip", "-n", targetNS, "route", "add", "default", "via", wanIPv4},
		// The service has no CAP_NET_BIND_SERVICE; let the target bind DNS/53 and
		// DoT/853 inside its own network namespace only.
		{"ip", "netns", "exec", targetNS, "sysctl", "-w", "net.ipv4.ip_unprivileged_port_start=0"},
	}
	for _, command := range targetCommands {
		if _, err := runCommand(ctx, command[0], command[1:]...); err != nil {
			return err
		}
	}

	if _, err := runCommand(ctx, "sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return err
	}
	// Docker sets the iptables FORWARD policy to DROP, and an nftables accept
	// cannot override it, so allow forwarding between the two lab bridges ahead
	// of Docker's chains. The rules carry a comment so cleanup removes exactly them.
	for _, rule := range forwardRules() {
		if _, err := runCommand(ctx, "iptables", append([]string{"-I", "FORWARD", "1"}, rule...)...); err != nil {
			return err
		}
	}
	if _, err := runCommand(ctx, "nft", "add", "table", "inet", testTable); err != nil {
		return err
	}
	if _, err := runCommand(ctx, "nft", "add", "chain", "inet", testTable, "forward", "{", "type", "filter", "hook", "forward", "priority", "-50", ";", "policy", "accept", ";", "}"); err != nil {
		return err
	}

	command := exec.CommandContext(ctx, "ip", "netns", "exec", targetNS, os.Args[0], "--target-server")
	command.Stdout = nil
	command.Stderr = nil
	if err := command.Start(); err != nil {
		return err
	}
	return waitForTarget(ctx)
}

func waitForTarget(ctx context.Context) error {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		probeCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		_, err := runCommand(probeCtx, "ip", "netns", "exec", normalNS, "curl", "--fail", "--silent", "--max-time", "1", "http://"+targetIPv4+":8080/health")
		cancel()
		if err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("virtual target did not become ready within 3 seconds")
}

// forwardRules are the iptables FORWARD rules that let the virtual clients
// reach the virtual target across the two lab bridges.
func forwardRules() [][]string {
	return [][]string{
		{"-i", clientBridge, "-o", wanBridge, "-m", "comment", "--comment", testTable, "-j", "ACCEPT"},
		{"-i", wanBridge, "-o", clientBridge, "-m", "comment", "--comment", testTable, "-j", "ACCEPT"},
	}
}

func cleanupLab(ctx context.Context) {
	killNamespaceProcesses(ctx, targetNS)
	for _, rule := range forwardRules() {
		// Delete every copy, e.g. after an interrupted earlier run.
		for attempt := 0; attempt < 8; attempt++ {
			if _, err := runCommand(ctx, "iptables", append([]string{"-D", "FORWARD"}, rule...)...); err != nil {
				break
			}
		}
	}
	_, _ = runCommand(ctx, "nft", "delete", "table", "inet", testTable)
	for _, namespace := range []string{normalNS, bypassNS, dnsNS, targetNS} {
		_, _ = runCommand(ctx, "ip", "netns", "delete", namespace)
	}
	for _, link := range []string{clientBridge, wanBridge, "lgtn0", "lgtb0", "lgtd0", "lgtt0"} {
		_, _ = runCommand(ctx, "ip", "link", "delete", link)
	}
}

func killNamespaceProcesses(ctx context.Context, namespace string) {
	output, err := runCommand(ctx, "ip", "netns", "pids", namespace)
	if err != nil {
		return
	}
	for _, field := range strings.Fields(output) {
		pid, err := strconv.Atoi(field)
		if err == nil && pid > 1 {
			_ = syscall.Kill(pid, syscall.SIGTERM)
		}
	}
}

func addDotBlock(ctx context.Context) error {
	_, err := runCommand(ctx, "nft", "add", "rule", "inet", testTable, "forward", "ip", "saddr", testlab.DefaultDNSClient, "tcp", "dport", "853", "drop")
	return err
}

func commandTest(ctx context.Context, id, name, category, namespace string, command []string, expectSuccess bool) testlab.Result {
	startedAt := time.Now()
	args := append([]string{"netns", "exec", namespace}, command...)
	output, err := runCommand(ctx, "ip", args...)
	succeeded := err == nil
	status := testlab.TestPass
	summary := "Observed expected result."
	if succeeded != expectSuccess {
		status = testlab.TestFail
		summary = fmt.Sprintf("Unexpected result: %v", err)
	}
	if !expectSuccess && !succeeded {
		summary = "Connection was blocked as expected by the isolated test-lab rule; this is a network-mechanic proof, not a ShakerProxy policy-classification claim."
	}
	return result(id, name, category, status, summary, bound(output, testlab.MaxOutputBytes), time.Since(startedAt))
}

func prerequisiteResults() []testlab.Result {
	checks := []string{"ip", "nft", "iptables", "curl", "sysctl"}
	results := make([]testlab.Result, 0, len(checks)+1)
	for _, name := range checks {
		path, err := exec.LookPath(name)
		status := testlab.TestPass
		summary := "Available"
		if err != nil {
			status = testlab.TestFail
			summary = "Required executable is missing"
			path = name
		}
		results = append(results, result("prereq-"+name, name, "prerequisite", status, summary, path, 0))
	}
	if _, err := os.Stat("/proc/self/ns/net"); err != nil {
		results = append(results, result("prereq-netns", "Network namespaces", "prerequisite", testlab.TestFail, "Network namespaces are unavailable", err.Error(), 0))
	} else {
		results = append(results, result("prereq-netns", "Network namespaces", "prerequisite", testlab.TestPass, "Available", "/proc/self/ns/net", 0))
	}
	return results
}

func shouldRun(profile testlab.Profile, category string) bool {
	return profile == testlab.ProfileFull ||
		profile == testlab.ProfileQuick && category == "network" ||
		profile == testlab.ProfileDNS && category == "dns" ||
		profile == testlab.ProfileTLS && category == "tls"
}

func result(id, name, category string, status testlab.TestStatus, summary, observed string, duration time.Duration) testlab.Result {
	return testlab.Result{
		ID:         id,
		Name:       name,
		Category:   category,
		Status:     status,
		Summary:    bound(summary, 1024),
		Observed:   bound(observed, testlab.MaxOutputBytes),
		DurationMS: duration.Milliseconds(),
	}
}

func bound(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "…"
}

func runCommand(ctx context.Context, name string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, name, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, bound(string(output), 512))
	}
	return string(output), nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func readFile(path string) string {
	value, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(value)
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envInt(name string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(name))
	if err == nil && value > 0 && value < 1<<31 {
		return value
	}
	return fallback
}

func randomID() string {
	value := make([]byte, 12)
	_, _ = rand.Read(value)
	return fmt.Sprintf("selftest-%x", value)
}

func cleanupOperationID() string {
	return "selftest-cleanup-" + strconv.FormatInt(time.Now().UnixNano(), 10)
}
