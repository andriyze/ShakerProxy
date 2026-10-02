package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shakerproxy.dev/shakerproxy/internal/dnsproxy"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

const labTestDevice = "device-0123456789abcdef0123456789abcdef"

func labTestManager(t *testing.T, runner *fakeTrafficRunner) *TrafficPolicyManager {
	t.Helper()
	root := t.TempDir()
	state := routedTrafficState()
	state.state.StagedNetworkPlan.Plan.IPv4.GatewayAddress = "10.77.0.1"
	manager := &TrafficPolicyManager{
		NetworkState:   state,
		PolicyStore:    &trafficpolicy.Store{Path: filepath.Join(root, "policy.json")},
		RuntimePath:    filepath.Join(root, "traffic", "policy.json"),
		OnboardingPath: filepath.Join(root, "onboarding", "lab-endpoints.json"),
		Runner:         runner,
		Probe:          func(context.Context, int) error { return nil },
		ProbeIPv6:      func(context.Context, int) error { return nil },
		IPv6Available:  func() bool { return true },
		Neighbors: func(context.Context, string) ([]trafficpolicy.Neighbor, error) {
			return []trafficpolicy.Neighbor{{Address: "10.77.0.23", HardwareAddress: "aa:bb:cc:dd:ee:01"}, {Address: "fe80::a8bb:ccff:fedd:ee01", HardwareAddress: "aa:bb:cc:dd:ee:01"}}, nil
		},
	}
	if err := manager.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	return manager
}

// Cross-component regression for "force plain DNS breaks all DNS": the runtime
// document the gateway publishes for ENFORCE_LOCAL must be accepted by the
// DNS forwarder with the configured upstreams.
func TestEnforceLocalRuntimeIsAcceptedByDNSForwarder(t *testing.T) {
	manager := labTestManager(t, &fakeTrafficRunner{})
	policy := trafficpolicy.LegacyDefaultPolicy()
	policy.Revision = 2
	policy.Name = "Force plain DNS"
	policy.EncryptedDNS.Mode = trafficpolicy.EncryptedDNSEnforceLocal
	policy.EncryptedDNS.RedirectPlainDNS = true
	policy.EncryptedDNS.UpstreamServers = []string{"9.9.9.9:53", "1.1.1.1:53"}
	if _, err := manager.Apply(t.Context(), policy, 1); err != nil {
		t.Fatal(err)
	}
	provider := &dnsproxy.FilePolicyProvider{Path: manager.RuntimePath, ResolvConfPaths: []string{filepath.Join(t.TempDir(), "absent")}}
	runtime, err := provider.Runtime()
	if err != nil {
		t.Fatalf("DNS forwarder rejected the gateway runtime: %v", err)
	}
	if runtime.HostResolver || strings.Join(runtime.Upstreams, ",") != "1.1.1.1:53,9.9.9.9:53" {
		t.Fatalf("forwarder upstreams = %v (host resolver %t)", runtime.Upstreams, runtime.HostResolver)
	}
}

func TestDeviceControlsRenderMACRulesForBothFamiliesAndPublishIdentity(t *testing.T) {
	runner := &fakeTrafficRunner{}
	manager := labTestManager(t, runner)
	policy := trafficpolicy.LegacyDefaultPolicy()
	policy.Revision = 2
	policy.Name = "Device lab controls"
	policy.TLS.Enabled = true
	policy.TLS.SelectedDeviceIDs = []string{labTestDevice}
	policy.DeviceControls = []trafficpolicy.DeviceControl{{DeviceID: labTestDevice, HardwareAddresses: []string{"AA:BB:CC:DD:EE:01"}, BlockedDomains: []string{"ads.example"}}}
	if _, err := manager.Apply(t.Context(), policy, 1); err != nil {
		t.Fatal(err)
	}
	v4 := runner.lastRestore("/usr/sbin/iptables-restore")
	v6 := runner.lastRestore("/usr/sbin/ip6tables-restore")
	for _, expected := range []string{
		"-i lab0 -s 10.77.0.0/24 -d 10.77.0.1 -p udp --dport 53 -j REDIRECT --to-ports 1053",
		"-i lab0 -m mac --mac-source aa:bb:cc:dd:ee:01 ! -d 10.77.0.0/24 -p udp --dport 53 -j REDIRECT --to-ports 1053",
		"-i lab0 -m mac --mac-source aa:bb:cc:dd:ee:01 ! -d 10.77.0.0/24 -p tcp --dport 443 -j REDIRECT --to-ports 8085",
		"-i lab0 -m mac --mac-source aa:bb:cc:dd:ee:01 ! -d 10.77.0.0/24 -p udp --dport 443 -j REJECT",
		"-d 10.77.0.1 -p tcp --dport 80 -j DNAT --to-destination 10.77.0.1:8086",
	} {
		if !strings.Contains(v4, expected) {
			t.Fatalf("IPv4 batch lacks %q:\n%s", expected, v4)
		}
	}
	for _, expected := range []string{
		"-i lab0 -m mac --mac-source aa:bb:cc:dd:ee:01 -p udp --dport 443 -j REJECT --reject-with icmp6-port-unreachable",
		"-i lab0 -m mac --mac-source aa:bb:cc:dd:ee:01 -p tcp --dport 443 -j REDIRECT --to-ports 8085",
		"-A SHAKERPROXY-SEC-INPUT -p tcp --dport 8085 -j DROP",
	} {
		if !strings.Contains(v6, expected) {
			t.Fatalf("IPv6 batch lacks %q:\n%s", expected, v6)
		}
	}
	if !runner.jumps["6:FORWARD->"+securityForwardChain] || !runner.jumps["6:INPUT->"+securityInputChain] || !runner.jumps["6:PREROUTING->"+securityPreroutingChain] {
		t.Fatalf("IPv6 jumps were not attached: %#v", runner.jumps)
	}

	data, err := os.ReadFile(manager.RuntimePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "aa:bb:cc") {
		t.Fatal("hardware address leaked into the mitmproxy runtime")
	}
	var runtime trafficpolicy.StandaloneProxyRuntime
	if err := json.Unmarshal(data, &runtime); err != nil {
		t.Fatal(err)
	}
	if runtime.DeviceByIP["10.77.0.23"] != labTestDevice || runtime.DeviceByIP["fe80::a8bb:ccff:fedd:ee01"] != labTestDevice {
		t.Fatalf("neighbor-derived identity was not published: %#v", runtime.DeviceByIP)
	}
	if !runtime.EncryptedDNS.RedirectPlainDNS || len(runtime.EncryptedDNS.BlockedDomains[labTestDevice]) != 1 || len(runtime.EncryptedDNS.UpstreamServers) != 0 {
		t.Fatalf("DNS runtime for domain blocking is wrong: %#v", runtime.EncryptedDNS)
	}

	endpoints := readOnboardingEndpoints(t, manager.OnboardingPath)
	if !endpoints.Serve || endpoints.IPv4 != "10.77.0.1" || endpoints.Port != trafficpolicy.DefaultOnboardingPort {
		t.Fatalf("onboarding endpoints were not published: %#v", endpoints)
	}
	status := manager.LabOnboarding()
	if !status.Routed || !status.Published || !status.InterceptionConfigured || status.GatewayIPv4 != "10.77.0.1" {
		t.Fatalf("unexpected onboarding status: %#v", status)
	}

	if err := manager.EnableEmergencyBypass(t.Context()); err != nil {
		t.Fatal(err)
	}
	if endpoints := readOnboardingEndpoints(t, manager.OnboardingPath); endpoints.Serve {
		t.Fatal("emergency bypass left the onboarding page published")
	}
	if strings.Contains(runner.lastRestore("/usr/sbin/ip6tables-restore"), "--mac-source") {
		t.Fatal("emergency bypass left IPv6 device rules installed")
	}
}

func TestIPv6RedirectsWaitForIPv6Listeners(t *testing.T) {
	runner := &fakeTrafficRunner{chains: map[string]bool{"6:DOCKER-USER": true}}
	manager := labTestManager(t, runner)
	manager.ProbeIPv6 = func(context.Context, int) error { return os.ErrNotExist }
	policy := trafficpolicy.LegacyDefaultPolicy()
	policy.Revision = 2
	policy.Name = "All devices"
	policy.TLS.Enabled = true
	if _, err := manager.Apply(t.Context(), policy, 1); err != nil {
		t.Fatal(err)
	}
	v6 := runner.lastRestore("/usr/sbin/ip6tables-restore")
	if strings.Contains(v6, "REDIRECT") {
		t.Fatalf("IPv6 traffic was redirected to an IPv4-only listener:\n%s", v6)
	}
	if !strings.Contains(v6, "-i lab0 -p udp --dport 443 -j REJECT --reject-with icmp6-port-unreachable") {
		t.Fatalf("IPv6 QUIC was not blocked:\n%s", v6)
	}
	if !runner.jumps["6:DOCKER-USER->"+securityForwardChain] || runner.jumps["6:FORWARD->"+securityForwardChain] {
		t.Fatalf("IPv6 forward jump must use DOCKER-USER when Docker manages ip6tables: %#v", runner.jumps)
	}
}

func TestLabIPv6ContextFollowsTheConfirmedPlan(t *testing.T) {
	for _, test := range []struct {
		ipv6            networkplan.IPv6Configuration
		prefix, gateway string
	}{
		{networkplan.IPv6Configuration{Strategy: networkplan.IPv6ULANAT66Lab, LabPrefix: "fd12:3456:789a:1::/64", GatewayAddress: "fd12:3456:789a:1::1"}, "fd12:3456:789a:1::/64", "fd12:3456:789a:1::1"},
		{networkplan.IPv6Configuration{Strategy: networkplan.IPv6ULANAT66Lab, LabPrefix: "fd12:3456:789a:1::/64"}, "fd12:3456:789a:1::/64", "fd12:3456:789a:1::1"},
		{networkplan.IPv6Configuration{Strategy: networkplan.IPv6Disabled, LabPrefix: "fd12:3456:789a:1::/64"}, "", ""},
	} {
		plan := networkplan.Plan{Topology: networkplan.TopologyTwoNIC, Interfaces: []networkplan.Interface{{CurrentName: "lab0", Role: networkplan.RoleLab}}, IPv6: test.ipv6}
		prefix, gateway := labIPv6Context(plan)
		if prefix != test.prefix || gateway != test.gateway {
			t.Fatalf("%+v: got %q %q", test.ipv6, prefix, gateway)
		}
	}
}

// The network restorer inserts ShakerProxy's forward and input hooks below ours,
// but if ours ended up below ShakerProxy's (restart order), the next reconcile
// must move it back in front so device blocks are not bypassed.
func TestSecurityHooksStayAboveShakerProxyHooks(t *testing.T) {
	runner := &fakeTrafficRunner{}
	manager := labTestManager(t, runner)
	runner.attach("", "DOCKER-USER", "SHAKERPROXY-FORWARD", 1)
	runner.attach("", "INPUT", "SHAKERPROXY-INPUT", 1)
	runner.attach("6:", "FORWARD", "SHAKERPROXY-FORWARD", 1)
	policy := trafficpolicy.LegacyDefaultPolicy()
	policy.Revision = 2
	policy.Name = "Block a device"
	policy.DeviceControls = []trafficpolicy.DeviceControl{{DeviceID: labTestDevice, HardwareAddresses: []string{"aa:bb:cc:dd:ee:01"}, BlockInternet: true}}
	if _, err := manager.Apply(t.Context(), policy, 1); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct{ prefix, parent, ours, theirs string }{
		{"", "DOCKER-USER", securityForwardChain, "SHAKERPROXY-FORWARD"},
		{"", "INPUT", securityInputChain, "SHAKERPROXY-INPUT"},
		{"6:", "FORWARD", securityForwardChain, "SHAKERPROXY-FORWARD"},
	} {
		order := runner.positions(check.prefix, check.parent)
		if len(order) != 2 || order[0] != check.ours || order[1] != check.theirs {
			t.Fatalf("%s%s order = %v, want %s above %s", check.prefix, check.parent, order, check.ours, check.theirs)
		}
	}
	// Already in front: a reconcile does not churn the hooks.
	calls := len(runner.calls)
	if err := manager.ReconcileNow(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, call := range runner.calls[calls:] {
		if len(call.arguments) > 2 && call.arguments[2] == "-D" && call.arguments[3] != "PREROUTING" {
			t.Fatalf("reconcile moved a correctly placed hook: %v", call.arguments)
		}
	}
}

// An IPv6 NAT failure leaves IPv6 unintercepted but must not tear down the
// IPv4 policy or the IPv6 blocks and listener protection.
func TestIPv6RedirectFailureKeepsIPv4PolicyAndIPv6Protection(t *testing.T) {
	runner := &fakeTrafficRunner{failRestore: func(executable, stdin string) error {
		if executable == "/usr/sbin/ip6tables-restore" && strings.Contains(stdin, "*nat") {
			return os.ErrPermission
		}
		return nil
	}}
	manager := labTestManager(t, runner)
	policy := trafficpolicy.LegacyDefaultPolicy()
	policy.Revision = 2
	policy.Name = "Decrypt and block"
	policy.TLS.Enabled = true
	policy.TLS.SelectedDeviceIDs = []string{labTestDevice}
	policy.DeviceControls = []trafficpolicy.DeviceControl{{DeviceID: labTestDevice, HardwareAddresses: []string{"aa:bb:cc:dd:ee:01"}, BlockedDomains: []string{"ads.example"}}}
	if _, err := manager.Apply(t.Context(), policy, 1); err != nil {
		t.Fatalf("IPv6 NAT failure failed the whole policy: %v", err)
	}
	if !runner.jumps["PREROUTING->"+securityPreroutingChain] {
		t.Fatal("IPv4 redirects were torn down")
	}
	if !runner.jumps["6:INPUT->"+securityInputChain] || !runner.jumps["6:FORWARD->"+securityForwardChain] || runner.jumps["6:PREROUTING->"+securityPreroutingChain] {
		t.Fatalf("unexpected IPv6 hooks: %#v", runner.jumps)
	}
}

// After a reboot gatewayd starts fail-open; the reconciler must restore the
// durable policy once the listeners answer.
func TestDurablePolicyIsReappliedAfterRestart(t *testing.T) {
	root := t.TempDir()
	newManager := func(runner *fakeTrafficRunner) *TrafficPolicyManager {
		state := routedTrafficState()
		state.state.StagedNetworkPlan.Plan.IPv4.GatewayAddress = "10.77.0.1"
		return &TrafficPolicyManager{
			NetworkState: state,
			PolicyStore:  &trafficpolicy.Store{Path: filepath.Join(root, "policy.json")},
			RuntimePath:  filepath.Join(root, "traffic", "policy.json"),
			Runner:       runner,
			Probe:        func(context.Context, int) error { return nil },
		}
	}
	first := newManager(&fakeTrafficRunner{})
	if err := first.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	policy := trafficpolicy.LegacyDefaultPolicy()
	policy.Revision = 2
	policy.Name = "Block a device"
	policy.DeviceControls = []trafficpolicy.DeviceControl{{DeviceID: labTestDevice, HardwareAddresses: []string{"aa:bb:cc:dd:ee:01"}, BlockInternet: true}}
	if _, err := first.Apply(t.Context(), policy, 1); err != nil {
		t.Fatal(err)
	}

	rebooted := &fakeTrafficRunner{}
	second := newManager(rebooted)
	if err := second.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	if rebooted.jumps["DOCKER-USER->"+securityForwardChain] {
		t.Fatal("startup attached client rules before proving the listeners")
	}
	if err := second.ReconcileNow(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !rebooted.jumps["DOCKER-USER->"+securityForwardChain] || !strings.Contains(rebooted.lastRestore("/usr/sbin/iptables-restore"), "--mac-source aa:bb:cc:dd:ee:01 ! -d 10.77.0.0/24 -j DROP") {
		t.Fatal("the durable device block was not restored after restart")
	}
}

func readOnboardingEndpoints(t *testing.T, path string) OnboardingEndpoints {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var endpoints OnboardingEndpoints
	if err := json.Unmarshal(data, &endpoints); err != nil {
		t.Fatal(err)
	}
	return endpoints
}

// Regression from a routed EC2 lab: after the network plan was confirmed,
// the default observe-only policy rendered no lab rules, so clients that
// use ShakerProxy as their resolver (DHCP's default) had no DNS at all.
// The default is now maximum visibility: every lab client's plain DNS is
// answered by ShakerProxy and encrypted DNS is blocked.
func TestDefaultPolicyAnswersAllLabDNSAndBlocksEncryptedDNSOnlyWhenAsked(t *testing.T) {
	runner := &fakeTrafficRunner{}
	manager := labTestManager(t, runner)
	if err := manager.ReconcileNow(t.Context()); err != nil {
		t.Fatal(err)
	}
	v4 := runner.lastRestore("/usr/sbin/iptables-restore")
	for _, expected := range []string{
		"-i lab0 -s 10.77.0.0/24 -d 10.77.0.1 -p udp --dport 53 -j REDIRECT --to-ports 1053",
		"-i lab0 -s 10.77.0.0/24 ! -d 10.77.0.0/24 -p udp --dport 53 -j REDIRECT --to-ports 1053",
	} {
		if !strings.Contains(v4, expected) {
			t.Fatalf("default policy lacks %q:\n%s", expected, v4)
		}
	}
	// Encrypted DNS is identified, not blocked, until the tester turns
	// blocking on.
	if strings.Contains(v4, "--dport 853 -j REJECT") || strings.Contains(v4, "-d 8.8.8.8 -p tcp --dport 443 -j REJECT") {
		t.Fatalf("the default blocks encrypted DNS:\n%s", v4)
	}
	blocking := trafficpolicy.BlockingPolicy()
	blocking.Revision = 2
	if _, err := manager.Apply(t.Context(), blocking, 1); err != nil {
		t.Fatal(err)
	}
	v4 = runner.lastRestore("/usr/sbin/iptables-restore")
	for _, expected := range []string{
		"-i lab0 -s 10.77.0.0/24 ! -d 10.77.0.0/24 -p tcp --dport 853 -j REJECT --reject-with tcp-reset",
		"-i lab0 -s 10.77.0.0/24 -d 8.8.8.8 -p tcp --dport 443 -j REJECT --reject-with tcp-reset",
	} {
		if !strings.Contains(v4, expected) {
			t.Fatalf("blocking policy lacks %q:\n%s", expected, v4)
		}
	}
	// An administrator who turns both switches off gets observe-only: only
	// DNS sent to ShakerProxy itself is answered.
	observe := trafficpolicy.LegacyDefaultPolicy()
	observe.Revision = 3
	if _, err := manager.Apply(t.Context(), observe, 2); err != nil {
		t.Fatal(err)
	}
	v4 = runner.lastRestore("/usr/sbin/iptables-restore")
	if !strings.Contains(v4, "-i lab0 -s 10.77.0.0/24 -d 10.77.0.1 -p udp --dport 53 -j REDIRECT --to-ports 1053") || strings.Contains(v4, "! -d 10.77.0.0/24 -p udp --dport 53") || strings.Contains(v4, "--dport 853") {
		t.Fatalf("observe-only must answer only DNS sent to ShakerProxy:\n%s", v4)
	}
}
