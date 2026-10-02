package main

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/coverage"
)

func freeAddress(t *testing.T, network string) string {
	t.Helper()
	if network == "udp" {
		connection, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		return connection.LocalAddr().String()
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().String()
}

func TestDNSQueryEncodesTheProbeName(t *testing.T) {
	query := dnsQuery("gw-ab12.coverage.shakerproxy.test", 1, 0x5301)
	want := []byte{0x53, 0x01, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'g', 'w', '-', 'a', 'b', '1', '2'}
	if !bytes.HasPrefix(query, want) || !bytes.HasSuffix(query, []byte{4, 't', 'e', 's', 't', 0, 0, 1, 0, 1}) {
		t.Fatalf("query = %x", query)
	}
}

func TestEveryCoverageProbeHasARunner(t *testing.T) {
	ipv4, ipv6 := ipv4Probes(), ipv6Probes()
	for _, probe := range coverage.Probes {
		_, v4 := ipv4[probe.ID]
		_, v6 := ipv6[probe.ID]
		if v4 == v6 || v6 != coverage.IPv6Probe(probe.ID) {
			t.Fatalf("probe %s: IPv4 runner %v, IPv6 runner %v", probe.ID, v4, v6)
		}
	}
}

func TestALabWithoutIPv6ReportsWhyInsteadOfProbing(t *testing.T) {
	plan := coverage.NewPlan("coverage-0123456789abcdef01234567", time.Now())
	ran := map[string]bool{}
	probes := map[string]probeFunc{}
	for _, probe := range coverage.Probes {
		id := probe.ID
		probes[id] = func(coverage.Plan) (bool, string) { ran[id] = true; return true, "sent" }
	}
	byID := func(outcomes []coverage.ProbeOutcome) map[string]coverage.ProbeOutcome {
		out := map[string]coverage.ProbeOutcome{}
		for _, outcome := range outcomes {
			out[outcome.ID] = outcome
		}
		return out
	}

	skipped := byID(runProbes(plan, probes, labIPv6{skip: "IPv6 is turned off on this appliance, so it was not probed."}))
	if ran[coverage.ProbeTCPIPv6] || !ran[coverage.ProbeTCP] {
		t.Fatalf("ran = %v", ran)
	}
	if got := skipped[coverage.ProbeICMPv6]; !got.Skipped || got.Sent || !strings.Contains(got.Detail, "turned off") {
		t.Fatalf("ICMPv6 = %+v", got)
	}

	clear(ran)
	failed := byID(runProbes(plan, probes, labIPv6{failure: "the virtual lab could not route IPv6: no answer"}))
	if got := failed[coverage.ProbeDNSIPv6]; got.Skipped || got.Sent || !strings.Contains(got.Detail, "could not route IPv6") || ran[coverage.ProbeDNSIPv6] {
		t.Fatalf("DNS over IPv6 = %+v", got)
	}

	clear(ran)
	working := byID(runProbes(plan, probes, labIPv6{}))
	if got := working[coverage.ProbeUDPIPv6]; !got.Sent || got.SentAt.IsZero() || !ran[coverage.ProbeUDPIPv6] {
		t.Fatalf("UDP over IPv6 = %+v", got)
	}
}

func TestTheProbeRunnerLearnsTheLabsIPv6StateFromItsEnvironment(t *testing.T) {
	if env := (labIPv6{}).probeEnvironment(); len(env) != 0 {
		t.Fatalf("a working lab sets %v", env)
	}
	if env := (labIPv6{skip: "off"}).probeEnvironment(); len(env) != 1 || env[0] != ipv6SkipEnv+"=off" {
		t.Fatalf("skip = %v", env)
	}
	if env := (labIPv6{failure: "broken"}).probeEnvironment(); len(env) != 1 || env[0] != ipv6FailureEnv+"=broken" {
		t.Fatalf("failure = %v", env)
	}
}

func TestAAAAQueryAsksForIPv6Addresses(t *testing.T) {
	query := dnsQuery("aaaa-ab12.coverage.shakerproxy.test", 28, 0x5306)
	if !bytes.HasSuffix(query, []byte{4, 't', 'e', 's', 't', 0, 0, 28, 0, 1}) {
		t.Fatalf("query = %x", query)
	}
}

// The target binds ":port", one socket that must answer both families: the
// IPv6 probes reach the same endpoints as the IPv4 ones.
func TestCoverageTargetEndpointsAnswerOverIPv6(t *testing.T) {
	probe, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback here: %v", err)
	}
	probe.Close()
	tcpPort, udpPort := freePort(t, "tcp"), freePort(t, "udp")
	go serveTCPEcho(":" + tcpPort)
	go serveUDPEcho(":" + udpPort)
	time.Sleep(100 * time.Millisecond)
	for _, host := range []string{"127.0.0.1", "::1"} {
		if sent, detail := tcpEcho(net.JoinHostPort(host, tcpPort)); !sent || detail != "connected" {
			t.Fatalf("TCP to %s: sent=%v %s", host, sent, detail)
		}
		if sent, detail := udpExchange(net.JoinHostPort(host, udpPort), []byte("coverage"), true); !sent || detail != "answered" {
			t.Fatalf("UDP to %s: sent=%v %s", host, sent, detail)
		}
	}
}

func freePort(t *testing.T, network string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(freeAddress(t, network))
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func TestCoverageTargetEndpointsAnswerTheProbes(t *testing.T) {
	ntp, echo, ssh := freeAddress(t, "udp"), freeAddress(t, "udp"), freeAddress(t, "tcp")
	go serveNTP(ntp)
	go serveUDPEcho(echo)
	go serveSSHBanner(ssh)
	time.Sleep(100 * time.Millisecond)
	request := make([]byte, 48)
	request[0] = 0x23
	if sent, detail := udpExchange(ntp, request, true); !sent || detail != "answered" {
		t.Fatalf("NTP: sent=%v %s", sent, detail)
	}
	if sent, detail := udpExchange(echo, []byte("coverage"), true); !sent || detail != "answered" {
		t.Fatalf("UDP echo: sent=%v %s", sent, detail)
	}
	connection, err := net.DialTimeout("tcp", ssh, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	banner := make([]byte, 64)
	n, _ := connection.Read(banner)
	if !strings.HasPrefix(string(banner[:n]), "SSH-2.0-") {
		t.Fatalf("SSH banner = %q", banner[:n])
	}
}
