package coverage

import (
	"strings"
	"testing"
	"time"
)

// sentAll is every probe sent at at, except the IPv6 ones when skipIPv6
// names why they were not.
func sentAll(at time.Time, skipIPv6 string) []ProbeOutcome {
	outcomes := []ProbeOutcome{}
	for _, probe := range Probes {
		if skipIPv6 != "" && IPv6Probe(probe.ID) {
			outcomes = append(outcomes, ProbeOutcome{ID: probe.ID, Skipped: true, Detail: skipIPv6})
			continue
		}
		outcomes = append(outcomes, ProbeOutcome{ID: probe.ID, SentAt: at, Sent: true})
	}
	return outcomes
}

func resultsByID(results []Result) map[string]Result {
	out := map[string]Result{}
	for _, result := range results {
		out[result.ID] = result
	}
	return out
}

func TestEvaluateNamesWhatIsSeenAndWhatIsMissing(t *testing.T) {
	at := time.Date(2026, 10, 2, 4, 0, 0, 0, time.UTC)
	plan := NewPlan("coverage-run-1", at)
	event := func(kind string, mutate func(*Event)) Event {
		e := Event{Kind: kind, Source: "ZEEK", SourceIP: NormalClient, OccurredAt: at.Add(time.Second), ReceivedAt: at.Add(20 * time.Second)}
		mutate(&e)
		return e
	}
	events := []Event{
		event("shakerproxy.dns", func(e *Event) {
			e.Source, e.DNSQuery, e.SourceIP, e.ReceivedAt = "HOST", plan.DNSGatewayName, DNSClient, at.Add(2*time.Second)
		}),
		event("zeek.dns", func(e *Event) { e.DNSQuery, e.DestinationIP, e.DestinationPort = plan.DNSDirectName, TargetIPv4, 53 }),
		event("zeek.conn", func(e *Event) {
			e.DestinationIP, e.DestinationPort, e.Protocol, e.AppProtocol, e.TLSServerName = TargetIPv4, PortDoT, "tcp", "dot", plan.DoTServerName
		}),
		// DoH is recorded, but only as TLS to the resolver name.
		event("zeek.conn", func(e *Event) {
			e.DestinationIP, e.DestinationPort, e.Protocol, e.AppProtocol, e.TLSServerName = TargetIPv4, PortDoH, "tcp", "tls", DoHResolverSNI
		}),
		event("zeek.http", func(e *Event) { e.HTTPPath, e.DestinationIP, e.DestinationPort = plan.HTTPPath, TargetIPv4, PortHTTP }),
		event("zeek.conn", func(e *Event) {
			e.TLSServerName, e.DestinationIP, e.DestinationPort, e.Protocol = plan.TLSServerName, TargetIPv4, PortHTTPS, "tcp"
		}),
		event("zeek.conn", func(e *Event) { e.DestinationIP, e.DestinationPort, e.Protocol = TargetIPv4, PortTCPOdd, "tcp" }),
		event("zeek.conn", func(e *Event) { e.DestinationIP, e.Protocol, e.AppProtocol = TargetIPv4, "icmp", "icmp" }),
		// SSH is recorded but Zeek did not name it.
		event("zeek.conn", func(e *Event) {
			e.DestinationIP, e.DestinationPort, e.Protocol, e.AppProtocol = TargetIPv4, PortSSH, "tcp", "unknown-tcp"
		}),
		event("zeek.conn", func(e *Event) {
			e.DestinationIP, e.DestinationPort, e.Protocol, e.AppProtocol = TargetIPv4, PortNTP, "udp", "ntp"
		}),
		// Traffic from outside the test lab never counts.
		event("zeek.conn", func(e *Event) {
			e.SourceIP, e.DestinationIP, e.DestinationPort, e.Protocol = "192.168.10.201", TargetIPv4, PortUDPOdd, "udp"
		}),
	}
	evaluated := Evaluate(plan, sentAll(at, "IPv6 is turned off on this appliance."), events)
	results := resultsByID(evaluated)
	for _, id := range []string{ProbeDNSGateway, ProbeDNSDirect, ProbeDoT, ProbeHTTP, ProbeHTTPS, ProbeTCP, ProbeICMP, ProbeNTP} {
		if results[id].Status != StatusPass {
			t.Fatalf("%s = %s: %s", id, results[id].Status, results[id].Summary)
		}
	}
	if got := results[ProbeDNSGateway].LatencyMS; got != 2000 {
		t.Fatalf("DNS latency = %d ms, want 2000", got)
	}
	if results[ProbeDoH].Status != StatusFail || !strings.Contains(results[ProbeDoH].Summary, "not identified as DNS over HTTPS") || !strings.Contains(results[ProbeDoH].Summary, "tls") {
		t.Fatalf("DoH = %+v", results[ProbeDoH])
	}
	if results[ProbeSSH].Status != StatusFail || results[ProbeSSH].Missing != "SSH is not recognised" {
		t.Fatalf("SSH = %+v", results[ProbeSSH])
	}
	for _, id := range []string{ProbeUDP, ProbeQUIC, ProbeMDNS, ProbeSSDP, ProbeDoQ} {
		if results[id].Status != StatusFail || !strings.HasPrefix(results[id].Summary, "Not recorded") {
			t.Fatalf("%s = %+v, want not recorded", id, results[id])
		}
	}
	if results[ProbeICMPv6].Status != StatusSkip || results[ProbeICMPv6].Summary != "IPv6 is turned off on this appliance." {
		t.Fatalf("ICMPv6 = %+v", results[ProbeICMPv6])
	}
	if results[ProbeHTTP].Attributed {
		t.Fatal("virtual clients have no device, so nothing is attributed")
	}
	if Settled(evaluated) {
		t.Fatal("a run with failures is not settled; later events may still arrive")
	}
	report := Report{Results: evaluated, Routing: []Finding{{Status: FindingGap}, {Status: FindingOK}}}
	report.Count()
	if report.PassCount != 8 || report.FailCount != 7 || report.SkipCount != 7 || report.GapCount != 1 {
		t.Fatalf("counts = %d/%d/%d gaps %d", report.PassCount, report.FailCount, report.SkipCount, report.GapCount)
	}
}

func TestEvaluateIPv6ProbesNeedIPv6Evidence(t *testing.T) {
	at := time.Date(2026, 10, 2, 4, 0, 0, 0, time.UTC)
	plan := NewPlan("coverage-run-3", at)
	// Zeek and the DNS forwarder may spell one address differently.
	target := "fd8a:6c1e:4b37:f1:0:0:0:FE"
	event := func(kind string, mutate func(*Event)) Event {
		e := Event{Kind: kind, Source: "ZEEK", SourceIP: NormalClientIPv6, DestinationIP: target, OccurredAt: at.Add(time.Second), ReceivedAt: at.Add(12 * time.Second)}
		mutate(&e)
		return e
	}
	events := []Event{
		event("shakerproxy.dns", func(e *Event) {
			e.Source, e.DNSQuery, e.DestinationIP, e.ReceivedAt = "HOST", plan.DNSIPv6Name, "", at.Add(time.Second)
		}),
		event("zeek.http", func(e *Event) { e.HTTPPath, e.DestinationPort, e.Protocol = plan.HTTPIPv6Path, PortHTTP, "tcp" }),
		event("zeek.conn", func(e *Event) {
			e.TLSServerName, e.DestinationPort, e.Protocol, e.AppProtocol = plan.TLSIPv6ServerName, PortHTTPS, "tcp", "tls"
		}),
		event("zeek.conn", func(e *Event) {
			e.TLSServerName, e.DestinationPort, e.Protocol, e.AppProtocol = plan.QUICIPv6ServerName, QUICPort, "udp", "quic"
		}),
		event("zeek.conn", func(e *Event) { e.DestinationPort, e.Protocol = PortTCPOdd, "tcp" }),
		event("suricata.flow", func(e *Event) { e.Source, e.DestinationPort, e.Protocol = "SURICATA", PortUDPOdd, "udp" }),
		// Zeek names ICMPv6 "icmp"; ingest names the protocol ICMPv6.
		event("zeek.conn", func(e *Event) { e.Protocol, e.AppProtocol = "icmp", "icmpv6" }),
		// The IPv4 probes' evidence never passes an IPv6 probe.
		event("zeek.conn", func(e *Event) {
			e.SourceIP, e.DestinationIP, e.TLSServerName, e.DestinationPort, e.Protocol = NormalClient, TargetIPv4, plan.TLSIPv6ServerName, PortHTTPS, "tcp"
		}),
	}
	results := resultsByID(Evaluate(plan, sentAll(at, ""), events))
	for _, id := range []string{ProbeDNSIPv6, ProbeHTTPIPv6, ProbeHTTPSIPv6, ProbeQUICIPv6, ProbeTCPIPv6, ProbeUDPIPv6, ProbeICMPv6} {
		if results[id].Status != StatusPass {
			t.Fatalf("%s = %s: %s", id, results[id].Status, results[id].Summary)
		}
	}
	if got := results[ProbeDNSIPv6].LatencyMS; got != 1000 {
		t.Fatalf("DNS over IPv6 latency = %d ms, want 1000", got)
	}
	// ...and IPv6 evidence never passes an IPv4 probe.
	for _, id := range []string{ProbeHTTP, ProbeQUIC, ProbeTCP, ProbeUDP, ProbeICMP} {
		if results[id].Status != StatusFail {
			t.Fatalf("%s passed on IPv6 evidence: %+v", id, results[id])
		}
	}
	if results[ProbeHTTPS].Status != StatusFail || !strings.Contains(results[ProbeHTTPS].Summary, "not identified as TLS") {
		t.Fatalf("an IPv4 TLS connection with the IPv6 marker is not the IPv4 HTTPS probe's proof: %+v", results[ProbeHTTPS])
	}

	unnamed := resultsByID(Evaluate(plan, sentAll(at, ""), []Event{event("zeek.conn", func(e *Event) { e.Protocol, e.AppProtocol = "icmp", "icmp" })}))
	if unnamed[ProbeICMPv6].Status != StatusFail || unnamed[ProbeICMPv6].Missing != "ICMPv6 is not recognised" {
		t.Fatalf("ICMPv6 recorded as plain ICMP = %+v", unnamed[ProbeICMPv6])
	}
}

func TestEvaluateReportsAnIPv6LabThatCouldNotRoute(t *testing.T) {
	plan := NewPlan("coverage-run-4", time.Now())
	results := resultsByID(Evaluate(plan, []ProbeOutcome{{ID: ProbeTCPIPv6, Detail: "the virtual lab could not route IPv6: no answer"}}, nil))
	if results[ProbeTCPIPv6].Status != StatusFail || !strings.Contains(results[ProbeTCPIPv6].Missing, "could not route IPv6") {
		t.Fatalf("TCP over IPv6 = %+v", results[ProbeTCPIPv6])
	}
}

func TestEveryIPv6ProbeIsInTheIPv6Category(t *testing.T) {
	ipv6 := 0
	for _, probe := range Probes {
		if _, ok := expectations[probe.ID]; !ok {
			t.Fatalf("probe %s has no expectation", probe.ID)
		}
		if IPv6Probe(probe.ID) {
			ipv6++
		}
	}
	if ipv6 != 7 || IPv6Probe(ProbeICMP) || !IPv6Probe(ProbeICMPv6) || IPv6Probe("unknown") {
		t.Fatalf("IPv6 probes = %d", ipv6)
	}
}

func TestEvaluateReportsAProbeThatCouldNotBeSent(t *testing.T) {
	plan := NewPlan("coverage-run-2", time.Now())
	results := resultsByID(Evaluate(plan, []ProbeOutcome{{ID: ProbeICMP, Detail: "ping: not found"}}, nil))
	if results[ProbeICMP].Status != StatusFail || !strings.Contains(results[ProbeICMP].Missing, "ping: not found") {
		t.Fatalf("ICMP = %+v", results[ProbeICMP])
	}
	if results[ProbeSSH].Status != StatusSkip {
		t.Fatalf("a probe without an outcome is skipped: %+v", results[ProbeSSH])
	}
}

func TestPlanMarkersAreUniquePerRunAndNeverResolve(t *testing.T) {
	first, second := NewPlan("run-a", time.Now()), NewPlan("run-b", time.Now())
	if first.DNSGatewayName == second.DNSGatewayName || first.HTTPPath == second.HTTPPath {
		t.Fatal("two runs share markers")
	}
	if first.DoTServerName == first.DoQServerName {
		t.Fatal("DoT and DoQ must use distinct names so one cannot pass for the other")
	}
	if first.TLSServerName == first.TLSIPv6ServerName || first.QUICServerName == first.QUICIPv6ServerName || strings.HasPrefix(first.HTTPIPv6Path, first.HTTPPath) {
		t.Fatal("the IPv6 probes must use markers of their own")
	}
	for _, name := range []string{first.DNSGatewayName, first.DNSDirectName, first.TLSServerName, first.DoTServerName, first.DoQServerName, first.QUICServerName,
		first.DNSIPv6Name, first.TLSIPv6ServerName, first.QUICIPv6ServerName} {
		if !strings.HasSuffix(name, ".coverage.shakerproxy.test") {
			t.Fatalf("%s is not under the reserved .test domain", name)
		}
	}
}
