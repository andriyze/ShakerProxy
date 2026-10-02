package coverage

import (
	"strings"
	"testing"
	"time"
)

func sentAll(at time.Time) []ProbeOutcome {
	outcomes := []ProbeOutcome{}
	for _, probe := range Probes {
		if probe.ID == ProbeIPv6 {
			outcomes = append(outcomes, ProbeOutcome{ID: probe.ID, Skipped: true, Detail: "The virtual test lab is IPv4-only."})
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
	evaluated := Evaluate(plan, sentAll(at), events)
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
	if results[ProbeIPv6].Status != StatusSkip || results[ProbeIPv6].Summary != "The virtual test lab is IPv4-only." {
		t.Fatalf("IPv6 = %+v", results[ProbeIPv6])
	}
	if results[ProbeHTTP].Attributed {
		t.Fatal("virtual clients have no device, so nothing is attributed")
	}
	if Settled(evaluated) {
		t.Fatal("a run with failures is not settled; later events may still arrive")
	}
	report := Report{Results: evaluated, Routing: []Finding{{Status: FindingGap}, {Status: FindingOK}}}
	report.Count()
	if report.PassCount != 8 || report.FailCount != 7 || report.SkipCount != 1 || report.GapCount != 1 {
		t.Fatalf("counts = %d/%d/%d gaps %d", report.PassCount, report.FailCount, report.SkipCount, report.GapCount)
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
	for _, name := range []string{first.DNSGatewayName, first.DNSDirectName, first.TLSServerName, first.DoTServerName, first.DoQServerName, first.QUICServerName} {
		if !strings.HasSuffix(name, ".coverage.shakerproxy.test") {
			t.Fatalf("%s is not under the reserved .test domain", name)
		}
	}
}
