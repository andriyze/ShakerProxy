package coverage

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// expectation says which stored events record a probe (match) and which of
// those also show ShakerProxy understood it: proof, such as a parsed DNS
// name, TLS server name or HTTP path, or the expected application protocol.
type expectation struct {
	match    func(Plan, Event) bool
	proof    func(Plan, Event) bool
	protocol string // expected app_protocol; empty when proof alone decides
	label    string // plain name of that protocol for messages
}

var (
	clientPrefix     = netip.MustParsePrefix(ClientCIDR)
	clientIPv6Prefix = netip.MustParsePrefix(ClientIPv6CIDR)
	targetIPv6       = netip.MustParseAddr(TargetIPv6)
)

func fromClient(event Event) bool {
	address, err := netip.ParseAddr(event.SourceIP)
	return err == nil && clientPrefix.Contains(address.Unmap())
}

func toTarget(event Event, port int) bool {
	return event.DestinationIP == TargetIPv4 && (port == 0 || event.DestinationPort == port)
}

// fromClientIPv6 and toTargetIPv6 compare parsed addresses: IPv6 has many
// spellings of one address.
func fromClientIPv6(event Event) bool {
	address, err := netip.ParseAddr(event.SourceIP)
	return err == nil && clientIPv6Prefix.Contains(address)
}

func toTargetIPv6(event Event, port int) bool {
	address, err := netip.ParseAddr(event.DestinationIP)
	return err == nil && address == targetIPv6 && (port == 0 || event.DestinationPort == port)
}

func isProtocol(event Event, protocol string) bool {
	return strings.EqualFold(event.Protocol, protocol)
}

// isICMPv6 accepts each analyzer's name for ICMPv6: Zeek calls it icmp,
// Suricata IPv6-ICMP.
func isICMPv6(event Event) bool {
	for _, name := range []string{"icmp", "icmpv6", "icmp6", "ipv6-icmp"} {
		if isProtocol(event, name) {
			return true
		}
	}
	return false
}

func sameName(left, right string) bool {
	return strings.EqualFold(strings.TrimSuffix(left, "."), strings.TrimSuffix(right, "."))
}

var expectations = map[string]expectation{
	ProbeDNSGateway: {
		match: func(p Plan, e Event) bool { return fromClient(e) && sameName(e.DNSQuery, p.DNSGatewayName) },
		proof: func(p Plan, e Event) bool { return sameName(e.DNSQuery, p.DNSGatewayName) },
		label: "DNS",
	},
	ProbeDNSDirect: {
		match: func(p Plan, e Event) bool {
			return fromClient(e) && (sameName(e.DNSQuery, p.DNSDirectName) || toTarget(e, 53))
		},
		proof: func(p Plan, e Event) bool { return sameName(e.DNSQuery, p.DNSDirectName) },
		label: "DNS",
	},
	ProbeDoT: {
		match: func(p Plan, e Event) bool {
			return fromClient(e) && (sameName(e.TLSServerName, p.DoTServerName) || toTarget(e, PortDoT) && isProtocol(e, "tcp"))
		},
		protocol: "dot", label: "DNS over TLS",
	},
	ProbeDoH: {
		match: func(_ Plan, e Event) bool {
			return fromClient(e) && toTarget(e, PortDoH) && (isProtocol(e, "tcp") || sameName(e.TLSServerName, DoHResolverSNI))
		},
		protocol: "doh", label: "DNS over HTTPS",
	},
	ProbeDoQ: {
		match: func(p Plan, e Event) bool {
			return fromClient(e) && (sameName(e.TLSServerName, p.DoQServerName) || toTarget(e, PortDoT) && isProtocol(e, "udp"))
		},
		protocol: "doq", label: "DNS over QUIC",
	},
	ProbeHTTP: {
		match: func(p Plan, e Event) bool {
			return fromClient(e) && (strings.HasPrefix(e.HTTPPath, p.HTTPPath) || toTarget(e, PortHTTP) && isProtocol(e, "tcp"))
		},
		proof:    func(p Plan, e Event) bool { return strings.HasPrefix(e.HTTPPath, p.HTTPPath) },
		protocol: "http", label: "HTTP",
	},
	ProbeHTTPS: {
		match: func(p Plan, e Event) bool {
			return fromClient(e) && (sameName(e.TLSServerName, p.TLSServerName) || toTarget(e, PortHTTPS) && isProtocol(e, "tcp"))
		},
		proof:    func(p Plan, e Event) bool { return sameName(e.TLSServerName, p.TLSServerName) },
		protocol: "tls", label: "TLS",
	},
	ProbeQUIC: {
		match: func(p Plan, e Event) bool {
			return fromClient(e) && (sameName(e.TLSServerName, p.QUICServerName) || toTarget(e, QUICPort) && isProtocol(e, "udp"))
		},
		proof:    func(p Plan, e Event) bool { return sameName(e.TLSServerName, p.QUICServerName) },
		protocol: "quic", label: "QUIC",
	},
	ProbeTCP:  {match: func(_ Plan, e Event) bool { return fromClient(e) && toTarget(e, PortTCPOdd) && isProtocol(e, "tcp") }},
	ProbeUDP:  {match: func(_ Plan, e Event) bool { return fromClient(e) && toTarget(e, PortUDPOdd) && isProtocol(e, "udp") }},
	ProbeICMP: {match: func(_ Plan, e Event) bool { return fromClient(e) && toTarget(e, 0) && isProtocol(e, "icmp") }, protocol: "icmp", label: "ICMP"},
	ProbeSSH:  {match: func(_ Plan, e Event) bool { return fromClient(e) && toTarget(e, PortSSH) }, protocol: "ssh", label: "SSH"},
	ProbeNTP:  {match: func(_ Plan, e Event) bool { return fromClient(e) && toTarget(e, PortNTP) }, protocol: "ntp", label: "NTP"},
	ProbeMDNS: {
		match: func(p Plan, e Event) bool {
			return fromClient(e) && (e.DestinationIP == MDNSGroup || sameName(e.DNSQuery, p.MDNSService))
		},
		proof:    func(p Plan, e Event) bool { return sameName(e.DNSQuery, p.MDNSService) },
		protocol: "mdns", label: "mDNS",
	},
	ProbeSSDP: {match: func(_ Plan, e Event) bool { return fromClient(e) && e.DestinationIP == SSDPGroup }, protocol: "ssdp", label: "SSDP"},
	ProbeDNSIPv6: {
		match: func(p Plan, e Event) bool { return fromClientIPv6(e) && sameName(e.DNSQuery, p.DNSIPv6Name) },
		proof: func(p Plan, e Event) bool { return sameName(e.DNSQuery, p.DNSIPv6Name) },
		label: "DNS",
	},
	ProbeHTTPIPv6: {
		match: func(p Plan, e Event) bool {
			return fromClientIPv6(e) && (strings.HasPrefix(e.HTTPPath, p.HTTPIPv6Path) || toTargetIPv6(e, PortHTTP) && isProtocol(e, "tcp"))
		},
		proof:    func(p Plan, e Event) bool { return strings.HasPrefix(e.HTTPPath, p.HTTPIPv6Path) },
		protocol: "http", label: "HTTP",
	},
	ProbeHTTPSIPv6: {
		match: func(p Plan, e Event) bool {
			return fromClientIPv6(e) && (sameName(e.TLSServerName, p.TLSIPv6ServerName) || toTargetIPv6(e, PortHTTPS) && isProtocol(e, "tcp"))
		},
		proof:    func(p Plan, e Event) bool { return sameName(e.TLSServerName, p.TLSIPv6ServerName) },
		protocol: "tls", label: "TLS",
	},
	ProbeQUICIPv6: {
		match: func(p Plan, e Event) bool {
			return fromClientIPv6(e) && (sameName(e.TLSServerName, p.QUICIPv6ServerName) || toTargetIPv6(e, QUICPort) && isProtocol(e, "udp"))
		},
		proof:    func(p Plan, e Event) bool { return sameName(e.TLSServerName, p.QUICIPv6ServerName) },
		protocol: "quic", label: "QUIC",
	},
	ProbeTCPIPv6: {match: func(_ Plan, e Event) bool {
		return fromClientIPv6(e) && toTargetIPv6(e, PortTCPOdd) && isProtocol(e, "tcp")
	}},
	ProbeUDPIPv6: {match: func(_ Plan, e Event) bool {
		return fromClientIPv6(e) && toTargetIPv6(e, PortUDPOdd) && isProtocol(e, "udp")
	}},
	ProbeICMPv6: {
		match:    func(_ Plan, e Event) bool { return fromClientIPv6(e) && toTargetIPv6(e, 0) && isICMPv6(e) },
		protocol: "icmpv6", label: "ICMPv6",
	},
}

// Evaluate judges every probe against the events stored for the run.
func Evaluate(plan Plan, outcomes []ProbeOutcome, events []Event) []Result {
	byID := make(map[string]ProbeOutcome, len(outcomes))
	for _, outcome := range outcomes {
		byID[outcome.ID] = outcome
	}
	results := make([]Result, 0, len(Probes))
	for _, probe := range Probes {
		results = append(results, evaluateProbe(plan, probe, byID[probe.ID], events))
	}
	return results
}

func evaluateProbe(plan Plan, probe Probe, outcome ProbeOutcome, events []Event) Result {
	result := Result{ID: probe.ID, Name: probe.Name, Category: probe.Category, EventKinds: []string{}}
	expected, known := expectations[probe.ID]
	if !known {
		result.Status, result.Summary = StatusSkip, "No check is defined for this traffic type yet."
		return result
	}
	if outcome.Skipped || outcome.ID == "" {
		result.Status = StatusSkip
		result.Summary = "Not probed in this lab."
		if outcome.Detail != "" {
			result.Summary = outcome.Detail
		}
		return result
	}
	if !outcome.Sent {
		result.Status = StatusFail
		result.Summary = "The virtual client could not send this traffic, so nothing could be seen."
		result.Missing = strings.TrimSpace("probe did not run: " + outcome.Detail)
		return result
	}
	kinds := map[string]bool{}
	protocols := map[string]bool{}
	proven := false
	var first time.Time
	for _, event := range events {
		if !expected.match(plan, event) {
			continue
		}
		kinds[event.Kind] = true
		if expected.proof != nil && expected.proof(plan, event) {
			proven = true
		}
		if event.AppProtocol != "" {
			protocols[strings.ToLower(event.AppProtocol)] = true
		}
		if event.DeviceID != "" {
			result.Attributed = true
		}
		arrived := event.ReceivedAt
		if arrived.IsZero() {
			arrived = event.OccurredAt
		}
		if first.IsZero() || arrived.Before(first) {
			first = arrived
		}
	}
	result.EventKinds = sortedKeys(kinds)
	if len(kinds) == 0 {
		result.Status = StatusFail
		result.Summary = fmt.Sprintf("Not recorded: no event shows this %s traffic.", strings.ToLower(probe.Name))
		result.Missing = "no stored event for this traffic"
		return result
	}
	if !outcome.SentAt.IsZero() && !first.IsZero() {
		result.LatencyMS = max(0, first.Sub(outcome.SentAt).Milliseconds())
	}
	names := sortedKeys(protocols)
	if expected.protocol != "" && protocols[expected.protocol] {
		result.AppProtocol = expected.protocol
	} else if len(names) > 0 {
		result.AppProtocol = names[0]
	}
	if expected.protocol != "" && protocols[expected.protocol] {
		proven = true
	}
	if expected.proof == nil && expected.protocol == "" {
		proven = true // any record proves a plain transport probe
	}
	if !proven {
		result.Status = StatusFail
		got := "without a protocol name"
		if len(names) > 0 {
			got = "as " + strings.Join(names, ", ")
		}
		result.Summary = fmt.Sprintf("Recorded (%s) but not identified as %s: it shows %s.", strings.Join(result.EventKinds, ", "), expected.label, got)
		result.Missing = expected.label + " is not recognised"
		return result
	}
	result.Status = StatusPass
	result.Summary = fmt.Sprintf("Seen as %s after %s.", strings.Join(result.EventKinds, ", "), latencyText(result.LatencyMS))
	return result
}

func latencyText(milliseconds int64) string {
	if milliseconds <= 0 {
		return "under a second"
	}
	if milliseconds < 1000 {
		return fmt.Sprintf("%d ms", milliseconds)
	}
	return fmt.Sprintf("%.1f s", float64(milliseconds)/1000)
}

func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Settled reports whether waiting longer cannot change the result: every
// probe that ran has passed.
func Settled(results []Result) bool {
	for _, result := range results {
		if result.Status == StatusFail {
			return false
		}
	}
	return true
}
