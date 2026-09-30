package devicereport

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/protocolclass"
)

// Finding IDs are stable so comparisons can report new and resolved findings.
const (
	FindingAcceptsUntrustedCertificates = "accepts-untrusted-certificates"
	FindingCleartextHTTP                = "cleartext-http"
	FindingInsecureRemoteAccess         = "insecure-remote-access"
	FindingOutdatedTLS                  = "outdated-tls"
	FindingEncryptedDNSBypass           = "encrypted-dns-bypass"
	FindingVPNOrTunnel                  = "vpn-or-tunnel"
	FindingOpaqueTraffic                = "opaque-traffic"
	FindingCertificatePinning           = "certificate-pinning"
	FindingExoticProtocols              = "exotic-protocols"
	FindingAlerts                       = "alerts"
	FindingExposedServices              = "exposed-services"
)

var insecureRemoteAccessProtocols = map[string]bool{"telnet": true, "ftp": true, "tftp": true, "vnc": true}

var encryptedDNSProtocols = map[string]bool{"dot": true, "doq": true, "doh": true}

// findings evaluates every rule. Each rule fires only on observed evidence
// and attaches that evidence; none infers behaviour that was not seen.
func (a *analysis) findings(report Report) []Finding {
	rules := []func(Report) (Finding, bool){
		a.acceptsUntrustedCertificates,
		a.cleartextHTTP,
		a.insecureRemoteAccess,
		a.exposedServices,
		a.outdatedTLS,
		a.encryptedDNSBypass,
		a.vpnOrTunnel,
		a.opaqueTraffic,
		a.certificatePinning,
		a.exoticProtocols,
		a.alerts,
	}
	findings := []Finding{}
	for _, rule := range rules {
		if finding, ok := rule(report); ok {
			findings = append(findings, finding)
		}
	}
	sort.SliceStable(findings, func(i, j int) bool {
		left, right := SeverityRank(findings[i].Severity), SeverityRank(findings[j].Severity)
		if left != right {
			return left > right
		}
		return findings[i].ID < findings[j].ID
	})
	return findings
}

func (a *analysis) acceptsUntrustedCertificates(report Report) (Finding, bool) {
	if report.CATrust != CATrustNotInstalled || a.input.Activity.Counts.TLSIntercepted == 0 {
		return Finding{}, false
	}
	evidence := []string{}
	total := 0
	for _, item := range a.input.Activity.TLSHosts {
		if item.State != "INTERCEPTED" {
			continue
		}
		total++
		host := item.Host
		if host == "" {
			host = "(no server name)"
		}
		evidence = append(evidence, fmt.Sprintf("%s at %s", host, timestamp(item.FirstSeen)))
	}
	if len(evidence) == 0 {
		evidence = append(evidence, fmt.Sprintf("%d decrypted HTTPS connections", a.input.Activity.Counts.TLSIntercepted))
	}
	return Finding{
		ID:       FindingAcceptsUntrustedCertificates,
		Severity: SeverityCritical,
		Title:    "Device accepts untrusted certificates",
		Detail: fmt.Sprintf("ShakerProxy decrypted %s from this device even though the ShakerProxy certificate authority is not installed on it. "+
			"The device (or an app on it) does not check server certificates, so anyone on the network path can read and change its encrypted traffic, including logins and tokens.",
			plural(a.input.Activity.Counts.TLSIntercepted, "HTTPS connection", "HTTPS connections")),
		Recommendation: "Treat this as a critical vulnerability (improper certificate validation, CWE-295) and report it to the vendor with the listed hosts. Re-test after the fix; the finding should disappear.",
		Evidence:       limitEvidence(evidence, total),
	}, true
}

func (a *analysis) cleartextHTTP(Report) (Finding, bool) {
	activity := a.input.Activity
	evidence := []string{}
	total := 0
	public := false
	var requests int64
	for _, item := range activity.CleartextHTTP {
		total++
		requests += item.Requests
		if !privateDestination(item.Host, item.SampleAddress) {
			public = true
		}
		evidence = append(evidence, fmt.Sprintf("%s — %s, first at %s", item.Host, plural(item.Requests, "request", "requests"), timestamp(item.FirstSeen)))
	}
	if total == 0 {
		// Fall back to connections an analyzer confirmed as HTTP.
		for _, usage := range a.protocols {
			if usage.Protocol.Protocol != "http" {
				continue
			}
			for _, sample := range usage.samples {
				if sample.Evidence != protocolclass.EvidenceAnalyzer {
					continue
				}
				total++
				requests += sample.Flows
				if !privateDestination(sample.Peer, sample.Peer) {
					public = true
				}
				evidence = append(evidence, fmt.Sprintf("HTTP %s (%s)", flowDescription(sample), plural(sample.Flows, "connection", "connections")))
			}
		}
	}
	if total == 0 {
		return Finding{}, false
	}
	severity := SeverityLow
	scope := "on the local network"
	if public {
		severity = SeverityMedium
		scope = "including internet hosts"
	}
	return Finding{
		ID:       FindingCleartextHTTP,
		Severity: severity,
		Title:    "Device sends unencrypted HTTP",
		Detail: fmt.Sprintf("The device made %s without encryption to %s, %s. Anyone on the network path can read or change this traffic, including credentials, tokens, personal data, or firmware downloads it carries.",
			plural(requests, "HTTP request", "HTTP requests"), plural(int64(total), "host", "hosts"), scope),
		Recommendation: "Open these requests in Traffic (search http.host:<host>) and check what they carry. Ask the vendor to move these endpoints to HTTPS, especially anything with credentials, personal data, or software updates.",
		Evidence:       limitEvidence(evidence, total),
	}, true
}

func (a *analysis) insecureRemoteAccess(Report) (Finding, bool) {
	evidence := []string{}
	total, inbound := 0, 0
	analyzerConfirmed := false
	labels := []string{}
	for _, usage := range a.protocols {
		if !insecureRemoteAccessProtocols[usage.Protocol.Protocol] {
			continue
		}
		labels = append(labels, usage.Label)
		for _, sample := range usage.samples {
			total++
			if sample.Inbound {
				inbound++
			}
			if sample.Evidence == protocolclass.EvidenceAnalyzer {
				analyzerConfirmed = true
			}
			evidence = append(evidence, fmt.Sprintf("%s %s (%s, %s)", usage.Label, flowDescription(sample), plural(sample.Flows, "connection", "connections"), evidenceNote(sample.Evidence)))
		}
	}
	if total == 0 {
		return Finding{}, false
	}
	severity := SeverityMedium
	if analyzerConfirmed || inbound > 0 {
		// A device that accepts these connections is itself the exposure.
		severity = SeverityHigh
	}
	title := "Device uses insecure remote-access or file-transfer protocols"
	detail := fmt.Sprintf("The device used %s. These protocols send data, often including passwords, without encryption, and are a common way into IoT devices.", strings.Join(labels, ", "))
	if inbound == total {
		title = "Device accepts insecure remote-access or file-transfer connections"
		detail = fmt.Sprintf("Other hosts connected to the device over %s. The device runs a service that sends data, often including passwords, without encryption — a common way into IoT devices.", strings.Join(labels, ", "))
	}
	return Finding{
		ID:             FindingInsecureRemoteAccess,
		Severity:       severity,
		Title:          title,
		Detail:         detail,
		Recommendation: "Disable these services on the device, or ask the vendor to replace them with SSH, SFTP, or HTTPS. If the device accepts these connections, make sure they are not reachable from untrusted networks.",
		Evidence:       limitEvidence(evidence, total),
	}, true
}

// exposedServices lists the services other hosts connected to on the device:
// its observed open ports. It is informational; insecure services also raise
// their own finding.
func (a *analysis) exposedServices(Report) (Finding, bool) {
	evidence := []string{}
	total := 0
	for _, usage := range a.protocols {
		for _, sample := range usage.samples {
			if !sample.Inbound {
				continue
			}
			total++
			evidence = append(evidence, fmt.Sprintf("%s %s (%s, %s)", usage.Label, flowDescription(sample), plural(sample.Flows, "connection", "connections"), evidenceNote(sample.Evidence)))
		}
	}
	if total == 0 {
		return Finding{}, false
	}
	return Finding{
		ID:             FindingExposedServices,
		Severity:       SeverityInfo,
		Title:          "Services the device accepts connections on",
		Detail:         "Other hosts on the lab network or the internet connected to these ports on the device, so the device is listening on them.",
		Recommendation: "Check that every listed service is expected and needed, and that it requires authentication. Close or firewall anything the product does not need.",
		Evidence:       limitEvidence(evidence, total),
	}, true
}

func (a *analysis) outdatedTLS(Report) (Finding, bool) {
	evidence := []string{}
	total := 0
	severity := SeverityMedium
	for _, item := range a.input.Activity.TLSVersions {
		total++
		if strings.HasPrefix(item.Version, "SSL") {
			severity = SeverityHigh
		}
		host := item.Host
		if host == "" {
			host = "(no server name)"
		}
		evidence = append(evidence, fmt.Sprintf("%s with %s (%s, last at %s)", item.Version, host, plural(item.Events, "handshake", "handshakes"), timestamp(item.LastSeen)))
	}
	if total == 0 {
		return Finding{}, false
	}
	return Finding{
		ID:             FindingOutdatedTLS,
		Severity:       severity,
		Title:          "Device uses outdated TLS versions",
		Detail:         "Some of the device's encrypted connections used SSL, TLS 1.0, or TLS 1.1. These versions have known weaknesses and are disabled by modern browsers and servers.",
		Recommendation: "Ask the vendor to require TLS 1.2 or newer on both the device and its servers. Check whether the listed servers still accept the old version, which also puts other clients at risk.",
		Evidence:       limitEvidence(evidence, total),
	}, true
}

func (a *analysis) encryptedDNSBypass(Report) (Finding, bool) {
	evidence := []string{}
	total := 0
	for _, item := range a.input.Activity.EncryptedDNS {
		total++
		host := item.Host
		if host == "" {
			host = "an unnamed resolver"
		}
		evidence = append(evidence, fmt.Sprintf("DNS over %s via %s (%s, last at %s)", encryptedDNSTransportLabel(item.Transport), host, plural(item.Events, "lookup", "lookups"), timestamp(item.LastSeen)))
	}
	for _, usage := range a.protocols {
		if !encryptedDNSProtocols[usage.Protocol.Protocol] {
			continue
		}
		for _, sample := range usage.samples {
			total++
			evidence = append(evidence, fmt.Sprintf("%s %s (%s, %s)", usage.Label, flowDescription(sample), plural(sample.Flows, "connection", "connections"), evidenceNote(sample.Evidence)))
		}
	}
	if total == 0 {
		return Finding{}, false
	}
	return Finding{
		ID:             FindingEncryptedDNSBypass,
		Severity:       SeverityMedium,
		Title:          "Device uses encrypted DNS that bypasses the lab resolver",
		Detail:         "The device looked up names with DNS over HTTPS, TLS, or QUIC instead of the lab's DNS server. ShakerProxy cannot see or block those lookups, so the domain list may be incomplete and domain blocking will not work for this device.",
		Recommendation: "To see every lookup, turn on encrypted-DNS blocking in Policy → DNS & HTTPS and re-run the test; most devices fall back to plain DNS. If the device stops working instead, it hard-codes its resolver, which is worth reporting to the vendor.",
		Evidence:       limitEvidence(evidence, total),
	}, true
}

func (a *analysis) vpnOrTunnel(Report) (Finding, bool) {
	evidence := []string{}
	total := 0
	analyzerConfirmed := false
	for _, usage := range a.protocols {
		if usage.Category != string(protocolclass.CategoryVPNTunnel) {
			continue
		}
		for _, sample := range usage.samples {
			total++
			if sample.Evidence == protocolclass.EvidenceAnalyzer {
				analyzerConfirmed = true
			}
			evidence = append(evidence, fmt.Sprintf("%s %s (%s, %s, %s)", usage.Label, flowDescription(sample), plural(sample.Flows, "connection", "connections"), FormatBytes(sample.Bytes), evidenceNote(sample.Evidence)))
		}
	}
	if total == 0 {
		return Finding{}, false
	}
	severity := SeverityLow
	if analyzerConfirmed {
		severity = SeverityMedium
	}
	return Finding{
		ID:             FindingVPNOrTunnel,
		Severity:       severity,
		Title:          "Device opens a VPN or tunnel",
		Detail:         "The device sent traffic through a VPN, proxy, or tunnel. Traffic inside the tunnel cannot be inspected or filtered by ShakerProxy, and a tunnel can carry remote access into your network.",
		Recommendation: "Confirm with the vendor what the tunnel is for (remote support, cloud relay, telemetry). If it is not needed, block the destination and check whether the device keeps working.",
		Evidence:       limitEvidence(evidence, total),
	}, true
}

func (a *analysis) opaqueTraffic(Report) (Finding, bool) {
	if a.totalBytes < opaqueMinimumBytes || a.opaqueBytes*4 <= a.totalBytes {
		return Finding{}, false
	}
	type opaque struct {
		label string
		bytes int64
	}
	items := []opaque{}
	for _, usage := range a.protocols {
		if usage.Visibility == string(protocolclass.VisibilityOpaque) && usage.Bytes > 0 {
			items = append(items, opaque{usage.Label, usage.Bytes})
		}
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].bytes > items[j].bytes })
	evidence := make([]string, 0, len(items))
	for _, item := range items {
		evidence = append(evidence, fmt.Sprintf("%s: %s (%d%% of traffic)", item.label, FormatBytes(item.bytes), percent(item.bytes, a.totalBytes)))
	}
	return Finding{
		ID:       FindingOpaqueTraffic,
		Severity: SeverityLow,
		Title:    "A large share of traffic cannot be identified",
		Detail: fmt.Sprintf("%d%% of this device's traffic (%s of %s) used protocols ShakerProxy cannot identify or see into, such as proprietary or tunneled protocols. The report cannot tell you what that data contains.",
			percent(a.opaqueBytes, a.totalBytes), FormatBytes(a.opaqueBytes), FormatBytes(a.totalBytes)),
		Recommendation: "Look up the destinations in Traffic. If they are vendor servers, ask the vendor what the protocol carries. Record a packet capture during the test run for deeper analysis.",
		Evidence:       limitEvidence(evidence, len(items)),
	}, true
}

func (a *analysis) certificatePinning(Report) (Finding, bool) {
	evidence := []string{}
	total := 0
	for _, item := range a.input.Activity.TLSHosts {
		if !item.PinningSuspected {
			continue
		}
		total++
		host := item.Host
		if host == "" {
			host = "(no server name)"
		}
		evidence = append(evidence, fmt.Sprintf("%s (%s, last at %s)", host, plural(item.Events, "failed handshake", "failed handshakes"), timestamp(item.LastSeen)))
	}
	if total == 0 {
		return Finding{}, false
	}
	return Finding{
		ID:             FindingCertificatePinning,
		Severity:       SeverityInfo,
		Title:          "Device appears to pin certificates",
		Detail:         "Connections to these hosts failed when ShakerProxy tried to decrypt them, in a way that suggests certificate pinning or a private trust store. That is good security practice, but ShakerProxy cannot inspect this traffic.",
		Recommendation: "No action is needed for security. To inspect this traffic, exclude these hosts from decryption in Policy → DNS & HTTPS, or test a build without pinning.",
		Evidence:       limitEvidence(evidence, total),
	}, true
}

func (a *analysis) exoticProtocols(Report) (Finding, bool) {
	evidence := []string{}
	labels := []string{}
	for _, usage := range a.protocols {
		if !usage.Exotic || usage.Category == string(protocolclass.CategoryUnknown) {
			continue
		}
		labels = append(labels, usage.Label)
		evidence = append(evidence, fmt.Sprintf("%s — %s, %s (%s)", usage.Label, plural(usage.Flows, "connection", "connections"), FormatBytes(usage.Bytes), evidenceNote(protocolclass.Evidence(usage.Evidence))))
	}
	if len(evidence) == 0 {
		return Finding{}, false
	}
	return Finding{
		ID:             FindingExoticProtocols,
		Severity:       SeverityInfo,
		Title:          "Device uses uncommon protocols",
		Detail:         fmt.Sprintf("The device used protocols that are unusual on a typical network: %s. They are often legitimate for this kind of device, but each one is extra attack surface worth understanding.", strings.Join(labels, ", ")),
		Recommendation: "Confirm each protocol is expected for this device and documented by the vendor. Open Protocols to see which servers it talked to.",
		Evidence:       limitEvidence(evidence, len(evidence)),
	}, true
}

func (a *analysis) alerts(Report) (Finding, bool) {
	evidence := []string{}
	severity := SeverityLow
	var count int64
	for _, item := range a.input.Activity.Alerts {
		count += item.Count
		if SeverityRank(Severity(item.Severity)) > SeverityRank(severity) {
			severity = Severity(item.Severity)
		}
		evidence = append(evidence, fmt.Sprintf("%s (%s, %s, last at %s)", item.Signature, item.Severity, plural(item.Count, "time", "times"), timestamp(item.LastSeen)))
	}
	if len(evidence) == 0 {
		return Finding{}, false
	}
	return Finding{
		ID:             FindingAlerts,
		Severity:       severity,
		Title:          "Intrusion detection raised alerts",
		Detail:         fmt.Sprintf("Suricata or ShakerProxy detections matched %s on this device's traffic. Each alert is a signature match, not proof of compromise.", plural(count, "alert", "alerts")),
		Recommendation: "Review the alerts in Traffic (search kind:suricata.alert) and check whether the matched traffic is expected for this device.",
		Evidence:       limitEvidence(evidence, len(evidence)),
	}, true
}

func encryptedDNSTransportLabel(transport string) string {
	switch transport {
	case "DOT":
		return "TLS"
	case "DOQ":
		return "QUIC"
	default:
		return "HTTPS"
	}
}

// flowDescription renders one flow sample in plain language, e.g.
// "to 203.0.113.9:23" or "from 10.77.0.5 to the device on port 23".
func flowDescription(sample flowSample) string {
	port := ""
	if sample.ServerPort > 0 {
		port = fmt.Sprintf("%d", sample.ServerPort)
		if sample.Transport != "" {
			port = sample.Transport + "/" + port
		}
	}
	if sample.Inbound {
		from := "another host"
		if sample.Peer != "" {
			from = sample.Peer
		}
		if port == "" {
			return "from " + from + " to the device"
		}
		return "from " + from + " to the device on port " + port
	}
	to := "a remote host"
	if sample.Peer != "" {
		to = sample.Peer
	}
	if port == "" {
		return "to " + to
	}
	if sample.Peer != "" && sample.ServerPort > 0 {
		return fmt.Sprintf("to %s:%d", sample.Peer, sample.ServerPort)
	}
	return "to " + to + " on port " + port
}

func evidenceNote(evidence protocolclass.Evidence) string {
	switch evidence {
	case protocolclass.EvidenceAnalyzer:
		return "identified by protocol analysis"
	case protocolclass.EvidencePort:
		return "identified by port number only"
	default:
		return "unidentified"
	}
}

// privateDestination reports whether a host or address is on a local or
// private network.
func privateDestination(host, address string) bool {
	for _, candidate := range []string{host, address} {
		if parsed, err := netip.ParseAddr(candidate); err == nil {
			parsed = parsed.Unmap()
			return parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() || parsed.IsMulticast()
		}
	}
	return strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".lan") || !strings.Contains(host, ".")
}

func limitEvidence(lines []string, total int) []string {
	if len(lines) > maxEvidenceLines {
		lines = lines[:maxEvidenceLines]
	}
	out := append([]string{}, lines...)
	if total > len(out) {
		out = append(out, fmt.Sprintf("…and %d more", total-len(out)))
	}
	return out
}

func percent(part, whole int64) int {
	if whole <= 0 {
		return 0
	}
	return int((part*100 + whole/2) / whole)
}

func timestamp(value time.Time) string {
	return value.UTC().Format(time.RFC3339)
}
