package devicereport

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/domainclass"
	"shakerproxy.dev/shakerproxy/internal/ingest"
	"shakerproxy.dev/shakerproxy/internal/protocolclass"
	"shakerproxy.dev/shakerproxy/internal/testsession"
)

const (
	MaxDomains         = 500
	MaxProtocols       = 256
	MaxHostList        = 50
	MaxOldVersionHosts = 20
	maxEvidenceLines   = 10
	maxFlowSamples     = 8
	// opaqueMinimumBytes avoids flagging tiny samples; a report must see at
	// least this much traffic before an opaque share is meaningful.
	opaqueMinimumBytes = 64 << 10
)

// Input is everything needed to build one report.
type Input struct {
	GeneratedAt time.Time
	Device      Device
	Session     *testsession.Session
	CATrust     CATrust
	Activity    ingest.DeviceActivity
}

// flowSample is bounded per-protocol evidence used by findings.
type flowSample struct {
	Peer       string
	ServerPort int
	Transport  string
	Inbound    bool
	Flows      int64
	Bytes      int64
	Evidence   protocolclass.Evidence
	LastSeen   time.Time
}

type protocolUsage struct {
	Protocol
	samples []flowSample
}

// analysis is the intermediate, evidence-carrying view shared by the report
// sections and the finding rules.
type analysis struct {
	input       Input
	protocols   []protocolUsage
	totalBytes  int64
	opaqueBytes int64
}

// Build computes a report. It never fails: missing sensors simply produce
// empty sections, and findings are only raised from observed evidence.
func Build(input Input) Report {
	activity := input.Activity
	a := analysis{input: input}
	a.classifyFlows()
	report := Report{
		Schema:      Schema,
		GeneratedAt: input.GeneratedAt.UTC(),
		Device:      normalizeDevice(input.Device),
		WindowStart: activity.Start.UTC(),
		WindowEnd:   activity.End.UTC(),
		Session:     input.Session,
		CATrust:     NormalizeCATrust(string(input.CATrust)),
		Totals:      a.totals(),
		Protocols:   make([]Protocol, 0, len(a.protocols)),
		Truncated:   activity.Truncated,
	}
	report.Domains, report.Truncated = a.domains(report.Truncated)
	for _, usage := range a.protocols {
		report.Protocols = append(report.Protocols, usage.Protocol)
	}
	report.TLS = a.tls()
	report.HTTP = a.http()
	report.Findings = a.findings(report)
	report.Summary = reportSummary(report)
	return report
}

func normalizeDevice(device Device) Device {
	if device.Addresses == nil {
		device.Addresses = []string{}
	}
	if device.HardwareAddresses == nil {
		device.HardwareAddresses = []string{}
	}
	return device
}

// preferredFlowSource picks one connection sensor so bytes and flows are
// not double counted when Zeek and Suricata both observe the same traffic.
func preferredFlowSource(counts ingest.DeviceActivityCounts) ingest.Source {
	switch {
	case counts.ZeekConnections == 0 && counts.SuricataFlows == 0:
		return ingest.SourceMitmproxy
	case counts.ZeekConnections >= counts.SuricataFlows:
		return ingest.SourceZeek
	default:
		return ingest.SourceSuricata
	}
}

func (a *analysis) classifyFlows() {
	source := preferredFlowSource(a.input.Activity.Counts)
	// The interceptor knows which server ports it decrypted; carry that onto
	// the passive sensor's connections so decrypted HTTPS reads DECRYPTED.
	intercepted := map[string]bool{}
	for _, group := range a.input.Activity.FlowGroups {
		if group.Source == ingest.SourceMitmproxy && group.Intercepted {
			intercepted[flowKey(group)] = true
		}
	}
	byID := map[string]int{}
	for _, group := range a.input.Activity.FlowGroups {
		if group.Source != source {
			continue
		}
		classification := protocolclass.Classify(protocolclass.Observation{
			Transport: group.Transport, Service: group.Service, ServerPort: group.ServerPort,
			ClientPort: group.ClientPort, Intercepted: group.Intercepted || intercepted[flowKey(group)],
		})
		index, ok := byID[classification.Protocol]
		if !ok {
			if len(a.protocols) >= MaxProtocols {
				continue
			}
			index = len(a.protocols)
			byID[classification.Protocol] = index
			a.protocols = append(a.protocols, protocolUsage{Protocol: Protocol{
				Protocol: classification.Protocol, Label: classification.Label, Category: string(classification.Category),
				Visibility: string(classification.Visibility), Evidence: string(classification.Evidence), Exotic: classification.Exotic,
			}})
		}
		usage := &a.protocols[index]
		usage.Flows += group.Flows
		usage.Bytes += group.Bytes
		if evidenceRank(classification.Evidence) > evidenceRank(protocolclass.Evidence(usage.Evidence)) {
			usage.Evidence = string(classification.Evidence)
		}
		if classification.Visibility == protocolclass.VisibilityDecrypted {
			usage.Visibility = string(protocolclass.VisibilityDecrypted)
		}
		if len(usage.samples) < maxFlowSamples {
			usage.samples = append(usage.samples, flowSample{
				Peer: group.SamplePeer, ServerPort: group.ServerPort, Transport: group.Transport, Inbound: group.Inbound,
				Flows: group.Flows, Bytes: group.Bytes, Evidence: classification.Evidence, LastSeen: group.LastSeen,
			})
		}
		a.totalBytes += group.Bytes
		if classification.Visibility == protocolclass.VisibilityOpaque {
			a.opaqueBytes += group.Bytes
		}
	}
	sort.SliceStable(a.protocols, func(i, j int) bool {
		if a.protocols[i].Flows != a.protocols[j].Flows {
			return a.protocols[i].Flows > a.protocols[j].Flows
		}
		return a.protocols[i].Protocol.Protocol < a.protocols[j].Protocol.Protocol
	})
}

func flowKey(group ingest.DeviceFlowGroup) string {
	return fmt.Sprintf("%s/%d", group.Transport, group.ServerPort)
}

func evidenceRank(value protocolclass.Evidence) int {
	switch value {
	case protocolclass.EvidenceAnalyzer:
		return 3
	case protocolclass.EvidencePort:
		return 2
	case protocolclass.EvidenceUnclassified:
		return 1
	}
	return 0
}

func (a *analysis) totals() Totals {
	counts := a.input.Activity.Counts
	totals := Totals{
		Events:         counts.Events,
		DNSQueries:     max(counts.ZeekDNS, counts.SuricataDNS, counts.ForwarderDNS) + counts.EncryptedDNSDetections,
		TLSConnections: max(counts.ZeekTLS, counts.SuricataTLS, counts.InterceptorTLS),
		HTTPRequests:   max(counts.InterceptorHTTPRequests-counts.InterceptorCleartextRequests, 0) + cleartextRequests(counts),
		Alerts:         counts.Alerts,
	}
	switch preferredFlowSource(counts) {
	case ingest.SourceZeek:
		totals.Flows, totals.Bytes = counts.ZeekConnections, counts.ZeekConnectionBytes
	case ingest.SourceSuricata:
		totals.Flows, totals.Bytes = counts.SuricataFlows, counts.SuricataFlowBytes
	default:
		for _, usage := range a.protocols {
			totals.Flows += usage.Flows
			totals.Bytes += usage.Bytes
		}
	}
	return totals
}

func cleartextRequests(counts ingest.DeviceActivityCounts) int64 {
	return max(counts.ZeekHTTP, counts.SuricataHTTP, counts.InterceptorCleartextRequests)
}

// reportableDomain excludes names that are not remote services: IP
// literals, single-label names, mDNS (.local), and reverse-DNS (.arpa).
func reportableDomain(name string) bool {
	if name == "" || !strings.Contains(name, ".") {
		return false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	for _, suffix := range []string{".local", ".arpa", ".localdomain", ".lan", ".home.arpa", ".internal"} {
		if strings.HasSuffix(name, suffix) {
			return false
		}
	}
	return true
}

func (a *analysis) domains(truncated bool) ([]Domain, bool) {
	index := map[string]int{}
	domains := []Domain{}
	sources := map[string]map[string]bool{}
	for _, observation := range a.input.Activity.Domains {
		if !reportableDomain(observation.Domain) {
			continue
		}
		position, ok := index[observation.Domain]
		if !ok {
			classification := domainclass.Classify(observation.Domain)
			position = len(domains)
			index[observation.Domain] = position
			domains = append(domains, Domain{
				Domain: observation.Domain, RegistrableDomain: classification.RegistrableDomain,
				Organization: classification.Organization, Category: string(classification.Category),
				FirstSeen: observation.FirstSeen, LastSeen: observation.LastSeen,
			})
			sources[observation.Domain] = map[string]bool{}
		}
		item := &domains[position]
		item.Events += observation.Events
		if observation.FirstSeen.Before(item.FirstSeen) {
			item.FirstSeen = observation.FirstSeen
		}
		if observation.LastSeen.After(item.LastSeen) {
			item.LastSeen = observation.LastSeen
		}
		sources[observation.Domain][observation.Source] = true
	}
	for position := range domains {
		item := &domains[position]
		item.Sources = []string{}
		for _, source := range []string{ingest.DeviceDomainSourceDNS, ingest.DeviceDomainSourceTLS, ingest.DeviceDomainSourceHTTP} {
			if sources[item.Domain][source] {
				item.Sources = append(item.Sources, source)
			}
		}
		if item.RegistrableDomain == "" {
			item.RegistrableDomain = item.Domain
		}
		if item.Category == "" {
			item.Category = string(domainclass.CategoryUnknown)
		}
	}
	sort.SliceStable(domains, func(i, j int) bool {
		if domains[i].Events != domains[j].Events {
			return domains[i].Events > domains[j].Events
		}
		return domains[i].Domain < domains[j].Domain
	})
	if len(domains) > MaxDomains {
		domains, truncated = domains[:MaxDomains], true
	}
	return domains, truncated
}

func (a *analysis) tls() TLS {
	counts := a.input.Activity.Counts
	result := TLS{
		Intercepted: counts.TLSIntercepted, Bypassed: counts.TLSBypassed, Failed: counts.TLSFailed,
		PinningSuspected: counts.TLSPinningSuspected, FailedHosts: []string{}, InterceptedHosts: []string{},
		OldVersions: []OldTLSVersion{},
	}
	result.FailedHosts = a.tlsHosts("FAILED")
	result.InterceptedHosts = a.tlsHosts("INTERCEPTED")
	versions := map[string][]string{}
	order := []string{}
	for _, item := range a.input.Activity.TLSVersions {
		if _, ok := versions[item.Version]; !ok {
			order = append(order, item.Version)
			versions[item.Version] = []string{}
		}
		host := item.Host
		if host == "" {
			host = "(no server name)"
		}
		if len(versions[item.Version]) < MaxOldVersionHosts && !contains(versions[item.Version], host) {
			versions[item.Version] = append(versions[item.Version], host)
		}
	}
	sort.Strings(order)
	for _, version := range order {
		hosts := versions[version]
		sort.Strings(hosts)
		result.OldVersions = append(result.OldVersions, OldTLSVersion{Version: version, Hosts: hosts})
	}
	return result
}

func (a *analysis) tlsHosts(state string) []string {
	hosts := []string{}
	for _, item := range a.input.Activity.TLSHosts {
		if item.State != state || item.Host == "" || contains(hosts, item.Host) {
			continue
		}
		hosts = append(hosts, item.Host)
		if len(hosts) == MaxHostList {
			break
		}
	}
	sort.Strings(hosts)
	return hosts
}

func (a *analysis) http() HTTP {
	activity := a.input.Activity
	counts := activity.Counts
	result := HTTP{
		Requests:          max(counts.InterceptorHTTPRequests-counts.InterceptorCleartextRequests, 0) + cleartextRequests(counts),
		CleartextRequests: cleartextRequests(counts),
	}
	hosts := map[string]bool{}
	for _, item := range activity.Domains {
		if item.Source == ingest.DeviceDomainSourceHTTP {
			hosts[item.Domain] = true
		}
	}
	result.Hosts = int64(len(hosts))
	// Decrypted HTTPS is seen only by the interceptor; cleartext HTTP may be
	// seen by every sensor, so take the largest cleartext count.
	decrypted := map[string]int64{}
	cleartext := map[ingest.Source]map[string]int64{}
	for _, item := range activity.HTTPStatus {
		if !item.Cleartext {
			decrypted[item.Class] += item.Count
			continue
		}
		if cleartext[item.Source] == nil {
			cleartext[item.Source] = map[string]int64{}
		}
		cleartext[item.Source][item.Class] += item.Count
	}
	class := func(name string) int64 {
		return decrypted[name] + max(cleartext[ingest.SourceZeek][name], cleartext[ingest.SourceSuricata][name], cleartext[ingest.SourceMitmproxy][name])
	}
	result.StatusClasses = StatusClasses{C2xx: class("2xx"), C3xx: class("3xx"), C4xx: class("4xx"), C5xx: class("5xx")}
	return result
}

func reportSummary(report Report) string {
	name := report.Device.FriendlyName
	if name == "" {
		name = "This device"
	}
	if report.Totals.Events == 0 {
		return fmt.Sprintf("%s: no traffic was recorded in this time range. Check that the device is connected to the lab network.", name)
	}
	parts := []string{fmt.Sprintf("%s contacted %s", name, plural(int64(len(report.Domains)), "domain", "domains"))}
	if len(report.Protocols) > 0 {
		labels := []string{}
		for _, protocol := range report.Protocols {
			if len(labels) == 3 {
				break
			}
			labels = append(labels, protocol.Label)
		}
		parts[0] += fmt.Sprintf(" using %s (%s)", plural(int64(len(report.Protocols)), "protocol", "protocols"), strings.Join(labels, ", "))
	}
	if len(report.Findings) == 0 {
		parts = append(parts, "no security findings")
	} else {
		counts := map[Severity]int{}
		for _, finding := range report.Findings {
			counts[finding.Severity]++
		}
		details := []string{}
		for _, severity := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo} {
			if counts[severity] > 0 {
				details = append(details, fmt.Sprintf("%d %s", counts[severity], strings.ToLower(string(severity))))
			}
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", plural(int64(len(report.Findings)), "finding", "findings"), strings.Join(details, ", ")))
	}
	summary := strings.Join(parts, "; ") + "."
	if report.CATrust == CATrustUnknown && report.TLS.Intercepted > 0 {
		summary += " HTTPS was decrypted: record whether the ShakerProxy CA is installed on the device to check certificate validation."
	}
	return summary
}

func plural(count int64, singular, pluralForm string) string {
	if count == 1 {
		return "1 " + singular
	}
	return fmt.Sprintf("%d %s", count, pluralForm)
}

func contains(items []string, wanted string) bool {
	for _, item := range items {
		if item == wanted {
			return true
		}
	}
	return false
}

// FormatBytes renders a byte count in plain units (B, KB, MB, GB).
func FormatBytes(value int64) string {
	switch {
	case value >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(value)/float64(1<<30))
	case value >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(value)/float64(1<<20))
	case value >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(value)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", value)
	}
}
