package devicereport

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/ingest"
)

var (
	reportEnd   = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	reportStart = reportEnd.Add(-24 * time.Hour)
	seenAt      = reportEnd.Add(-2 * time.Hour)
)

const reportDeviceID = "device-0123456789abcdef0123456789abcdef"

func baseActivity() ingest.DeviceActivity {
	return ingest.DeviceActivity{
		Schema: ingest.SchemaVersion, GeneratedAt: reportEnd, DeviceID: reportDeviceID, Start: reportStart, End: reportEnd,
		Domains: []ingest.DeviceDomainObservation{}, FlowGroups: []ingest.DeviceFlowGroup{}, TLSHosts: []ingest.DeviceTLSHost{},
		TLSVersions: []ingest.DeviceTLSVersion{}, CleartextHTTP: []ingest.DeviceHTTPHost{}, HTTPStatus: []ingest.DeviceHTTPStatusCount{},
		Alerts: []ingest.DeviceAlertGroup{}, EncryptedDNS: []ingest.DeviceResolver{},
	}
}

func flow(transport, service string, port int, peer string, flows, bytes int64) ingest.DeviceFlowGroup {
	return ingest.DeviceFlowGroup{Source: ingest.SourceZeek, Transport: transport, Service: service, ServerPort: port, Flows: flows, Bytes: bytes, Peers: 1, SamplePeer: peer, FirstSeen: seenAt, LastSeen: seenAt}
}

func withFlows(activity ingest.DeviceActivity, groups ...ingest.DeviceFlowGroup) ingest.DeviceActivity {
	activity.FlowGroups = append(activity.FlowGroups, groups...)
	for _, group := range groups {
		if group.Source == ingest.SourceZeek {
			activity.Counts.ZeekConnections += group.Flows
			activity.Counts.ZeekConnectionBytes += group.Bytes
		}
		activity.Counts.Events += group.Flows
	}
	return activity
}

func build(activity ingest.DeviceActivity, trust CATrust) Report {
	return Build(Input{GeneratedAt: reportEnd, Device: Device{DeviceID: reportDeviceID, FriendlyName: "Living room TV"}, CATrust: trust, Activity: activity})
}

func findingByID(report Report, id string) (Finding, bool) {
	for _, finding := range report.Findings {
		if finding.ID == id {
			return finding, true
		}
	}
	return Finding{}, false
}

func TestEmptyActivityProducesAnEmptyReportWithoutFindings(t *testing.T) {
	report := build(baseActivity(), CATrustUnknown)
	if report.Schema != 1 || report.CATrust != CATrustUnknown || len(report.Findings) != 0 || len(report.Domains) != 0 || len(report.Protocols) != 0 {
		t.Fatalf("unexpected empty report: %#v", report)
	}
	if !strings.Contains(report.Summary, "no traffic") {
		t.Fatalf("empty summary does not say so: %q", report.Summary)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"session":null`, `"domains":[]`, `"findings":[]`, `"hardware_addresses":[]`, `"failed_hosts":[]`, `"old_versions":[]`, `"status_classes":{"2xx":0,"3xx":0,"4xx":0,"5xx":0}`, `"ca_trust":"UNKNOWN"`} {
		if !strings.Contains(string(encoded), field) {
			t.Errorf("report JSON lacks %s: %s", field, encoded)
		}
	}
}

func TestTotalsPreferOneConnectionSensorAndAvoidDoubleCounting(t *testing.T) {
	activity := baseActivity()
	activity.Counts = ingest.DeviceActivityCounts{
		Events: 100, ZeekConnections: 10, ZeekConnectionBytes: 1000, SuricataFlows: 9, SuricataFlowBytes: 900,
		ZeekDNS: 20, SuricataDNS: 18, EncryptedDNSDetections: 2, ZeekTLS: 5, SuricataTLS: 6, InterceptorTLS: 4,
		InterceptorHTTPRequests: 7, InterceptorCleartextRequests: 2, ZeekHTTP: 3, SuricataHTTP: 1, Alerts: 4,
	}
	totals := build(activity, CATrustUnknown).Totals
	want := Totals{Events: 100, Flows: 10, Bytes: 1000, DNSQueries: 22, TLSConnections: 6, HTTPRequests: 8, Alerts: 4}
	if totals != want {
		t.Fatalf("totals %#v want %#v", totals, want)
	}
	activity.Counts.ZeekConnections, activity.Counts.ZeekConnectionBytes = 0, 0
	if totals := build(activity, CATrustUnknown).Totals; totals.Flows != 9 || totals.Bytes != 900 {
		t.Fatalf("Suricata fallback totals: %#v", totals)
	}
	activity.Counts.SuricataFlows, activity.Counts.SuricataFlowBytes = 0, 0
	activity.FlowGroups = []ingest.DeviceFlowGroup{{Source: ingest.SourceMitmproxy, Transport: "tcp", Service: "tls", ServerPort: 443, Flows: 3, Bytes: 30, FirstSeen: seenAt, LastSeen: seenAt, Intercepted: true}}
	report := build(activity, CATrustUnknown)
	if report.Totals.Flows != 3 || report.Totals.Bytes != 30 || len(report.Protocols) != 1 || report.Protocols[0].Visibility != "DECRYPTED" {
		t.Fatalf("interceptor-only fallback: %#v %#v", report.Totals, report.Protocols)
	}
}

func TestDomainsMergeSourcesClassifyAndSkipLocalNames(t *testing.T) {
	activity := baseActivity()
	activity.Counts.Events = 10
	observe := func(domain, source string, events int64, first time.Time) ingest.DeviceDomainObservation {
		return ingest.DeviceDomainObservation{Domain: domain, Source: source, Events: events, FirstSeen: first, LastSeen: seenAt}
	}
	activity.Domains = []ingest.DeviceDomainObservation{
		observe("log.samsungacr.com", "dns", 4, seenAt.Add(-time.Hour)),
		observe("log.samsungacr.com", "tls", 3, seenAt),
		observe("api.example.co.uk", "http", 1, seenAt),
		observe("_googlecast._tcp.local", "dns", 9, seenAt),
		observe("23.0.77.10.in-addr.arpa", "dns", 9, seenAt),
		observe("192.0.2.10", "http", 9, seenAt),
		observe("wpad", "dns", 9, seenAt),
	}
	report := build(activity, CATrustUnknown)
	if len(report.Domains) != 2 {
		t.Fatalf("unexpected domains: %#v", report.Domains)
	}
	acr := report.Domains[0]
	if acr.Domain != "log.samsungacr.com" || acr.RegistrableDomain != "samsungacr.com" || acr.Organization != "Samsung" || acr.Category != "telemetry" || acr.Events != 7 || strings.Join(acr.Sources, ",") != "dns,tls" || !acr.FirstSeen.Equal(seenAt.Add(-time.Hour)) {
		t.Fatalf("unexpected merged domain: %#v", acr)
	}
	other := report.Domains[1]
	if other.RegistrableDomain != "example.co.uk" || other.Category != "unknown" || other.Organization != "" {
		t.Fatalf("unknown domain classification: %#v", other)
	}
	if report.HTTP.Hosts != 2 {
		t.Fatalf("HTTP hosts should count every HTTP host including IP literals: %d", report.HTTP.Hosts)
	}
}

func TestHTTPStatusClassesAddInterceptorToOnePassiveSensor(t *testing.T) {
	activity := baseActivity()
	activity.HTTPStatus = []ingest.DeviceHTTPStatusCount{
		{Source: ingest.SourceMitmproxy, Class: "2xx", Count: 5}, {Source: ingest.SourceZeek, Cleartext: true, Class: "2xx", Count: 3},
		{Source: ingest.SourceSuricata, Cleartext: true, Class: "2xx", Count: 2}, {Source: ingest.SourceZeek, Cleartext: true, Class: "4xx", Count: 1},
		{Source: ingest.SourceSuricata, Cleartext: true, Class: "5xx", Count: 2}, {Source: ingest.SourceMitmproxy, Cleartext: true, Class: "2xx", Count: 4},
	}
	classes := build(activity, CATrustUnknown).HTTP.StatusClasses
	// 5 decrypted plus the largest cleartext count (4) — cleartext seen by
	// several sensors is counted once.
	if classes != (StatusClasses{C2xx: 9, C4xx: 1, C5xx: 2}) {
		t.Fatalf("status classes %#v", classes)
	}
}

func TestProtocolsAreClassifiedWithEvidenceAndSorted(t *testing.T) {
	activity := withFlows(baseActivity(),
		flow("tcp", "ssl", 443, "203.0.113.20", 30, 30000),
		flow("tcp", "", 1883, "203.0.113.21", 5, 500),
		flow("tcp", "mqtt", 1883, "203.0.113.21", 2, 200),
		ingest.DeviceFlowGroup{Source: ingest.SourceSuricata, Transport: "tcp", Service: "tls", ServerPort: 443, Flows: 99, Bytes: 1, FirstSeen: seenAt, LastSeen: seenAt},
	)
	report := build(activity, CATrustUnknown)
	if len(report.Protocols) != 2 || report.Protocols[0].Protocol != "tls" || report.Protocols[1].Protocol != "mqtt" {
		t.Fatalf("unexpected protocols: %#v", report.Protocols)
	}
	mqtt := report.Protocols[1]
	if mqtt.Flows != 7 || mqtt.Bytes != 700 || mqtt.Evidence != "ANALYZER" || !mqtt.Exotic || mqtt.Category != "iot-messaging" {
		t.Fatalf("MQTT aggregation should keep the strongest evidence: %#v", mqtt)
	}
}

func TestAcceptsUntrustedCertificatesRequiresNotInstalledAndInterception(t *testing.T) {
	activity := baseActivity()
	activity.Counts.Events, activity.Counts.TLSIntercepted = 2, 2
	activity.TLSHosts = []ingest.DeviceTLSHost{{Host: "api.example.com", State: "INTERCEPTED", Events: 2, FirstSeen: seenAt, LastSeen: seenAt}}
	report := build(activity, CATrustNotInstalled)
	finding, ok := findingByID(report, FindingAcceptsUntrustedCertificates)
	if !ok || finding.Severity != SeverityCritical || len(finding.Evidence) != 1 || finding.Evidence[0] != "api.example.com at 2026-09-29T10:00:00Z" {
		t.Fatalf("missing or wrong finding: %#v", report.Findings)
	}
	if report.Findings[0].ID != FindingAcceptsUntrustedCertificates {
		t.Fatalf("critical finding is not first: %#v", report.Findings)
	}
	for _, trust := range []CATrust{CATrustInstalled, CATrustUnknown} {
		if _, ok := findingByID(build(activity, trust), FindingAcceptsUntrustedCertificates); ok {
			t.Fatalf("finding raised with CA trust %s", trust)
		}
	}
	if !strings.Contains(build(activity, CATrustUnknown).Summary, "record whether the ShakerProxy CA is installed") {
		t.Fatal("unknown CA trust with interception should prompt the tester")
	}
	activity.Counts.TLSIntercepted = 0
	activity.TLSHosts = nil
	if _, ok := findingByID(build(activity, CATrustNotInstalled), FindingAcceptsUntrustedCertificates); ok {
		t.Fatal("finding raised without any interception")
	}
}

func TestCleartextHTTPSeverityDependsOnDestination(t *testing.T) {
	activity := baseActivity()
	activity.CleartextHTTP = []ingest.DeviceHTTPHost{{Host: "192.168.1.20", Requests: 3, SampleAddress: "192.168.1.20", FirstSeen: seenAt, LastSeen: seenAt}}
	finding, ok := findingByID(build(activity, CATrustUnknown), FindingCleartextHTTP)
	if !ok || finding.Severity != SeverityLow || !strings.Contains(finding.Detail, "local network") {
		t.Fatalf("local cleartext HTTP: %#v", finding)
	}
	activity.CleartextHTTP = append(activity.CleartextHTTP, ingest.DeviceHTTPHost{Host: "fw.vendor.example", Requests: 1, SampleAddress: "203.0.113.9", FirstSeen: seenAt, LastSeen: seenAt})
	finding, ok = findingByID(build(activity, CATrustUnknown), FindingCleartextHTTP)
	if !ok || finding.Severity != SeverityMedium || len(finding.Evidence) != 2 {
		t.Fatalf("public cleartext HTTP: %#v", finding)
	}
	// Analyzer-confirmed HTTP connections count when no request metadata exists.
	fallback := withFlows(baseActivity(), flow("tcp", "http", 80, "203.0.113.10", 2, 100))
	if finding, ok := findingByID(build(fallback, CATrustUnknown), FindingCleartextHTTP); !ok || !strings.Contains(finding.Evidence[0], "203.0.113.10:80") {
		t.Fatalf("analyzer HTTP fallback: %#v", finding)
	}
	// A port-80 guess alone is not evidence of HTTP.
	guess := withFlows(baseActivity(), flow("tcp", "", 80, "203.0.113.10", 2, 100))
	if _, ok := findingByID(build(guess, CATrustUnknown), FindingCleartextHTTP); ok {
		t.Fatal("port heuristic alone raised a cleartext HTTP finding")
	}
}

func TestInsecureRemoteAccessDistinguishesAnalyzerFromPortEvidence(t *testing.T) {
	portOnly := withFlows(baseActivity(), flow("tcp", "", 23, "203.0.113.9", 1, 60))
	finding, ok := findingByID(build(portOnly, CATrustUnknown), FindingInsecureRemoteAccess)
	if !ok || finding.Severity != SeverityMedium || !strings.Contains(finding.Evidence[0], "port number only") {
		t.Fatalf("port-only telnet: %#v", finding)
	}
	inbound := flow("tcp", "ftp", 21, "10.77.0.5", 1, 60)
	inbound.Inbound = true
	confirmed := withFlows(baseActivity(), inbound)
	finding, ok = findingByID(build(confirmed, CATrustUnknown), FindingInsecureRemoteAccess)
	if !ok || finding.Severity != SeverityHigh || !strings.Contains(finding.Evidence[0], "from 10.77.0.5 to the device on port tcp/21") {
		t.Fatalf("analyzer-confirmed inbound FTP: %#v", finding)
	}
	if _, ok := findingByID(build(withFlows(baseActivity(), flow("tcp", "ssh", 22, "203.0.113.9", 1, 60)), CATrustUnknown), FindingInsecureRemoteAccess); ok {
		t.Fatal("SSH was reported as insecure remote access")
	}
}

func TestInboundInsecureServiceIsReportedAsExposure(t *testing.T) {
	telnet := flow("tcp", "", 23, "10.77.0.26", 9, 1600)
	telnet.Inbound = true
	report := build(withFlows(baseActivity(), telnet), CATrustUnknown)
	finding, ok := findingByID(report, FindingInsecureRemoteAccess)
	if !ok || finding.Severity != SeverityHigh || !strings.Contains(finding.Title, "accepts") || !strings.Contains(finding.Evidence[0], "from 10.77.0.26 to the device on port tcp/23") {
		t.Fatalf("inbound telnet: %#v", finding)
	}
	exposed, ok := findingByID(report, FindingExposedServices)
	if !ok || exposed.Severity != SeverityInfo || !strings.Contains(exposed.Evidence[0], "Telnet") {
		t.Fatalf("exposed services: %#v", exposed)
	}
	outbound := withFlows(baseActivity(), flow("tcp", "ssh", 22, "203.0.113.9", 1, 60))
	if _, ok := findingByID(build(outbound, CATrustUnknown), FindingExposedServices); ok {
		t.Fatal("outbound connections were reported as exposed services")
	}
}

func TestOutdatedTLSFlagsSSLAsHigh(t *testing.T) {
	activity := baseActivity()
	activity.TLSVersions = []ingest.DeviceTLSVersion{{Version: "TLSv1.0", Host: "legacy.example.com", Events: 2, FirstSeen: seenAt, LastSeen: seenAt}}
	report := build(activity, CATrustUnknown)
	finding, ok := findingByID(report, FindingOutdatedTLS)
	if !ok || finding.Severity != SeverityMedium || len(report.TLS.OldVersions) != 1 || report.TLS.OldVersions[0].Hosts[0] != "legacy.example.com" {
		t.Fatalf("TLS 1.0: %#v %#v", finding, report.TLS)
	}
	activity.TLSVersions = append(activity.TLSVersions, ingest.DeviceTLSVersion{Version: "SSLv3", Events: 1, FirstSeen: seenAt, LastSeen: seenAt})
	if finding, _ := findingByID(build(activity, CATrustUnknown), FindingOutdatedTLS); finding.Severity != SeverityHigh {
		t.Fatalf("SSLv3 severity: %#v", finding)
	}
	if _, ok := findingByID(build(baseActivity(), CATrustUnknown), FindingOutdatedTLS); ok {
		t.Fatal("outdated TLS raised without evidence")
	}
}

func TestEncryptedDNSBypassUsesDetectionsAndDoTFlows(t *testing.T) {
	activity := baseActivity()
	activity.EncryptedDNS = []ingest.DeviceResolver{{Host: "dns.google", Transport: "DOH", Events: 4, FirstSeen: seenAt, LastSeen: seenAt}}
	finding, ok := findingByID(build(activity, CATrustUnknown), FindingEncryptedDNSBypass)
	if !ok || finding.Severity != SeverityMedium || !strings.HasPrefix(finding.Evidence[0], "DNS over HTTPS via dns.google (4 lookups") {
		t.Fatalf("DoH detection: %#v", finding)
	}
	dot := withFlows(baseActivity(), flow("tcp", "", 853, "1.1.1.1", 3, 300))
	if finding, ok := findingByID(build(dot, CATrustUnknown), FindingEncryptedDNSBypass); !ok || !strings.Contains(finding.Evidence[0], "DNS over TLS to 1.1.1.1:853") {
		t.Fatalf("DoT flow: %#v", finding)
	}
	plain := withFlows(baseActivity(), flow("udp", "dns", 53, "10.77.0.1", 3, 300))
	if _, ok := findingByID(build(plain, CATrustUnknown), FindingEncryptedDNSBypass); ok {
		t.Fatal("plain DNS raised an encrypted DNS finding")
	}
}

func TestVPNOrTunnelSeverityFollowsEvidence(t *testing.T) {
	portOnly := withFlows(baseActivity(), flow("udp", "", 51820, "198.51.100.7", 2, 4000))
	finding, ok := findingByID(build(portOnly, CATrustUnknown), FindingVPNOrTunnel)
	if !ok || finding.Severity != SeverityLow {
		t.Fatalf("port-only WireGuard: %#v", finding)
	}
	confirmed := withFlows(baseActivity(), flow("udp", "wireguard", 51821, "198.51.100.7", 2, 4000))
	if finding, ok := findingByID(build(confirmed, CATrustUnknown), FindingVPNOrTunnel); !ok || finding.Severity != SeverityMedium {
		t.Fatalf("analyzer WireGuard: %#v", finding)
	}
	if _, ok := findingByID(build(withFlows(baseActivity(), flow("tcp", "ssl", 443, "203.0.113.1", 2, 4000)), CATrustUnknown), FindingVPNOrTunnel); ok {
		t.Fatal("TLS raised a tunnel finding")
	}
}

func TestOpaqueTrafficNeedsMoreThanAQuarterOfMeaningfulVolume(t *testing.T) {
	opaque := withFlows(baseActivity(), flow("tcp", "ssl", 443, "203.0.113.1", 10, 200<<10), flow("tcp", "", 40000, "203.0.113.2", 5, 100<<10))
	finding, ok := findingByID(build(opaque, CATrustUnknown), FindingOpaqueTraffic)
	if !ok || finding.Severity != SeverityLow || !strings.Contains(finding.Detail, "33%") || !strings.Contains(finding.Evidence[0], "Unidentified TCP") {
		t.Fatalf("opaque share: %#v", finding)
	}
	quarter := withFlows(baseActivity(), flow("tcp", "ssl", 443, "203.0.113.1", 10, 300<<10), flow("tcp", "", 40000, "203.0.113.2", 5, 100<<10))
	if _, ok := findingByID(build(quarter, CATrustUnknown), FindingOpaqueTraffic); ok {
		t.Fatal("exactly 25% opaque raised a finding")
	}
	tiny := withFlows(baseActivity(), flow("tcp", "", 40000, "203.0.113.2", 1, 1000))
	if _, ok := findingByID(build(tiny, CATrustUnknown), FindingOpaqueTraffic); ok {
		t.Fatal("a tiny sample raised an opaque traffic finding")
	}
}

func TestCertificatePinningUsesOnlyExactPinningEvidence(t *testing.T) {
	activity := baseActivity()
	activity.TLSHosts = []ingest.DeviceTLSHost{
		{Host: "pinned.example.com", State: "FAILED", FailureReason: "probable_certificate_pinning_or_custom_trust_store", PinningSuspected: true, Events: 3, FirstSeen: seenAt, LastSeen: seenAt},
		{Host: "generic.example.com", State: "FAILED", FailureReason: "ca_not_trusted_or_pinning", Events: 3, FirstSeen: seenAt, LastSeen: seenAt},
	}
	report := build(activity, CATrustUnknown)
	finding, ok := findingByID(report, FindingCertificatePinning)
	if !ok || finding.Severity != SeverityInfo || len(finding.Evidence) != 1 || !strings.HasPrefix(finding.Evidence[0], "pinned.example.com") {
		t.Fatalf("pinning finding: %#v", finding)
	}
	if strings.Join(report.TLS.FailedHosts, ",") != "generic.example.com,pinned.example.com" {
		t.Fatalf("failed hosts: %#v", report.TLS.FailedHosts)
	}
	activity.TLSHosts = activity.TLSHosts[1:]
	if _, ok := findingByID(build(activity, CATrustUnknown), FindingCertificatePinning); ok {
		t.Fatal("generic CA failure raised a pinning finding")
	}
}

func TestExoticProtocolsListsUncommonButNotUnidentified(t *testing.T) {
	activity := withFlows(baseActivity(), flow("tcp", "mqtt", 1883, "203.0.113.21", 2, 200), flow("udp", "", 40000, "203.0.113.2", 1, 10), flow("tcp", "ssl", 443, "203.0.113.1", 1, 10))
	finding, ok := findingByID(build(activity, CATrustUnknown), FindingExoticProtocols)
	if !ok || finding.Severity != SeverityInfo || len(finding.Evidence) != 1 || !strings.HasPrefix(finding.Evidence[0], "MQTT") {
		t.Fatalf("exotic protocols: %#v", finding)
	}
	mainstream := withFlows(baseActivity(), flow("tcp", "ssl", 443, "203.0.113.1", 1, 10), flow("udp", "", 40000, "203.0.113.2", 1, 10))
	if _, ok := findingByID(build(mainstream, CATrustUnknown), FindingExoticProtocols); ok {
		t.Fatal("mainstream or unidentified protocols raised an exotic finding")
	}
}

func TestAlertsTakeTheHighestSeverity(t *testing.T) {
	activity := baseActivity()
	activity.Alerts = []ingest.DeviceAlertGroup{
		{Engine: "SURICATA", Signature: "ET INFO something", Severity: "LOW", Count: 2, FirstSeen: seenAt, LastSeen: seenAt},
		{Engine: "SURICATA", Signature: "ET POLICY Telnet login", Severity: "HIGH", Count: 1, FirstSeen: seenAt, LastSeen: seenAt},
	}
	finding, ok := findingByID(build(activity, CATrustUnknown), FindingAlerts)
	if !ok || finding.Severity != SeverityHigh || len(finding.Evidence) != 2 || !strings.Contains(finding.Detail, "3 alerts") {
		t.Fatalf("alerts: %#v", finding)
	}
	if _, ok := findingByID(build(baseActivity(), CATrustUnknown), FindingAlerts); ok {
		t.Fatal("alerts finding without alerts")
	}
}

func TestEvidenceIsBoundedWithAMoreLine(t *testing.T) {
	activity := baseActivity()
	for index := 0; index < 15; index++ {
		activity.CleartextHTTP = append(activity.CleartextHTTP, ingest.DeviceHTTPHost{Host: strings.Repeat("a", index+1) + ".example", Requests: 1, FirstSeen: seenAt, LastSeen: seenAt})
	}
	finding, _ := findingByID(build(activity, CATrustUnknown), FindingCleartextHTTP)
	if len(finding.Evidence) != maxEvidenceLines+1 || finding.Evidence[maxEvidenceLines] != "…and 5 more" {
		t.Fatalf("evidence bound: %#v", finding.Evidence)
	}
}

func TestCompareReportsWhatChangedBetweenRuns(t *testing.T) {
	base := baseActivity()
	base.Counts.Events = 5
	base.Domains = []ingest.DeviceDomainObservation{
		{Domain: "api.example.com", Source: "dns", Events: 1, FirstSeen: seenAt, LastSeen: seenAt},
		{Domain: "old.example.com", Source: "dns", Events: 1, FirstSeen: seenAt, LastSeen: seenAt},
	}
	base.TLSHosts = []ingest.DeviceTLSHost{{Host: "stable.example.com", State: "FAILED", Events: 1, FirstSeen: seenAt, LastSeen: seenAt}}
	base.TLSVersions = []ingest.DeviceTLSVersion{{Version: "TLSv1.0", Host: "legacy.example.com", Events: 1, FirstSeen: seenAt, LastSeen: seenAt}}
	base = withFlows(base, flow("tcp", "ssl", 443, "203.0.113.1", 1, 10))

	next := baseActivity()
	next.Counts.Events = 9
	next.Domains = []ingest.DeviceDomainObservation{
		{Domain: "api.example.com", Source: "dns", Events: 1, FirstSeen: seenAt, LastSeen: seenAt},
		{Domain: "new.example.com", Source: "tls", Events: 1, FirstSeen: seenAt, LastSeen: seenAt},
	}
	next.TLSHosts = []ingest.DeviceTLSHost{
		{Host: "stable.example.com", State: "FAILED", Events: 1, FirstSeen: seenAt, LastSeen: seenAt},
		{Host: "broken.example.com", State: "FAILED", Events: 1, FirstSeen: seenAt, LastSeen: seenAt},
		{Host: "open.example.com", State: "INTERCEPTED", Events: 1, FirstSeen: seenAt, LastSeen: seenAt},
	}
	next.CleartextHTTP = []ingest.DeviceHTTPHost{{Host: "fw.example.com", Requests: 1, SampleAddress: "203.0.113.50", FirstSeen: seenAt, LastSeen: seenAt}}
	next = withFlows(next, flow("tcp", "ssl", 443, "203.0.113.1", 1, 10), flow("tcp", "mqtt", 1883, "203.0.113.2", 1, 10))

	result := Compare(reportEnd, build(base, CATrustUnknown), build(next, CATrustUnknown), Side{SessionID: "ts-000000000000000000000001", Name: "Firmware 1.2"}, Side{SessionID: "ts-000000000000000000000002", Name: "Firmware 1.3"})
	if strings.Join(result.Domains.Added, ",") != "new.example.com" || strings.Join(result.Domains.Removed, ",") != "old.example.com" {
		t.Fatalf("domain change: %#v", result.Domains)
	}
	if strings.Join(result.Protocols.Added, ",") != "mqtt" || len(result.Protocols.Removed) != 0 {
		t.Fatalf("protocol change: %#v", result.Protocols)
	}
	newIDs := []string{}
	for _, finding := range result.Findings.New {
		newIDs = append(newIDs, finding.ID)
	}
	if strings.Join(newIDs, ",") != "cleartext-http,exotic-protocols" || len(result.Findings.Resolved) != 1 || result.Findings.Resolved[0].ID != FindingOutdatedTLS {
		t.Fatalf("finding change: new=%v resolved=%#v", newIDs, result.Findings.Resolved)
	}
	if strings.Join(result.TLS.NewlyFailedHosts, ",") != "broken.example.com" || strings.Join(result.TLS.NewlyInterceptedHosts, ",") != "open.example.com" {
		t.Fatalf("TLS change: %#v", result.TLS)
	}
	if result.Base.SessionID != "ts-000000000000000000000001" || result.Compare.Totals.Events != 11 || !strings.Contains(result.Summary, "Firmware 1.2") || !strings.Contains(result.Summary, "new protocols: mqtt") {
		t.Fatalf("comparison sides or summary: %#v", result)
	}
	same := Compare(reportEnd, build(base, CATrustUnknown), build(base, CATrustUnknown), Side{}, Side{})
	if !strings.HasPrefix(same.Summary, "No differences") || len(same.Domains.Added) != 0 || same.Findings.New == nil {
		t.Fatalf("identical runs: %#v", same)
	}
}

func TestCATrustHelpers(t *testing.T) {
	if NormalizeCATrust("") != CATrustUnknown || NormalizeCATrust("INSTALLED") != CATrustInstalled || NormalizeCATrust("bogus") != CATrustUnknown {
		t.Fatal("NormalizeCATrust")
	}
	if !ValidCATrust("UNKNOWN") || !ValidCATrust("NOT_INSTALLED") || ValidCATrust("") || ValidCATrust("installed") {
		t.Fatal("ValidCATrust")
	}
	if FormatBytes(512) != "512 B" || FormatBytes(2048) != "2 KB" || FormatBytes(3<<20) != "3.0 MB" || FormatBytes(5<<30) != "5.0 GB" {
		t.Fatal("FormatBytes")
	}
}

func TestPassiveSensorFlowsInheritInterceptorDecryption(t *testing.T) {
	activity := withFlows(baseActivity(), flow("tcp", "ssl", 443, "203.0.113.1", 10, 1000), flow("tcp", "ssl", 8443, "203.0.113.2", 1, 10))
	activity.FlowGroups = append(activity.FlowGroups, ingest.DeviceFlowGroup{Source: ingest.SourceMitmproxy, Transport: "tcp", Service: "tls", ServerPort: 443, Flows: 4, Bytes: 400, Intercepted: true, FirstSeen: seenAt, LastSeen: seenAt})
	report := build(activity, CATrustUnknown)
	if len(report.Protocols) != 1 || report.Protocols[0].Protocol != "tls" || report.Protocols[0].Visibility != "DECRYPTED" || report.Protocols[0].Flows != 11 {
		t.Fatalf("Zeek TLS flows should read DECRYPTED where the interceptor decrypted: %#v", report.Protocols)
	}
	plain := withFlows(baseActivity(), flow("tcp", "ssl", 443, "203.0.113.1", 10, 1000))
	if protocols := build(plain, CATrustUnknown).Protocols; protocols[0].Visibility != "ENCRYPTED_METADATA" {
		t.Fatalf("TLS without interception: %#v", protocols)
	}
}

func TestCompareFlagsTruncatedLists(t *testing.T) {
	base := baseActivity()
	for index := 0; index < MaxHostList; index++ {
		base.TLSHosts = append(base.TLSHosts, ingest.DeviceTLSHost{Host: fmt.Sprintf("h%02d.example.com", index), State: "FAILED", Events: 1, FirstSeen: seenAt, LastSeen: seenAt})
	}
	result := Compare(reportEnd, build(base, CATrustUnknown), build(baseActivity(), CATrustUnknown), Side{}, Side{})
	if !result.Truncated || !strings.Contains(result.Summary, "size limit") {
		t.Fatalf("truncated comparison: %#v", result)
	}
	if clean := Compare(reportEnd, build(baseActivity(), CATrustUnknown), build(baseActivity(), CATrustUnknown), Side{}, Side{}); clean.Truncated {
		t.Fatal("untruncated comparison flagged")
	}
}
