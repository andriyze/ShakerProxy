import assert from "node:assert/strict"
import test from "node:test"
import { escapeHTML, formatBytes, formatDuration, formatPercent, formatRelative, humanize, isTimeWindow, plural, safeFileName } from "../../apps/web-ui/src/features/format.ts"
import { coverageSegments, coverageSentence, filterCatalog, portSummary, protocolChips, protocolsPath, deviceProtocolsPath, sortProtocols, trafficQueryForProtocol } from "../../apps/web-ui/src/features/protocols-model.ts"
import { domainKind, findingsHeadline, groupDomains, reportPath, severityCounts, sortFindings, tlsSummaryLines, windowCovering, worstSeverity } from "../../apps/web-ui/src/features/report-model.ts"
import { canCompare, comparePath, compareSummary, defaultRunName, diffTotals, orderForCompare, sessionsFromResponse, sortSessions, testSessionsPath } from "../../apps/web-ui/src/features/tests-model.ts"
import { controlsUpdate, mergeDomains, normalizeDomain, parseDomainList } from "../../apps/web-ui/src/features/controls-model.ts"
import { outcomeExplanation, suggestPlatform, summarizeOutcomes, verdict, verifyEventsPath } from "../../apps/web-ui/src/features/wizard-model.ts"

const DEVICE = "device-0123456789abcdef0123456789abcdef"

test("formatters are plain-language and robust", () => {
  assert.equal(formatBytes(0), "0 B")
  assert.equal(formatBytes(1023), "1023 B")
  assert.equal(formatBytes(1536), "1.5 KB")
  assert.equal(formatBytes(12 * 1024), "12 KB")
  assert.equal(formatBytes(150 * 1024 * 1024), "150 MB")
  assert.equal(formatBytes(-1), "—")
  assert.equal(formatBytes(undefined), "—")
  assert.equal(plural(1, "connection"), "1 connection")
  assert.equal(plural(1200, "connection"), "1,200 connections")
  assert.equal(formatPercent(1, 400), "<1%")
  assert.equal(formatPercent(0, 0), "0%")
  const now = Date.parse("2026-09-29T12:00:00Z")
  assert.equal(formatRelative("2026-09-29T11:59:40Z", now), "just now")
  assert.equal(formatRelative("2026-09-29T11:55:00Z", now), "5 min ago")
  assert.equal(formatRelative("2026-09-29T09:00:00Z", now), "3 h ago")
  assert.equal(formatRelative("2026-09-27T12:00:00Z", now), "2 days ago")
  assert.equal(formatRelative("not a date", now), "—")
  assert.equal(formatDuration("2026-09-29T10:55:00Z", "2026-09-29T12:00:00Z"), "1 h 5 min")
  assert.equal(formatDuration("2026-09-29T11:59:15Z", null, now), "45 s")
  assert.equal(humanize("iot-messaging"), "IoT messaging")
  assert.equal(humanize("os-services"), "OS services")
  assert.equal(humanize("smart-tv"), "Smart TV")
  assert.equal(escapeHTML(`<a href="x">'&'</a>`), "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;")
  assert.equal(safeFileName("shakerproxy-report-Living room TV/../2026"), "shakerproxy-report-Living-room-TV-..-2026")
  assert.equal(safeFileName("///"), "shakerproxy")
  assert.ok(isTimeWindow("7d") && !isTimeWindow("2h"))
})

const coverage = { total_bytes: 1000, decrypted_bytes: 100, cleartext_bytes: 50, encrypted_metadata_bytes: 700, opaque_bytes: 150, opaque_percent: 15 }

test("protocol coverage is explained in one line", () => {
  const segments = coverageSegments(coverage)
  assert.deepEqual(segments.map((segment) => Math.round(segment.percent)), [10, 5, 70, 15])
  assert.equal(coverageSentence(coverage), "ShakerProxy can read 15% of this traffic, sees only server names for 70% and cannot see inside 15%.")
  assert.equal(coverageSentence({ ...coverage, decrypted_bytes: 0, total_bytes: 900 }), "ShakerProxy can read 6% of this traffic, sees only server names for 78% and cannot see inside 17%. Turn on Decrypt HTTPS for a device to see inside its encrypted traffic.")
  assert.equal(coverageSentence({ total_bytes: 0, decrypted_bytes: 0, cleartext_bytes: 0, encrypted_metadata_bytes: 0, opaque_bytes: 0, opaque_percent: 0 }), "No traffic in this window yet.")
})

test("protocol paths, sorting and traffic links", () => {
  assert.equal(protocolsPath({ window: "24h", device: "", category: "", exotic: false }), "/api/v1/protocols?window=24h")
  assert.equal(protocolsPath({ window: "7d", device: " Living room TV ", category: "iot-messaging", exotic: true }), "/api/v1/protocols?window=7d&device=Living+room+TV&category=iot-messaging&exotic=true")
  assert.equal(deviceProtocolsPath("Living room TV", "1h"), "/api/v1/devices/Living%20room%20TV/protocols?window=1h")
  assert.equal(trafficQueryForProtocol("mqtt"), "app.protocol:mqtt")
  assert.equal(trafficQueryForProtocol("unknown-tcp"), "app.protocol:unknown-tcp")
  const base = { visibility: "CLEARTEXT", evidence: "ANALYZER", exotic: false, novel: false, description: "", devices: [], unattributed_flows: 0, ports: [], category: "web" }
  const list = [
    { ...base, protocol: "http", label: "HTTP", flows: 50, bytes: 100, device_count: 1, first_seen: "2026-09-29T10:00:00Z", last_seen: "2026-09-29T10:00:00Z" },
    { ...base, protocol: "mqtt", label: "MQTT", flows: 5, bytes: 900, device_count: 3, first_seen: "2026-09-29T09:00:00Z", last_seen: "2026-09-29T11:00:00Z" },
  ]
  assert.deepEqual(sortProtocols(list).map((item) => item.protocol), ["mqtt", "http"])
  assert.deepEqual(sortProtocols(list, "flows").map((item) => item.protocol), ["http", "mqtt"])
  assert.deepEqual(sortProtocols(list, "label").map((item) => item.protocol), ["http", "mqtt"])
  assert.deepEqual(protocolChips({ novel: true, exotic: true }).map((chip) => chip.label), ["New", "Exotic"])
  assert.equal(portSummary([{ transport: "tcp", port: 1883 }, { transport: "udp", port: 5683 }], 1), "TCP 1883 +1")
  const catalog = [
    { id: "mqtt", label: "MQTT", category: "iot-messaging", visibility: "CLEARTEXT", exotic: true, description: "IoT publish/subscribe", ports: [{ transport: "tcp", port: 1883 }] },
    { id: "http", label: "HTTP", category: "web", visibility: "CLEARTEXT", exotic: false, description: "Web", ports: [{ transport: "tcp", port: 80 }] },
  ]
  assert.deepEqual(filterCatalog(catalog, "1883", "").map((item) => item.id), ["mqtt"])
  assert.deepEqual(filterCatalog(catalog, "", "web").map((item) => item.id), ["http"])
  assert.deepEqual(filterCatalog(catalog, "publish", "").map((item) => item.id), ["mqtt"])
})

const finding = (id, severity, title = id) => ({ id, severity, title, detail: "", recommendation: "", evidence: [] })

test("findings sort by severity, critical first", () => {
  const findings = [finding("a", "INFO", "Zeta"), finding("b", "CRITICAL"), finding("c", "MEDIUM"), finding("d", "INFO", "Alpha"), finding("e", "HIGH")]
  assert.deepEqual(sortFindings(findings).map((item) => item.id), ["b", "e", "c", "d", "a"])
  assert.equal(worstSeverity(findings), "CRITICAL")
  assert.equal(worstSeverity([]), undefined)
  assert.deepEqual(severityCounts(findings), { CRITICAL: 1, HIGH: 1, MEDIUM: 1, LOW: 0, INFO: 2 })
  assert.equal(findingsHeadline(findings), "5 findings: 1 critical, 1 high, 1 medium, 2 info.")
  assert.equal(findingsHeadline([]), "No security findings in this window.")
})

test("domains group with trackers highlighted first", () => {
  const domain = (name, category, events, organization = "") => ({ domain: name, registrable_domain: name.split(".").slice(-2).join("."), organization, category, sources: ["dns"], events, first_seen: "", last_seen: "" })
  const domains = [domain("cdn.example.com", "cdn", 500), domain("app-measurement.com", "analytics", 3, "Google"), domain("x.unknown.net", "unknown", 900), domain("crash.example.com", "crash-reporting", 10), domain("ads.example.com", "advertising", 1)]
  const groups = groupDomains(domains)
  assert.deepEqual(groups.map((group) => group.key), ["analytics", "advertising", "crash-reporting", "cdn", "unknown"])
  assert.deepEqual(groups.map((group) => group.kind), ["tracker", "tracker", "telemetry", "normal", "normal"])
  // By company: example.com includes an ad domain, so both tracker groups lead, busiest first.
  const byOrg = groupDomains(domains, "organization")
  assert.deepEqual(byOrg.map((group) => [group.label, group.kind]), [["example.com", "tracker"], ["Google", "tracker"], ["unknown.net", "normal"]])
  assert.equal(domainKind("telemetry"), "telemetry")
  assert.equal(domainKind("streaming"), "normal")
})

test("report paths, TLS explanations and protocol windows", () => {
  assert.equal(reportPath(DEVICE, { window: "7d" }), `/api/v1/devices/${DEVICE}/report?window=7d`)
  assert.equal(reportPath("tv", { session: "ts-0123456789abcdef01234567" }), "/api/v1/devices/tv/report?session=ts-0123456789abcdef01234567")
  assert.equal(reportPath("tv", {}), "/api/v1/devices/tv/report?window=24h")
  const tls = { intercepted: 2, bypassed: 0, failed: 1, pinning_suspected: 1, failed_hosts: ["a"], old_versions: [{ version: "TLSv1.0", hosts: ["old.example.com"] }] }
  const lines = tlsSummaryLines({ tls, ca_trust: "NOT_INSTALLED" })
  assert.match(lines[0], /accepts untrusted certificates/)
  assert.match(lines.join(" "), /TLSv1\.0 \(outdated\)/)
  assert.doesNotMatch(tlsSummaryLines({ tls, ca_trust: "INSTALLED" })[0], /untrusted/)
  assert.match(tlsSummaryLines({ tls: { ...tls, intercepted: 0, failed: 0, bypassed: 0 }, ca_trust: "UNKNOWN" })[0], /Turn on Decrypt HTTPS/)
  const now = Date.parse("2026-09-29T12:00:00Z")
  assert.equal(windowCovering("2026-09-29T11:30:00Z", now), "1h")
  assert.equal(windowCovering("2026-09-29T01:00:00Z", now), "24h")
  assert.equal(windowCovering("2026-09-25T01:00:00Z", now), "7d")
  assert.equal(windowCovering("2026-08-01T01:00:00Z", now), "30d")
  assert.equal(windowCovering(null, now), "24h")
})

const session = (id, state, started, device = DEVICE) => ({ schema: 1, id, device_id: device, device_name: "TV", name: id, notes: "", state, started_at: started, ended_at: null, capture_session_id: null, created_by: "admin" })

test("test runs list running first, then newest", () => {
  const list = [session("old", "STOPPED", "2026-09-01T00:00:00Z"), session("new", "STOPPED", "2026-09-20T00:00:00Z"), session("live", "RUNNING", "2026-09-10T00:00:00Z")]
  assert.deepEqual(sortSessions(list).map((item) => item.id), ["live", "new", "old"])
  assert.deepEqual(sessionsFromResponse({ schema: 1, sessions: list }).length, 3)
  assert.deepEqual(sessionsFromResponse({ test_sessions: list }).length, 3)
  assert.deepEqual(sessionsFromResponse(list).length, 3)
  assert.deepEqual(sessionsFromResponse({ nope: true }), [])
  assert.deepEqual(sessionsFromResponse([{ id: 5 }, null, list[0]]).length, 1)
  assert.equal(testSessionsPath({ device: "Living room TV", state: "RUNNING" }), "/api/v1/test-sessions?device=Living+room+TV&state=RUNNING&limit=50")
  assert.equal(testSessionsPath({ limit: 5000 }), "/api/v1/test-sessions?limit=200")
  assert.equal(defaultRunName("Living room TV", new Date(2026, 8, 29, 7, 5)), "Living room TV — 2026-09-29 07:05")
})

test("comparing runs checks the pair and orders base before compare", () => {
  const a = session("a", "STOPPED", "2026-09-20T00:00:00Z")
  const b = session("b", "STOPPED", "2026-09-01T00:00:00Z")
  assert.deepEqual(canCompare([a]), { ok: false, reason: "Select exactly two runs to compare." })
  assert.equal(canCompare([a, session("c", "STOPPED", "2026-09-02T00:00:00Z", "device-ffffffffffffffffffffffffffffffff")]).ok, false)
  assert.equal(canCompare([a, b]).ok, true)
  assert.deepEqual(orderForCompare(a, b).map((item) => item.id), ["b", "a"])
  assert.equal(comparePath(DEVICE, "b", "a"), `/api/v1/devices/${DEVICE}/compare?base=b&compare=a`)
})

test("compare diff helpers summarise changes plainly", () => {
  const totals = (flows, bytes) => ({ events: 0, flows, bytes, dns_queries: 0, tls_connections: 0, http_requests: 0, alerts: 0 })
  const diff = diffTotals(totals(10, 2048), totals(15, 1024))
  assert.deepEqual(diff.find((row) => row.key === "flows"), { key: "flows", label: "Connections", bytes: false, base: 10, compare: 15, delta: 5 })
  assert.equal(diff.find((row) => row.key === "bytes").delta, -1024)
  const empty = { schema: 1, device_id: DEVICE, base: {}, compare: {}, domains: { added: [], removed: [] }, protocols: { added: [], removed: [] }, findings: { new: [], resolved: [] }, tls: { newly_failed_hosts: [], newly_intercepted_hosts: [] } }
  assert.equal(compareSummary(empty).changes, 0)
  assert.match(compareSummary(empty).headline, /No differences/)
  const changed = { ...empty, domains: { added: ["new.example.com"], removed: ["old.example.com"] }, protocols: { added: ["mqtt"], removed: [] } }
  assert.equal(compareSummary(changed).headline, "3 changes between the runs; no new findings.")
  const worse = { ...changed, findings: { new: [finding("cleartext-http", "HIGH")], resolved: [] } }
  assert.equal(compareSummary(worse).headline, "1 new finding in the later run, plus 3 other changes.")
  assert.equal(compareSummary({ ...empty, findings: { new: [finding("x", "LOW")], resolved: [] } }).headline, "1 new finding in the later run.")
})

test("blocked domains are normalised from what people paste", () => {
  assert.equal(normalizeDomain("https://Ads.Example.com/path?q=1"), "ads.example.com")
  assert.equal(normalizeDomain("*.tracker.example."), "tracker.example")
  assert.equal(normalizeDomain("user@mail.example.com:8443"), "mail.example.com")
  assert.equal(normalizeDomain("_dmarc.example.com"), "_dmarc.example.com")
  for (const bad of ["localhost", "10.0.0.1", "exa mple.com", "-bad.example.com", "fe80::1", "", "a".repeat(64) + ".com"]) assert.equal(normalizeDomain(bad), undefined, bad)
  assert.deepEqual(parseDomainList("ads.example.com, ADS.example.com\ntracker.io; nope"), { valid: ["ads.example.com", "tracker.io"], invalid: ["nope"] })
  const merged = mergeDomains(["a.com", "b.com"], ["b.com", "c.com", "d.com"], 3)
  assert.deepEqual(merged, { domains: ["a.com", "b.com", "c.com"], added: ["c.com"], skipped: ["d.com"] })
  assert.deepEqual(controlsUpdate({ decrypt_https: false, internet: "ALLOW", blocked_domains: ["a.com"] }, { internet: "BLOCK" }), { decrypt_https: false, internet: "BLOCK", blocked_domains: ["a.com"] })
})

test("wizard verification explains TLS outcomes and flags untrusted-certificate acceptance", () => {
  const event = (id, host, state, at, extra = {}) => ({ record_id: id, occurred_at: at, tls_server_name: host, tls_interception_state: state, ...extra })
  const events = [
    event("1", "api.example.com", "FAILED", "2026-09-29T10:00:00Z"),
    event("2", "api.example.com", "INTERCEPTED", "2026-09-29T10:01:00Z"),
    event("3", "pinned.example.com", "FAILED", "2026-09-29T10:02:00Z", { tls_pinning_suspected: true }),
    event("4", "early.example.com", "INTERCEPTED", "2026-09-29T09:00:00Z"),
    { record_id: "5", occurred_at: "2026-09-29T10:03:00Z", kind: "dns" },
  ]
  const since = Date.parse("2026-09-29T09:30:00Z")
  const validate = summarizeOutcomes(events, "validate", since)
  assert.deepEqual(validate.map((item) => [item.host, item.state, item.count]), [["api.example.com", "INTERCEPTED", 2], ["pinned.example.com", "FAILED", 1]])
  assert.equal(validate[0].tone, "critical")
  const critical = verdict(validate, "validate")
  assert.equal(critical.status, "critical")
  assert.match(critical.title, /accepted an untrusted certificate/)
  assert.equal(verdict(summarizeOutcomes([events[0]], "validate"), "validate").status, "pass")
  const decrypt = summarizeOutcomes(events, "decrypt", since)
  assert.equal(verdict(decrypt, "decrypt").status, "partial")
  assert.equal(decrypt.find((item) => item.host === "pinned.example.com").tone, "warn")
  assert.match(outcomeExplanation("decrypt", "FAILED", true).explanation, /pins/)
  assert.match(outcomeExplanation("decrypt", "FAILED", false).explanation, /not trusted yet/)
  assert.equal(verdict([], "decrypt").status, "waiting")
  assert.equal(verdict(summarizeOutcomes([events[0]], "decrypt"), "decrypt").status, "refused")
  assert.equal(verdict(summarizeOutcomes([events[1]], "decrypt"), "decrypt").status, "success")
  const path = verifyEventsPath(DEVICE)
  assert.ok(path.startsWith("/api/v1/events?limit=100&q="))
  assert.equal(new URLSearchParams(path.split("?")[1]).get("q"), `device.id:${DEVICE} AND (tls.state:INTERCEPTED OR tls.state:FAILED OR tls.state:BYPASSED)`)
})

test("onboarding tab is suggested from the device vendor", () => {
  const all = ["ios", "android", "android-tv", "macos", "windows", "linux", "smart-tv", "other"]
  assert.equal(suggestPlatform("Apple", "Office iPad", all), "ios")
  assert.equal(suggestPlatform("Samsung", "Living room TV", all), "smart-tv")
  assert.equal(suggestPlatform("Google", "Pixel 9", all), "android")
  assert.equal(suggestPlatform("NVIDIA", "Shield Android TV", all), "android-tv")
  assert.equal(suggestPlatform("Espressif", "Bench sensor", all), undefined)
  assert.equal(suggestPlatform("Samsung", "Galaxy S25", ["android"]), "android")
})
