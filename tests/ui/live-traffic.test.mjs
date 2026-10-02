import assert from "node:assert/strict"
import test from "node:test"
import {
  ALL_STREAM_KINDS,
  STREAM_KINDS,
  DEFAULT_LIVE_FILTERS,
  composeLiveQuery,
  eventsPerMinute,
  liveFiltersFromURL,
  streamLine,
  writeLiveFiltersToURL,
} from "../../apps/web-ui/src/lib/liveTraffic.ts"
import { webUIFile } from "./web-ui-source.mjs"

const PHONE = `device-${"72".repeat(16)}`
const FORMER = `device-${"8a".repeat(16)}`
const base = { record_id: "r", source: "ZEEK", occurred_at: "2026-10-02T01:45:01Z", received_at: "", source_version: "", parser_version: "", confidence: 70 }

test("each kind of traffic reads as one line", () => {
  assert.deepEqual(
    streamLine({ ...base, kind: "shakerproxy.dns", source: "HOST", dns_query: "maps.google.com", dns_record_type: "A", dns_response_code: "NOERROR", dns_answers: ["142.250.1.1", "142.250.1.2", "142.250.1.3", "142.250.1.4"] }),
    { kind: "dns", badge: "DNS", name: "maps.google.com", detail: "A → 142.250.1.1, 142.250.1.2, 142.250.1.3 +1", peer: "via ShakerProxy", problem: false },
  )
  const nx = streamLine({ ...base, kind: "zeek.dns", dns_query: "nope.example", dns_record_type: "AAAA", dns_response_code: "NXDOMAIN", destination_ip: "8.8.8.8", destination_port: 53 })
  assert.equal(nx.detail, "AAAA NXDOMAIN")
  assert.equal(nx.peer, "8.8.8.8:53")
  assert.equal(nx.problem, true)
  const tls = streamLine({ ...base, kind: "zeek.conn", protocol: "tcp", tls_server_name: "github.com", network_bytes: 311, destination_ip: "140.82.121.4", destination_port: 443 })
  assert.equal(tls.badge, "TLS")
  assert.equal(tls.name, "github.com")
  assert.equal(tls.peer, "140.82.121.4:443")
  const quic = streamLine({ ...base, kind: "zeek.conn", protocol: "udp", tls_server_name: "www.youtube.com", network_bytes: 9400 })
  assert.equal(quic.badge, "QUIC")
  const http = streamLine({ ...base, kind: "zeek.http", http_method: "GET", http_host: "connectivitycheck.grapheneos.network", http_path: "/generate_204", http_status: 204 })
  assert.deepEqual([http.badge, http.name, http.detail], ["HTTP", "GET connectivitycheck.grapheneos.network/generate_204", "204 · cleartext"])
  const other = streamLine({ ...base, kind: "zeek.conn", protocol: "udp", service: "ntp", destination_ip: "162.159.200.1", destination_port: 123, network_bytes: 96 })
  assert.deepEqual([other.kind, other.badge, other.name], ["other", "NTP", "162.159.200.1:123"])
})

test("chips compose one filter, including a client's merged records", () => {
  const chip = (id) => STREAM_KINDS.find((kind) => kind.id === id).query
  // All kinds: everything but the analyzers' duplicates, not a join of
  // every chip (which ran past the server's term limit).
  assert.ok(composeLiveQuery(DEFAULT_LIVE_FILTERS).startsWith("NOT (kind:suricata.flow"))
  const query = composeLiveQuery({ kinds: ["dns", "http"], clients: [PHONE], time: "last_1h", search: "github" }, "", (id) => (id === PHONE ? [FORMER] : []))
  assert.equal(
    query,
    `time:last_1h AND (${chip("dns")} OR ${chip("http")}) AND (device.id:${PHONE} OR device.id:${FORMER}) AND github`,
  )
  assert.equal(composeLiveQuery({ kinds: [], clients: [], time: "", search: "a b" }, "proto:mqtt"), `"a b" AND (proto:mqtt)`)
  // The server accepts 128 query terms: at most 12 device IDs go into one
  // filter (14 still parse with time, search and an advanced filter).
  const many = composeLiveQuery({ ...DEFAULT_LIVE_FILTERS, clients: Array.from({ length: 30 }, (_, index) => `device-${String(index).padStart(32, "0")}`) })
  assert.equal(many.match(/device\.id:/g).length, 12)
  assert.ok(many.length < 2048)
})

test("filters survive a reload through the page address", () => {
  const url = new URL("https://127.0.0.1:8443/#/traffic")
  const filters = { kinds: ["tls", "quic"], clients: [PHONE], time: "last_5m", search: "github", include: [], exclude: [] }
  writeLiveFiltersToURL(url, filters)
  assert.deepEqual(liveFiltersFromURL(url.search), filters)
  assert.deepEqual(liveFiltersFromURL("").kinds, ALL_STREAM_KINDS)
  // An old link with only an advanced filter keeps seeing every event.
  assert.deepEqual(liveFiltersFromURL("?traffic_q=kind%3Asuricata.flow").kinds, [])
  assert.deepEqual(liveFiltersFromURL("?traffic_clients=not-a-device,"+PHONE+"&traffic_time=forever").clients, [PHONE])
})

test("the rate counts the last minute", () => {
  const now = Date.parse("2026-10-02T01:45:30Z")
  const events = ["2026-10-02T01:45:01Z", "2026-10-02T01:44:40Z", "2026-10-02T01:40:00Z"].map((at, index) => ({ ...base, record_id: String(index), kind: "zeek.conn", occurred_at: at }))
  assert.equal(eventsPerMinute(events, now), 2)
})

test("the Traffic page is a live stream with chip filters", () => {
  const traffic = webUIFile("workspaces/traffic/TrafficWorkspace.tsx")
  assert.match(traffic, /<LiveFilterBar filters=\{filters\}/)
  assert.match(traffic, /<TrafficStream/)
  assert.match(traffic, /if \(!holding && !manualPaused && traffic\.pending\.length > 0\) showPendingEvents\(\)/)
  assert.match(traffic, /<summary>Advanced: field filters/)
  assert.match(webUIFile("main.tsx"), /import "\.\/styles\/live-traffic\.css"/)
})

test("retry storms collapse into one line", async () => {
  const { collapseRepeats } = await import("../../apps/web-ui/src/lib/liveTraffic.ts")
  const retries = ["03:34:35", "03:34:35", "03:34:35", "03:34:36"].map((time, index) => ({ ...base, record_id: String(index), occurred_at: `2026-10-02T${time}Z`, name: index === 3 ? "other" : "v.ipinfo.io" }))
  const collapsed = collapseRepeats(retries, (event) => event.name)
  assert.deepEqual(collapsed.map((row) => [row.event.record_id, row.count]), [["0", 3], ["3", 1]])
})

const instant = (overrides) => ({
  ...base,
  record_id: "conn",
  source: "HOST",
  kind: "shakerproxy.conn",
  occurred_at: "2026-10-02T03:34:36.200Z",
  source_ip: "192.168.10.201",
  source_port: 37064,
  destination_ip: "140.82.121.4",
  destination_port: 443,
  protocol: "tcp",
  dns_name: "github.com",
  ...overrides,
})

test("a connection shows the moment it opens, named from the phone's own lookup", async () => {
  const { streamLine } = await import("../../apps/web-ui/src/lib/liveTraffic.ts")
  assert.deepEqual(streamLine(instant({})), { kind: "tls", badge: "TLS", name: "github.com", detail: "", peer: "140.82.121.4:443", problem: false, pending: true })
  assert.equal(streamLine(instant({ protocol: "udp" })).badge, "QUIC")
  assert.equal(streamLine(instant({ destination_port: 80 })).badge, "HTTP")
  const other = streamLine(instant({ destination_port: 8883, dns_name: undefined, destination_ip: "52.1.2.3" }))
  assert.deepEqual([other.kind, other.badge, other.name], ["other", "TCP", "52.1.2.3:8883"])
})

test("the analysis fills in the same row later instead of adding another", async () => {
  const { mergeInstantConnections, streamLine } = await import("../../apps/web-ui/src/lib/liveTraffic.ts")
  const events = [
    // Newest first, as the page holds them.
    { ...base, record_id: "http", kind: "zeek.http", occurred_at: "2026-10-02T03:34:36.500Z", source_ip: "192.168.10.201", source_port: 37064, destination_ip: "140.82.121.4", destination_port: 443, http_method: "GET", http_host: "github.com" },
    instant({}),
    { ...base, record_id: "zeek", kind: "zeek.conn", occurred_at: "2026-10-02T03:34:36.180Z", protocol: "tcp", source_ip: "192.168.10.201", source_port: 37064, destination_ip: "140.82.121.4", destination_port: 443, tls_server_name: "github.com", network_bytes: 311 },
    { ...base, record_id: "other-port", kind: "zeek.conn", occurred_at: "2026-10-02T03:34:36.180Z", protocol: "tcp", source_ip: "192.168.10.201", source_port: 37065, destination_ip: "140.82.121.4", destination_port: 443, tls_server_name: "github.com", network_bytes: 99 },
    { ...base, record_id: "much-later", kind: "zeek.conn", occurred_at: "2026-10-02T03:40:00Z", protocol: "tcp", source_ip: "192.168.10.201", source_port: 37064, destination_ip: "140.82.121.4", destination_port: 443, tls_server_name: "github.com", network_bytes: 5 },
  ]
  const merged = mergeInstantConnections(events)
  assert.deepEqual(merged.map((event) => event.record_id), ["http", "conn", "other-port", "much-later"])
  const row = merged.find((event) => event.record_id === "conn")
  assert.equal(row.occurred_at, "2026-10-02T03:34:36.200Z", "the row keeps the time the connection opened")
  assert.deepEqual(streamLine(row), { kind: "tls", badge: "TLS", name: "github.com", detail: "311 B", peer: "140.82.121.4:443", problem: false, pending: false })
  // Without a gateway report the analyzer rows stay as they were.
  assert.deepEqual(mergeInstantConnections(events.filter((event) => event.kind !== "shakerproxy.conn")).length, 4)
})

test("type chips include the connections the gateway reports", async () => {
  const { STREAM_KINDS } = await import("../../apps/web-ui/src/lib/liveTraffic.ts")
  const query = Object.fromEntries(STREAM_KINDS.map((kind) => [kind.id, kind.query]))
  assert.match(query.tls, /kind:shakerproxy\.conn AND protocol:tcp AND dst\.port:443/)
  assert.match(query.quic, /kind:shakerproxy\.conn AND protocol:udp AND dst\.port:443/)
  assert.match(query.http, /kind:shakerproxy\.conn AND protocol:tcp AND dst\.port:80/)
  assert.match(query.other, /kind:shakerproxy\.conn AND NOT dst\.port:443 AND NOT dst\.port:80 AND NOT dst\.port:53/)
  assert.match(webUIFile("workspaces/traffic/TrafficStream.tsx"), /mergeInstantConnections\(foldSplitConnections\(/)
})

test("encrypted DNS is identified by kind", () => {
  const line = (app_protocol, extra = {}) => streamLine({ ...base, kind: "zeek.conn", app_protocol, ...extra })
  assert.equal(line("dot", { protocol: "tcp", destination_ip: "1.1.1.1", destination_port: 853 }).badge, "DoT")
  assert.equal(line("doq", { protocol: "udp", destination_ip: "94.140.14.14", destination_port: 853 }).badge, "DoQ")
  assert.equal(line("doh", { protocol: "tcp", tls_server_name: "dns.google", destination_port: 443 }).badge, "DoH")
  for (const kind of ["dot", "doq", "doh"]) assert.equal(line(kind).kind, "dns")
  assert.match(composeLiveQuery({ ...DEFAULT_LIVE_FILTERS, kinds: ["dns"] }), /app\.protocol:dot OR app\.protocol:doq/)
})

test("discovery traffic on the network has its own type", () => {
  const mdns = streamLine({ ...base, kind: "zeek.dns", protocol: "udp", source_ip: "192.168.10.50", destination_ip: "224.0.0.251", destination_port: 5353, dns_query: "_googlecast._tcp.local", dns_record_type: "PTR", dns_answers: ["Living-Room-TV._googlecast._tcp.local"] })
  assert.deepEqual([mdns.kind, mdns.badge, mdns.name, mdns.detail], ["discovery", "mDNS", "_googlecast._tcp.local", "PTR → Living-Room-TV._googlecast._tcp.local"])
  const ssdp = streamLine({ ...base, kind: "zeek.conn", protocol: "udp", destination_ip: "239.255.255.250", destination_port: 1900, network_bytes: 410 })
  assert.deepEqual([ssdp.kind, ssdp.badge, ssdp.name], ["discovery", "SSDP", "239.255.255.250:1900"])
  const chip = (id) => STREAM_KINDS.find((kind) => kind.id === id).query
  assert.match(chip("discovery"), /protocol\.category:local-discovery OR app\.protocol:dhcp/)
  assert.match(chip("dns"), /NOT protocol\.category:local-discovery/)
  assert.match(chip("other"), /NOT \(protocol\.category:local-discovery/)
  assert.equal(streamLine({ ...base, kind: "zeek.conn", app_protocol: "ws-discovery", protocol_category: "local-discovery", destination_port: 4000 }).kind, "discovery")
  assert.ok(composeLiveQuery(DEFAULT_LIVE_FILTERS).length < 2048)
})

test("rows say where traffic went from and to", async () => {
  const { streamEnds, ownerLine, transferLine } = await import("../../apps/web-ui/src/lib/liveTraffic.ts")
  const outbound = { ...base, kind: "zeek.conn", protocol: "tcp", source_ip: "192.168.10.201", source_port: 42612, destination_ip: "140.82.121.4", destination_port: 443, attribution_evidence: { endpoint: "SOURCE" } }
  assert.deepEqual(streamEnds(outbound, "Pixel"), { from: { primary: "Pixel", secondary: "192.168.10.201:42612" }, to: { primary: "140.82.121.4:443", secondary: "TCP" }, inbound: false })
  const inbound = { ...outbound, source_ip: "52.1.2.3", source_port: 443, destination_ip: "192.168.10.201", destination_port: 50000, attribution_evidence: { endpoint: "DESTINATION" } }
  const ends = streamEnds(inbound, "Pixel")
  assert.equal(ends.inbound, true)
  assert.equal(ends.to.primary, "Pixel")
  assert.equal(ends.from.primary, "52.1.2.3:443")
  assert.equal(streamEnds({ ...base, kind: "shakerproxy.dns", source_ip: "192.168.10.201", source_port: 41000, destination_ip: "192.168.10.177", destination_port: 53 }, "Pixel").to.primary, "ShakerProxy DNS")
  assert.equal(ownerLine({ ...base, destination_organization: "GitHub", destination_category: "cloud-platform" }), "GitHub · cloud platform")
  assert.equal(transferLine({ ...base, bytes_sent: 3100, bytes_received: 22600 }), "↑ 3 KB ↓ 22 KB")
  assert.equal(transferLine({ ...base, network_bytes: 512 }), "512 B")
})

test("the Traffic page has a wide view", () => {
  const traffic = webUIFile("workspaces/traffic/TrafficWorkspace.tsx")
  assert.match(traffic, /document\.body\.classList\.toggle\("traffic-wide", wide\)/)
  assert.match(traffic, /traffic_view/)
  assert.match(webUIFile("styles/live-traffic.css"), /body\.traffic-wide main\.workspace\{max-width:none/)
})

// The server accepts at most 128 terms. "All" once joined every chip's query
// and ran past it ("query contains too many tokens"), so Traffic showed
// nothing.
test("every selection of kinds stays within the server's term limit", async () => {
  const { queryTerms } = await import("../../apps/web-ui/src/lib/liveTraffic.ts")
  const clients = Array.from({ length: 30 }, (_, index) => `device-${String(index).padStart(32, "0")}`)
  let worst = 0
  for (let mask = 1; mask < 1 << ALL_STREAM_KINDS.length; mask++) {
    const kinds = ALL_STREAM_KINDS.filter((_, index) => mask & (1 << index))
    const query = composeLiveQuery({ kinds, clients, time: "last_24h", search: "github" }, "proto:mqtt")
    worst = Math.max(worst, queryTerms(query))
    assert.ok(query.length < 2048, `${kinds} is ${query.length} bytes`)
  }
  assert.ok(worst <= 120, `the longest selection has ${worst} terms`)
  assert.match(composeLiveQuery(DEFAULT_LIVE_FILTERS), /^NOT \(kind:suricata\.flow/)
})

test("network chatter gets plain badges", () => {
  const line = (extra) => streamLine({ ...base, kind: "zeek.conn", protocol: "udp", ...extra })
  assert.equal(line({ destination_ip: "255.255.255.255", destination_port: 10001, app_protocol: "ubnt-discovery", protocol_category: "local-discovery" }).badge, "UniFi")
  assert.equal(line({ destination_ip: "192.168.200.255", destination_port: 58866, app_protocol: "local-broadcast", protocol_category: "local-discovery" }).badge, "Bcast")
})

test("the Live view filters by facets and the row menu, and draws a timeline", async () => {
  const { pageFacets, pageTimeline, validFieldFilter } = await import("../../apps/web-ui/src/lib/liveTraffic.ts")
  const now = Date.parse("2026-10-02T14:00:00Z")
  const events = [
    { ...base, record_id: "1", kind: "zeek.conn", protocol: "tcp", device_id: PHONE, tls_server_name: "www.github.com", destination_organization: "GitHub", destination_port: 443, occurred_at: "2026-10-02T13:59:30Z" },
    { ...base, record_id: "2", kind: "zeek.conn", protocol: "tcp", device_id: PHONE, tls_server_name: "api.github.com", destination_organization: "GitHub", destination_port: 443, occurred_at: "2026-10-02T13:59:40Z" },
    { ...base, record_id: "3", kind: "shakerproxy.dns", source: "HOST", source_ip: "192.168.10.50", dns_query: "tv.example.co.uk", occurred_at: "2026-10-02T13:50:00Z" },
  ]
  const facets = pageFacets(events, (event) => (event.device_id ? "Pixel" : ""))
  assert.deepEqual(facets.clients.map((value) => [value.label, value.count, value.filter]), [["Pixel", 2, `device.id:${PHONE}`], ["192.168.10.50", 1, "src.ip:192.168.10.50"]])
  assert.deepEqual(facets.owners.map((value) => [value.label, value.filter]), [["GitHub", "owner:github"]])
  assert.deepEqual(facets.domains.map((value) => [value.label, value.count]), [["github.com", 2], ["example.co.uk", 1]])
  assert.equal(facets.ports[0].filter, "dst.port:443")
  const timeline = pageTimeline(events, 60, now, 15 * 60_000)
  assert.equal(timeline.length, 60)
  assert.equal(timeline.reduce((sum, bucket) => sum + bucket.total, 0), 3)
  assert.equal(timeline.reduce((sum, bucket) => sum + (bucket.counts.tls ?? 0), 0), 2)
  assert.ok(timeline.at(-1).start > Date.parse("2026-10-02T13:59:40Z"), "the newest bucket is last")
  // Field filters from the address bar cannot smuggle query syntax.
  for (const ok of ["owner:google", "dst.port:443", "github.com", "src.ip:192.168.10.50", `device.id:${PHONE}`]) assert.ok(validFieldFilter(ok), ok)
  for (const bad of ["a OR b", "owner:x)", "NOT x", "x\"", "foo:bar"]) assert.ok(!validFieldFilter(bad), bad)
  const query = composeLiveQuery({ ...DEFAULT_LIVE_FILTERS, include: ["owner:github", "a OR b"], exclude: ["dst.port:53"] })
  assert.match(query, / AND owner:github AND NOT dst\.port:53$/)
  assert.doesNotMatch(query, /a OR b/)
  const url = new URL("https://127.0.0.1:8443/#/traffic")
  writeLiveFiltersToURL(url, { ...DEFAULT_LIVE_FILTERS, include: ["owner:github"], exclude: ["dst.port:53"] })
  assert.deepEqual([liveFiltersFromURL(url.search).include, liveFiltersFromURL(url.search).exclude], [["owner:github"], ["dst.port:53"]])
})

test("the wide Traffic view is a three-pane Live view", () => {
  const traffic = webUIFile("workspaces/traffic/TrafficWorkspace.tsx")
  assert.match(traffic, /<LiveFacetsPane/)
  assert.match(traffic, /<LiveTimeline/)
  assert.match(traffic, /<EventDetailDrawer\s+docked/)
  assert.match(webUIFile("workspaces/traffic/TrafficStream.tsx"), /onContextMenu=/)
})

test("the Live view draws the server summary when it has one", async () => {
  const { summaryFacets, summaryTimeline } = await import("../../apps/web-ui/src/lib/liveTraffic.ts")
  const summary = {
    buckets: [
      { start: "2026-10-02T14:00:00Z", counts: { dns: 3, tls: 2, quic: 0, http: 0, discovery: 5, alert: 0, other: 1, blocked: 1 } },
      { start: "2026-10-02T14:01:00Z", counts: { dns: 0, tls: 0, quic: 0, http: 0, discovery: 0, alert: 0, other: 0, blocked: 0 } },
    ],
    totals: { events: 12 },
    facets: [
      { field: "device", exact: true, values: [{ value: PHONE, label: "Pixel", count: 6 }, { value: "ip:192.168.200.156", label: "192.168.200.156", count: 4 }] },
      { field: "type", exact: true, values: [{ value: "discovery", count: 5 }] },
      { field: "organization", exact: false, sampled_events: 20000, values: [{ value: "Google", count: 3 }] },
      { field: "destination_port", exact: true, values: [{ value: "443", label: "443/tcp", count: 2 }] },
    ],
  }
  const timeline = summaryTimeline(summary)
  assert.deepEqual([timeline[0].total, timeline[0].counts.dns, timeline[1].total], [12, 4, 0])
  const facets = summaryFacets(summary, [{ key: "github.com", label: "github.com", count: 2, filter: "github.com" }])
  assert.deepEqual(facets.clients.map((value) => value.filter), [`device.id:${PHONE}`, "src.ip:192.168.200.156"])
  assert.equal(facets.kinds[0].label, "Discovery")
  assert.equal(facets.owners[0].filter, "owner:google")
  assert.equal(facets.ports[0].filter, "dst.port:443")
  assert.equal(facets.domains[0].label, "github.com")
})

test("interleaved repeats fold together and chatter is measured", async () => {
  const { collapseRepeats, chatterShare } = await import("../../apps/web-ui/src/lib/liveTraffic.ts")
  const at = (second) => `2026-10-02T14:00:${String(second).padStart(2, "0")}Z`
  const rows = [
    { name: "a", occurred_at: at(50) }, { name: "b", occurred_at: at(49) }, { name: "a", occurred_at: at(40) },
    { name: "b", occurred_at: at(39) }, { name: "c", occurred_at: at(30) }, { name: "a", occurred_at: at(5) },
  ]
  assert.deepEqual(collapseRepeats(rows, (row) => row.name).map((row) => [row.event.name, row.count]), [["a", 3], ["b", 2], ["c", 1]])
  assert.equal(chatterShare({ events: 3731, types: { discovery: 3716 } }) > 0.99, true)
  assert.equal(chatterShare(undefined), 0)
})

