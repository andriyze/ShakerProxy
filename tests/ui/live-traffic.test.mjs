import assert from "node:assert/strict"
import test from "node:test"
import {
  ALL_STREAM_KINDS,
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
  assert.match(composeLiveQuery(DEFAULT_LIVE_FILTERS), /^\(\(kind:shakerproxy\.dns OR kind:zeek\.dns\) OR /)
  const query = composeLiveQuery({ kinds: ["dns", "http"], clients: [PHONE], time: "last_1h", search: "github" }, "", (id) => (id === PHONE ? [FORMER] : []))
  assert.equal(
    query,
    `time:last_1h AND ((kind:shakerproxy.dns OR kind:zeek.dns) OR ((http.host:* AND NOT source:SURICATA) OR (kind:shakerproxy.conn AND protocol:tcp AND dst.port:80))) AND (device.id:${PHONE} OR device.id:${FORMER}) AND github`,
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
  const filters = { kinds: ["tls", "quic"], clients: [PHONE], time: "last_5m", search: "github" }
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
