import assert from "node:assert/strict"
import test from "node:test"
import { compactBytes, eventSummary, eventTone } from "../../apps/web-ui/src/lib/eventSummary.ts"
import {
  DNS_PREDICATE,
  TRAFFIC_PRESETS,
  activeTimeWindow,
  combinedQuery,
  deviceQuery,
  withTimeWindow,
} from "../../apps/web-ui/src/lib/trafficPresets.ts"
import { httpActivityPath } from "../../apps/web-ui/src/lib/httpActivity.ts"
import { webUIFile } from "./web-ui-source.mjs"

const DEVICE = `device-${"ab".repeat(16)}`

test("server summary wins when present", () => {
  assert.equal(eventSummary({ kind: "x", summary: "MQTT to 3.4.5.6:1883 · 12 KB" }), "MQTT to 3.4.5.6:1883 · 12 KB")
  assert.equal(eventSummary({ kind: "x", summary: "a".repeat(200) }).length, 160)
})

test("fallback summaries follow the contract examples", () => {
  assert.equal(
    eventSummary({ kind: "zeek.dns", dns_query: "api.example.com", dns_record_type: "A", dns_answer_count: 3 }),
    "DNS lookup api.example.com (A) → 3 answers",
  )
  assert.equal(eventSummary({ kind: "zeek.dns", dns_query: "nx.example", dns_response_code: "NXDOMAIN" }), "DNS lookup nx.example → NXDOMAIN")
  assert.equal(
    eventSummary({ kind: "tls_intercepted", tls_server_name: "api.example.com", tls_interception_state: "INTERCEPTED" }),
    "HTTPS api.example.com — decrypted",
  )
  assert.equal(
    eventSummary({ kind: "tls_interception_failed", tls_server_name: "api.example.com", tls_interception_state: "FAILED", tls_pinning_suspected: true }),
    "HTTPS api.example.com — not decrypted (pinned?)",
  )
  assert.equal(
    eventSummary({ kind: "http_request", http_method: "GET", http_host: "api.example.com", http_path: "/v1/status", http_status: 200 }),
    "GET api.example.com/v1/status → 200",
  )
  assert.equal(
    eventSummary({ kind: "alert", detection_severity: "high", detection_summary: "ET POLICY test" }),
    "Alert (HIGH): ET POLICY test",
  )
  assert.equal(
    eventSummary({ kind: "conn", protocol: "udp", destination_ip: "5.6.7.8", destination_port: 34567, network_bytes: 2048 }),
    "Unidentified UDP to 5.6.7.8:34567 · 2 KB",
  )
  assert.equal(
    eventSummary({ kind: "conn", app_protocol: "mqtt", destination_ip: "3.4.5.6", destination_port: 1883, network_bytes: 12 * 1024 }),
    "MQTT to 3.4.5.6:1883 · 12 KB",
  )
  assert.equal(compactBytes(512), "512 B")
})

test("row accents come from structured fields, not text matching", () => {
  assert.equal(eventTone({ kind: "x", detection_severity: "CRITICAL" }), "alert")
  // A hostname containing "high" is not an alert.
  assert.equal(eventTone({ kind: "tls_intercepted", tls_server_name: "highscore.example" }), "tls-ok")
  assert.equal(eventTone({ kind: "tls_passthrough" }), "bypass")
  assert.equal(eventTone({ kind: "http_response" }), "http")
  assert.equal(eventTone({ kind: "zeek.dns" }), "dns")
})

test("quick views and time windows build valid queries", () => {
  const dns = TRAFFIC_PRESETS.find((preset) => preset.id === "dns")
  assert.equal(DNS_PREDICATE, "(kind:zeek.dns OR kind:suricata.dns OR kind:encrypted_dns_detected OR service:doh)")
  assert.equal(dns.query, `time:last_15m AND ${DNS_PREDICATE}`)
  assert.equal(withTimeWindow("", "last_1h"), "time:last_1h")
  assert.equal(withTimeWindow("kind:x", "last_1h"), "time:last_1h AND (kind:x)")
  assert.equal(withTimeWindow("time:last_15m AND kind:x", "last_6h"), "time:last_6h AND kind:x")
  assert.equal(activeTimeWindow("time:last_6h AND kind:x"), "last_6h")
  assert.equal(activeTimeWindow("kind:x"), "")
  assert.equal(deviceQuery(DEVICE), `device.id:${DEVICE}`)
  assert.equal(deviceQuery(DEVICE, "last_15m"), `time:last_15m AND (device.id:${DEVICE})`)
  assert.equal(deviceQuery("../etc"), "")
  assert.equal(combinedQuery("kind:x", "ZEEK"), "source:ZEEK AND (kind:x)")
})

test("traffic table shows the summary column and loads older events by cursor", () => {
  const table = webUIFile("workspaces/traffic/TrafficTable.tsx")
  assert.match(table, /<span role="columnheader">What happened<\/span>/)
  assert.match(table, /const summary = eventSummary\(item\)/)
  const workspace = webUIFile("workspaces/traffic/TrafficWorkspace.tsx")
  assert.match(workspace, /Load older events/)
  assert.match(workspace, /new URLSearchParams\(\{ limit: String\(OLDER_PAGE_LIMIT\), cursor \}\)/)
  assert.match(workspace, /get\("traffic_q"\)/)
  assert.match(workspace, /get\("traffic_source"\)/)
})

test("web requests use the bounded HTTP activity API", () => {
  assert.equal(
    httpActivityPath({ window: "1h", host: " API.Example.com ", method: "get", device: DEVICE }, "c1"),
    `/api/v1/agent/http-activity?limit=50&window=1h&device_id=${DEVICE}&host=api.example.com&method=GET&cursor=c1`,
  )
  assert.equal(httpActivityPath({ window: "7d", host: "", method: "", device: "bad" }), "/api/v1/agent/http-activity?limit=50&window=1h")
  assert.match(webUIFile("workspaces/traffic/TrafficWorkspace.tsx"), /<HTTPActivity \/>/)
})

test("numeric Suricata alert severity never breaks the traffic table", () => {
  const alert = { kind: "suricata.alert", alert_signature: "ET POLICY Telnet login", alert_severity: 1 }
  assert.equal(eventSummary(alert), "Alert (HIGH): ET POLICY Telnet login")
  assert.equal(eventTone(alert), "alert")
  assert.equal(eventTone({ kind: "suricata.alert", alert_signature: "x", alert_severity: 3 }), "")
  assert.equal(eventTone({ kind: "shakerproxy.detection.x", detection_type: "rogue_dhcp", detection_severity: "critical" }), "alert")
})

test("the readable traffic list keeps one row per connection and lookup", async () => {
  const { isAnalyzerDuplicate } = await import("../../apps/web-ui/src/lib/eventSummary.ts")
  for (const kind of ["suricata.flow", "suricata.dns", "suricata.mdns", "zeek.weird"]) assert.equal(isAnalyzerDuplicate({ kind }), true, kind)
  assert.equal(isAnalyzerDuplicate({ kind: "zeek.conn", service: "dns" }), true)
  for (const event of [{ kind: "zeek.conn", service: "ssl" }, { kind: "zeek.dns" }, { kind: "zeek.ssl" }, { kind: "suricata.alert" }, { kind: "tls_intercepted" }])
    assert.equal(isAnalyzerDuplicate(event), false, event.kind)
})

test("rows say what an event is in plain words, not which analyzer wrote it", async () => {
  const { eventTypeLabel } = await import("../../apps/web-ui/src/lib/eventSummary.ts")
  assert.equal(eventTypeLabel({ kind: "zeek.dns", dns_query: "x.com" }), "DNS")
  assert.equal(eventTypeLabel({ kind: "zeek.conn", tls_server_name: "x.com" }), "Connection")
  assert.equal(eventTypeLabel({ kind: "suricata.alert", alert_signature: "ET POLICY" }), "Alert")
  assert.equal(eventTypeLabel({ kind: "http_request", http_host: "x.com" }), "Web request")
  assert.equal(eventTypeLabel({ kind: "tls_intercepted", tls_interception_state: "INTERCEPTED" }), "HTTPS")
})

test("devices say when they were last seen", async () => {
  const { timeAgo } = await import("../../apps/web-ui/src/lib/format.ts")
  const now = Date.parse("2026-10-01T12:00:00Z")
  assert.equal(timeAgo("2026-10-01T11:59:40Z", now), "just now")
  assert.equal(timeAgo("2026-10-01T11:56:00Z", now), "4 min ago")
  assert.equal(timeAgo("2026-10-01T09:50:00Z", now), "2 h ago")
  assert.equal(timeAgo("2026-09-28T12:00:00Z", now), "3 days ago")
  assert.equal(timeAgo("not a date", now), "unknown")
})

test("a connection split across capture segments shows as one row", async () => {
  const { foldSplitConnections } = await import("../../apps/web-ui/src/lib/eventSummary.ts")
  const flow = "flow-zeek-CDStDS3JdzMOd0IFVb"
  // Newest first, as the Traffic page lists them.
  const events = [
    { record_id: "reset", kind: "zeek.conn", flow_id: flow, occurred_at: "2026-10-02T00:29:46Z", network_bytes: 52, tls_server_name: "www.amazon.com" },
    { record_id: "dns", kind: "zeek.dns", occurred_at: "2026-10-02T00:29:00Z" },
    { record_id: "middle", kind: "zeek.conn", flow_id: flow, occurred_at: "2026-10-02T00:28:29Z", network_bytes: 166316, tls_server_name: "www.amazon.com" },
    { record_id: "first", kind: "zeek.conn", flow_id: flow, occurred_at: "2026-10-02T00:28:20Z", network_bytes: 151194, tls_server_name: "www.amazon.com" },
    { record_id: "other", kind: "zeek.conn", flow_id: "flow-zeek-Cother", occurred_at: "2026-10-02T00:28:00Z", network_bytes: 10 },
  ]
  const folded = foldSplitConnections(events)
  assert.deepEqual(folded.map((event) => event.record_id), ["dns", "first", "other"])
  assert.equal(folded[1].network_bytes, 52 + 166316 + 151194)
  assert.equal(events[3].network_bytes, 151194, "the loaded events are not modified")
  // Without its first record loaded, a continuation still shows.
  assert.deepEqual(foldSplitConnections(events.slice(0, 2)).map((event) => event.record_id), ["reset", "dns"])
})
