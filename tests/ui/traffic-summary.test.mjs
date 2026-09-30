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
