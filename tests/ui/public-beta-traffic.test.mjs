import assert from "node:assert/strict"
import test from "node:test"
import { INSIGHT_SAMPLE_LIMIT, activeDevices, countSample, insightSamplePath, tlsAttention } from "../../apps/web-ui/src/lib/trafficInsights.ts"
import {
  MAX_SELECTED_DEVICES,
  parseMobileClients,
  tlsModeFromPolicy,
  tlsSelection,
} from "../../apps/web-ui/src/lib/trafficPolicy.ts"
import { EXPORT_LIMIT, PAGE_LIMIT, collectEvents, encodeExport, exportPath, toCSV } from "../../apps/web-ui/src/lib/trafficExport.ts"
import { webUIFile } from "./web-ui-source.mjs"

const device = (n) => `device-${String(n).repeat(32).slice(0, 32)}`

test("traffic overview stays within the bounded event API contract", () => {
  assert.equal(INSIGHT_SAMPLE_LIMIT, 100)
  assert.match(insightSamplePath(), /^\/api\/v1\/events\?limit=100&q=/)
  const overview = webUIFile("workspaces/traffic/TrafficOverview.tsx")
  assert.match(overview, /insightSamplePath\(\)/)
  assert.doesNotMatch(overview, /limit=200/)
  // Loads on mount and refreshes on an interval (no DOM observation).
  assert.match(overview, /useResource<Overview>\([\s\S]*intervalMs: 20_000/)
})

test("overview counts and rankings use structured fields", () => {
  const events = [
    { kind: "tls_intercepted", device_id: device(1), device_friendly_name: "TV", tls_server_name: "a.example" },
    { kind: "tls_interception_failed", device_id: device(1), tls_server_name: "pinned.example", tls_pinning_suspected: true },
    { kind: "http_request", device_id: device(2) },
    { kind: "zeek.dns", service: "dns", dns_query: "a.example" },
  ]
  const counts = countSample(events)
  assert.deepEqual(counts, { dns: 1, tlsOK: 1, tlsFailed: 1, bypass: 0, http: 1, pinning: 1, devices: 2 })
  assert.equal(tlsAttention(events)[0].label, "pinned.example")
  assert.equal(activeDevices(events)[0].deviceID, device(1))
})

test("public beta exposes stable per-device TLS interception modes in one policy editor", () => {
  const panel = webUIFile("workspaces/policy/TrafficPolicyPanel.tsx")
  assert.match(panel, /Pass through all/)
  assert.match(panel, /Decrypt all eligible/)
  assert.match(panel, /Decrypt selected clients/)
  assert.match(panel, /selected_device_ids: selection\.selected_device_ids/)
  assert.match(panel, /Missing, expired, or ambiguous identity is passed through/)
  assert.match(panel, /Existing TLS sessions can remain on their previous interception decision/)
  assert.match(panel, /\/api\/v1\/traffic-policy\/preview/)
  assert.match(panel, /method: "PUT"/)
  // The form element is captured before any await (React clears currentTarget).
  assert.match(panel, /const form = event\.currentTarget\s+const data = new FormData\(form\)[\s\S]*api<TrafficPolicyDocument>\("\/api\/v1\/traffic-policy", \{\s*method: "PUT"/)
  // Decrypting every device always needs the password; other changes confirm on demand.
  assert.match(panel, /\{decryptsEveryDevice && \(/)
  assert.match(panel, /withPassword\(\s*"apply these settings"/)
  // There is no second, DOM-injected policy editor any more.
  assert.doesNotMatch(panel, /retireLegacyTLSModeControl|guardLegacyPolicySubmit/)
})

test("TLS selection maps the three modes onto the policy fields", () => {
  assert.equal(MAX_SELECTED_DEVICES, 512)
  assert.equal(tlsModeFromPolicy({ enabled: false, selected_device_ids: [device(1)] }), "off")
  assert.equal(tlsModeFromPolicy({ enabled: true }), "all")
  assert.equal(tlsModeFromPolicy({ enabled: true, selected_device_ids: [device(1)] }), "selected")
  assert.deepEqual(tlsSelection("off", [device(1)]), { enabled: false, selected_device_ids: [] })
  assert.deepEqual(tlsSelection("all", [device(1)]), { enabled: true, selected_device_ids: [] })
  assert.deepEqual(tlsSelection("selected", [device(2), device(1), device(1), "not-a-device"]), {
    enabled: true,
    selected_device_ids: [device(1), device(2)],
  })
  assert.throws(() => tlsSelection("selected", []), /at least one device/)
  assert.deepEqual(parseMobileClients("192.0.2.40/32 Android-TV\n"), [{ cidr: "192.0.2.40/32", platform: "android-tv" }])
  assert.throws(() => parseMobileClients("192.0.2.40/32 desktop"), /platform must be/)
})

test("filtered traffic export uses the applied query and source and is cursor-bounded", async () => {
  assert.equal(PAGE_LIMIT, 100)
  assert.equal(EXPORT_LIMIT, 10_000)
  assert.equal(exportPath("kind:tls_intercepted", "ZEEK", ""), "/api/v1/events?limit=100&source=ZEEK&q=kind%3Atls_intercepted")
  assert.equal(exportPath("", "", "c2"), "/api/v1/events?limit=100&cursor=c2")
  const cursors = []
  const result = await collectEvents(async (cursor) => {
    cursors.push(cursor)
    return cursor ? { events: [{ record_id: "b" }], canonical_query: "q2" } : { events: [{ record_id: "a" }], next_cursor: "n1" }
  }, "q")
  assert.deepEqual(cursors, ["", "n1"])
  assert.deepEqual(result, { events: [{ record_id: "a" }, { record_id: "b" }], truncated: false, canonicalQuery: "q2" })
  const encoded = encodeExport("json", result.events, "q2", false, new Date("2026-09-29T00:00:00Z"))
  assert.equal(JSON.parse(encoded.body).plaintext_included, false)
  assert.match(toCSV([{ summary: 'GET "x"' }]).split("\r\n")[1], /"GET ""x"""/)
  const component = webUIFile("workspaces/traffic/TrafficExport.tsx")
  assert.match(component, /exportPath\(query, source, cursor\)/)
  assert.doesNotMatch(component, /#traffic-query|querySelector/)
  assert.match(component, /CSV/)
  assert.match(component, /JSONL/)
})
