// Wi-Fi visibility in the web UI: Live rows, the Wi-Fi chip, a device's
// Wi-Fi panel and the System page switch.
import assert from "node:assert/strict"
import test from "node:test"
import { ALL_STREAM_KINDS, composeLiveQuery, streamEnds, streamKind, streamLine } from "../../apps/web-ui/src/lib/liveTraffic.ts"
import { summarizeWiFi, wifiActivityQuery } from "../../apps/web-ui/src/lib/wifiActivity.ts"
import { webUIFile } from "./web-ui-source.mjs"

const PHONE = `device-${"72".repeat(16)}`
const base = { record_id: "r", source: "HOST", occurred_at: "2026-10-02T12:00:00Z", received_at: "", source_version: "", parser_version: "", confidence: 90 }
const wifiEvent = (kind, wifi, extra = {}) => ({ ...base, kind, protocol: "802.11", service: "wifi", app_protocol: "wifi", wifi: { scope: "lab", ...wifi }, ...extra })

test("Wi-Fi events read as one line each", () => {
  const probe = streamLine(wifiEvent("wifi.probe", { client_mac: "3c:22:fb:00:00:10", ssid: "HomeWiFi", signal_dbm: -52, channel: 6 }))
  assert.deepEqual(probe, { kind: "wifi", badge: "PROBE", name: "search for “HomeWiFi”", detail: "-52 dBm · ch 6", peer: "", problem: false })
  assert.equal(streamLine(wifiEvent("wifi.probe", { wildcard: true })).name, "scan for any network")
  const possible = streamLine(wifiEvent("wifi.probe", { client_mac: "da:a1:19:00:00:01", randomized_mac: true, ssid: "Work", possible_mac: "3c:22:fb:00:00:10" }))
  assert.match(possible.detail, /possibly 3c:22:fb:00:00:10/)
  const join = streamLine(wifiEvent("wifi.assoc", { ssid: "ShakerProxy-Lab", bssid: "aa:bb:cc:00:00:01", success: true }))
  assert.equal(join.badge, "JOIN")
  assert.equal(join.detail, "joined")
  const roam = streamLine(wifiEvent("wifi.assoc", { ssid: "Office", bssid: "aa:bb:cc:00:00:02", success: true, reassociation: true, previous_bssid: "aa:bb:cc:00:00:01" }))
  assert.equal(roam.badge, "ROAM")
  assert.match(roam.detail, /roamed from aa:bb:cc:00:00:01/)
  const refused = streamLine(wifiEvent("wifi.assoc", { ssid: "Lab", success: false, status: "access point is full" }))
  assert.ok(refused.problem)
  assert.match(refused.detail, /refused: access point is full/)
  const dropped = streamLine(wifiEvent("wifi.deauth", { ssid: "Lab", direction: "from_ap", reason: "4-way handshake timeout (often a wrong password)", reason_code: 15 }))
  assert.equal(dropped.badge, "DEAUTH")
  assert.ok(dropped.problem)
  assert.match(dropped.detail, /dropped by the access point · 4-way handshake timeout/)
  const hidden = streamLine(wifiEvent("wifi.disassoc", { ssid: "Lab", direction: "from_client", protected: true }))
  assert.match(hidden.detail, /reason hidden/)
  const beacon = streamLine(wifiEvent("wifi.beacon_summary", { scope: "nearby", ssid: "Cafe", bssid: "10:22:33:00:00:09", security: "open", signal_min_dbm: -80, signal_max_dbm: -70, channel: 11 }))
  assert.equal(beacon.badge, "AP")
  assert.ok(beacon.problem, "an open network is worth a look")
  assert.equal(beacon.detail, "open · -80…-70 dBm · ch 11")
  // Only the gateway's HOST events count as Wi-Fi.
  assert.notEqual(streamKind({ ...base, source: "ZEEK", kind: "wifi.probe" }), "wifi")
})

test("Wi-Fi rows go from the device to the network", () => {
  const ends = streamEnds(wifiEvent("wifi.probe", { client_mac: "3c:22:fb:00:00:10", ssid: "HomeWiFi" }), "Pixel")
  assert.deepEqual(ends.from, { primary: "Pixel", secondary: "3c:22:fb:00:00:10" })
  assert.equal(ends.to.primary, "“HomeWiFi”")
  const unknown = streamEnds(wifiEvent("wifi.probe", { client_mac: "da:a1:19:00:00:01", randomized_mac: true, wildcard: true }), "")
  assert.deepEqual(unknown.from, { primary: "da:a1:19:00:00:01", secondary: "randomized address" })
  const dropped = streamEnds(wifiEvent("wifi.deauth", { client_mac: "3c:22:fb:00:00:10", ssid: "Lab", bssid: "aa:bb:cc:00:00:01", direction: "from_ap" }), "Pixel")
  assert.ok(dropped.inbound)
  assert.equal(dropped.from.primary, "“Lab”")
  assert.equal(dropped.to.primary, "Pixel")
})

test("the Wi-Fi chip selects Wi-Fi events and fits the term limit", () => {
  assert.ok(ALL_STREAM_KINDS.includes("wifi"))
  assert.equal(composeLiveQuery({ kinds: ["wifi"], clients: [], time: "", search: "" }), "kind:wifi.*")
  const allButWiFi = composeLiveQuery({ kinds: ALL_STREAM_KINDS.filter((kind) => kind !== "wifi"), clients: [], time: "", search: "" })
  assert.match(allButWiFi, /AND NOT kind:wifi\.\*\)$/)
})

test("a device's Wi-Fi panel lists searches, joins and addresses", () => {
  assert.equal(wifiActivityQuery([PHONE]), `time:last_7d AND kind:wifi.* AND NOT kind:wifi.beacon_summary AND device.id:${PHONE}`)
  const activity = summarizeWiFi([
    wifiEvent("wifi.probe", { client_mac: "3c:22:fb:00:00:10", ssid: "HomeWiFi" }, { occurred_at: "2026-10-02T12:00:00Z" }),
    wifiEvent("wifi.probe", { client_mac: "da:a1:19:00:00:01", randomized_mac: true, possible_mac: "3c:22:fb:00:00:10", ssid: "HomeWiFi" }, { occurred_at: "2026-10-02T12:01:00Z" }),
    wifiEvent("wifi.probe", { client_mac: "3c:22:fb:00:00:10", ssid: "Hotel" }, { occurred_at: "2026-10-02T11:00:00Z" }),
    wifiEvent("wifi.assoc", { client_mac: "3c:22:fb:00:00:10", ssid: "Lab", success: true }, { occurred_at: "2026-10-02T12:02:00Z" }),
    wifiEvent("wifi.deauth", { client_mac: "3c:22:fb:00:00:10", ssid: "Lab", direction: "from_ap", reason: "disassociated due to inactivity" }, { occurred_at: "2026-10-02T12:03:00Z" }),
    wifiEvent("wifi.auth", { client_mac: "3c:22:fb:00:00:10", ssid: "Lab", success: true }, { occurred_at: "2026-10-02T12:02:00Z" }),
  ])
  assert.deepEqual(activity.networks.map((network) => [network.ssid, network.count]), [["HomeWiFi", 2], ["Hotel", 1]])
  assert.deepEqual(activity.moments.map((moment) => moment.text), ["Dropped by “Lab” (disassociated due to inactivity)", "Joined “Lab”"])
  assert.deepEqual(activity.addresses.map((address) => [address.mac, address.randomized, address.possible]), [["3c:22:fb:00:00:10", false, false], ["da:a1:19:00:00:01", true, true]])
})

test("the System page has the Wi-Fi switch and nearby recording needs a confirmation", () => {
  const panel = webUIFile("workspaces/system/WiFiVisibilityPanel.tsx")
  assert.match(panel, /api<WiFiVisibility>\("\/api\/v1\/wifi-visibility"\)/)
  assert.match(panel, /\{ nearby: true, acknowledge_nearby: true \}/)
  assert.match(panel, /records people who are not part of\s+your test/)
  assert.match(webUIFile("workspaces/devices/DeviceDetailDrawer.tsx"), /<DeviceWiFiPanel deviceID=\{device\.id\} formerIDs=\{device\.former_ids\} \/>/)
})
