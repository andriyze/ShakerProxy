import assert from "node:assert/strict"
import test from "node:test"
import { deviceDirectory, deviceIPv4, deviceTitle, eventDeviceTitle } from "../../apps/web-ui/src/lib/deviceTitle.ts"
import { webUIFile } from "./web-ui-source.mjs"

const PHONE = `device-${"72".repeat(16)}`
const FORMER = `device-${"09".repeat(16)}`

function device(overrides = {}) {
  return {
    id: PHONE,
    identities: [
      { kind: "MAC", value: "8a:23:46:10:cf:33", source: "ARP", confidence: 70, first_seen: "2026-10-01T13:00:00Z", last_seen: "2026-10-01T13:01:00Z" },
      { kind: "MAC", value: "72:58:49:e8:e4:00", source: "ARP", confidence: 70, first_seen: "2026-10-02T00:00:00Z", last_seen: "2026-10-02T01:00:00Z" },
    ],
    addresses: [
      { address: "192.168.10.201", family: "IPv4", source: "ARP", confidence: 70, valid_from: "", valid_until: "", observed_at: "2026-10-02T01:00:00Z", active: true },
      { address: "fe80::1", family: "IPv6", source: "NDP", confidence: 70, valid_from: "", valid_until: "", observed_at: "2026-10-02T01:00:00Z", active: true },
    ],
    hostnames: [],
    first_seen: "2026-10-01T13:00:00Z",
    last_seen: "2026-10-02T01:00:00Z",
    online: true,
    attribution_confidence: 70,
    last_reconciled: "2026-10-02T01:00:00Z",
    ...overrides,
  }
}

const GRAPHENE = { platform: "GrapheneOS phone", domain: "connectivitycheck.grapheneos.network", last_seen: "2026-10-02T01:00:00Z" }

test("a device is titled by name and IPv4, never by its private MAC", () => {
  assert.equal(deviceTitle(device(), "", GRAPHENE), "GrapheneOS phone · 192.168.10.201")
  assert.equal(deviceTitle(device()), "Device with a private Wi-Fi address · 192.168.10.201")
  assert.equal(deviceTitle(device({ friendly_name: "Pixel 9" }), "", GRAPHENE), "Pixel 9 · 192.168.10.201")
  const named = device({ hostnames: [{ hostname: "andriys-pixel", source: "DHCP4_LEASE", confidence: 80, first_seen: "", last_seen: "2026-10-02T00:00:00Z" }] })
  assert.equal(deviceTitle(named, "", GRAPHENE), "andriys-pixel · 192.168.10.201", "the name a device broadcasts beats the platform hint")
  const tv = device({
    identities: [{ kind: "MAC", value: "00:1a:2b:3c:4d:5e", source: "ARP", confidence: 70, first_seen: "", last_seen: "" }],
    vendor: { name: "LG Electronics", registry: "MA-L", assignment: "001A2B", confidence: 90, database_sha256: "", observed_at: "" },
  })
  assert.equal(deviceTitle(tv), "LG Electronics · 192.168.10.201")
})

test("the pinned address wins, then the current one, then the event's", () => {
  assert.equal(deviceIPv4(device({ pinned_address: "192.168.10.50" })), "192.168.10.50")
  const offline = device({
    addresses: [{ address: "192.168.10.201", family: "IPv4", source: "ARP", confidence: 70, valid_from: "", valid_until: "", observed_at: "2026-10-01T13:00:00Z", active: false }],
  })
  assert.equal(deviceIPv4(offline, "192.168.10.77"), "192.168.10.77")
  assert.equal(deviceIPv4(offline), "192.168.10.201")
  assert.equal(deviceTitle(device({ addresses: [] }), "", GRAPHENE), "GrapheneOS phone")
  assert.equal(deviceTitle(device({ addresses: [], identities: [] })), PHONE)
})

test("traffic recorded under a merged record finds the device", () => {
  const directory = deviceDirectory([device({ former_ids: [FORMER], friendly_name: "Pixel 9" })], { [PHONE]: GRAPHENE })
  const event = { device_id: FORMER, attribution_evidence: { address: "192.168.10.201" } }
  assert.equal(eventDeviceTitle(event, directory), "Pixel 9 · 192.168.10.201")
  assert.equal(eventDeviceTitle({ device_id: PHONE, device_friendly_name: "Pixel 9", attribution_evidence: { address: "192.168.10.9" } }), "Pixel 9 · 192.168.10.9")
  assert.equal(eventDeviceTitle({ device_id: PHONE }), PHONE)
})

test("devices, the drawer and Traffic all use the shared title", () => {
  assert.match(webUIFile("workspaces/devices/DeviceRow.tsx"), /deviceTitle\(device, "", platformHint, serviceHint\)/)
  assert.match(webUIFile("workspaces/devices/DeviceRow.tsx"), />\s*Rename\s*</)
  assert.match(webUIFile("workspaces/devices/DeviceDetailDrawer.tsx"), /deviceTitle\(device, "", platformHint, serviceHint\)/)
  assert.match(webUIFile("workspaces/traffic/TrafficTable.tsx"), /eventDeviceTitle\(item, directory\)/)
  assert.doesNotMatch(webUIFile("workspaces/devices/DeviceInventory.tsx"), /address assignments \(DHCP\)\. /)
})

test("a device the router leased is titled by its own DHCP name and says how it was identified", async () => {
  const { dhcpIdentityParts, platformEvidence } = await import("../../apps/web-ui/src/lib/deviceTitle.ts")
  const ipad = device({
    hostnames: [{ hostname: "ipad", source: "OBSERVED_DHCP", confidence: 70, first_seen: "2026-10-02T01:00:00Z", last_seen: "2026-10-02T01:00:00Z" }],
    observed_dhcp: { hardware_addr: "0e:47:eb:9f:1b:6a", host_name: "iPad", parameter_list: "1,121,3,6,15,108,114,119,252,95,44,46", server: "192.168.10.1", router: "192.168.10.1", last_seen: "2026-10-02T01:00:00Z" },
  })
  assert.equal(deviceTitle(ipad), "iPad · 192.168.10.201", "the device's own spelling, not the lower-cased evidence")
  assert.equal(deviceTitle(device({ friendly_name: "Kitchen iPad", observed_dhcp: ipad.observed_dhcp, hostnames: ipad.hostnames })), "Kitchen iPad · 192.168.10.201")
  assert.deepEqual(dhcpIdentityParts(ipad), ["calls itself iPad", "asks for options 1,121,3,6,15,108,114,119,252,95,44,46", "answered by 192.168.10.1"])
  assert.deepEqual(dhcpIdentityParts(device()), [])
  const android = device({ observed_dhcp: { hardware_addr: "3c:28:6d:65:54:a2", vendor_class: "android-dhcp-14", server: "192.168.10.1", router: "192.168.10.254", last_seen: "2026-10-02T01:00:00Z" } })
  assert.deepEqual(dhcpIdentityParts(android), ["android-dhcp-14", "answered by 192.168.10.1 (gateway 192.168.10.254)"])
  const dhcpHint = { platform: "Android device", source: "dhcp", detail: "android-dhcp-14", last_seen: "2026-10-02T01:00:00Z" }
  assert.equal(deviceTitle(android, "", dhcpHint), "Android device · 192.168.10.201")
  assert.equal(platformEvidence(dhcpHint), "Identified from its DHCP request: android-dhcp-14")
  assert.equal(platformEvidence(GRAPHENE), "Identified from its system traffic to connectivitycheck.grapheneos.network")
  assert.match(webUIFile("workspaces/devices/DeviceRow.tsx"), /platformEvidence\(platformHint\)/)
  assert.match(webUIFile("workspaces/devices/DeviceDetailDrawer.tsx"), /dhcpIdentityParts\(device\)/)
})
