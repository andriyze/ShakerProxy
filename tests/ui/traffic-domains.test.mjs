import assert from "node:assert/strict"
import test from "node:test"
import { uniqueAddresses } from "../../apps/web-ui/src/lib/deviceAddresses.ts"
import { withDomain } from "../../apps/web-ui/src/lib/trafficPresets.ts"
import { webUIFile } from "./web-ui-source.mjs"

const observation = (address, active, from, until, extra = {}) => ({
  address,
  family: address.includes(":") ? "IPv6" : "IPv4",
  source: "ARP",
  confidence: 70,
  valid_from: from,
  valid_until: until,
  observed_at: until,
  active,
  interface: "ens18",
  ...extra,
})

test("a device shows each address once, and the current sighting wins", () => {
  const addresses = uniqueAddresses([
    observation("192.168.10.201", false, "2026-10-01T13:00:00Z", "2026-10-01T13:20:00Z"),
    observation("192.168.10.201", true, "2026-10-01T23:50:00Z", "2026-10-02T00:30:00Z"),
    observation("fe80::1", false, "2026-10-01T09:00:00Z", "2026-10-01T09:10:00Z"),
  ])
  assert.equal(addresses.length, 2)
  assert.deepEqual(
    { ...addresses[0] },
    {
      address: "192.168.10.201",
      interface: "ens18",
      vlan_id: undefined,
      active: true,
      first_seen: "2026-10-01T13:00:00Z",
      last_seen: "2026-10-02T00:30:00Z",
      windows: 2,
    },
  )
  assert.equal(addresses[1].address, "fe80::1")
  assert.equal(addresses[1].active, false)
})

test("the same address on another interface or VLAN stays separate", () => {
  const addresses = uniqueAddresses([
    observation("10.77.0.20", true, "2026-10-01T10:00:00Z", "2026-10-01T11:00:00Z"),
    observation("10.77.0.20", true, "2026-10-01T10:00:00Z", "2026-10-01T11:00:00Z", { vlan_id: 20 }),
  ])
  assert.equal(addresses.length, 2)
  assert.deepEqual(uniqueAddresses(null), [])
})

test("clicking a domain narrows the current filter to it", () => {
  assert.equal(withDomain("", "grapheneos.network"), "grapheneos.network")
  assert.equal(
    withDomain("device.id:device-0123456789abcdef0123456789abcdef", "googleapis.com"),
    "(device.id:device-0123456789abcdef0123456789abcdef) AND googleapis.com",
  )
  assert.equal(withDomain("a OR b", "example.com"), "(a OR b) AND example.com")
  // Anything that is not a plain domain name never reaches the filter.
  assert.equal(withDomain("source:ZEEK", "x) OR (y"), "source:ZEEK")
  assert.equal(withDomain("source:ZEEK", "localhost"), "source:ZEEK")
})

test("the Traffic page lists domains and the Devices page de-duplicates addresses", () => {
  const traffic = webUIFile("workspaces/traffic/TrafficWorkspace.tsx")
  assert.match(traffic, /<legend>Domains<\/legend>/)
  assert.match(traffic, /applyDomain\(value\.domain\)/)
  assert.match(traffic, /FACET_REFRESH_MS/)
  for (const file of ["workspaces/devices/DeviceRow.tsx", "workspaces/devices/DeviceDetailDrawer.tsx"]) {
    assert.match(webUIFile(file), /uniqueAddresses\(device\.addresses\)/)
  }
})
