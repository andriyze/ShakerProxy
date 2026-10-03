import assert from "node:assert/strict"
import test from "node:test"
import { deviceDirectory, deviceName, deviceTitle, serviceSummary } from "../../apps/web-ui/src/lib/deviceTitle.ts"

const PHONE = `device-${"72".repeat(16)}`

function device(overrides = {}) {
  return {
    id: PHONE,
    identities: [{ kind: "MAC", value: "00:1a:2b:3c:4d:5e", source: "ARP", confidence: 70, first_seen: "", last_seen: "" }],
    addresses: [{ address: "192.168.10.201", family: "IPv4", source: "ARP", confidence: 70, valid_from: "", valid_until: "", observed_at: "2026-10-02T01:00:00Z", active: true }],
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
const CASTER = {
  type: "Chromecast / Google Cast device",
  services: [
    { service: "_googlecast._tcp", label: "Google Cast", last_seen: "2026-10-02T01:00:00Z" },
    { service: "_spotify-connect._tcp", label: "Spotify Connect", last_seen: "2026-10-02T00:50:00Z" },
  ],
  last_seen: "2026-10-02T01:00:00Z",
}

test("the discovery type names an otherwise-unknown device", () => {
  assert.equal(deviceTitle(device(), "", undefined, CASTER), "Chromecast / Google Cast device · 192.168.10.201")
  assert.equal(deviceName(device(), undefined, CASTER).source, "services")
})

test("a platform hint and a friendly name beat the discovery type", () => {
  assert.equal(deviceName(device(), GRAPHENE, CASTER).source, "platform")
  assert.equal(deviceTitle(device({ friendly_name: "Living room TV" }), "", undefined, CASTER), "Living room TV · 192.168.10.201")
})

test("serviceSummary lists the service labels", () => {
  assert.equal(serviceSummary(CASTER), "Google Cast, Spotify Connect")
  assert.equal(serviceSummary(undefined), "")
})

test("the directory threads service hints so Live-view titles use them", () => {
  const directory = deviceDirectory([device()], {}, { [PHONE]: CASTER })
  assert.equal(directory.get(PHONE).services.type, "Chromecast / Google Cast device")
})
