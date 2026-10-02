import assert from "node:assert/strict"
import test from "node:test"
import { inlineBridgeFields, routerGuess } from "../../apps/web-ui/src/lib/inlineBridgePlan.ts"
import { extensionsApply } from "../../apps/web-ui/src/lib/planExtensions.ts"
import { webUIFile } from "./web-ui-source.mjs"

test("the inline bridge keeps ShakerProxy's address and makes the network the lab", () => {
  const fields = inlineBridgeFields(" 192.168.10.177/24 ", "192.168.10.1", { workingConnection: true, cloudInit: false })
  assert.deepEqual(fields.wan, {
    ipv4_mode: "STATIC",
    ipv4_address: "192.168.10.177/24",
    ipv4_gateway: "192.168.10.1",
    ipv6_mode: "SLAAC",
    dns_mode: "USE_DHCP",
    upstream_nat: false,
    clamp_mss: false,
    allow_working_wan_change: true,
    allow_cloud_init_override: false,
  })
  assert.deepEqual(fields.ipv4, {
    enabled: true,
    lab_cidr: "192.168.10.0/24",
    gateway_address: "192.168.10.177",
    nat44: false,
    client_isolation: false,
  })
  assert.deepEqual(fields.ipv6, { strategy: "OBSERVE_ONLY" })
})

test("the router is guessed from the network ShakerProxy is on", () => {
  assert.equal(routerGuess("192.168.10.177/24"), "192.168.10.1")
  assert.equal(routerGuess("10.0.5.9/16"), "10.0.0.1")
  assert.equal(routerGuess("10.0.5.9/32"), "")
  assert.equal(routerGuess("not an address"), "")
})

test("the Network page offers the inline bridge without Wi-Fi or IPv6 extensions", async () => {
  assert.equal(extensionsApply("TRANSPARENT_BRIDGE"), false)
  const source = await webUIFile("workspaces/network/NetworkPlanBuilder.tsx")
  assert.match(source, /<option value="TRANSPARENT_BRIDGE">/)
  assert.doesNotMatch(source, /Transparent inline bridge · post-v1/)
})
