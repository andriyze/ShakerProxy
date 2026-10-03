import assert from "node:assert/strict"
import test from "node:test"

import { bypassHeadline, bypassingDevices, fixSteps, labDeviceTitle, labRoutingSummary } from "../../apps/web-ui/src/lib/labRouting.ts"

// The test VM on 2026-10-02: the owner's iPhone took the router's DHCP and
// browsed; ShakerProxy saw only its DHCP request and mDNS.
const report = {
  schema: 1,
  generated_at: "2026-10-02T23:52:30Z",
  available: true,
  topology: "SINGLE_ARM",
  prefix: "192.168.10.0/24",
  subnet_mask: "255.255.255.0",
  shakerproxy_address: "192.168.10.177",
  router_address: "192.168.10.1",
  threshold_seconds: 120,
  counts: { through_shakerproxy: 1, bypassing: 1, unknown: 0 },
  devices: [
    {
      address: "192.168.10.130",
      hardware_addrs: ["62:bc:f1:bc:1d:8d"],
      host_name: "iPhone",
      routing: "BYPASSING",
      since: "2026-10-02T23:48:30Z",
      last_seen: "2026-10-02T23:52:06Z",
      evidence: ["asked the network's DHCP server for 192.168.10.130", "30 local discovery messages (mDNS, SSDP and similar)", "no connections or DNS lookups through ShakerProxy"],
      reason: "It got its address from your router's DHCP, so it uses the router (192.168.10.1) as its gateway, not ShakerProxy.",
      device_id: "device-0123456789abcdef0123456789abcdef",
    },
    { address: "192.168.10.201", display_name: "Pixel", routing: "THROUGH_SHAKERPROXY", since: "2026-10-02T23:00:00Z", last_seen: "2026-10-02T23:52:00Z", evidence: [] },
  ],
}

test("the banner names the bypassing device, the router and that ShakerProxy can't see it", () => {
  const devices = bypassingDevices(report)
  assert.equal(devices.length, 1)
  assert.equal(labDeviceTitle(devices[0]), "iPhone · 192.168.10.130")
  assert.equal(
    bypassHeadline(devices[0], report),
    "iPhone · 192.168.10.130 is on the lab network, but its traffic goes straight to your router (192.168.10.1), so ShakerProxy can't see it.",
  )
  assert.deepEqual(bypassingDevices({ ...report, available: false }), [])
  assert.deepEqual(bypassingDevices(null), [])
})

test("the fix uses the device's real address, ShakerProxy's address and the lab's mask", () => {
  const steps = fixSteps(report.devices[0], report)
  assert.ok(steps.iphone.some((step) => step === "Configure IP → Manual: IP Address 192.168.10.130, Subnet Mask 255.255.255.0, Router 192.168.10.177."))
  assert.ok(steps.iphone.some((step) => step.includes("Configure DNS → Manual") && step.includes("192.168.10.177")))
  assert.ok(steps.android.some((step) => step === "IP settings: Static. IP address 192.168.10.130, Gateway 192.168.10.177, Network prefix length 24, DNS 1 192.168.10.177."))
  assert.match(steps.vpn, /VPN devices.*WireGuard/)
  assert.ok(steps.router.some((step) => step.includes('"DHCP Default Gateway" and "DNS Server" to 192.168.10.177')))
  assert.ok(steps.router.some((step) => step.includes("no internet")))
})

test("the System and Start pages count who goes through ShakerProxy", () => {
  assert.equal(labRoutingSummary(report), "1 device sends its traffic through ShakerProxy; 1 device bypasses it.")
  assert.equal(labRoutingSummary({ ...report, counts: { through_shakerproxy: 3, bypassing: 2, unknown: 0 } }), "3 devices send their traffic through ShakerProxy; 2 devices bypass it.")
  assert.equal(labRoutingSummary({ ...report, counts: { through_shakerproxy: 0, bypassing: 0, unknown: 1 } }), "1 just appeared and is not judged yet.")
  assert.equal(labRoutingSummary({ ...report, counts: { through_shakerproxy: 0, bypassing: 0, unknown: 0 } }), "No devices seen on the lab network in the last 10 minutes.")
  assert.equal(labRoutingSummary({ ...report, available: false, unavailable: "No lab network routes through ShakerProxy right now." }), "No lab network routes through ShakerProxy right now.")
})
