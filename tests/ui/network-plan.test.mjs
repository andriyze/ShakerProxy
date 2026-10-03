import assert from "node:assert/strict"
import test from "node:test"
import {
  applyExtensionRoles,
  extensionsApply,
  interfaceLabel,
  mergePlanExtensions,
  shellRoles,
} from "../../apps/web-ui/src/lib/planExtensions.ts"
import {
  describePhase,
  formatCountdown,
  isTransactionActive,
  pollInterval,
  secondsLeft,
  shouldSendHeartbeat,
} from "../../apps/web-ui/src/lib/networkTransaction.ts"
import { webUIFile } from "./web-ui-source.mjs"

const interfaces = [
  { name: "eth0", stable_id: "pci:1", hardware_address: "aa" },
  { name: "eth1", stable_id: "pci:2", hardware_address: "bb" },
  { name: "wlan0", stable_id: "pci:3", hardware_address: "cc" },
]

test("extension values are merged under their plan key", () => {
  const plan = { schema: 1, ipv6: { strategy: "DISABLED" } }
  const merged = mergePlanExtensions(plan, { ipv6: { strategy: "ULA_NAT66_LAB" }, wifi: { enabled: true } }, ["ipv6", "wifi"])
  assert.deepEqual(merged.ipv6, { strategy: "ULA_NAT66_LAB" })
  assert.deepEqual(merged.wifi, { enabled: true })
  assert.deepEqual(plan.ipv6, { strategy: "DISABLED" }, "input plan is not mutated")
  // An extension without a value leaves the shell's value alone.
  assert.deepEqual(mergePlanExtensions(plan, {}, ["ipv6"]).ipv6, { strategy: "DISABLED" })
  assert.equal(extensionsApply("TWO_NIC"), true)
  assert.equal(extensionsApply("PASSIVE_SENSOR"), false)
  assert.equal(extensionsApply("SINGLE_ARM"), false)
})

test("extension roles add or replace interface roles", () => {
  const planned = [
    { stable_id: "pci:1", current_name: "eth0", role: "WAN" },
    { stable_id: "pci:2", current_name: "eth1", role: "LAB" },
  ]
  const withAP = applyExtensionRoles(planned, { "pci:3": "WIFI_AP" }, interfaces)
  assert.deepEqual(withAP.at(-1), { stable_id: "pci:3", current_name: "wlan0", permanent_mac: "cc", role: "WIFI_AP" })
  assert.equal(planned.length, 2, "input is not mutated")
  const replaced = applyExtensionRoles(planned, { "pci:2": "WIFI_AP" }, interfaces)
  assert.equal(replaced.length, 2)
  assert.equal(replaced[1].role, "WIFI_AP")
  assert.equal(applyExtensionRoles(planned, { "pci:3": "" }, interfaces).length, 2)
  assert.deepEqual(shellRoles([{ stableID: "pci:1", role: "WAN" }, { stableID: undefined, role: "LAB" }]), { "pci:1": "WAN" })
})

test("wireless interfaces are labelled", () => {
  assert.equal(interfaceLabel({ name: "wlan0", wireless: true, ap_supported: true }), "wlan0 · Wi-Fi (can host an access point)")
  assert.equal(interfaceLabel({ name: "wlan1", wireless: true, ap_supported: null }), "wlan1 · Wi-Fi")
  assert.equal(interfaceLabel({ name: "eth0", driver: "e1000e" }), "eth0 · e1000e")
})

test("the browser heartbeat is sent only once the host waits for health evidence", () => {
  assert.equal(shouldSendHeartbeat("ACCEPTED", false), false)
  assert.equal(shouldSendHeartbeat("APPLYING", false), false)
  assert.equal(shouldSendHeartbeat("AWAITING_HEALTH", false), true)
  assert.equal(shouldSendHeartbeat("AWAITING_HEALTH", true), false)
  const change = webUIFile("workspaces/network/NetworkChange.tsx")
  // Commit stores the token; it does not post the heartbeat itself.
  const commit = change.slice(change.indexOf("async function commit"), change.indexOf("async function confirm"))
  assert.doesNotMatch(commit, /\/heartbeat/)
  assert.match(commit, /storeHeartbeat\(summary\.apply_id, \{ token: committed\.health_token/)
  // The shell sends it, so it keeps going on other pages and in hidden tabs,
  // with a timeout per request so a hung connection cannot stall the loop.
  const watcher = webUIFile("shell/networkHeartbeat.tsx")
  assert.match(watcher, /shouldSendHeartbeat\(plan\.status, sent\.current\.has\(watching\)\)/)
  assert.match(watcher, /whileHidden: true/)
  assert.match(watcher, /timeoutSignal\(signal, REQUEST_TIMEOUT_MS\)/)
  assert.match(webUIFile("shell/Dashboard.tsx"), /<NetworkHeartbeat \/>/)
})

test("staged and in-flight changes are tracked until final", () => {
  assert.equal(isTransactionActive("STAGED_NOT_APPLIED"), true)
  assert.equal(isTransactionActive("AWAITING_CONFIRMATION"), true)
  assert.equal(isTransactionActive("CONFIRMED"), false)
  assert.equal(isTransactionActive(undefined), false)
  assert.equal(pollInterval("APPLYING"), 1000)
  assert.equal(pollInterval("AWAITING_CONFIRMATION"), 2000)
  assert.equal(pollInterval("ROLLED_BACK"), 0)
  assert.equal(secondsLeft("2026-09-29T00:01:30Z", Date.parse("2026-09-29T00:00:00Z")), 90)
  assert.equal(secondsLeft("2026-09-29T00:00:00Z", Date.parse("2026-09-29T00:01:00Z")), 0)
  assert.equal(secondsLeft(undefined, 0), null)
  assert.equal(formatCountdown(90), "1:30")
  assert.match(describePhase("AWAITING_CONFIRMATION"), /Confirm to keep it/)
})

test("the plan builder renders registered plan extensions and restores staged changes", () => {
  const builder = webUIFile("workspaces/network/NetworkPlanBuilder.tsx")
  assert.match(builder, /sortedPlanExtensions\(\)/)
  assert.match(builder, /<extension\.Component planKey=\{extension\.planKey\}/)
  assert.match(builder, /onRoleChange=\{updateRole\}/)
  // The shell's own IPv6 control appears only where the IPv6 extension does not.
  assert.match(builder, /!activeKeys\.has\("ipv6"\)/)
  assert.match(builder, /status\?\.staged_network_plan/)
  assert.match(builder, /restored: true/)
  const types = webUIFile("types.ts")
  assert.match(types, /wireless\?: boolean/)
  assert.match(types, /ap_supported\?: boolean \| null/)
  assert.match(types, /wireless_bands\?: string\[\]/)
  assert.match(types, /hostapd_conf\?: string/)
  assert.match(types, /firewall_restore_ipv6\?: string/)
  assert.match(types, /radvd_conf\?: string/)
})

test("the running lab is recognised, including behind a staged candidate", async () => {
  const { runningLab } = await import("../../apps/web-ui/src/lib/networkTransaction.ts")
  assert.equal(runningLab(null), null)
  assert.equal(runningLab({ operating_mode: "SETUP_SAFE" }), null)
  assert.equal(runningLab({ operating_mode: "ROUTED_PASSTHROUGH" }), null, "no lab interface: nothing to turn off")
  assert.deepEqual(
    runningLab({ operating_mode: "ROUTED_PASSTHROUGH", lab_interface: "ens5", staged_network_plan: { plan_hash: "abc", status: "CONFIRMED" } }),
    { labInterface: "ens5", planHash: "abc", bypass: false },
  )
  assert.deepEqual(
    runningLab({
      operating_mode: "ROUTED_PASSTHROUGH",
      lab_interface: "ens5",
      staged_network_plan: { plan_hash: "new", status: "STAGED_NOT_APPLIED" },
      confirmed_network_plan: { plan_hash: "running" },
    }),
    { labInterface: "ens5", planHash: "running", bypass: false },
    "a staged candidate does not hide the running plan",
  )
  assert.equal(runningLab({ operating_mode: "EMERGENCY", emergency_bypass: true, lab_interface: "enp2s0" }).bypass, true)
})

test("the Network page offers to turn the lab network off with the password", () => {
  const component = webUIFile("workspaces/network/LabNetworkOff.tsx")
  assert.match(component, /withPassword\("turn off the lab network"/)
  assert.match(component, /\/api\/v1\/network\/active\/revert/)
  assert.match(webUIFile("workspaces/network/NetworkWorkspace.tsx"), /<LabNetworkOff \/>/)
})

test("single-arm plans prefill the LAN network, not the computer's own address", async () => {
  const { ipv4NetworkCIDR } = await import("../../apps/web-ui/src/lib/networkTransaction.ts")
  assert.equal(ipv4NetworkCIDR("192.168.10.177/24"), "192.168.10.0/24")
  assert.equal(ipv4NetworkCIDR("10.1.2.3/8"), "10.0.0.0/8")
  assert.equal(ipv4NetworkCIDR("172.16.5.9/32"), "172.16.5.9/32")
  assert.equal(ipv4NetworkCIDR("not-an-address"), "not-an-address")
})

test("a one-port computer starts on the one-port topology and cannot pick the same port twice", async () => {
  const source = webUIFile("workspaces/network/NetworkPlanBuilder.tsx")
  assert.match(source, /useState<NetworkTopology>\(interfaces\.length < 2 \? "SINGLE_ARM" : "TWO_NIC"\)/)
  assert.match(source, /One network port \(devices use ShakerProxy as their gateway\)/)
  assert.match(source, /The internet \(WAN\) and lab need different ports\./)
  assert.match(source, /disabled=\{busy \|\| interfaces\.length < requiredInterfaces \|\| sameWANAndLab\}/)
  assert.match(source, /ipv4NetworkCIDR\(selectedIPv4HostCIDR\)/)
  assert.match(source, /this computer has \$\{interfaces\.length\}\.\$\{interfaces\.length === 1 \? " Choose “One network port” as the topology\." : ""\}/)
})

test("after saving, the page says the plan still has to be applied", async () => {
  const source = webUIFile("workspaces/network/NetworkChange.tsx")
  assert.match(source, /Saved — now apply it/)
  assert.match(source, /autoComplete="current-password" required autoFocus/)
})

test("a device without hostnames (seen only in the ARP table) does not break the Devices page", () => {
  const row = webUIFile("workspaces/devices/DeviceRow.tsx")
  // The row's title comes from the shared helper, which guards hostnames.
  assert.match(row, /deviceTitle\(device, "", platformHint, serviceHint\)/)
  assert.match(webUIFile("lib/deviceTitle.ts"), /device\.hostnames \?\? \[\]/)
  assert.doesNotMatch(row, /device\.hostnames\.at\(/)
  assert.match(webUIFile("workspaces/devices/DeviceDetailDrawer.tsx"), /device\.hostnames\?\.length/)
})
