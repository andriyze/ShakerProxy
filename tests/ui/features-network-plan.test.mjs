import assert from "node:assert/strict"
import test from "node:test"
import {
  derivedAddresses,
  formatIPv6,
  generateULAPrefix,
  isULA,
  normalizeIPv6Plan,
  parseIPv6,
  parseIPv6Prefix,
  planForStrategy,
  prefixContains,
  validateIPv6Plan,
} from "../../apps/web-ui/src/features/ipv6-model.ts"
import {
  apSupport,
  channelsFor,
  countryFromLocale,
  defaultWifiPlan,
  generatePassphrase,
  normalizeWifiPlan,
  validateWifiPlan,
  wifiTopologySupport,
  wirelessInterfaces,
} from "../../apps/web-ui/src/features/wifi-model.ts"
import { serverPlanIssues } from "../../apps/web-ui/src/features/plan-issues.ts"

const fixedBytes = (values) => (bytes) => {
  for (let i = 0; i < bytes.length; i++) bytes[i] = values[i % values.length]
}

test("ULA generation follows RFC 4193: fd00::/8, 40-bit global ID, subnet 1, /64", () => {
  assert.equal(generateULAPrefix(fixedBytes([0x12, 0x34, 0x56, 0x78, 0x9a])), "fd12:3456:789a:1::/64")
  // RFC 5952 compresses the longest zero run (the interface ID), not the first.
  assert.equal(generateULAPrefix(fixedBytes([0, 0, 0, 0, 0])), "fd00:0:0:1::/64")
  const seen = new Set()
  for (let i = 0; i < 20; i++) {
    const prefix = generateULAPrefix()
    const parsed = parseIPv6Prefix(prefix)
    assert.ok(parsed && parsed.length === 64 && isULA(parsed.groups), prefix)
    assert.equal(parsed.groups[0] >> 8, 0xfd, "L bit set (fd, not fc)")
    assert.equal(parsed.groups[3], 1)
    seen.add(prefix)
  }
  assert.ok(seen.size > 15, "random global IDs differ")
  assert.throws(() => generateULAPrefix(fixedBytes([1]), 0x10000), RangeError)
})

test("IPv6 parsing and RFC 5952 formatting", () => {
  const cases = [
    ["2001:0db8:0000:0000:0000:0000:0002:0001", "2001:db8::2:1"],
    ["2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"],
    ["2001:db8:0:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"],
    ["::", "::"],
    ["::1", "::1"],
    ["FD12:3456:789A:1::1", "fd12:3456:789a:1::1"],
    ["::ffff:10.0.0.1", "::ffff:a00:1"],
    ["fe80::", "fe80::"],
  ]
  for (const [input, canonical] of cases) assert.equal(formatIPv6(parseIPv6(input)), canonical, input)
  for (const bad of ["", "1::2::3", "12345::", "fe80::1%eth0", "1:2:3:4:5:6:7:8:9", "::g", "fd00::/64", "::ffff:10.0.0.256", "::ffff:10.0.0.01", ":1::"]) {
    assert.equal(parseIPv6(bad), undefined, bad)
  }
})

test("gateway and DNS are derived from the /64", () => {
  assert.deepEqual(derivedAddresses("fd12:3456:789a:1::/64"), { gateway_address: "fd12:3456:789a:1::1", dns_addresses: ["fd12:3456:789a:1::1"] })
  assert.equal(derivedAddresses("fd12:3456:789a::/48"), undefined)
  assert.equal(derivedAddresses("nonsense"), undefined)
  const prefix = parseIPv6Prefix("fd12:3456:789a:1::/64")
  assert.ok(prefixContains(prefix, parseIPv6("fd12:3456:789a:1::abcd")))
  assert.ok(!prefixContains(prefix, parseIPv6("fd12:3456:789a:2::1")))
})

test("IPv6 plan validation mirrors the plan contract", () => {
  assert.deepEqual(validateIPv6Plan({ strategy: "DISABLED" }), [])
  assert.deepEqual(validateIPv6Plan({ strategy: "OBSERVE_ONLY" }), [])
  const good = { strategy: "ULA_NAT66_LAB", lab_prefix: "fd12:3456:789a:1::/64", gateway_address: "fd12:3456:789a:1::1", dns_addresses: ["fd12:3456:789a:1::1"] }
  assert.deepEqual(validateIPv6Plan(good), [])
  const fields = (plan) => validateIPv6Plan(plan).map((issue) => issue.field)
  assert.deepEqual(fields({ ...good, lab_prefix: "2001:db8:1:1::/64", gateway_address: "2001:db8:1:1::1" }), ["lab_prefix"], "ULA strategy needs an fd prefix")
  assert.deepEqual(fields({ ...good, lab_prefix: "fd12:3456:789a::/48" }), ["lab_prefix"], "must be a /64")
  assert.deepEqual(fields({ ...good, lab_prefix: "fd12:3456:789a:1::5/64" }), ["lab_prefix"], "host bits set")
  assert.deepEqual(fields({ ...good, gateway_address: "fd12:3456:789a:2::1" }), ["gateway_address"])
  assert.deepEqual(fields({ ...good, gateway_address: "fd12:3456:789a:1::" }), ["gateway_address"])
  assert.deepEqual(fields({ ...good, dns_addresses: [] }), ["dns_addresses"])
  assert.deepEqual(fields({ ...good, dns_addresses: ["10.0.0.1"] }), ["dns_addresses"])
  const routed = { strategy: "NATIVE_ROUTED_PREFIX", lab_prefix: "2001:db8:1:1::/64", gateway_address: "2001:db8:1:1::1", dns_addresses: ["2001:db8:1:1::1"] }
  assert.deepEqual(validateIPv6Plan(routed), [])
  assert.deepEqual(fields({ ...routed, lab_prefix: "fd12:3456:789a:1::/64", gateway_address: "fd12:3456:789a:1::1", dns_addresses: ["fd12:3456:789a:1::1"] }), ["lab_prefix"])
  assert.deepEqual(fields({ strategy: "PREFIX_DELEGATION" }), ["strategy"])
  assert.deepEqual(fields({ strategy: "BOGUS" }), ["strategy"])
})

test("switching strategy generates or drops addresses", () => {
  const ula = planForStrategy({ strategy: "DISABLED" }, "ULA_NAT66_LAB", fixedBytes([0xab, 0xcd, 0xef, 0x01, 0x23]))
  assert.deepEqual(ula, { strategy: "ULA_NAT66_LAB", lab_prefix: "fdab:cdef:123:1::/64", gateway_address: "fdab:cdef:123:1::1", dns_addresses: ["fdab:cdef:123:1::1"] })
  assert.deepEqual(validateIPv6Plan(ula), [])
  assert.deepEqual(planForStrategy(ula, "ULA_NAT66_LAB", fixedBytes([1])), ula, "keeps an existing ULA prefix")
  assert.deepEqual(planForStrategy(ula, "DISABLED"), { strategy: "DISABLED" })
  assert.equal(planForStrategy(ula, "NATIVE_ROUTED_PREFIX").lab_prefix, "", "a private prefix is not a routed prefix")
  assert.deepEqual(normalizeIPv6Plan(undefined), { strategy: "DISABLED" })
  assert.deepEqual(normalizeIPv6Plan({ strategy: "NOPE", lab_prefix: 5 }), { strategy: "DISABLED" })
  assert.deepEqual(normalizeIPv6Plan({ strategy: "ULA_NAT66_LAB", dns_addresses: ["a", 1] }), { strategy: "ULA_NAT66_LAB", dns_addresses: ["a"] })
})

test("Wi-Fi channel lists are non-DFS and country aware", () => {
  assert.deepEqual(channelsFor("5GHZ", "US"), [36, 40, 44, 48, 149, 153, 157, 161, 165])
  assert.deepEqual(channelsFor("2.4GHZ", "US"), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])
  assert.equal(channelsFor("2.4GHZ", "DE").length, 13)
  assert.ok(!channelsFor("5GHZ", "DE").includes(52), "DFS channel 52 excluded")
})

test("country defaults come from the browser locale region", () => {
  assert.equal(countryFromLocale("en-GB"), "GB")
  assert.equal(countryFromLocale("de-Latn-AT"), "AT")
  assert.equal(countryFromLocale("en_US"), "US")
  assert.equal(countryFromLocale("en"), undefined)
  assert.equal(countryFromLocale("es-419"), undefined)
  assert.equal(countryFromLocale("und-ZZ"), undefined)
  assert.equal(countryFromLocale(undefined), undefined)
  assert.equal(defaultWifiPlan("XX").country_code, "US")
  assert.equal(defaultWifiPlan("FR").country_code, "FR")
})

test("generated passphrases are uniform, unambiguous and valid", () => {
  const passphrase = generatePassphrase()
  assert.match(passphrase, /^[a-km-np-z2-9]{4}(-[a-km-np-z2-9]{4}){3}$/)
  // The 32-character alphabet divides 256, so every byte maps to one character uniformly.
  assert.equal(generatePassphrase(fixedBytes([255, 224, 0, 1, 31, 32])), "9aab-9a9a-ab9a-9aab")
  assert.deepEqual(validateWifiPlan({ ...defaultWifiPlan("US"), passphrase }), [])
  const seen = new Set(Array.from({ length: 50 }, () => generatePassphrase()))
  assert.equal(seen.size, 50)
})

test("Wi-Fi plan validation mirrors the plan contract", () => {
  const good = { ...defaultWifiPlan("US"), passphrase: "correct horse" }
  assert.deepEqual(validateWifiPlan(good), [])
  assert.deepEqual(validateWifiPlan({ ...good, enabled: false, ssid: "" }), [], "disabled plans are not validated")
  const fields = (plan) => validateWifiPlan(plan).map((issue) => issue.field)
  assert.deepEqual(fields({ ...good, ssid: "" }), ["ssid"])
  assert.deepEqual(fields({ ...good, ssid: "📡".repeat(9) }), ["ssid"], "36 UTF-8 bytes")
  assert.deepEqual(fields({ ...good, ssid: "📡".repeat(8) }), [], "32 UTF-8 bytes")
  assert.deepEqual(fields({ ...good, passphrase: "short" }), ["passphrase"])
  assert.deepEqual(fields({ ...good, passphrase: "x".repeat(64) }), ["passphrase"])
  assert.deepEqual(fields({ ...good, passphrase: "pässwörter" }), ["passphrase"])
  assert.deepEqual(fields({ ...good, security: "OPEN", passphrase: "" }), [])
  assert.deepEqual(fields({ ...good, channel: 12 }), ["channel"])
  assert.deepEqual(fields({ ...good, country_code: "DE", channel: 13 }), [])
  assert.deepEqual(fields({ ...good, band: "5GHZ", channel: 52 }), ["channel"])
  assert.deepEqual(fields({ ...good, band: "5GHZ", channel: 149 }), [])
  assert.deepEqual(fields({ ...good, country_code: "usa" }), ["country_code"])
  assert.deepEqual(fields({ ...good, ssid: "Lab\u0085Net" }), ["ssid"], "C1 control characters are rejected like the plan validator")
  assert.deepEqual(validateWifiPlan({ ...good, bridge_with_lab: false }, { wiredLab: true }).map((issue) => issue.field), ["bridge_with_lab"], "a wired lab port requires bridging")
  assert.deepEqual(validateWifiPlan({ ...good, bridge_with_lab: false }, { wiredLab: false }), [])
})

test("Wi-Fi topology support mirrors the plan validator", () => {
  for (const topology of ["TWO_NIC", "THREE_INTERFACE", "EXISTING_ROUTED_VLAN", "ADVANCED_CUSTOM"]) assert.equal(wifiTopologySupport(topology, {}).supported, true, topology)
  for (const topology of ["SINGLE_ARM", "VLAN_TRUNK", "PASSIVE_SENSOR"]) {
    const support = wifiTopologySupport(topology, {})
    assert.equal(support.supported, false, topology)
    assert.match(support.reason, /choose a Two-NIC, Three-interface, Existing routed VLAN or Advanced plan/)
  }
  assert.equal(wifiTopologySupport(undefined, { a: "WAN_LAB" }).supported, false, "single-arm inferred from roles")
  assert.equal(wifiTopologySupport(undefined, { a: "MIRROR" }).supported, false, "passive sensor inferred from roles")
  assert.equal(wifiTopologySupport(undefined, { a: "WAN", b: "LAB" }).supported, true)
})

test("server plan issues map onto editor fields", () => {
  const validation = {
    errors: [
      { code: "WIFI_SSID_INVALID", path: "wifi.ssid", message: "SSID too long" },
      { code: "WIFI_INTERFACE_MISSING", path: "interfaces", message: "No WIFI_AP" },
      { code: "WIFI_INTERFACE_MTU_UNSUPPORTED", path: "interfaces[2].mtu", message: "MTU" },
      { code: "WIFI_TOPOLOGY_UNSUPPORTED", path: "topology", message: "Topology" },
      { code: "GATEWAY_INVALID", path: "ipv4.gateway_address", message: "not ours" },
      { code: "IPV6_PREFIX_INVALID", path: "ipv6.lab_prefix", message: "bad prefix" },
    ],
    warnings: [
      { code: "WIFI_OPEN_NETWORK", path: "wifi.security", message: "Open" },
      { code: "WIFI_HIDDEN_NETWORK", path: "wifi.hidden", message: "Hidden" },
    ],
  }
  assert.deepEqual(serverPlanIssues(validation, "wifi", "WIFI_").map((issue) => [issue.field, issue.severity]), [
    ["ssid", "error"], ["interface", "error"], ["interface", "error"], ["", "error"], ["security", "warning"], ["hidden", "warning"],
  ])
  assert.deepEqual(serverPlanIssues(validation, "ipv6", "IPV6_").map((issue) => issue.field), ["lab_prefix"])
  assert.deepEqual(serverPlanIssues(undefined, "wifi"), [])
})

test("Wi-Fi plan normalisation and interface support", () => {
  assert.equal(normalizeWifiPlan({ enabled: true, band: "5GHZ", channel: 0 }, "US").channel, 36, "channel 0 means the band default")
  assert.equal(normalizeWifiPlan({ enabled: true, band: "" }, "US").band, "2.4GHZ", "empty band means 2.4 GHz")
  assert.equal(normalizeWifiPlan({ enabled: true }, "US").channel, 6)
  assert.equal(normalizeWifiPlan(undefined, "US").enabled, false)
  const normalized = normalizeWifiPlan({ enabled: true, ssid: "Lab", channel: "6", band: "60GHZ", hidden: "yes" }, "US")
  assert.equal(normalized.ssid, "Lab")
  assert.equal(normalized.channel, 6, "non-integer channel falls back to default")
  assert.equal(normalized.band, "2.4GHZ")
  assert.equal(normalized.hidden, false)
  const ifaces = [
    { name: "eth0", stable_id: "a", addresses: [], flags: [], wireless: false },
    { name: "wlan1", stable_id: "b", addresses: [], flags: [], wireless: true, ap_supported: null },
    { name: "wlan0", stable_id: "c", addresses: [], flags: [], wireless: true, ap_supported: true },
    { name: "wlan2", stable_id: "d", addresses: [], flags: [], wireless: true, ap_supported: false },
    { name: "wlp3s0", stable_id: "e", addresses: [], flags: [] },
  ]
  assert.deepEqual(ifaces.map(apSupport), ["not-wireless", "unknown", "supported", "unsupported", "unknown"])
  assert.deepEqual(wirelessInterfaces(ifaces).map((iface) => iface.name), ["wlan0", "wlan1", "wlp3s0", "wlan2"])
})
