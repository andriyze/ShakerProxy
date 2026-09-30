// Pure IPv6 helpers for the network-plan IPv6 editor (§8): RFC 4193 ULA
// prefix generation, RFC 5952 formatting, derived gateway/DNS addresses and
// client-side validation that mirrors the plan validator.
// Keep this file free of runtime imports so node --test can load it directly.
import type { IPv6Plan, IPv6Strategy } from "./types"

export type IPv6StrategyInfo = {
  value: IPv6Strategy
  label: string
  summary: string
  detail: string
  recommended?: boolean
  available: boolean
}

export const IPV6_STRATEGIES: readonly IPv6StrategyInfo[] = [
  {
    value: "DISABLED",
    label: "Off",
    summary: "Lab devices use IPv4 only.",
    detail: "ShakerProxy blocks IPv6 forwarding for the lab and does not advertise IPv6. Every connection goes through IPv4, where ShakerProxy sees and controls all of it. Choose this when unsure.",
    recommended: true,
    available: true,
  },
  {
    value: "OBSERVE_ONLY",
    label: "Observe only",
    summary: "Watch IPv6 without providing it.",
    detail: "ShakerProxy does not hand out IPv6 addresses but records any IPv6 traffic devices produce on the lab network (for example link-local discovery).",
    available: true,
  },
  {
    value: "ULA_NAT66_LAB",
    label: "Lab IPv6 (private prefix)",
    summary: "Give devices IPv6 using a private prefix; ShakerProxy translates it to your upstream IPv6.",
    detail: "Devices get addresses from a private fd00::/8 prefix that only exists in the lab. ShakerProxy translates (NAT66) to its upstream IPv6 address, so this works even if your network does not delegate prefixes.",
    available: true,
  },
  {
    value: "NATIVE_ROUTED_PREFIX",
    label: "Routed prefix from upstream",
    summary: "Use a public /64 your network routes to ShakerProxy.",
    detail: "Devices get real global IPv6 addresses. Only choose this if your network administrator has routed a /64 prefix to ShakerProxy's upstream address.",
    available: true,
  },
  {
    value: "PREFIX_DELEGATION",
    label: "Prefix delegation (DHCPv6-PD)",
    summary: "Not available yet.",
    detail: "Requesting a prefix automatically from the upstream router is not supported yet. Use a private lab prefix instead.",
    available: false,
  },
]

export function strategyInfo(strategy: IPv6Strategy): IPv6StrategyInfo {
  return IPV6_STRATEGIES.find((item) => item.value === strategy) ?? IPV6_STRATEGIES[0]
}

// strategyNeedsPrefix reports whether a strategy hands out addresses and so
// needs lab_prefix, gateway_address and dns_addresses.
export function strategyNeedsPrefix(strategy: IPv6Strategy): boolean {
  return strategy === "ULA_NAT66_LAB" || strategy === "NATIVE_ROUTED_PREFIX"
}

// parseIPv6 parses a textual IPv6 address (no zone, no prefix) into eight
// 16-bit groups, or returns undefined. Embedded IPv4 tails are accepted.
export function parseIPv6(text: string): number[] | undefined {
  const value = text.trim().toLowerCase()
  if (!value || value.length > 45 || value.includes("%") || value.includes("/")) return undefined
  let head = value
  let tail: number[] = []
  const ipv4 = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value)
  if (ipv4) {
    const octets = ipv4.slice(1).map(Number)
    if (octets.some((octet, index) => octet > 255 || (ipv4[index + 1].length > 1 && ipv4[index + 1].startsWith("0")))) return undefined
    tail = [(octets[0] << 8) | octets[1], (octets[2] << 8) | octets[3]]
    head = value.slice(0, value.length - ipv4[0].length)
    if (!head.endsWith(":")) return undefined
    if (!head.endsWith("::")) head = head.slice(0, -1)
  }
  const parseGroups = (part: string): number[] | undefined => {
    if (part === "") return []
    const groups = part.split(":")
    const result: number[] = []
    for (const group of groups) {
      if (!/^[0-9a-f]{1,4}$/.test(group)) return undefined
      result.push(parseInt(group, 16))
    }
    return result
  }
  const doubleColon = head.indexOf("::")
  if (doubleColon !== head.lastIndexOf("::")) return undefined
  let groups: number[]
  if (doubleColon >= 0) {
    const left = parseGroups(head.slice(0, doubleColon))
    const right = parseGroups(head.slice(doubleColon + 2))
    if (!left || !right) return undefined
    const missing = 8 - left.length - right.length - tail.length
    if (missing < 1) return undefined
    groups = [...left, ...new Array<number>(missing).fill(0), ...right, ...tail]
  } else {
    const all = parseGroups(head)
    if (!all) return undefined
    groups = [...all, ...tail]
  }
  return groups.length === 8 ? groups : undefined
}

// formatIPv6 renders eight groups in RFC 5952 canonical form.
export function formatIPv6(groups: readonly number[]): string {
  if (groups.length !== 8) throw new RangeError("IPv6 address needs eight groups")
  let bestStart = -1
  let bestLength = 0
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++
      continue
    }
    let j = i
    while (j < 8 && groups[j] === 0) j++
    if (j - i > bestLength) {
      bestStart = i
      bestLength = j - i
    }
    i = j
  }
  const hex = groups.map((group) => group.toString(16))
  if (bestLength < 2) return hex.join(":")
  const left = hex.slice(0, bestStart).join(":")
  const right = hex.slice(bestStart + bestLength).join(":")
  return `${left}::${right}`
}

export type IPv6Prefix = { groups: number[]; length: number }

export function parseIPv6Prefix(text: string): IPv6Prefix | undefined {
  const match = /^([^/]+)\/(\d{1,3})$/.exec(text.trim())
  if (!match) return undefined
  const length = Number(match[2])
  const groups = parseIPv6(match[1])
  if (!groups || length > 128) return undefined
  return { groups, length }
}

export function formatIPv6Prefix(prefix: IPv6Prefix): string {
  return `${formatIPv6(prefix.groups)}/${prefix.length}`
}

function hostBitsZero(prefix: IPv6Prefix): boolean {
  for (let bit = prefix.length; bit < 128; bit++) {
    const group = prefix.groups[Math.floor(bit / 16)]
    if ((group >> (15 - (bit % 16))) & 1) return false
  }
  return true
}

export function prefixContains(prefix: IPv6Prefix, address: readonly number[]): boolean {
  for (let bit = 0; bit < prefix.length; bit++) {
    const index = Math.floor(bit / 16)
    const shift = 15 - (bit % 16)
    if (((prefix.groups[index] >> shift) & 1) !== ((address[index] >> shift) & 1)) return false
  }
  return true
}

export function isULA(groups: readonly number[]): boolean {
  return (groups[0] & 0xfe00) === 0xfc00
}

export function isGlobalUnicast(groups: readonly number[]): boolean {
  return (groups[0] & 0xe000) === 0x2000
}

export type RandomSource = (bytes: Uint8Array<ArrayBuffer>) => void

function defaultRandom(bytes: Uint8Array<ArrayBuffer>): void {
  globalThis.crypto.getRandomValues(bytes)
}

// generateULAPrefix returns an RFC 4193 /64: fd00::/8, a random 40-bit Global
// ID, and the given 16-bit subnet ID (default 1), e.g. "fd12:3456:789a:1::/64".
export function generateULAPrefix(random: RandomSource = defaultRandom, subnetID = 1): string {
  if (!Number.isInteger(subnetID) || subnetID < 0 || subnetID > 0xffff) throw new RangeError("Subnet ID must be 0–65535")
  const globalID = new Uint8Array(5)
  random(globalID)
  const groups = [0xfd00 | globalID[0], (globalID[1] << 8) | globalID[2], (globalID[3] << 8) | globalID[4], subnetID, 0, 0, 0, 0]
  return formatIPv6Prefix({ groups, length: 64 })
}

// derivedAddresses returns the conventional gateway (prefix::1) and DNS
// server (the gateway) for a /64 lab prefix, or undefined for bad input.
export function derivedAddresses(labPrefix: string): { gateway_address: string; dns_addresses: string[] } | undefined {
  const prefix = parseIPv6Prefix(labPrefix)
  if (!prefix || prefix.length !== 64) return undefined
  const gateway = [...prefix.groups.slice(0, 4), 0, 0, 0, 1]
  const text = formatIPv6(gateway)
  return { gateway_address: text, dns_addresses: [text] }
}

// planForStrategy switches strategy, keeping or deriving address fields only
// for strategies that hand out addresses.
export function planForStrategy(current: IPv6Plan, strategy: IPv6Strategy, random: RandomSource = defaultRandom): IPv6Plan {
  if (!strategyNeedsPrefix(strategy)) return { strategy }
  let labPrefix = current.lab_prefix ?? ""
  const parsed = parseIPv6Prefix(labPrefix)
  if (strategy === "ULA_NAT66_LAB" && (!parsed || !isULA(parsed.groups))) labPrefix = generateULAPrefix(random)
  if (strategy === "NATIVE_ROUTED_PREFIX" && parsed && isULA(parsed.groups)) labPrefix = ""
  const derived = derivedAddresses(labPrefix)
  return { strategy, lab_prefix: labPrefix, gateway_address: derived?.gateway_address ?? "", dns_addresses: derived?.dns_addresses ?? [] }
}

export type PlanFieldIssue = { field: string; message: string }

export function validateIPv6Plan(plan: IPv6Plan): PlanFieldIssue[] {
  const issues: PlanFieldIssue[] = []
  const info = IPV6_STRATEGIES.find((item) => item.value === plan.strategy)
  if (!info) return [{ field: "strategy", message: "Choose an IPv6 option." }]
  if (!info.available) issues.push({ field: "strategy", message: `${info.label} is not available yet. Choose "Lab IPv6 (private prefix)" instead.` })
  if (!strategyNeedsPrefix(plan.strategy)) return issues
  const prefix = parseIPv6Prefix(plan.lab_prefix ?? "")
  if (!prefix) {
    issues.push({ field: "lab_prefix", message: "Enter the lab prefix as an IPv6 /64, for example fd12:3456:789a:1::/64." })
    return issues
  }
  if (prefix.length !== 64) issues.push({ field: "lab_prefix", message: "The lab prefix must be a /64 so devices can configure themselves (SLAAC)." })
  else if (!hostBitsZero(prefix)) issues.push({ field: "lab_prefix", message: "The prefix has bits set after /64. Use the network address, ending in ::/64." })
  if (plan.strategy === "ULA_NAT66_LAB" && !isULA(prefix.groups)) issues.push({ field: "lab_prefix", message: "A private lab prefix must start with fd (RFC 4193). Use “Generate private prefix”." })
  if (plan.strategy === "NATIVE_ROUTED_PREFIX" && !isGlobalUnicast(prefix.groups)) issues.push({ field: "lab_prefix", message: "A routed prefix must be a global address (2000::/3) that your network routes to ShakerProxy." })
  const gateway = parseIPv6(plan.gateway_address ?? "")
  if (!gateway) issues.push({ field: "gateway_address", message: "Enter ShakerProxy's lab IPv6 address, usually the prefix followed by ::1." })
  else if (!prefixContains(prefix, gateway)) issues.push({ field: "gateway_address", message: "The gateway address must be inside the lab prefix." })
  else if (gateway.slice(4).every((group) => group === 0)) issues.push({ field: "gateway_address", message: "The gateway cannot be the prefix's network address; use ::1." })
  const dns = plan.dns_addresses ?? []
  if (dns.length < 1 || dns.length > 3) issues.push({ field: "dns_addresses", message: "List one to three DNS server addresses." })
  else if (dns.some((address) => !parseIPv6(address))) issues.push({ field: "dns_addresses", message: "Every DNS server must be a valid IPv6 address." })
  return issues
}

// normalizeIPv6Plan coerces an unknown plan value (from the shell) into a
// well-formed IPv6Plan, defaulting to DISABLED.
export function normalizeIPv6Plan(value: unknown): IPv6Plan {
  if (!value || typeof value !== "object") return { strategy: "DISABLED" }
  const record = value as Record<string, unknown>
  const strategy = IPV6_STRATEGIES.some((item) => item.value === record.strategy) ? (record.strategy as IPv6Strategy) : "DISABLED"
  const plan: IPv6Plan = { strategy }
  if (typeof record.lab_prefix === "string") plan.lab_prefix = record.lab_prefix
  if (typeof record.gateway_address === "string") plan.gateway_address = record.gateway_address
  if (Array.isArray(record.dns_addresses)) plan.dns_addresses = record.dns_addresses.filter((item): item is string => typeof item === "string")
  return plan
}
