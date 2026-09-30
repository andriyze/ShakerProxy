// Pure helpers for the network-plan Wi-Fi access point editor (§8): channel
// lists, country defaults, passphrase generation and validation mirrors.
// Keep this file free of runtime imports so node --test can load it directly.
import type { PlanInterface } from "./registry"
import type { WifiBand, WifiPlan, WifiSecurity } from "./types"

export const SECURITY_OPTIONS: readonly { value: WifiSecurity; label: string; detail: string }[] = [
  { value: "WPA2_WPA3", label: "WPA2/WPA3 (recommended)", detail: "Works with older and newer devices; newer ones use WPA3 automatically." },
  { value: "WPA3_SAE", label: "WPA3 only", detail: "Strongest, but older phones, TVs and IoT devices may not be able to join." },
  { value: "WPA2_PSK", label: "WPA2 only", detail: "For older devices that fail to join a mixed WPA2/WPA3 network." },
  { value: "OPEN", label: "Open (no password)", detail: "Anyone nearby can join and use the lab network. Only for short tests in a shielded room." },
]

export const BAND_OPTIONS: readonly { value: WifiBand; label: string; detail: string }[] = [
  { value: "2.4GHZ", label: "2.4 GHz", detail: "Best compatibility and range. Many IoT devices only support 2.4 GHz." },
  { value: "5GHZ", label: "5 GHz", detail: "Faster with less interference, shorter range. Some IoT devices cannot see it." },
]

// Non-DFS 5 GHz channels; DFS channels need radar detection and can switch
// channel under the devices' feet, which makes tests unreliable.
export const CHANNELS_5GHZ: readonly number[] = [36, 40, 44, 48, 149, 153, 157, 161, 165]
export const DEFAULT_CHANNEL: Record<WifiBand, number> = { "2.4GHZ": 6, "5GHZ": 36 }

// Countries that only permit 2.4 GHz channels 1–11.
const ELEVEN_CHANNEL_COUNTRIES = new Set(["US", "CA", "TW", "PR", "GU", "AS", "VI", "MP", "UM"])

export function channelsFor(band: WifiBand, countryCode: string): number[] {
  if (band === "5GHZ") return [...CHANNELS_5GHZ]
  const last = ELEVEN_CHANNEL_COUNTRIES.has(countryCode.toUpperCase()) ? 11 : 13
  return Array.from({ length: last }, (_, index) => index + 1)
}

export function channelHint(band: WifiBand, channel: number): string {
  if (band === "2.4GHZ") return [1, 6, 11].includes(channel) ? "Non-overlapping channel." : "Channels 1, 6 and 11 overlap least with neighbours."
  if (channel >= 149) return "Upper 5 GHz channels are not allowed in some countries (for example much of Europe). Use 36–48 if devices cannot see the network."
  return "Widely permitted 5 GHz channel."
}

const RESERVED_REGIONS = new Set(["AA", "QM", "QN", "QO", "QP", "QQ", "QR", "QS", "QT", "QU", "QV", "QW", "QX", "QY", "QZ", "XA", "XB", "XC", "XD", "XE", "XF", "XG", "XH", "XI", "XJ", "XL", "XM", "XN", "XO", "XP", "XQ", "XR", "XS", "XT", "XU", "XV", "XW", "XX", "XY", "XZ", "ZZ", "EU", "UN", "EZ"])

export function isValidCountryCode(value: string): boolean {
  return /^[A-Z]{2}$/.test(value) && !RESERVED_REGIONS.has(value)
}

// countryFromLocale returns the ISO 3166-1 alpha-2 region of a BCP 47 locale
// ("en-GB" → "GB", "de-Latn-AT" → "AT"), or undefined when it has none.
export function countryFromLocale(locale: string | undefined): string | undefined {
  if (!locale) return undefined
  const parts = locale.replace(/_/g, "-").split("-").slice(1)
  for (const part of parts) {
    if (/^[A-Za-z]{2}$/.test(part)) {
      const region = part.toUpperCase()
      return isValidCountryCode(region) ? region : undefined
    }
    if (/^\d{3}$/.test(part)) return undefined
  }
  return undefined
}

export function browserCountry(): string {
  const candidates: string[] = []
  try {
    if (typeof navigator !== "undefined") candidates.push(...(navigator.languages ?? []), navigator.language)
  } catch {
    // Ignore unavailable navigator.
  }
  try {
    candidates.push(Intl.DateTimeFormat().resolvedOptions().locale)
  } catch {
    // Ignore unavailable Intl.
  }
  for (const candidate of candidates) {
    const country = countryFromLocale(candidate)
    if (country) return country
  }
  return "US"
}

export function defaultWifiPlan(countryCode = "US"): WifiPlan {
  return {
    enabled: true,
    ssid: "ShakerProxy",
    security: "WPA2_WPA3",
    passphrase: "",
    country_code: isValidCountryCode(countryCode) ? countryCode : "US",
    band: "2.4GHZ",
    channel: DEFAULT_CHANNEL["2.4GHZ"],
    hidden: false,
    client_isolation: false,
    bridge_with_lab: true,
  }
}

// Unambiguous characters (no 0/O, 1/l/I) so the passphrase is easy to type on a TV remote.
const PASSPHRASE_ALPHABET = "abcdefghijkmnpqrstuvwxyz23456789"

export type RandomSource = (bytes: Uint8Array<ArrayBuffer>) => void

function defaultRandom(bytes: Uint8Array<ArrayBuffer>): void {
  globalThis.crypto.getRandomValues(bytes)
}

// generatePassphrase returns four dash-separated groups of four characters
// (~80 bits of entropy), drawn uniformly with rejection sampling.
export function generatePassphrase(random: RandomSource = defaultRandom, groups = 4, groupLength = 4): string {
  const alphabet = PASSPHRASE_ALPHABET
  const limit = 256 - (256 % alphabet.length)
  const chars: string[] = []
  const buffer = new Uint8Array(64)
  while (chars.length < groups * groupLength) {
    random(buffer)
    for (const byte of buffer) {
      if (byte < limit && chars.length < groups * groupLength) chars.push(alphabet[byte % alphabet.length])
    }
  }
  const parts: string[] = []
  for (let i = 0; i < groups; i++) parts.push(chars.slice(i * groupLength, (i + 1) * groupLength).join(""))
  return parts.join("-")
}

export function utf8Length(value: string): number {
  return new TextEncoder().encode(value).length
}

export type WifiFieldIssue = { field: keyof WifiPlan | "interface"; message: string }

// validateWifiPlan mirrors internal/networkplan validateWiFi for the fields
// this editor owns. `wiredLab` says whether the plan also has a wired LAB
// port, which requires bridging the two into one lab network.
export function validateWifiPlan(plan: WifiPlan, context: { wiredLab?: boolean } = {}): WifiFieldIssue[] {
  if (!plan.enabled) return []
  const issues: WifiFieldIssue[] = []
  const ssidBytes = utf8Length(plan.ssid)
  if (!plan.ssid.trim()) issues.push({ field: "ssid", message: "Enter a network name (SSID)." })
  else if (ssidBytes > 32) issues.push({ field: "ssid", message: `The network name is ${ssidBytes} bytes; the limit is 32.` })
  else if (/[\u0000-\u001f\u007f-\u009f]/.test(plan.ssid)) issues.push({ field: "ssid", message: "The network name cannot contain control characters." })
  if (context.wiredLab && !plan.bridge_with_lab) issues.push({ field: "bridge_with_lab", message: "This plan also has a wired lab port, so Wi-Fi and wired lab devices must share one lab network." })
  if (!SECURITY_OPTIONS.some((option) => option.value === plan.security)) issues.push({ field: "security", message: "Choose a security mode." })
  if (plan.security !== "OPEN") {
    if (plan.passphrase.length < 8 || plan.passphrase.length > 63) issues.push({ field: "passphrase", message: "The password must be 8–63 characters." })
    else if (!/^[\x20-\x7e]+$/.test(plan.passphrase)) issues.push({ field: "passphrase", message: "Use only printable ASCII characters (letters, digits, punctuation, space)." })
  }
  if (!isValidCountryCode(plan.country_code)) issues.push({ field: "country_code", message: "Choose the country where ShakerProxy is used; it decides which channels are legal." })
  if (plan.band !== "2.4GHZ" && plan.band !== "5GHZ") issues.push({ field: "band", message: "Choose 2.4 GHz or 5 GHz." })
  else if (!channelsFor(plan.band, plan.country_code).includes(plan.channel)) issues.push({ field: "channel", message: `Channel ${plan.channel} is not available on ${plan.band === "5GHZ" ? "5 GHz (non-DFS)" : "2.4 GHz"} here.` })
  return issues
}

// normalizeWifiPlan coerces an unknown plan value (from the shell) into a
// WifiPlan, filling gaps from defaults. Missing or non-object means disabled.
export function normalizeWifiPlan(value: unknown, countryCode = "US"): WifiPlan {
  const defaults = defaultWifiPlan(countryCode)
  if (!value || typeof value !== "object") return { ...defaults, enabled: false }
  const record = value as Record<string, unknown>
  const pick = <T,>(key: keyof WifiPlan, valid: (item: unknown) => item is T, fallback: T): T => (valid(record[key]) ? (record[key] as T) : fallback)
  const isString = (item: unknown): item is string => typeof item === "string"
  const isBoolean = (item: unknown): item is boolean => typeof item === "boolean"
  const isNumber = (item: unknown): item is number => typeof item === "number" && Number.isInteger(item)
  const isSecurity = (item: unknown): item is WifiSecurity => SECURITY_OPTIONS.some((option) => option.value === item)
  const isBand = (item: unknown): item is WifiBand => item === "2.4GHZ" || item === "5GHZ"
  // Like the plan validator: an empty band means 2.4 GHz and channel 0 (or
  // none) means the band's default channel.
  const band = pick("band", isBand, "2.4GHZ" as WifiBand)
  const channel = pick("channel", isNumber, 0)
  return {
    enabled: pick("enabled", isBoolean, false),
    ssid: pick("ssid", isString, defaults.ssid),
    security: pick("security", isSecurity, defaults.security),
    passphrase: pick("passphrase", isString, ""),
    country_code: pick("country_code", isString, defaults.country_code),
    band,
    channel: channel === 0 ? DEFAULT_CHANNEL[band] : channel,
    hidden: pick("hidden", isBoolean, false),
    client_isolation: pick("client_isolation", isBoolean, false),
    bridge_with_lab: pick("bridge_with_lab", isBoolean, true),
  }
}

// Topologies where the plan validator accepts a Wi-Fi access point.
export const WIFI_TOPOLOGIES: readonly string[] = ["TWO_NIC", "THREE_INTERFACE", "EXISTING_ROUTED_VLAN", "ADVANCED_CUSTOM"]

const UNSUPPORTED_TOPOLOGY_REASONS: Record<string, string> = {
  SINGLE_ARM: "This plan uses one port for both the internet and the lab (single-arm), so there is no routed lab network to add Wi-Fi to.",
  VLAN_TRUNK: "This plan puts the lab on a tagged VLAN trunk, which cannot include a Wi-Fi access point.",
  PASSIVE_SENSOR: "This plan only watches a mirror port (passive sensor); ShakerProxy does not route a lab network there.",
}

// wifiTopologySupport says whether the plan's topology allows an access
// point. Without an explicit topology it infers single-arm (WAN_LAB role)
// and passive-sensor (MIRROR role) plans from interface roles.
export function wifiTopologySupport(topology: string | undefined, roles: Record<string, string>): { supported: boolean; reason: string } {
  const roleValues = Object.values(roles)
  const effective = topology || (roleValues.includes("WAN_LAB") ? "SINGLE_ARM" : roleValues.includes("MIRROR") ? "PASSIVE_SENSOR" : "")
  if (!effective || WIFI_TOPOLOGIES.includes(effective)) return { supported: true, reason: "" }
  const reason = UNSUPPORTED_TOPOLOGY_REASONS[effective] ?? "This network topology does not support a Wi-Fi access point."
  return { supported: false, reason: `${reason} To add Wi-Fi, choose a Two-NIC, Three-interface, Existing routed VLAN or Advanced plan.` }
}

export type APSupport = "supported" | "unsupported" | "unknown" | "not-wireless"

// apSupport classifies an interface for hosting the access point. When the
// preflight predates the "wireless" field, Linux "wl*" names count as wireless.
export function apSupport(iface: PlanInterface): APSupport {
  const wireless = iface.wireless ?? /^wl/.test(iface.name)
  if (!wireless) return "not-wireless"
  if (iface.ap_supported === true) return "supported"
  if (iface.ap_supported === false) return "unsupported"
  return "unknown"
}

// wirelessInterfaces lists interfaces that could host the AP, best first.
export function wirelessInterfaces(interfaces: readonly PlanInterface[]): PlanInterface[] {
  const rank: Record<APSupport, number> = { supported: 0, unknown: 1, unsupported: 2, "not-wireless": 3 }
  return interfaces
    .filter((iface) => apSupport(iface) !== "not-wireless")
    .sort((a, b) => rank[apSupport(a)] - rank[apSupport(b)] || a.name.localeCompare(b.name))
}

export function bandSupported(iface: PlanInterface | undefined, band: WifiBand): boolean | undefined {
  if (!iface?.wireless_bands || iface.wireless_bands.length === 0) return undefined
  return iface.wireless_bands.includes(band)
}
