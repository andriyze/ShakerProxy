// Quick views and time windows for the Traffic workspace. Pure.

export type TrafficPreset = {
  id: string
  label: string
  query: string
  tone?: "good" | "warn" | "danger"
  description: string
}

export const DNS_PREDICATE = "(kind:zeek.dns OR kind:suricata.dns OR kind:encrypted_dns_detected OR service:doh)"

export const TRAFFIC_PRESETS: readonly TrafficPreset[] = [
  { id: "all", label: "Everything", query: "", description: "Show all traffic." },
  {
    id: "dns",
    label: "DNS lookups",
    query: `time:last_15m AND ${DNS_PREDICATE}`,
    description: "Names devices looked up, including DNS over HTTPS.",
  },
  {
    id: "encrypted-dns",
    label: "Encrypted DNS",
    query: "time:last_15m AND kind:encrypted_dns_detected",
    tone: "warn",
    description: "Devices using DNS over HTTPS or TLS, which can hide lookups.",
  },
  {
    id: "tls",
    label: "HTTPS",
    query: "time:last_15m AND service:tls",
    description: "Encrypted connections and whether ShakerProxy could decrypt them.",
  },
  {
    id: "decrypted-tls",
    label: "Decrypted",
    query: "time:last_15m AND kind:tls_intercepted",
    tone: "good",
    description: "HTTPS connections ShakerProxy decrypted.",
  },
  {
    id: "tls-failures",
    label: "Decryption failed",
    query: "time:last_15m AND kind:tls_interception_failed",
    tone: "danger",
    description: "The device rejected ShakerProxy's certificate — often certificate pinning.",
  },
  {
    id: "bypasses",
    label: "Passed through",
    query: "time:last_15m AND kind:tls_passthrough",
    tone: "warn",
    description: "HTTPS ShakerProxy let through without decrypting.",
  },
  {
    id: "http",
    label: "Web requests",
    query: "time:last_15m AND kind:http_*",
    description: "HTTP requests and responses.",
  },
  {
    id: "decrypted-http",
    label: "Decrypted web requests",
    query: "time:last_15m AND source:MITMPROXY AND service:https AND kind:http_*",
    tone: "good",
    description: "Requests seen inside decrypted HTTPS.",
  },
  {
    id: "http-errors",
    label: "Web errors",
    query: "time:last_15m AND kind:http_flow_error",
    tone: "danger",
    description: "Requests that failed in the proxy or upstream.",
  },
]

export const TIME_WINDOWS: readonly (readonly [label: string, value: string])[] = [
  ["5 min", "last_5m"],
  ["15 min", "last_15m"],
  ["1 hour", "last_1h"],
  ["6 hours", "last_6h"],
  ["24 hours", "last_24h"],
]

const RELATIVE_TIME = /\btime:last_[0-9]+[smhd]\b/i

// withTimeWindow sets (or replaces) the relative time predicate of a query.
export function withTimeWindow(query: string, relative: string): string {
  const predicate = `time:${relative}`
  if (RELATIVE_TIME.test(query)) return query.replace(RELATIVE_TIME, predicate)
  return query ? `${predicate} AND (${query})` : predicate
}

// activeTimeWindow returns the relative window in a query, if any.
export function activeTimeWindow(query: string): string {
  const match = RELATIVE_TIME.exec(query)
  return match ? match[0].slice("time:".length).toLowerCase() : ""
}

const DEVICE_ID = /^device-[a-f0-9]{32}$/

// deviceQuery filters traffic to one device. Records merged into it, such as
// a phone that changed its private MAC, keep their own device ID on traffic
// recorded before the merge, so those IDs are included.
export function deviceQuery(deviceID: string, relative = "", formerIDs: readonly string[] = []): string {
  if (!DEVICE_ID.test(deviceID)) return ""
  const ids = [deviceID, ...formerIDs.filter((id) => DEVICE_ID.test(id) && id !== deviceID).slice(0, 16)]
  const predicate = ids.length === 1 ? `device.id:${deviceID}` : `(${ids.map((id) => `device.id:${id}`).join(" OR ")})`
  return relative ? withTimeWindow(predicate, relative) : predicate
}

// combinedQuery folds the Source dropdown into a single query string, the way
// saved views and frozen selections store it.
export function combinedQuery(query: string, source: string): string {
  if (!source) return query
  return query ? `source:${source} AND (${query})` : `source:${source}`
}
