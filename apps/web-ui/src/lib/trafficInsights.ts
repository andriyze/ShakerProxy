// Summaries of the newest decrypted-traffic sample for the Traffic overview.
// Pure so the counting rules can be unit tested.

export type InsightEvent = {
  kind: string
  service?: string
  device_id?: string
  device_friendly_name?: string
  dns_query?: string
  tls_server_name?: string
  tls_interception_state?: string
  tls_pinning_suspected?: boolean
  tls_bypass_activated?: boolean
}

// The events API caps limit at 100; the overview asks for exactly that.
export const INSIGHT_SAMPLE_LIMIT = 100
export const INSIGHT_QUERY = "time:last_15m AND source:MITMPROXY"

export function insightSamplePath(): string {
  return `/api/v1/events?limit=${INSIGHT_SAMPLE_LIMIT}&q=${encodeURIComponent(INSIGHT_QUERY)}`
}

export type SampleCounts = {
  dns: number
  tlsOK: number
  tlsFailed: number
  bypass: number
  http: number
  pinning: number
  devices: number
}

export function countSample(events: InsightEvent[]): SampleCounts {
  const counts = { dns: 0, tlsOK: 0, tlsFailed: 0, bypass: 0, http: 0, pinning: 0, devices: 0 }
  const devices = new Set<string>()
  for (const event of events) {
    const kind = event.kind.toLowerCase()
    const service = String(event.service ?? "").toLowerCase()
    if (event.device_id) devices.add(event.device_id)
    if (service === "dns" || service === "doh" || kind.includes("dns")) counts.dns++
    if (kind === "tls_intercepted" || event.tls_interception_state === "INTERCEPTED") counts.tlsOK++
    if (kind === "tls_interception_failed" || event.tls_interception_state === "FAILED") counts.tlsFailed++
    if (kind === "tls_passthrough" || event.tls_interception_state === "BYPASSED") counts.bypass++
    if (kind.startsWith("http_")) counts.http++
    if (event.tls_pinning_suspected || event.tls_bypass_activated) counts.pinning++
  }
  counts.devices = devices.size
  return counts
}

export type RankedItem = { key: string; label: string; count: number; detail?: string; deviceID?: string }

export function rank(values: Omit<RankedItem, "count">[], limit = 5): RankedItem[] {
  const counts = new Map<string, RankedItem>()
  for (const item of values) {
    if (!item.key) continue
    const current = counts.get(item.key)
    if (current) current.count++
    else counts.set(item.key, { ...item, count: 1 })
  }
  return [...counts.values()]
    .sort((left, right) => right.count - left.count || left.label.localeCompare(right.label))
    .slice(0, limit)
}

const DEVICE_ID = /^device-[a-f0-9]{32}$/

export function tlsAttention(events: InsightEvent[]): RankedItem[] {
  return rank(
    events
      .filter(
        (event) =>
          event.kind === "tls_interception_failed" ||
          event.kind === "tls_passthrough" ||
          event.tls_pinning_suspected ||
          event.tls_bypass_activated,
      )
      .map((event) => ({
        key: `${event.tls_server_name || "unknown"}|${event.kind}`,
        label: event.tls_server_name || "Hostname unavailable",
        detail:
          event.tls_pinning_suspected || event.tls_bypass_activated
            ? "probably pins its certificate"
            : event.kind === "tls_passthrough"
              ? "passed through without decrypting"
              : "decryption failed",
      })),
  )
}

export function topDestinations(events: InsightEvent[]): RankedItem[] {
  return rank(
    events.flatMap((event) => {
      const values: Omit<RankedItem, "count">[] = []
      if (event.dns_query) values.push({ key: `dns:${event.dns_query}`, label: event.dns_query, detail: "DNS lookup" })
      if (event.tls_server_name)
        values.push({ key: `tls:${event.tls_server_name}`, label: event.tls_server_name, detail: "HTTPS" })
      return values
    }),
  )
}

export function activeDevices(events: InsightEvent[]): RankedItem[] {
  return rank(
    events
      .filter((event) => DEVICE_ID.test(event.device_id ?? ""))
      .map((event) => ({
        key: event.device_id!,
        label: event.device_friendly_name || event.device_id!,
        detail: event.device_friendly_name ? event.device_id : "no name yet",
        deviceID: event.device_id,
      })),
  )
}
