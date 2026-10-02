import type { RecentEvent } from "../types"

// The live Traffic stream shows each lookup, connection and web request on one
// line: what kind it is, which client, and what it talked to.

export type StreamKind = "dns" | "tls" | "quic" | "http" | "alert" | "other"

// Each chip selects the events that carry that kind of information once. The
// analyzers record the same traffic several times (Suricata flows, Zeek's
// connection records of DNS and mDNS, TLS handshakes next to their
// connection); those stay out of the stream and remain reachable through
// Advanced.
export const STREAM_KINDS: { id: StreamKind; label: string; description: string; query: string }[] = [
  {
    id: "dns",
    label: "DNS",
    description: "Name lookups and their answers",
    query: "(kind:shakerproxy.dns OR kind:zeek.dns)",
  },
  {
    id: "tls",
    label: "TLS",
    description: "Encrypted connections (HTTPS and other TLS) by server name",
    query: "(kind:zeek.conn AND protocol:tcp AND tls.sni:*)",
  },
  {
    id: "quic",
    label: "QUIC",
    description: "HTTP/3 and other QUIC connections by server name",
    query: "(kind:zeek.conn AND protocol:udp AND tls.sni:*)",
  },
  {
    id: "http",
    label: "HTTP",
    description: "Cleartext web requests, and decrypted HTTPS when decryption is on",
    query: "(http.host:* AND NOT source:SURICATA)",
  },
  { id: "alert", label: "Alerts", description: "Suricata alerts", query: "kind:suricata.alert" },
  {
    id: "other",
    label: "Other",
    description: "Connections without a name: IP-only, NTP, ICMP and other protocols",
    query: "(kind:zeek.conn AND NOT tls.sni:* AND NOT dst.port:53 AND NOT dst.port:5353)",
  },
]

export const ALL_STREAM_KINDS: StreamKind[] = STREAM_KINDS.map((kind) => kind.id)

export const STREAM_TIMES: [string, string][] = [
  ["Live", ""],
  ["5 min", "last_5m"],
  ["1 hour", "last_1h"],
  ["24 hours", "last_24h"],
  ["7 days", "last_7d"],
]

export type LiveFilters = {
  // Empty means any event, including the analyzers' own records.
  kinds: StreamKind[]
  clients: string[]
  time: string
  search: string
}

export const DEFAULT_LIVE_FILTERS: LiveFilters = { kinds: ALL_STREAM_KINDS, clients: [], time: "", search: "" }

const DEVICE_ID = /^device-[a-f0-9]{32}$/
const TIME = /^last_\d{1,3}[smhd]$/
const BARE_WORD = /^[A-Za-z0-9._:/*-]+$/

function searchTerm(value: string): string {
  const term = value.trim().slice(0, 128)
  if (!term) return ""
  return BARE_WORD.test(term) ? term : `"${term.replace(/["\\]/g, "")}"`
}

// composeLiveQuery turns the chips into one ShakerProxy filter. formerIDs
// adds the IDs of device records merged into a client, so its earlier
// traffic stays visible.
export function composeLiveQuery(filters: LiveFilters, advanced = "", formerIDs: (id: string) => readonly string[] = () => []): string {
  const parts: string[] = []
  if (TIME.test(filters.time)) parts.push(`time:${filters.time}`)
  const kinds = STREAM_KINDS.filter((kind) => filters.kinds.includes(kind.id))
  if (kinds.length === 1) parts.push(kinds[0].query)
  else if (kinds.length > 1) parts.push(`(${kinds.map((kind) => kind.query).join(" OR ")})`)
  const ids = Array.from(
    new Set(filters.clients.filter((id) => DEVICE_ID.test(id)).flatMap((id) => [id, ...formerIDs(id).filter((former) => DEVICE_ID.test(former))])),
  ).slice(0, 24)
  if (ids.length === 1) parts.push(`device.id:${ids[0]}`)
  else if (ids.length > 1) parts.push(`(${ids.map((id) => `device.id:${id}`).join(" OR ")})`)
  const term = searchTerm(filters.search)
  if (term) parts.push(term)
  if (advanced.trim()) parts.push(`(${advanced.trim()})`)
  return parts.join(" AND ")
}

// The chips live in the page address so a view can be shared and survives a
// reload; traffic_q holds the advanced filter.
export function liveFiltersFromURL(search: string): LiveFilters {
  const parameters = new URLSearchParams(search)
  const kindsValue = parameters.get("traffic_kinds")
  const kinds =
    kindsValue === null
      ? parameters.get("traffic_q")
        ? []
        : ALL_STREAM_KINDS
      : kindsValue === "any"
        ? []
        : (kindsValue.split(",").filter((value) => ALL_STREAM_KINDS.includes(value as StreamKind)) as StreamKind[])
  return {
    kinds,
    clients: (parameters.get("traffic_clients") ?? "").split(",").filter((value) => DEVICE_ID.test(value)),
    time: TIME.test(parameters.get("traffic_time") ?? "") ? (parameters.get("traffic_time") as string) : "",
    search: (parameters.get("traffic_search") ?? "").slice(0, 128),
  }
}

export function writeLiveFiltersToURL(url: URL, filters: LiveFilters) {
  const kinds = filters.kinds.length === 0 ? "any" : filters.kinds.length === ALL_STREAM_KINDS.length ? "" : filters.kinds.join(",")
  const set = (name: string, value: string) => (value ? url.searchParams.set(name, value) : url.searchParams.delete(name))
  set("traffic_kinds", kinds)
  set("traffic_clients", filters.clients.join(","))
  set("traffic_time", filters.time)
  set("traffic_search", filters.search)
}

export function streamKind(event: RecentEvent): StreamKind {
  if (event.alert_signature || event.kind === "suricata.alert") return "alert"
  if (event.dns_query) return "dns"
  if (event.http_method || event.http_host || event.kind.endsWith(".http")) return "http"
  if (event.kind.endsWith(".quic") || (event.tls_server_name && event.protocol?.toLowerCase() === "udp")) return "quic"
  if (event.tls_server_name || event.kind.endsWith(".ssl") || event.kind.endsWith(".tls")) return "tls"
  return "other"
}

// Same format as eventSummary's compactBytes; this module has no runtime
// imports so it loads on its own in tests.
function compactBytes(value: number): string {
  if (!Number.isFinite(value) || value < 0) return ""
  if (value < 1024) return `${Math.round(value)} B`
  if (value < 1024 * 1024) return `${Math.round(value / 1024)} KB`
  if (value < 1024 * 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MB`
  return `${(value / (1024 * 1024 * 1024)).toFixed(1)} GB`
}

function endpoint(address?: string, port?: number): string {
  if (!address) return ""
  const host = address.includes(":") ? `[${address}]` : address
  return port ? `${host}:${port}` : host
}

export type StreamLine = { kind: StreamKind; badge: string; name: string; detail: string; peer: string; problem: boolean }

// streamLine is what one row says, e.g. DNS · maps.google.com · A → 142.250.1.1
export function streamLine(event: RecentEvent): StreamLine {
  const kind = streamKind(event)
  const peer = endpoint(event.destination_ip, event.destination_port)
  const bytes = event.network_bytes ? compactBytes(event.network_bytes) : ""
  switch (kind) {
    case "dns": {
      const rcode = event.dns_response_code ?? ""
      const answers = event.dns_answers ?? []
      const type = event.dns_record_type ?? ""
      let detail: string
      if (rcode && rcode !== "NOERROR") detail = `${type} ${rcode}`.trim()
      else if (answers.length) detail = `${type} → ${answers.slice(0, 3).join(", ")}${answers.length > 3 ? ` +${answers.length - 3}` : ""}`.trim()
      else if (event.dns_answer_count) detail = `${type} · ${event.dns_answer_count} answer${event.dns_answer_count === 1 ? "" : "s"}`.trim()
      else detail = type ? `${type} · no answer` : "no answer"
      return {
        kind,
        badge: "DNS",
        name: event.dns_query ?? "",
        detail,
        peer: event.kind === "shakerproxy.dns" ? "via ShakerProxy" : peer,
        problem: Boolean(rcode && rcode !== "NOERROR"),
      }
    }
    case "http": {
      const host = event.http_host ?? event.tls_server_name ?? event.destination_ip ?? ""
      const decrypted = event.source === "MITMPROXY"
      return {
        kind,
        badge: decrypted ? "HTTPS" : "HTTP",
        name: `${event.http_method ? `${event.http_method} ` : ""}${host}${event.http_path ?? ""}`,
        detail: [event.http_status ? String(event.http_status) : "", decrypted ? "decrypted" : "cleartext"].filter(Boolean).join(" · "),
        peer,
        problem: (event.http_status ?? 0) >= 400,
      }
    }
    case "tls":
    case "quic":
      return {
        kind,
        badge: kind === "quic" ? "QUIC" : "TLS",
        name: event.tls_server_name ?? peer,
        detail: [bytes, event.tls_interception_state === "FAILED" ? "decryption failed" : event.tls_interception_state === "INTERCEPTED" ? "decrypted" : ""]
          .filter(Boolean)
          .join(" · "),
        peer,
        problem: event.tls_interception_state === "FAILED",
      }
    case "alert":
      return {
        kind,
        badge: "ALERT",
        name: event.alert_signature ?? event.detection_summary ?? event.kind,
        detail: event.alert_category ?? event.detection_severity ?? "",
        peer,
        problem: true,
      }
    default: {
      const protocol = (event.app_protocol || event.service || event.protocol || "").toUpperCase()
      return { kind, badge: protocol && protocol.length <= 6 ? protocol : "CONN", name: peer || event.kind, detail: bytes, peer: "", problem: false }
    }
  }
}

// eventsPerMinute counts events in the minute before now.
export function eventsPerMinute(events: readonly RecentEvent[], now = Date.now()): number {
  let count = 0
  for (const event of events) {
    const at = Date.parse(event.occurred_at)
    if (now - at <= 60_000 && at <= now + 5_000) count++
  }
  return count
}
