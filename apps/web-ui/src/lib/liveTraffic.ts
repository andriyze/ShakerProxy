import type { RecentEvent } from "../types"

// The live Traffic stream shows each lookup, connection and web request on one
// line: what kind it is, which client, and what it talked to.

export type StreamKind = "dns" | "tls" | "quic" | "http" | "alert" | "other"

// Each chip selects the events that carry that kind of information once. The
// analyzers record the same traffic several times (Suricata flows, Zeek's
// connection records of DNS and mDNS, TLS handshakes next to their
// connection); those stay out of the stream and remain reachable through
// Advanced. The gateway reports each connection the moment it opens
// (kind shakerproxy.conn); by port it counts as TLS (TCP 443), QUIC (UDP 443),
// HTTP (TCP 80) or Other until the recording's analysis fills it in.
export const STREAM_KINDS: { id: StreamKind; label: string; description: string; query: string }[] = [
  {
    id: "dns",
    label: "DNS",
    description: "Name lookups and their answers",
    query: "(kind:shakerproxy.dns OR kind:zeek.dns OR kind:shakerproxy.blocked OR app.protocol:doh)",
  },
  {
    id: "tls",
    label: "TLS",
    description: "Encrypted connections (HTTPS and other TLS) by server name",
    query: "((kind:zeek.conn AND protocol:tcp AND tls.sni:*) OR (kind:shakerproxy.conn AND protocol:tcp AND dst.port:443))",
  },
  {
    id: "quic",
    label: "QUIC",
    description: "HTTP/3 and other QUIC connections by server name",
    query: "((kind:zeek.conn AND protocol:udp AND tls.sni:*) OR (kind:shakerproxy.conn AND protocol:udp AND dst.port:443))",
  },
  {
    id: "http",
    label: "HTTP",
    description: "Cleartext web requests, and decrypted HTTPS when decryption is on",
    query: "((http.host:* AND NOT source:SURICATA) OR (kind:shakerproxy.conn AND protocol:tcp AND dst.port:80))",
  },
  { id: "alert", label: "Alerts", description: "Suricata alerts", query: "kind:suricata.alert" },
  {
    id: "other",
    label: "Other",
    description: "Connections without a name: IP-only, NTP, ICMP and other protocols",
    query:
      "((kind:zeek.conn AND NOT tls.sni:* AND NOT dst.port:53 AND NOT dst.port:5353) OR (kind:shakerproxy.conn AND NOT dst.port:443 AND NOT dst.port:80 AND NOT dst.port:53))",
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
const MAX_CLIENT_IDS = 12
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
  // The server accepts 128 query terms; 12 device IDs leave room for the
  // kind chips, time, search and an advanced filter.
  const ids = Array.from(
    new Set(filters.clients.filter((id) => DEVICE_ID.test(id)).flatMap((id) => [id, ...formerIDs(id).filter((former) => DEVICE_ID.test(former))])),
  ).slice(0, MAX_CLIENT_IDS)
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

// INSTANT_CONNECTION is a connection the gateway reported as it opened.
export const INSTANT_CONNECTION = "shakerproxy.conn"

function instantConnectionKind(event: RecentEvent): StreamKind {
  const protocol = event.protocol?.toLowerCase()
  if (protocol === "udp" && (event.destination_port === 443 || event.tls_server_name)) return "quic"
  if (protocol === "tcp" && (event.destination_port === 443 || event.tls_server_name)) return "tls"
  if (protocol === "tcp" && event.destination_port === 80) return "http"
  return "other"
}

export function streamKind(event: RecentEvent): StreamKind {
  if (event.kind === INSTANT_CONNECTION) return instantConnectionKind(event)
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

// StreamLine is what one row says. pending marks a connection the gateway
// reported whose details (server name, bytes) are still being analyzed.
export type StreamLine = { kind: StreamKind; badge: string; name: string; detail: string; peer: string; problem: boolean; pending?: boolean }

const INSTANT_BADGES: Record<StreamKind, string> = { dns: "DNS", tls: "TLS", quic: "QUIC", http: "HTTP", alert: "ALERT", other: "" }

// streamLine is what one row says, e.g. DNS · maps.google.com · A → 142.250.1.1
export function streamLine(event: RecentEvent): StreamLine {
  if (event.blocked) return blockedStreamLine(event)
  if (event.app_protocol === "doh") return dohStreamLine(event)
  const kind = streamKind(event)
  const peer = endpoint(event.destination_ip, event.destination_port)
  const bytes = event.network_bytes ? compactBytes(event.network_bytes) : ""
  if (event.kind === INSTANT_CONNECTION) {
    const enriched = Boolean(event.network_bytes || event.tls_server_name)
    return {
      kind,
      badge: INSTANT_BADGES[kind] || (event.protocol ?? "conn").toUpperCase(),
      name: event.tls_server_name || event.dns_name || peer,
      detail: bytes,
      peer,
      problem: false,
      pending: !enriched,
    }
  }
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

export type CollapsedRow<T> = { event: T; count: number }

// collapseRepeats folds identical consecutive lines (same client, kind, name
// and detail within a minute) into one, so a retry storm reads as "×12".
export function collapseRepeats<T extends Pick<RecentEvent, "occurred_at">>(
  rows: readonly T[],
  key: (event: T) => string,
): CollapsedRow<T>[] {
  const out: CollapsedRow<T>[] = []
  let previousKey = ""
  for (const event of rows) {
    const current = key(event)
    const last = out.at(-1)
    if (last && current === previousKey && Math.abs(Date.parse(last.event.occurred_at) - Date.parse(event.occurred_at)) <= 60_000) {
      last.count++
      continue
    }
    out.push({ event, count: 1 })
    previousKey = current
  }
  return out
}

const BLOCK_REASONS: Record<string, string> = {
  dot: "DNS over TLS",
  doq: "DNS over QUIC",
  "doh-ip": "DNS over HTTPS",
  "doh3-ip": "DNS over HTTP/3",
  "doh-name": "encrypted DNS resolver",
  canary: "encrypted DNS check",
  "device-domain": "blocked for this device",
}

// blockReasonLabel names what ShakerProxy refused in plain language.
export function blockReasonLabel(reason?: string): string {
  return BLOCK_REASONS[reason ?? ""] ?? "encrypted DNS"
}

// dohStreamLine is an encrypted DNS connection (DNS over HTTPS): its lookups
// are hidden from ShakerProxy unless encrypted DNS is blocked or decrypted.
function dohStreamLine(event: RecentEvent): StreamLine {
  const peer = endpoint(event.destination_ip, event.destination_port)
  const bytes = event.network_bytes ? compactBytes(event.network_bytes) : ""
  return {
    kind: "dns",
    badge: "DoH",
    name: event.tls_server_name || event.dns_name || peer || event.kind,
    detail: ["encrypted DNS, lookups hidden", bytes].filter(Boolean).join(" · "),
    peer,
    problem: false,
  }
}

// blockedStreamLine is a lookup or connection ShakerProxy refused: the device
// tried encrypted DNS (and falls back to plain DNS), or a blocked domain.
function blockedStreamLine(event: RecentEvent): StreamLine {
  const peer = endpoint(event.destination_ip, event.destination_port)
  const label = blockReasonLabel(event.blocked_reason)
  return {
    kind: "dns",
    badge: "BLOCKED",
    name: event.dns_query || peer || event.kind,
    detail: event.dns_query ? label : `${label} · falls back to plain DNS`,
    peer: event.dns_query ? "via ShakerProxy" : peer,
    problem: true,
  }
}

// The analyzer records that describe a whole connection. A request inside it
// (zeek.http) stays its own row.
const CONNECTION_RECORD_KINDS = new Set(["zeek.conn", "zeek.ssl", "zeek.quic", "suricata.flow", "suricata.tls", "suricata.quic"])
// Zeek logs a connection's start time; the gateway reports it as it opens.
const CONNECTION_MATCH_MS = 10_000

function fiveTuple(event: RecentEvent): string {
  return [event.protocol?.toLowerCase() ?? "", event.source_ip, event.source_port ?? 0, event.destination_ip, event.destination_port ?? 0].join("|")
}

// mergeInstantConnections keeps one row per connection: a connection the
// gateway reported as it opened takes the details the packet analyzers add
// later for the same five-tuple (server name, bytes) and keeps its own time,
// position and row; the analyzer records it absorbed leave the list.
export function mergeInstantConnections<T extends RecentEvent>(events: readonly T[]): T[] {
  const instant = new Map<string, T[]>()
  for (const event of events) {
    if (event.kind !== INSTANT_CONNECTION || !event.source_ip || !event.destination_ip) continue
    const key = fiveTuple(event)
    instant.set(key, [...(instant.get(key) ?? []), event])
  }
  if (instant.size === 0) return [...events]
  const absorbed = new Set<string>()
  const details = new Map<string, { serverName?: string; bytes: number }>()
  for (const event of events) {
    if (!CONNECTION_RECORD_KINDS.has(event.kind) || !event.source_ip || !event.destination_ip) continue
    const at = Date.parse(event.occurred_at)
    const owner = instant.get(fiveTuple(event))?.find((candidate) => Math.abs(Date.parse(candidate.occurred_at) - at) <= CONNECTION_MATCH_MS)
    if (!owner) continue
    absorbed.add(event.record_id)
    const current = details.get(owner.record_id) ?? { bytes: 0 }
    details.set(owner.record_id, {
      serverName: current.serverName || event.tls_server_name || undefined,
      bytes: Math.max(current.bytes, event.network_bytes ?? 0),
    })
  }
  return events
    .filter((event) => !absorbed.has(event.record_id))
    .map((event) => {
      const found = details.get(event.record_id)
      if (!found) return event
      return {
        ...event,
        tls_server_name: event.tls_server_name || found.serverName,
        network_bytes: Math.max(event.network_bytes ?? 0, found.bytes) || undefined,
      }
    })
}
