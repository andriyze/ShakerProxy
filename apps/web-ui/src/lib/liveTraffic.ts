import type { RecentEvent } from "../types"

// The live Traffic stream shows each lookup, connection and web request on one
// line: what kind it is, which client, and what it talked to.

export type StreamKind = "dns" | "tls" | "quic" | "http" | "discovery" | "alert" | "other"

// Discovery is how devices find each other and announce themselves on the
// network (AirPlay, casting, smart-home apps), mostly multicast.
const DISCOVERY_PORTS: Record<number, string> = {
  5353: "mDNS",
  5355: "LLMNR",
  1900: "SSDP",
  137: "NetBIOS",
  138: "NetBIOS",
  67: "DHCP",
  68: "DHCP",
  546: "DHCPv6",
  547: "DHCPv6",
  3702: "WS-Disc",
  10001: "UniFi",
}

const DISCOVERY_LABELS: Record<string, string> = {
  "ubnt-discovery": "UniFi",
  "local-broadcast": "Bcast",
  "netbios-ns": "NetBIOS",
  "ws-discovery": "WS-Disc",
}
// Ingest classifies these (protocolclass): mDNS, SSDP, LLMNR, NetBIOS and
// WS-Discovery are local-discovery; DHCP is network management.
const DISCOVERY_QUERY = "(protocol.category:local-discovery OR app.protocol:dhcp OR app.protocol:dhcpv6)"
const DISCOVERY_APPS = new Set(["mdns", "ssdp", "llmnr", "netbios-ns", "ws-discovery", "dhcp", "dhcpv6"])

export function discoveryProtocol(event: Pick<RecentEvent, "destination_port" | "kind" | "app_protocol" | "protocol_category">): string {
  const byPort = DISCOVERY_PORTS[event.destination_port ?? 0]
  if (byPort) return byPort
  if (event.kind === "zeek.dhcp") return "DHCP"
  if (event.protocol_category === "local-discovery" || DISCOVERY_APPS.has(event.app_protocol ?? "")) {
    const app = event.app_protocol ?? ""
    return DISCOVERY_LABELS[app] ?? (app ? app.toUpperCase() : "Bcast")
  }
  return ""
}

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
    query:
      "(kind:shakerproxy.dns OR (kind:zeek.dns AND NOT protocol.category:local-discovery) OR kind:shakerproxy.blocked OR app.protocol:doh OR app.protocol:dot OR app.protocol:doq)",
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
  {
    id: "discovery",
    label: "Discovery",
    description: "How devices find each other and announce their names: mDNS/Bonjour, SSDP/UPnP, LLMNR, NetBIOS, DHCP",
    query: `(${DISCOVERY_QUERY} AND NOT source:SURICATA)`,
  },
  { id: "alert", label: "Alerts", description: "Suricata alerts", query: "kind:suricata.alert" },
  {
    id: "other",
    label: "Other",
    description: "Connections without a name: IP-only, NTP, ICMP and other protocols",
    query:
      `((kind:zeek.conn AND NOT tls.sni:* AND NOT dst.port:53 AND NOT ${DISCOVERY_QUERY}) OR (kind:shakerproxy.conn AND NOT dst.port:443 AND NOT dst.port:80 AND NOT dst.port:53))`,
  },
]

export const ALL_STREAM_KINDS: StreamKind[] = STREAM_KINDS.map((kind) => kind.id)

// EVERYTHING_QUERY is every event except the analyzers' duplicate records.
// Joining all chips' queries runs past the server's 128-term limit, so a
// selection of most kinds is written as this minus the kinds left out.
export const EVERYTHING_QUERY =
  "NOT (kind:suricata.flow OR kind:suricata.dns OR kind:suricata.mdns OR kind:suricata.quic OR kind:suricata.tls OR kind:suricata.http OR kind:suricata.anomaly OR kind:zeek.ssl OR kind:zeek.quic OR kind:zeek.weird OR kind:zeek.known_services OR kind:zeek.software OR kind:zeek.reporter OR (kind:zeek.conn AND (dst.port:53 OR dst.port:5353 OR dst.port:5355)))"

// queryTerms approximates how the server counts terms: words and brackets.
export function queryTerms(query: string): number {
  return query.match(/[()]|[^\s()]+/g)?.length ?? 0
}

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
  // Field filters added from facets and the row menu, e.g. "owner:google",
  // "dst.port:443", "github.com": each one included, or excluded with NOT.
  include?: string[]
  exclude?: string[]
}

export const DEFAULT_LIVE_FILTERS: LiveFilters = { kinds: ALL_STREAM_KINDS, clients: [], time: "", search: "", include: [], exclude: [] }

// A field filter is one predicate from a facet or the row menu: a field and a
// plain value, or a bare host or address. Anything else is refused so the
// address bar cannot inject query syntax.
const FIELD_FILTER = /^(?:(?:device\.id|owner|category|dst\.port|src\.ip|dst\.ip|app\.protocol|kind|protocol):[A-Za-z0-9._:/-]{1,128}|[A-Za-z0-9.-]{1,128}|[0-9A-Fa-f:.]{2,45})$/
export const MAX_FIELD_FILTERS = 8

export function validFieldFilter(value: string): boolean {
  return FIELD_FILTER.test(value)
}

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
  const left = STREAM_KINDS.filter((kind) => !filters.kinds.includes(kind.id))
  const union = (list: typeof STREAM_KINDS) => (list.length === 1 ? list[0].query : `(${list.map((kind) => kind.query).join(" OR ")})`)
  if (kinds.length > 0) {
    // The shorter of "these kinds" and "everything but the others".
    const chosen = union(kinds)
    const rest = left.length === 0 ? EVERYTHING_QUERY : `(${EVERYTHING_QUERY} AND NOT ${union(left)})`
    parts.push(queryTerms(rest) < queryTerms(chosen) ? rest : chosen)
  }
  // The server accepts 128 query terms; 12 device IDs leave room for the
  // kind chips, time, search and an advanced filter.
  const ids = Array.from(
    new Set(filters.clients.filter((id) => DEVICE_ID.test(id)).flatMap((id) => [id, ...formerIDs(id).filter((former) => DEVICE_ID.test(former))])),
  ).slice(0, MAX_CLIENT_IDS)
  if (ids.length === 1) parts.push(`device.id:${ids[0]}`)
  else if (ids.length > 1) parts.push(`(${ids.map((id) => `device.id:${id}`).join(" OR ")})`)
  const term = searchTerm(filters.search)
  if (term) parts.push(term)
  for (const value of (filters.include ?? []).filter(validFieldFilter).slice(0, MAX_FIELD_FILTERS)) parts.push(value)
  for (const value of (filters.exclude ?? []).filter(validFieldFilter).slice(0, MAX_FIELD_FILTERS)) parts.push(`NOT ${value}`)
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
    include: (parameters.get("traffic_inc") ?? "").split(" ").filter(validFieldFilter).slice(0, MAX_FIELD_FILTERS),
    exclude: (parameters.get("traffic_exc") ?? "").split(" ").filter(validFieldFilter).slice(0, MAX_FIELD_FILTERS),
  }
}

export function writeLiveFiltersToURL(url: URL, filters: LiveFilters) {
  const kinds = filters.kinds.length === 0 ? "any" : filters.kinds.length === ALL_STREAM_KINDS.length ? "" : filters.kinds.join(",")
  const set = (name: string, value: string) => (value ? url.searchParams.set(name, value) : url.searchParams.delete(name))
  set("traffic_kinds", kinds)
  set("traffic_clients", filters.clients.join(","))
  set("traffic_time", filters.time)
  set("traffic_search", filters.search)
  set("traffic_inc", (filters.include ?? []).join(" "))
  set("traffic_exc", (filters.exclude ?? []).join(" "))
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
  if (discoveryProtocol(event)) return "discovery"
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

const INSTANT_BADGES: Record<StreamKind, string> = { dns: "DNS", tls: "TLS", quic: "QUIC", http: "HTTP", discovery: "", alert: "ALERT", other: "" }

// streamLine is what one row says, e.g. DNS · maps.google.com · A → 142.250.1.1
export function streamLine(event: RecentEvent): StreamLine {
  if (event.blocked) return blockedStreamLine(event)
  if (event.app_protocol === "doh" || event.app_protocol === "dot" || event.app_protocol === "doq") return dohStreamLine(event)
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
    case "discovery": {
      // An mDNS/LLMNR question or announcement names a service or a device
      // ("_googlecast._tcp.local", "Living-Room-TV.local"); SSDP and the rest
      // are shown by protocol and group.
      const answers = event.dns_answers ?? []
      return {
        kind,
        badge: discoveryProtocol(event),
        name: event.dns_query || peer || event.kind,
        detail: event.dns_query
          ? [event.dns_record_type ?? "", answers.length ? `→ ${answers.slice(0, 2).join(", ")}${answers.length > 2 ? ` +${answers.length - 2}` : ""}` : ""]
              .filter(Boolean)
              .join(" ")
          : bytes,
        peer: event.dns_query ? peer : "",
        problem: false,
      }
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
// dohStreamLine is encrypted DNS ShakerProxy identified but cannot read:
// DNS over HTTPS, over TLS (TCP 853) or over QUIC (UDP 853).
function dohStreamLine(event: RecentEvent): StreamLine {
  const peer = endpoint(event.destination_ip, event.destination_port)
  const bytes = event.network_bytes ? compactBytes(event.network_bytes) : ""
  return {
    kind: "dns",
    badge: event.app_protocol === "dot" ? "DoT" : event.app_protocol === "doq" ? "DoQ" : "DoH",
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

// StreamEnd is one side of a row: what it is, then its address.
export type StreamEnd = { primary: string; secondary: string }

// streamEnds says where traffic went from and to. The device side carries its
// name; the other side its address, so each row reads "Pixel
// 192.168.10.201:42612 → 140.82.121.4:443". inbound marks traffic towards
// the device.
export function streamEnds(event: RecentEvent, deviceName: string): { from: StreamEnd; to: StreamEnd; inbound: boolean } {
  const source = endpoint(event.source_ip, event.source_port)
  const destination = endpoint(event.destination_ip, event.destination_port)
  const inbound = event.attribution_evidence?.endpoint === "DESTINATION"
  const protocol = (event.protocol ?? "").toUpperCase()
  const remote = (address: string): StreamEnd => ({ primary: address || "—", secondary: protocol })
  const local = (address: string): StreamEnd => ({ primary: deviceName || address || "—", secondary: deviceName ? address : "" })
  if (event.kind === "shakerproxy.dns") {
    return { from: local(source), to: { primary: "ShakerProxy DNS", secondary: destination || "port 53" }, inbound: false }
  }
  return inbound
    ? { from: remote(source), to: local(destination), inbound }
    : { from: local(source), to: remote(destination), inbound }
}

// whatSecondary is the line under a row's subject: who operates the
// destination and what kind of service it is.
export function ownerLine(event: RecentEvent): string {
  const category = event.destination_category && event.destination_category !== "unknown" ? event.destination_category.replace(/-/g, " ") : ""
  return [event.destination_organization ?? "", category].filter(Boolean).join(" · ")
}

// transferLine is bytes each way when known ("↑ 3 KB ↓ 22 KB"), else the total.
export function transferLine(event: RecentEvent): string {
  const sent = event.bytes_sent
  const received = event.bytes_received
  if (sent !== undefined || received !== undefined) return `↑ ${compactBytes(sent ?? 0)} ↓ ${compactBytes(received ?? 0)}`
  return event.network_bytes ? compactBytes(event.network_bytes) : ""
}

// Facets and the timeline are first computed from the events on the page
// (newest first, at most 1,000), so the sidebar works before and without
// the server summary.

export type FacetValue = { key: string; label: string; count: number; filter: string }
export type LiveFacets = { clients: FacetValue[]; kinds: FacetValue[]; owners: FacetValue[]; domains: FacetValue[]; ports: FacetValue[] }

function topValues(counts: Map<string, FacetValue>, limit: number): FacetValue[] {
  return Array.from(counts.values())
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label))
    .slice(0, limit)
}

function bump(counts: Map<string, FacetValue>, key: string, label: string, filter: string) {
  if (!key) return
  const current = counts.get(key)
  if (current) current.count++
  else counts.set(key, { key, label, count: 1, filter })
}

function registrableDomain(host: string): string {
  const labels = host.toLowerCase().replace(/\.$/, "").split(".")
  if (labels.length <= 2) return labels.join(".")
  const secondLevel = new Set(["co", "com", "net", "org", "gov", "ac", "edu"])
  return secondLevel.has(labels[labels.length - 2]) && labels[labels.length - 1].length === 2 ? labels.slice(-3).join(".") : labels.slice(-2).join(".")
}

export function pageFacets(events: readonly RecentEvent[], clientName: (event: RecentEvent) => string): LiveFacets {
  const clients = new Map<string, FacetValue>()
  const kinds = new Map<string, FacetValue>()
  const owners = new Map<string, FacetValue>()
  const domains = new Map<string, FacetValue>()
  const ports = new Map<string, FacetValue>()
  for (const event of events) {
    const line = streamLine(event)
    if (event.device_id) bump(clients, event.device_id, clientName(event) || event.device_id, `device.id:${event.device_id}`)
    else if (event.source_ip) bump(clients, `ip:${event.source_ip}`, event.source_ip, `src.ip:${event.source_ip}`)
    bump(kinds, line.kind, STREAM_KINDS.find((kind) => kind.id === line.kind)?.label ?? line.kind, "")
    if (event.destination_organization) bump(owners, event.destination_organization.toLowerCase(), event.destination_organization, `owner:${event.destination_organization.toLowerCase().replace(/[^a-z0-9.-]/g, "")}`)
    const host = event.tls_server_name || event.http_host || event.dns_query || event.dns_name
    if (host && !host.endsWith(".local") && !host.endsWith(".arpa")) {
      const domain = registrableDomain(host)
      bump(domains, domain, domain, domain)
    }
    if (event.destination_port) bump(ports, String(event.destination_port), `${event.destination_port}/${(event.protocol ?? "").toLowerCase()}`, `dst.port:${event.destination_port}`)
  }
  return { clients: topValues(clients, 12), kinds: topValues(kinds, 8), owners: topValues(owners, 10), domains: topValues(domains, 12), ports: topValues(ports, 10) }
}

export type TimelineBucket = { start: number; counts: Partial<Record<StreamKind, number>>; total: number }

// pageTimeline counts the page's events per bucket and kind, newest bucket last.
export function pageTimeline(events: readonly RecentEvent[], buckets: number, now: number, spanMs: number): TimelineBucket[] {
  const width = spanMs / buckets
  const start = now - spanMs
  const out: TimelineBucket[] = Array.from({ length: buckets }, (_, index) => ({ start: start + index * width, counts: {}, total: 0 }))
  for (const event of events) {
    const at = Date.parse(event.occurred_at)
    if (!(at >= start && at <= now)) continue
    const bucket = out[Math.min(buckets - 1, Math.floor((at - start) / width))]
    const kind = streamKind(event)
    bucket.counts[kind] = (bucket.counts[kind] ?? 0) + 1
    bucket.total++
  }
  return out
}

