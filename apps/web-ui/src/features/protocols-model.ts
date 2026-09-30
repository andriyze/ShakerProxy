// Pure helpers for the Protocols workspace (§2).
// Keep this file free of runtime imports so node --test can load it directly.
import type { CatalogProtocol, ProtocolCoverage, ProtocolEvidence, ProtocolUsage, ProtocolVisibility, TimeWindow } from "./types"

export type Tone = "good" | "info" | "warn" | "bad" | "muted"

export const VISIBILITY_INFO: Record<ProtocolVisibility, { label: string; short: string; tone: Tone; explanation: string }> = {
  DECRYPTED: { label: "Decrypted", short: "Decrypted", tone: "good", explanation: "ShakerProxy decrypted this HTTPS traffic and can show full requests." },
  CLEARTEXT: { label: "Cleartext", short: "Cleartext", tone: "warn", explanation: "Not encrypted: anyone on the network path can read it, and so can ShakerProxy." },
  ENCRYPTED_METADATA: { label: "Encrypted (names visible)", short: "Encrypted", tone: "info", explanation: "Encrypted, but ShakerProxy sees who it talks to (server names, certificates)." },
  OPAQUE: { label: "Opaque", short: "Opaque", tone: "bad", explanation: "ShakerProxy cannot see what this traffic carries (VPN, tunnel, or unknown protocol)." },
}

export const EVIDENCE_INFO: Record<ProtocolEvidence, { label: string; explanation: string }> = {
  ANALYZER: { label: "Confirmed", explanation: "A traffic analyzer recognised the protocol from its content." },
  PORT_HEURISTIC: { label: "Port guess", explanation: "Guessed from the port number only; the traffic may be something else." },
  UNCLASSIFIED: { label: "Unidentified", explanation: "Neither an analyzer nor a well-known port identified this traffic." },
}

export type CoverageSegment = {
  key: "decrypted" | "cleartext" | "encrypted_metadata" | "opaque"
  label: string
  bytes: number
  // Share of total bytes, 0–100 (unrounded).
  percent: number
  tone: Tone
  explanation: string
}

export function coverageSegments(coverage: ProtocolCoverage): CoverageSegment[] {
  const parts: [CoverageSegment["key"], ProtocolVisibility, number][] = [
    ["decrypted", "DECRYPTED", coverage.decrypted_bytes],
    ["cleartext", "CLEARTEXT", coverage.cleartext_bytes],
    ["encrypted_metadata", "ENCRYPTED_METADATA", coverage.encrypted_metadata_bytes],
    ["opaque", "OPAQUE", coverage.opaque_bytes],
  ]
  const sum = parts.reduce((total, [, , bytes]) => total + Math.max(0, bytes || 0), 0)
  const total = Math.max(coverage.total_bytes || 0, sum)
  return parts.map(([key, visibility, bytes]) => ({
    key,
    label: VISIBILITY_INFO[visibility].label,
    bytes: Math.max(0, bytes || 0),
    percent: total > 0 ? (Math.max(0, bytes || 0) / total) * 100 : 0,
    tone: VISIBILITY_INFO[visibility].tone,
    explanation: VISIBILITY_INFO[visibility].explanation,
  }))
}

function roundPercent(value: number): string {
  if (value > 0 && value < 1) return "<1%"
  return `${Math.round(value)}%`
}

// coverageSentence explains the coverage bar in one plain-language line.
export function coverageSentence(coverage: ProtocolCoverage): string {
  const segments = coverageSegments(coverage)
  const [decrypted, cleartext, encrypted, opaque] = segments
  if (segments.every((segment) => segment.bytes === 0)) return "No traffic in this window yet."
  const readable = decrypted.percent + cleartext.percent
  const parts = [`ShakerProxy can read ${roundPercent(readable)} of this traffic`]
  if (encrypted.percent > 0) parts.push(`sees only server names for ${roundPercent(encrypted.percent)}`)
  if (opaque.percent > 0) parts.push(`cannot see inside ${roundPercent(opaque.percent)}`)
  let sentence = parts.length === 1 ? parts[0] : `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}`
  if (encrypted.percent >= 25 && decrypted.percent < 1) sentence += ". Turn on Decrypt HTTPS for a device to see inside its encrypted traffic"
  return `${sentence}.`
}

export type ProtocolFilters = {
  window: TimeWindow
  device: string
  category: string
  exotic: boolean
}

export const DEFAULT_PROTOCOL_FILTERS: ProtocolFilters = { window: "24h", device: "", category: "", exotic: false }

export function protocolsPath(filters: ProtocolFilters): string {
  const params = new URLSearchParams({ window: filters.window })
  if (filters.device.trim()) params.set("device", filters.device.trim())
  if (filters.category) params.set("category", filters.category)
  if (filters.exotic) params.set("exotic", "true")
  return `/api/v1/protocols?${params.toString()}`
}

export function deviceProtocolsPath(device: string, window: TimeWindow): string {
  return `/api/v1/devices/${encodeURIComponent(device)}/protocols?window=${encodeURIComponent(window)}`
}

export type ProtocolSort = "bytes" | "flows" | "devices" | "last_seen" | "label"

export function sortProtocols(protocols: readonly ProtocolUsage[], sort: ProtocolSort = "bytes"): ProtocolUsage[] {
  const byLabel = (a: ProtocolUsage, b: ProtocolUsage) => a.label.localeCompare(b.label)
  const compare: Record<ProtocolSort, (a: ProtocolUsage, b: ProtocolUsage) => number> = {
    bytes: (a, b) => b.bytes - a.bytes || byLabel(a, b),
    flows: (a, b) => b.flows - a.flows || byLabel(a, b),
    devices: (a, b) => b.device_count - a.device_count || b.bytes - a.bytes || byLabel(a, b),
    last_seen: (a, b) => Date.parse(b.last_seen) - Date.parse(a.last_seen) || byLabel(a, b),
    label: byLabel,
  }
  return [...protocols].sort(compare[sort])
}

// trafficQueryForProtocol builds the Traffic workspace query for one protocol.
export function trafficQueryForProtocol(protocolID: string): string {
  return /^[a-z0-9][a-z0-9.+-]*$/i.test(protocolID) ? `app.protocol:${protocolID}` : `app.protocol:"${protocolID.replace(/["\\]/g, "")}"`
}

export function protocolChips(protocol: Pick<ProtocolUsage, "novel" | "exotic">): { label: string; title: string }[] {
  const chips: { label: string; title: string }[] = []
  if (protocol.novel) chips.push({ label: "New", title: "First seen on this ShakerProxy during the selected window." })
  if (protocol.exotic) chips.push({ label: "Exotic", title: "Uncommon on typical networks; worth a closer look." })
  return chips
}

export function portSummary(ports: readonly { transport: string; port: number }[], limit = 4): string {
  if (!ports.length) return "—"
  const shown = ports.slice(0, limit).map((port) => `${port.transport.toUpperCase()} ${port.port}`)
  return ports.length > limit ? `${shown.join(", ")} +${ports.length - limit}` : shown.join(", ")
}

export function filterCatalog(catalog: readonly CatalogProtocol[], text: string, category: string): CatalogProtocol[] {
  const needle = text.trim().toLowerCase()
  return catalog
    .filter((item) => !category || item.category === category)
    .filter((item) => {
      if (!needle) return true
      if (item.id.toLowerCase().includes(needle) || item.label.toLowerCase().includes(needle) || item.description.toLowerCase().includes(needle)) return true
      return (item.ports ?? []).some((port) => String(port.port) === needle)
    })
    .sort((a, b) => a.label.localeCompare(b.label))
}
