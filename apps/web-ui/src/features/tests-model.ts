// Pure helpers for test runs (§5) and run comparison (§4 compare).
// Keep this file free of runtime imports so node --test can load it directly.
import type { DeviceCompare, ReportTotals, TestSession } from "./types"

// sessionsFromResponse accepts the list endpoint's body in either of the
// plausible shapes ({sessions:[…]}, {test_sessions:[…]} or a bare array).
export function sessionsFromResponse(body: unknown): TestSession[] {
  const list = Array.isArray(body)
    ? body
    : body && typeof body === "object"
      ? ((body as Record<string, unknown>).sessions ?? (body as Record<string, unknown>).test_sessions ?? (body as Record<string, unknown>).items)
      : undefined
  if (!Array.isArray(list)) return []
  return list.filter((item): item is TestSession => !!item && typeof item === "object" && typeof (item as TestSession).id === "string")
}

// sortSessions puts running sessions first, then the newest.
export function sortSessions(sessions: readonly TestSession[]): TestSession[] {
  return [...sessions].sort((a, b) => {
    const running = Number(b.state === "RUNNING") - Number(a.state === "RUNNING")
    return running || Date.parse(b.started_at) - Date.parse(a.started_at) || a.id.localeCompare(b.id)
  })
}

export function testSessionsPath(filters: { device?: string; state?: "RUNNING" | "STOPPED" | ""; limit?: number } = {}): string {
  const params = new URLSearchParams()
  if (filters.device) params.set("device", filters.device)
  if (filters.state) params.set("state", filters.state)
  params.set("limit", String(Math.min(Math.max(filters.limit ?? 50, 1), 200)))
  return `/api/v1/test-sessions?${params.toString()}`
}

function pad(value: number): string {
  return String(value).padStart(2, "0")
}

// defaultRunName mirrors the server default "<device name> — <YYYY-MM-DD HH:MM>" (local time shown as a hint).
export function defaultRunName(deviceName: string, date: Date = new Date()): string {
  const stamp = `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`
  return `${deviceName || "Device"} — ${stamp}`
}

// orderForCompare returns [base, compare] with the earlier run as the base.
export function orderForCompare(a: TestSession, b: TestSession): [TestSession, TestSession] {
  return Date.parse(a.started_at) <= Date.parse(b.started_at) ? [a, b] : [b, a]
}

export function comparePath(device: string, baseSession: string, compareSession: string): string {
  const params = new URLSearchParams({ base: baseSession, compare: compareSession })
  return `/api/v1/devices/${encodeURIComponent(device)}/compare?${params.toString()}`
}

export type CompareCheck = { ok: true } | { ok: false; reason: string }

export function canCompare(selected: readonly TestSession[]): CompareCheck {
  if (selected.length !== 2) return { ok: false, reason: "Select exactly two runs to compare." }
  if (selected[0].device_id !== selected[1].device_id) return { ok: false, reason: "Both runs must be for the same device." }
  return { ok: true }
}

export const TOTAL_LABELS: readonly { key: keyof ReportTotals; label: string; bytes?: boolean }[] = [
  { key: "events", label: "Events" },
  { key: "flows", label: "Connections" },
  { key: "bytes", label: "Data", bytes: true },
  { key: "dns_queries", label: "DNS lookups" },
  { key: "tls_connections", label: "TLS connections" },
  { key: "http_requests", label: "HTTP requests" },
  { key: "alerts", label: "IDS alerts" },
]

export type TotalDiff = { key: keyof ReportTotals; label: string; bytes: boolean; base: number; compare: number; delta: number }

export function diffTotals(base: Partial<ReportTotals> | undefined, compare: Partial<ReportTotals> | undefined): TotalDiff[] {
  return TOTAL_LABELS.map(({ key, label, bytes }) => {
    const left = Number(base?.[key] ?? 0) || 0
    const right = Number(compare?.[key] ?? 0) || 0
    return { key, label, bytes: !!bytes, base: left, compare: right, delta: right - left }
  })
}

export type CompareSummary = {
  changes: number
  headline: string
  sections: { key: string; label: string; count: number; tone: "added" | "removed" | "bad" | "good" }[]
}

export function compareSummary(compare: DeviceCompare): CompareSummary {
  const sections: CompareSummary["sections"] = [
    { key: "findings-new", label: "New findings", count: compare.findings.new.length, tone: "bad" },
    { key: "findings-resolved", label: "Resolved findings", count: compare.findings.resolved.length, tone: "good" },
    { key: "domains-added", label: "New domains", count: compare.domains.added.length, tone: "added" },
    { key: "domains-removed", label: "Domains no longer contacted", count: compare.domains.removed.length, tone: "removed" },
    { key: "protocols-added", label: "New protocols", count: compare.protocols.added.length, tone: "added" },
    { key: "protocols-removed", label: "Protocols no longer used", count: compare.protocols.removed.length, tone: "removed" },
    { key: "tls-failed", label: "Hosts now refusing decryption", count: compare.tls.newly_failed_hosts.length, tone: "bad" },
    { key: "tls-intercepted", label: "Hosts now decrypted", count: compare.tls.newly_intercepted_hosts.length, tone: "added" },
  ]
  const changes = sections.reduce((total, section) => total + section.count, 0)
  const newFindings = compare.findings.new.length
  let headline: string
  if (changes === 0) headline = "No differences in domains, protocols, findings or TLS outcomes between these runs."
  else if (newFindings > 0) {
    const other = changes - newFindings
    headline = `${newFindings} new finding${newFindings === 1 ? "" : "s"} in the later run${other > 0 ? `, plus ${other} other change${other === 1 ? "" : "s"}` : ""}.`
  } else headline = `${changes} change${changes === 1 ? "" : "s"} between the runs; no new findings.`
  return { changes, headline, sections }
}
