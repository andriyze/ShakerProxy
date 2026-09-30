// Pure helpers for the device report (§4).
// Keep this file free of runtime imports so node --test can load it directly.
import type { CATrust, DeviceReport, Finding, ReportDomain, Severity, TimeWindow } from "./types"

export const SEVERITIES: readonly Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

export const SEVERITY_INFO: Record<Severity, { label: string; tone: "critical" | "high" | "medium" | "low" | "info"; meaning: string }> = {
  CRITICAL: { label: "Critical", tone: "critical", meaning: "Exploitable now; fix before shipping." },
  HIGH: { label: "High", tone: "high", meaning: "Serious weakness; plan a fix." },
  MEDIUM: { label: "Medium", tone: "medium", meaning: "Worth fixing; lower risk." },
  LOW: { label: "Low", tone: "low", meaning: "Minor; fix when convenient." },
  INFO: { label: "Info", tone: "info", meaning: "Observation, not a problem by itself." },
}

export function severityRank(severity: string): number {
  const index = SEVERITIES.indexOf(severity as Severity)
  return index < 0 ? SEVERITIES.length : index
}

// sortFindings orders by severity (critical first), then by title.
export function sortFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || a.title.localeCompare(b.title))
}

export function worstSeverity(findings: readonly Finding[]): Severity | undefined {
  return sortFindings(findings)[0]?.severity
}

export function severityCounts(findings: readonly Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
  for (const finding of findings) if (finding.severity in counts) counts[finding.severity]++
  return counts
}

// findingsHeadline summarises findings in one line for headers and reports.
export function findingsHeadline(findings: readonly Finding[]): string {
  if (!findings.length) return "No security findings in this window."
  const counts = severityCounts(findings)
  const parts = SEVERITIES.filter((severity) => counts[severity] > 0).map((severity) => `${counts[severity]} ${SEVERITY_INFO[severity].label.toLowerCase()}`)
  return `${findings.length} finding${findings.length === 1 ? "" : "s"}: ${parts.join(", ")}.`
}

export type DomainKind = "tracker" | "telemetry" | "normal"

const TRACKER_CATEGORIES = new Set(["analytics", "advertising"])
const TELEMETRY_CATEGORIES = new Set(["telemetry", "crash-reporting"])

export function domainKind(category: string): DomainKind {
  if (TRACKER_CATEGORIES.has(category)) return "tracker"
  if (TELEMETRY_CATEGORIES.has(category)) return "telemetry"
  return "normal"
}

export const DOMAIN_CATEGORY_LABELS: Record<string, string> = {
  analytics: "Analytics & tracking",
  advertising: "Advertising",
  "crash-reporting": "Crash reporting",
  telemetry: "Telemetry",
  "cloud-platform": "Cloud platform",
  cdn: "Content delivery (CDN)",
  push: "Push notifications",
  "os-services": "Operating system services",
  streaming: "Streaming",
  "iot-cloud": "IoT cloud",
  unknown: "Other / unknown",
}

export function domainCategoryLabel(category: string): string {
  return DOMAIN_CATEGORY_LABELS[category] ?? (category ? category.replace(/-/g, " ") : "Other / unknown")
}

export type DomainGroup = {
  key: string
  label: string
  kind: DomainKind
  events: number
  domains: ReportDomain[]
}

// groupDomains groups report domains by category or organization. Tracker and
// telemetry groups sort first, then by activity; domains sort by activity.
export function groupDomains(domains: readonly ReportDomain[], by: "category" | "organization" = "category"): DomainGroup[] {
  const groups = new Map<string, DomainGroup>()
  for (const domain of domains) {
    const key = by === "category" ? domain.category || "unknown" : domain.organization || domain.registrable_domain || "Unknown organization"
    let group = groups.get(key)
    if (!group) {
      group = { key, label: by === "category" ? domainCategoryLabel(key) : key, kind: "normal", events: 0, domains: [] }
      groups.set(key, group)
    }
    group.domains.push(domain)
    group.events += domain.events
    const kind = domainKind(domain.category)
    if (kind === "tracker" || (kind === "telemetry" && group.kind === "normal")) group.kind = kind
  }
  const kindRank: Record<DomainKind, number> = { tracker: 0, telemetry: 1, normal: 2 }
  const result = [...groups.values()]
  for (const group of result) group.domains.sort((a, b) => b.events - a.events || a.domain.localeCompare(b.domain))
  return result.sort((a, b) => {
    const unknownLast = Number(a.key === "unknown") - Number(b.key === "unknown")
    return kindRank[a.kind] - kindRank[b.kind] || unknownLast || b.events - a.events || a.label.localeCompare(b.label)
  })
}

export function trackerDomainCount(domains: readonly ReportDomain[]): number {
  return domains.filter((domain) => domainKind(domain.category) === "tracker").length
}

export const CA_TRUST_OPTIONS: readonly { value: CATrust; label: string; explanation: string }[] = [
  { value: "UNKNOWN", label: "Not recorded", explanation: "You have not told ShakerProxy whether this device trusts its certificate." },
  { value: "INSTALLED", label: "ShakerProxy certificate installed", explanation: "You installed ShakerProxy's certificate on the device, so decrypted HTTPS is expected." },
  { value: "NOT_INSTALLED", label: "Not installed (validation test)", explanation: "The certificate is not installed. Any connection ShakerProxy manages to decrypt means the device accepts untrusted certificates." },
]

export function caTrustInfo(state: CATrust): { value: CATrust; label: string; explanation: string } {
  return CA_TRUST_OPTIONS.find((option) => option.value === state) ?? CA_TRUST_OPTIONS[0]
}

export type ReportScope = { window?: TimeWindow; session?: string }

export function reportPath(device: string, scope: ReportScope): string {
  const params = new URLSearchParams()
  if (scope.session) params.set("session", scope.session)
  else params.set("window", scope.window ?? "24h")
  return `/api/v1/devices/${encodeURIComponent(device)}/report?${params.toString()}`
}

// tlsSummaryLines explains the report's TLS outcomes in plain language.
export function tlsSummaryLines(report: Pick<DeviceReport, "tls" | "ca_trust">): string[] {
  const { tls } = report
  const lines: string[] = []
  const total = tls.intercepted + tls.bypassed + tls.failed
  if (total === 0) return ["No HTTPS connections were handled by ShakerProxy's decryption in this window. Turn on Decrypt HTTPS for this device to test it."]
  if (tls.intercepted > 0) {
    lines.push(
      report.ca_trust === "NOT_INSTALLED"
        ? `${tls.intercepted} connection${tls.intercepted === 1 ? " was" : "s were"} decrypted even though ShakerProxy's certificate is not installed: the device accepts untrusted certificates.`
        : `${tls.intercepted} connection${tls.intercepted === 1 ? " was" : "s were"} decrypted.`,
    )
  }
  if (tls.failed > 0) lines.push(`${tls.failed} connection${tls.failed === 1 ? "" : "s"} refused ShakerProxy's certificate (expected when it is not installed, or when an app pins its certificate).`)
  if (tls.pinning_suspected > 0) lines.push(`${tls.pinning_suspected} host${tls.pinning_suspected === 1 ? " looks" : "s look"} certificate-pinned: the app refuses any certificate but its own.`)
  if (tls.bypassed > 0) lines.push(`${tls.bypassed} connection${tls.bypassed === 1 ? " was" : "s were"} passed through without decryption (bypass rules or pinning fallback).`)
  for (const old of tls.old_versions) if (old.hosts.length) lines.push(`${old.version} (outdated) used with ${old.hosts.length} host${old.hosts.length === 1 ? "" : "s"}.`)
  return lines
}

// windowCovering picks the smallest protocol window that reaches back to
// `start` (the protocols endpoint takes windows, not arbitrary ranges).
export function windowCovering(start: string | null | undefined, now: number = Date.now()): TimeWindow {
  const began = start ? Date.parse(start) : NaN
  if (Number.isNaN(began)) return "24h"
  const hours = (now - began) / 3_600_000
  if (hours <= 1) return "1h"
  if (hours <= 24) return "24h"
  if (hours <= 24 * 7) return "7d"
  return "30d"
}

export function reportTitle(report: Pick<DeviceReport, "device" | "session">): string {
  const name = report.device.friendly_name || report.device.device_id
  return report.session ? `${name} — ${report.session.name}` : `${name} — security report`
}
