// Plain-language one-line description of a traffic event (contracts §3).
// The server sends `summary` when it can; older events and older appliances
// do not, so the UI builds an equivalent line from the structured fields.

export type SummarizableEvent = {
  kind: string
  source?: string
  summary?: string
  protocol?: string
  service?: string
  app_protocol?: string
  destination_ip?: string
  destination_port?: number
  network_bytes?: number
  dns_query?: string
  dns_record_type?: string
  dns_response_code?: string
  dns_answer_count?: number
  tls_server_name?: string
  tls_interception_state?: string
  tls_pinning_suspected?: boolean
  http_method?: string
  http_host?: string
  http_path?: string
  http_status?: number
  detection_type?: string
  detection_severity?: string
  detection_summary?: string
  alert_signature?: string
  alert_severity?: number | string
}

export function compactBytes(value: number): string {
  if (!Number.isFinite(value) || value < 0) return ""
  if (value < 1024) return `${Math.round(value)} B`
  if (value < 1024 * 1024) return `${Math.round(value / 1024)} KB`
  if (value < 1024 * 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MB`
  return `${(value / (1024 * 1024 * 1024)).toFixed(1)} GB`
}

function endpoint(address?: string, port?: number): string {
  if (!address) return port ? `port ${port}` : "an unknown address"
  const host = address.includes(":") ? `[${address}]` : address
  return port ? `${host}:${port}` : host
}

function withBytes(text: string, bytes?: number): string {
  return bytes && bytes > 0 ? `${text} · ${compactBytes(bytes)}` : text
}

function upperLabel(value: string): string {
  return value.replace(/[_-]+/g, " ").trim().toUpperCase()
}

const MAX_SUMMARY = 160

function clip(text: string): string {
  return text.length > MAX_SUMMARY ? `${text.slice(0, MAX_SUMMARY - 1)}…` : text
}

// severityLabel turns Suricata's numeric alert priority (1 is highest) or a
// ShakerProxy detection severity into HIGH/MEDIUM/LOW/INFO/CRITICAL.
export function severityLabel(event: Pick<SummarizableEvent, "alert_severity" | "detection_severity">): string {
  const alert = event.alert_severity
  if (typeof alert === "number") return ({ 1: "HIGH", 2: "MEDIUM", 3: "LOW", 4: "INFO" } as Record<number, string>)[alert] ?? ""
  if (typeof alert === "string" && alert.trim()) return alert.trim().toUpperCase()
  return typeof event.detection_severity === "string" ? event.detection_severity.trim().toUpperCase() : ""
}

export function eventSummary(event: SummarizableEvent): string {
  if (event.summary && event.summary.trim()) return clip(event.summary.trim())

  if (event.alert_signature || event.detection_type || event.detection_summary) {
    const level = severityLabel(event)
    const severity = level ? ` (${level})` : ""
    return clip(
      `Alert${severity}: ${event.alert_signature || event.detection_summary || event.detection_type?.replaceAll("_", " ")}`,
    )
  }

  if (event.http_method || event.http_host) {
    const target =
      `${event.http_host ?? ""}${event.http_path ?? ""}` || endpoint(event.destination_ip, event.destination_port)
    const status = event.http_status ? ` → ${event.http_status}` : ""
    return clip(`${event.http_method ?? "HTTP"} ${target}${status}`)
  }

  if (event.dns_query) {
    const type = event.dns_record_type ? ` (${event.dns_record_type})` : ""
    let outcome = ""
    if (event.dns_answer_count !== undefined && event.dns_answer_count > 0) {
      outcome = ` → ${event.dns_answer_count} answer${event.dns_answer_count === 1 ? "" : "s"}`
    } else if (event.dns_response_code && event.dns_response_code.toUpperCase() !== "NOERROR") {
      outcome = ` → ${event.dns_response_code.toUpperCase()}`
    } else if (event.dns_answer_count === 0) {
      outcome = " → no answers"
    }
    return clip(`DNS lookup ${event.dns_query}${type}${outcome}`)
  }

  if (event.tls_server_name || event.tls_interception_state) {
    const name = event.tls_server_name || endpoint(event.destination_ip, event.destination_port)
    switch (event.tls_interception_state) {
      case "INTERCEPTED":
        return clip(`HTTPS ${name} — decrypted`)
      case "FAILED":
        return clip(
          `HTTPS ${name} — not decrypted${event.tls_pinning_suspected ? " (pinned?)" : " (certificate rejected)"}`,
        )
      case "BYPASSED":
        return clip(`HTTPS ${name} — not decrypted (passed through)`)
      default:
        return clip(`HTTPS ${name}`)
    }
  }

  const label = event.app_protocol || event.service
  if (label) {
    return clip(
      withBytes(
        `${upperLabel(label)} to ${endpoint(event.destination_ip, event.destination_port)}`,
        event.network_bytes,
      ),
    )
  }
  if (event.destination_ip) {
    const transport = event.protocol ? upperLabel(event.protocol) : "Traffic"
    return clip(
      withBytes(
        `Unidentified ${transport} to ${endpoint(event.destination_ip, event.destination_port)}`,
        event.network_bytes,
      ),
    )
  }
  return clip(event.kind.replace(/[._]+/g, " "))
}

export type EventTone = "alert" | "tls-ok" | "tls-fail" | "bypass" | "http" | "dns" | ""

// eventTone picks the row accent from structured fields (never from text).
export function eventTone(event: SummarizableEvent): EventTone {
  const severity = severityLabel(event)
  if (severity === "HIGH" || severity === "CRITICAL") return "alert"
  const kind = event.kind.toLowerCase()
  if (kind === "tls_interception_failed" || event.tls_interception_state === "FAILED") return "tls-fail"
  if (kind === "tls_intercepted" || event.tls_interception_state === "INTERCEPTED") return "tls-ok"
  if (kind === "tls_passthrough" || event.tls_interception_state === "BYPASSED") return "bypass"
  if (kind.startsWith("http_") || event.http_method) return "http"
  if (event.dns_query || kind.includes("dns") || event.service === "dns" || event.service === "doh") return "dns"
  return ""
}

// Zeek and Suricata both describe the same traffic. The readable list keeps
// one row per connection and per lookup (Zeek's conn, dns and ssl records,
// alerts, interception and web requests) and drops Suricata's flow, DNS and
// mDNS copies, Zeek's protocol warnings, and the connection records of DNS
// lookups that already appear as named lookups.
export function isAnalyzerDuplicate(event: { kind: string; service?: string; app_protocol?: string }): boolean {
  switch (event.kind) {
    case "suricata.flow":
    case "suricata.dns":
    case "suricata.mdns":
    case "zeek.weird":
      return true
    case "zeek.conn":
      return event.app_protocol === "dns" || (event.service ?? "").split(",").includes("dns")
    default:
      return false
  }
}

// eventTypeLabel names what kind of thing an event is, in plain words.
export function eventTypeLabel(event: SummarizableEvent): string {
  if (event.alert_signature || event.detection_type || event.detection_summary) return "Alert"
  if (event.kind === "encrypted_dns_detected") return "Encrypted DNS"
  if (event.dns_query) return "DNS"
  if (event.tls_interception_state) return "HTTPS"
  if (event.http_method || event.http_host) return "Web request"
  if (event.kind === "zeek.weird") return "Protocol warning"
  if (/\.(conn|flow|quic|ssl|tls)$/.test(event.kind)) return "Connection"
  const name = event.kind.split(".").pop() ?? event.kind
  return name.replace(/[_-]+/g, " ").replace(/^./, (first) => first.toUpperCase())
}
