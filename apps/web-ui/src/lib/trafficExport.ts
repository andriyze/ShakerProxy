// Filtered traffic export: metadata only, collected through the bounded
// server cursor. The encoding helpers are pure; collection takes a page
// fetcher so it can be tested without a network.

export type ExportEvent = Record<string, unknown> & { record_id?: string; occurred_at?: string }
export type ExportPage = { events?: ExportEvent[]; next_cursor?: string; canonical_query?: string }
export type ExportFormat = "csv" | "jsonl" | "json"

export const PAGE_LIMIT = 100
export const EXPORT_LIMIT = 10_000

// exportPath builds the events request for one export page. It uses the
// applied query and Source, exactly as the table shows them.
export function exportPath(query: string, source: string, cursor: string): string {
  const parameters = new URLSearchParams({ limit: String(PAGE_LIMIT) })
  if (source) parameters.set("source", source)
  if (query) parameters.set("q", query)
  if (cursor) parameters.set("cursor", cursor)
  return `/api/v1/events?${parameters.toString()}`
}

export async function collectEvents(
  fetchPage: (cursor: string) => Promise<ExportPage>,
  fallbackQuery: string,
): Promise<{ events: ExportEvent[]; truncated: boolean; canonicalQuery: string }> {
  const events: ExportEvent[] = []
  let cursor = ""
  let canonicalQuery = fallbackQuery
  while (events.length < EXPORT_LIMIT) {
    const page = await fetchPage(cursor)
    const batch = Array.isArray(page.events) ? page.events : []
    if (events.length + batch.length > EXPORT_LIMIT) events.push(...batch.slice(0, EXPORT_LIMIT - events.length))
    else events.push(...batch)
    if (page.canonical_query) canonicalQuery = page.canonical_query
    if (!page.next_cursor || batch.length === 0) return { events, truncated: false, canonicalQuery }
    cursor = page.next_cursor
  }
  return { events, truncated: Boolean(cursor), canonicalQuery }
}

function csvCell(value: unknown): string {
  if (value === null || value === undefined) return ""
  const text = typeof value === "object" ? JSON.stringify(value) : String(value)
  return `"${text.replaceAll('"', '""')}"`
}

const PREFERRED_COLUMNS = [
  "occurred_at",
  "record_id",
  "device_id",
  "device_friendly_name",
  "summary",
  "source",
  "kind",
  "protocol",
  "service",
  "app_protocol",
  "source_ip",
  "source_port",
  "destination_ip",
  "destination_port",
  "network_bytes",
  "confidence",
  "dns_query",
  "dns_record_type",
  "dns_response_code",
  "dns_answer_count",
  "tls_server_name",
  "tls_interception_state",
  "tls_failure_reason",
  "tls_pinning_suspected",
  "tls_bypass_activated",
  "tls_platform",
  "http_method",
  "http_host",
  "http_path",
  "http_status",
]

export function toCSV(events: ExportEvent[]): string {
  const extras = new Set<string>()
  for (const event of events)
    for (const key of Object.keys(event)) if (!PREFERRED_COLUMNS.includes(key)) extras.add(key)
  const headers = [...PREFERRED_COLUMNS, ...[...extras].sort()]
  const rows = [headers.map(csvCell).join(",")]
  for (const event of events) rows.push(headers.map((key) => csvCell(event[key])).join(","))
  return rows.join("\r\n") + "\r\n"
}

export function encodeExport(
  format: ExportFormat,
  events: ExportEvent[],
  query: string,
  truncated: boolean,
  exportedAt = new Date(),
): { body: string; type: string; extension: string } {
  if (format === "csv") return { body: toCSV(events), type: "text/csv;charset=utf-8", extension: "csv" }
  if (format === "jsonl") {
    return {
      body: events.map((event) => JSON.stringify(event)).join("\n") + (events.length ? "\n" : ""),
      type: "application/x-ndjson;charset=utf-8",
      extension: "jsonl",
    }
  }
  return {
    body:
      JSON.stringify(
        {
          schema: 1,
          exported_at: exportedAt.toISOString(),
          canonical_query: query,
          row_count: events.length,
          truncated,
          plaintext_included: false,
          events,
        },
        null,
        2,
      ) + "\n",
    type: "application/json;charset=utf-8",
    extension: "json",
  }
}

export function exportFileName(extension: string, at = new Date()): string {
  return `shakerproxy-traffic-${at.toISOString().replaceAll(/[:.]/g, "-")}.${extension}`
}
