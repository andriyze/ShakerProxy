import React, { useState } from "react"
import { api, describeError, downloadBlob } from "../../api"
import {
  EXPORT_LIMIT,
  collectEvents,
  encodeExport,
  exportFileName,
  exportPath,
  type ExportFormat,
  type ExportPage,
} from "../../lib/trafficExport"

// Export exactly what the table shows: the applied query and Source filter,
// never an unapplied draft (audit #11). Metadata only; no HTTP plaintext.
export function TrafficExport({ query, source }: { query: string; source: string }) {
  const [busy, setBusy] = useState(false)
  const [status, setStatus] = useState<{ text: string; tone: string }>({
    text: "Exports the events matching the filter you applied.",
    tone: "",
  })
  async function run(format: ExportFormat) {
    if (busy) return
    setBusy(true)
    setStatus({ text: "Collecting events…", tone: "" })
    try {
      const result = await collectEvents((cursor) => api<ExportPage>(exportPath(query, source, cursor)), query)
      const encoded = encodeExport(format, result.events, result.canonicalQuery, result.truncated)
      downloadBlob(new Blob([encoded.body], { type: encoded.type }), exportFileName(encoded.extension))
      setStatus({
        text: `${result.events.length.toLocaleString()} event${result.events.length === 1 ? "" : "s"} exported${result.truncated ? ` · stopped at ${EXPORT_LIMIT.toLocaleString()}` : ""}. Decrypted content is never included.`,
        tone: result.truncated ? "warn" : "success",
      })
    } catch (reason) {
      setStatus({ text: describeError(reason, "The export failed"), tone: "error" })
    } finally {
      setBusy(false)
    }
  }
  return (
    <section className="traffic-export" aria-label="Export traffic">
      <div className="traffic-export-title">
        <strong>Export these events</strong>
        <small>Up to {EXPORT_LIMIT.toLocaleString()} events · summary fields only, no decrypted content</small>
      </div>
      <div className="traffic-export-actions">
        {(
          [
            ["csv", "CSV (spreadsheet)"],
            ["jsonl", "JSONL"],
            ["json", "JSON"],
          ] as const
        ).map(([format, label]) => (
          <button
            key={format}
            type="button"
            className="traffic-workspace-chip subtle"
            disabled={busy}
            onClick={() => void run(format)}
          >
            {label}
          </button>
        ))}
      </div>
      <span className={`traffic-export-status ${status.tone}`} role="status">
        {status.text}
      </span>
    </section>
  )
}
