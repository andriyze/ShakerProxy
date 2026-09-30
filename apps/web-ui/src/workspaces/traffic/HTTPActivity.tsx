import React, { FormEvent, useEffect, useState } from "react"
import { api, describeError } from "../../api"
import { compactBytes } from "../../lib/eventSummary"
import { ErrorBox } from "../../shell/common"
import { httpActivityPath, type HTTPActivityFilters as Filters } from "../../lib/httpActivity"
import type { InventorySnapshot } from "../../types"

// Web requests seen inside decrypted HTTPS, from GET /api/v1/agent/http-activity:
// one row per request with method, host, path and status. Metadata only.

type HTTPActivityEvent = {
  record_id: string
  source: string
  kind: string
  occurred_at: string
  device_id?: string
  method?: string
  scheme?: string
  host?: string
  port?: number
  path?: string
  status?: number
  request_bytes?: number
  response_bytes?: number
  decrypted?: boolean
  url_truncated?: boolean
}

type HTTPActivityPage = { schema: number; generated_at: string; events: HTTPActivityEvent[]; next_cursor?: string }

const WINDOWS: [string, string][] = [
  ["5m", "5 minutes"],
  ["15m", "15 minutes"],
  ["1h", "1 hour"],
  ["6h", "6 hours"],
  ["24h", "24 hours"],
]
const METHODS = ["", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
function statusTone(status?: number): string {
  if (!status) return ""
  if (status >= 500) return "danger"
  if (status >= 400) return "warn"
  return "good"
}

function HTTPActivityBody({ initialDevice }: { initialDevice: string }) {
  const [filters, setFilters] = useState<Filters>({ window: "1h", host: "", method: "", device: initialDevice })
  const [events, setEvents] = useState<HTTPActivityEvent[]>([])
  const [cursor, setCursor] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const [devices, setDevices] = useState<Map<string, string>>(new Map())

  useEffect(() => {
    api<InventorySnapshot>("/api/v1/devices?sort=name&direction=asc")
      .then((snapshot) =>
        setDevices(new Map((snapshot.devices ?? []).map((device) => [device.id, device.friendly_name || device.id]))),
      )
      .catch(() => setDevices(new Map()))
  }, [])

  async function load(next: Filters, more = false) {
    setBusy(true)
    setError("")
    try {
      const page = await api<HTTPActivityPage>(httpActivityPath(next, more ? cursor : ""))
      const rows = Array.isArray(page.events) ? page.events : []
      setEvents((current) => (more ? [...current, ...rows] : rows))
      setCursor(page.next_cursor ?? "")
    } catch (reason) {
      setError(describeError(reason, "Web requests are unavailable"))
    } finally {
      setBusy(false)
    }
  }

  useEffect(() => {
    void load(filters)
    // Load once on open; later loads come from the form.
  }, [])

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const next = {
      window: String(data.get("window") ?? "1h"),
      host: String(data.get("host") ?? ""),
      method: String(data.get("method") ?? ""),
      device: String(data.get("device") ?? ""),
    }
    setFilters(next)
    void load(next)
  }

  return (
    <>
      <form className="http-activity-filters" onSubmit={submit}>
        <label>
          Time
          <select name="window" defaultValue={filters.window}>
            {WINDOWS.map(([value, label]) => (
              <option key={value} value={value}>
                Last {label}
              </option>
            ))}
          </select>
        </label>
        <label>
          Device
          <select name="device" defaultValue={filters.device}>
            <option value="">All devices</option>
            {[...devices].map(([id, name]) => (
              <option key={id} value={id}>
                {name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Host
          <input name="host" defaultValue={filters.host} placeholder="api.example.com" spellCheck={false} />
        </label>
        <label>
          Method
          <select name="method" defaultValue={filters.method}>
            {METHODS.map((method) => (
              <option key={method || "any"} value={method}>
                {method || "Any"}
              </option>
            ))}
          </select>
        </label>
        <button className="quiet" disabled={busy}>
          {busy ? "Loading…" : "Show requests"}
        </button>
      </form>
      {error && <ErrorBox message={error} onRetry={() => void load(filters)} />}
      {!error && !busy && events.length === 0 && (
        <p className="http-activity-empty">
          No decrypted web requests in this time window. Requests appear here once HTTPS decryption is on for a device.
        </p>
      )}
      {events.length > 0 && (
        <div className="http-activity-table" role="table" aria-label="Decrypted web requests">
          <div className="http-activity-row header" role="row">
            <span role="columnheader">When</span>
            <span role="columnheader">Device</span>
            <span role="columnheader">Request</span>
            <span role="columnheader">Status</span>
            <span role="columnheader">Size</span>
          </div>
          {events.map((event) => (
            <div className="http-activity-row" role="row" key={event.record_id}>
              <span role="cell">{new Date(event.occurred_at).toLocaleTimeString()}</span>
              <span role="cell">{event.device_id ? (devices.get(event.device_id) ?? event.device_id) : "Unknown"}</span>
              <span role="cell" className="http-activity-request" title={`${event.host ?? ""}${event.path ?? ""}`}>
                <strong>{event.method ?? "HTTP"}</strong> {event.host}
                {event.path}
                {event.url_truncated ? "…" : ""}
              </span>
              <span role="cell" className={`http-activity-status ${statusTone(event.status)}`}>
                {event.status ?? "—"}
              </span>
              <span role="cell">
                {[event.request_bytes, event.response_bytes].some((value) => value !== undefined)
                  ? `${compactBytes(event.request_bytes ?? 0)} ↑ ${compactBytes(event.response_bytes ?? 0)} ↓`
                  : "—"}
              </span>
            </div>
          ))}
        </div>
      )}
      {cursor && (
        <button type="button" className="quiet" disabled={busy} onClick={() => void load(filters, true)}>
          {busy ? "Loading…" : "Load more requests"}
        </button>
      )}
    </>
  )
}

// HTTPActivity is collapsed until opened, so it costs nothing while hidden.
export function HTTPActivity({ deviceID = "" }: { deviceID?: string }) {
  const [open, setOpen] = useState(false)
  return (
    <details className="http-activity" onToggle={(event) => setOpen(event.currentTarget.open)}>
      <summary>Web requests (decrypted HTTPS): method, host, path and status</summary>
      {open && <HTTPActivityBody initialDevice={deviceID} />}
    </details>
  )
}
