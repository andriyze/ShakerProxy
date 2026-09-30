import React, { useState } from "react"
import { api, describeError } from "../../api"
import { ErrorBox } from "../../shell/common"
import { useResource } from "../../shell/hooks"
import type { Device, DeviceAuditEvent, DeviceTrafficDeletionJob } from "../../types"

const AUDIT_LIMIT = 200

function actionLabel(action: string): string {
  const words = action.replace(/[_-]+/g, " ").toLowerCase()
  return words.charAt(0).toUpperCase() + words.slice(1)
}

type AuditPage = { schema: number; events: DeviceAuditEvent[]; next_cursor?: string }

function newestFirst(events: DeviceAuditEvent[] | null | undefined): DeviceAuditEvent[] {
  return (Array.isArray(events) ? events : [])
    .slice()
    .sort((left, right) => right.occurred_at.localeCompare(left.occurred_at))
}

function useDeviceAudit(enabled = true) {
  return useResource(
    async (signal) => {
      const page = await api<AuditPage>(`/api/v1/device-audit?limit=${AUDIT_LIMIT}`, { signal })
      return { events: newestFirst(page.events), nextCursor: page.next_cursor ?? "" }
    },
    [],
    { enabled },
  )
}

function touches(event: DeviceAuditEvent, deviceID: string): boolean {
  return Boolean(event.source_device_ids?.includes(deviceID) || event.result_device_ids?.includes(deviceID))
}

function AuditRow({ event, names }: { event: DeviceAuditEvent; names: Map<string, string> }) {
  const devices = [...new Set([...(event.source_device_ids ?? []), ...(event.result_device_ids ?? [])])]
  return (
    <article className="audit-row">
      <div>
        <strong>{actionLabel(event.action)}</strong>
        <span>
          {event.actor} · {new Date(event.occurred_at).toLocaleString()}
        </span>
      </div>
      {devices.length > 0 && <small>{devices.map((id) => names.get(id) || id).join(", ")}</small>}
      {event.changes && event.changes.length > 0 && <small>{event.changes.join(" · ")}</small>}
    </article>
  )
}

// DeviceAuditLog lists recent device corrections (renames, merges, splits,
// metadata and alias changes) from GET /api/v1/device-audit.
export function DeviceAuditLog({ devices }: { devices: Device[] }) {
  const audit = useDeviceAudit()
  const [older, setOlder] = useState<{ events: DeviceAuditEvent[]; cursor: string } | null>(null)
  const [olderError, setOlderError] = useState("")
  const [busy, setBusy] = useState(false)
  const names = new Map(devices.map((device) => [device.id, device.friendly_name || device.id]))
  const events = [...(audit.data?.events ?? []), ...(older?.events ?? [])]
  const cursor = older ? older.cursor : (audit.data?.nextCursor ?? "")
  async function loadOlder() {
    if (!cursor) return
    setBusy(true)
    setOlderError("")
    try {
      const page = await api<AuditPage>(
        `/api/v1/device-audit?limit=${AUDIT_LIMIT}&before=${encodeURIComponent(cursor)}`,
      )
      setOlder((current) => ({
        events: [...(current?.events ?? []), ...newestFirst(page.events)],
        cursor: page.next_cursor ?? "",
      }))
    } catch (reason) {
      setOlderError(describeError(reason, "Older changes could not be loaded"))
    } finally {
      setBusy(false)
    }
  }
  return (
    <details className="device-history">
      <summary>
        Change history · {audit.data ? `${events.length} change${events.length === 1 ? "" : "s"}` : "loading"}
      </summary>
      {audit.error && <ErrorBox message={audit.error} onRetry={() => void audit.reload()} />}
      {events.length === 0 && !audit.error && audit.data && <p>No device changes have been made yet.</p>}
      <div className="audit-list">
        {events.map((event) => (
          <AuditRow key={event.id} event={event} names={names} />
        ))}
      </div>
      {olderError && <ErrorBox message={olderError} />}
      {audit.data && (
        <div className="device-row-actions">
          {cursor && (
            <button type="button" className="quiet" disabled={busy} onClick={() => void loadOlder()}>
              {busy ? "Loading…" : "Show older changes"}
            </button>
          )}
          <button
            type="button"
            className="quiet"
            onClick={() => {
              setOlder(null)
              void audit.reload()
            }}
          >
            Refresh
          </button>
        </div>
      )}
    </details>
  )
}

// DeviceAuditEntries shows the changes that involved one device.
export function DeviceAuditEntries({ deviceID }: { deviceID: string }) {
  const audit = useDeviceAudit()
  const events = (audit.data?.events ?? []).filter((event) => touches(event, deviceID))
  return (
    <section className="device-drawer-evidence">
      <h3>Change history</h3>
      {audit.error && <p className="device-warning">{audit.error}</p>}
      {audit.data && events.length === 0 && <p>No changes recorded for this device.</p>}
      {events.slice(0, 20).map((event) => (
        <AuditRow key={event.id} event={event} names={new Map()} />
      ))}
    </section>
  )
}

// DeviceTrafficDeletionJobs lists past "delete this device's traffic" jobs
// from GET /api/v1/device-traffic-deletion-jobs.
export function DeviceTrafficDeletionJobs() {
  const jobs = useResource(async (signal) => {
    const page = await api<{ jobs: DeviceTrafficDeletionJob[] }>("/api/v1/device-traffic-deletion-jobs", { signal })
    return Array.isArray(page.jobs) ? page.jobs : []
  })
  const list = jobs.data ?? []
  if (jobs.data && list.length === 0 && !jobs.error) return null
  return (
    <details className="device-history">
      <summary>Traffic deletion jobs · {jobs.data ? list.length : "loading"}</summary>
      {jobs.error && <ErrorBox message={jobs.error} onRetry={() => void jobs.reload()} />}
      <div className="audit-list">
        {list.map((job) => (
          <article className="audit-row" key={job.id}>
            <div>
              <strong>
                {actionLabel(job.choice)} · {job.state.toLowerCase()}
              </strong>
              <span>
                {job.administrator} · {new Date(job.created_at).toLocaleString()} · {job.progress_percent}%
              </span>
            </div>
            <small>
              Device <code>{job.device_id}</code> · {job.phase.replaceAll("_", " ").toLowerCase()}
            </small>
            {job.failure && <small className="device-warning">{job.failure}</small>}
          </article>
        ))}
      </div>
    </details>
  )
}
