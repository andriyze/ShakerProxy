import React, { FormEvent, useState } from "react"
import { withPassword } from "../../shell/passwordPrompt"
import { formatBytes, formatDataClass, idempotencyKey } from "../../lib/format"
import { ErrorBox } from "../../shell/common"
import {
  captureDeletionCanCancel,
  captureDeletionCanRetry,
  coordinatedDeletionRequest,
  deletionBackendLabel,
} from "../../lib/captureDeletion"
import { api } from "../../api"
import type { CaptureDeletionJob, CaptureDeletionPreview, CaptureView } from "../../types"

export function CaptureDeletionControl({
  view,
  onDeleted,
}: {
  view: CaptureView
  onDeleted: (job: CaptureDeletionJob) => void
}) {
  const [preview, setPreview] = useState<CaptureDeletionPreview | null>(null)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState("")
  async function loadPreview() {
    setBusy(true)
    setMessage("")
    try {
      setPreview(
        await api<CaptureDeletionPreview>(`/api/v1/captures/${view.session.id}/deletion-preview`, {
          method: "POST",
          body: JSON.stringify({}),
        }),
      )
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Deletion preview is unavailable")
    } finally {
      setBusy(false)
    }
  }
  async function remove(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!preview) return
    setBusy(true)
    setMessage("")
    const form = event.currentTarget
    const data = new FormData(form)
    try {
      const job = await api<CaptureDeletionJob>(`/api/v1/captures/${view.session.id}/deletion-jobs`, {
        method: "POST",
        headers: { "Idempotency-Key": idempotencyKey("capture-delete") },
        body: JSON.stringify(coordinatedDeletionRequest(preview, data.get("password"), data.get("confirmation"))),
      })
      onDeleted(job)
      if (job.state !== "COMPLETED")
        setMessage(`Deletion ended ${job.state.toLowerCase()}; review the backend results below.`)
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Capture deletion failed")
    } finally {
      setBusy(false)
    }
  }
  const host = preview?.host_artifacts
  const events = preview?.normalized_events
  const zeek = preview?.zeek_checkpoint
  const suricata = preview?.suricata_checkpoint
  return (
    <details className="capture-delete">
      <summary>Deletion preview</summary>
      {!preview && (
        <button type="button" className="quiet danger" onClick={loadPreview} disabled={busy}>
          {busy ? "Calculating exact impact…" : "Preview capture deletion"}
        </button>
      )}
      {preview && host && events && zeek && suricata && (
        <div className="capture-delete-preview">
          <dl>
            <div>
              <dt>PCAP</dt>
              <dd>
                {host.footprint.capture_files.toLocaleString()} files · {formatBytes(host.footprint.capture_bytes)}
              </dd>
            </div>
            <div>
              <dt>Session metadata</dt>
              <dd>
                {host.footprint.metadata_files.toLocaleString()} files · {formatBytes(host.footprint.metadata_bytes)}
              </dd>
            </div>
            <div>
              <dt>Normalized events</dt>
              <dd>
                {events.database.event_rows.toLocaleString()} rows · {formatBytes(events.database.event_logical_bytes)}
              </dd>
            </div>
            <div>
              <dt>Exclusive identities</dt>
              <dd>
                {events.database.exclusive_identity_rows.toLocaleString()} rows ·{" "}
                {formatBytes(events.database.identity_logical_bytes)}
              </dd>
            </div>
            <div>
              <dt>Zeek analyzer state</dt>
              <dd>
                {zeek.checkpoint_present || zeek.active_progress_present
                  ? `${formatBytes(zeek.checkpoint_bytes + zeek.active_progress_bytes)} · ${zeek.events_delivered.toLocaleString()} checkpointed events`
                  : "Not present"}
              </dd>
            </div>
            <div>
              <dt>Suricata analyzer state</dt>
              <dd>
                {suricata.checkpoint_present || suricata.active_progress_present
                  ? `${formatBytes(suricata.checkpoint_bytes + suricata.active_progress_bytes)} · ${suricata.events_delivered.toLocaleString()} checkpointed events`
                  : "Not present"}
              </dd>
            </div>
            <div>
              <dt>Pending ingest spool</dt>
              <dd>
                {events.spool.pending_records.toLocaleString()} records · {formatBytes(events.spool.pending_file_bytes)}
              </dd>
            </div>
            <div>
              <dt>Recoverable now</dt>
              <dd>
                {formatBytes(
                  host.estimated_recoverable_bytes +
                    events.estimated_immediately_reclaimable_bytes +
                    zeek.checkpoint_bytes +
                    zeek.active_progress_bytes +
                    suricata.checkpoint_bytes +
                    suricata.active_progress_bytes,
                )}
              </dd>
            </div>
            <div>
              <dt>After database maintenance</dt>
              <dd>{formatBytes(events.logical_bytes_reclaimable_after_maintenance)}</dd>
            </div>
            <div>
              <dt>Preview expires</dt>
              <dd>{new Date(preview.expires_at).toLocaleTimeString()}</dd>
            </div>
          </dl>
          <p className="capture-delete-warning">
            This permanently marks the recording as deleted (so it is never re-imported), removes its events and the
            device identities only it referenced, verifies both analyzers' final checkpoints and active-rotation
            progress absent, then removes the entire named capture. PCAP may contain traffic from multiple devices;
            cross-device membership is not claimed known.
          </p>
          {(preview.copy_boundaries ?? []).map((boundary) => (
            <p className="device-boundary" key={boundary.data_class}>
              <strong>{formatDataClass(boundary.data_class)}</strong> ·{" "}
              {boundary.count_exact ? boundary.object_count.toLocaleString() : "unknown"} ·{" "}
              {formatDataClass(boundary.disposition)}. {boundary.warning}
            </p>
          ))}
          <p>Retained or independently managed: {preview.retained_data_classes.map(formatDataClass).join(", ")}.</p>
          <form onSubmit={remove}>
            <label>
              Type the capture ID
              <input name="confirmation" required pattern="capture-[a-f0-9]{32}" placeholder={preview.confirmation} />
            </label>
            <label>
              Administrator password
              <input name="password" type="password" autoComplete="current-password" required />
            </label>
            <button className="danger" disabled={busy}>
              {busy ? "Deleting and verifying…" : "Delete capture and derived data"}
            </button>
          </form>
        </div>
      )}
      {message && <p role="status">{message}</p>}
    </details>
  )
}

export function CaptureDeletionJobs({
  jobs,
  onUpdated,
}: {
  jobs: CaptureDeletionJob[]
  onUpdated: (job: CaptureDeletionJob) => void
}) {
  return (
    <section className="capture-deletion-jobs" aria-label="Capture deletion jobs">
      <h3>Capture deletion jobs</h3>
      {jobs.map((job) => (
        <CaptureDeletionJobCard key={job.id} job={job} onUpdated={onUpdated} />
      ))}
    </section>
  )
}

export function CaptureDeletionJobCard({
  job,
  onUpdated,
}: {
  job: CaptureDeletionJob
  onUpdated: (job: CaptureDeletionJob) => void
}) {
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState("")
  const [retryKey, setRetryKey] = useState(() => idempotencyKey("capture-delete-retry"))
  const [cancelKey, setCancelKey] = useState(() => idempotencyKey("capture-delete-cancel"))
  const [supersedeKey, setSupersedeKey] = useState(() => idempotencyKey("capture-delete-supersede"))
  async function retry(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setMessage("")
    const form = event.currentTarget
    const data = new FormData(form)
    try {
      const updated = await api<CaptureDeletionJob>(`/api/v1/capture-deletion-jobs/${job.id}/retry`, {
        method: "POST",
        headers: { "Idempotency-Key": retryKey },
        body: JSON.stringify({ password: data.get("password") }),
      })
      onUpdated(updated)
      setRetryKey(idempotencyKey("capture-delete-retry"))
      form.reset()
      if (updated.state !== "COMPLETED")
        setMessage(`Retry ended ${updated.state.toLowerCase()}; completed backend acknowledgements remain preserved.`)
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Capture deletion retry failed")
    } finally {
      setBusy(false)
    }
  }
  async function cancel(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setMessage("")
    try {
      const updated = await withPassword("cancel this deletion", (password) =>
        api<CaptureDeletionJob>(`/api/v1/capture-deletion-jobs/${job.id}/cancel`, {
          method: "POST",
          headers: { "Idempotency-Key": cancelKey },
          body: JSON.stringify(password ? { password } : {}),
        }),
      )
      onUpdated(updated)
      setCancelKey(idempotencyKey("capture-delete-cancel"))
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Capture deletion cancellation failed")
    } finally {
      setBusy(false)
    }
  }
  async function supersede(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setMessage("")
    const form = event.currentTarget
    const data = new FormData(form)
    try {
      const preview = await api<CaptureDeletionPreview>(`/api/v1/captures/${job.session_id}/deletion-preview`, {
        method: "POST",
        body: JSON.stringify({}),
      })
      const updated = await api<CaptureDeletionJob>(`/api/v1/capture-deletion-jobs/${job.id}/supersede`, {
        method: "POST",
        headers: { "Idempotency-Key": supersedeKey },
        body: JSON.stringify({ password: data.get("password"), preview, confirmation: job.session_id }),
      })
      onUpdated(updated)
      setSupersedeKey(idempotencyKey("capture-delete-supersede"))
      form.reset()
      if (updated.state !== "COMPLETED")
        setMessage(`Fresh evidence was persisted; unfinished backends ended ${updated.state.toLowerCase()}.`)
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Fresh-preview supersession failed")
    } finally {
      setBusy(false)
    }
  }
  return (
    <article>
      <div>
        <strong>
          {job.state} · {job.phase}
        </strong>
        <span>{job.progress_percent}%</span>
      </div>
      <code>{job.id}</code>
      <p>
        {job.session_id}
        {job.state === "COMPLETED"
          ? " · all configured backends acknowledged deletion"
          : job.state === "CANCELLED"
            ? " · cancelled before any replay barrier or backend mutation"
            : " · deletion is not complete across configured backends"}
      </p>
      <div className="capture-deletion-backends">
        {job.backends.map((backend) => (
          <div key={backend.backend}>
            <span>
              <strong>{deletionBackendLabel(backend.backend)}</strong>
              <small>{backend.state}</small>
            </span>
            {backend.normalized_events && (
              <small>
                {backend.normalized_events.database.deleted_event_rows.toLocaleString()} event rows ·{" "}
                {backend.normalized_events.spool.purged_records.toLocaleString()} spool records acknowledged
              </small>
            )}
            {backend.analyzer_checkpoint && (
              <small>
                {backend.analyzer_checkpoint.checkpoint_was_present
                  ? formatBytes(backend.analyzer_checkpoint.deleted_checkpoint_bytes)
                  : "No checkpoint present"}{" "}
                · absence verified
              </small>
            )}
            {backend.host_artifacts && (
              <small>
                {backend.host_artifacts.footprint.capture_files.toLocaleString()} PCAP files ·{" "}
                {formatBytes(backend.host_artifacts.footprint.capture_bytes)} acknowledged
              </small>
            )}
            {backend.failure && <small className="capture-delete-backend-failure">{backend.failure}</small>}
          </div>
        ))}
      </div>
      <small>Retained or independently managed: {job.retained_data_classes.map(formatDataClass).join(", ")}.</small>
      {job.failure && <ErrorBox message={`${job.failure}. Successful backend acknowledgements are preserved.`} />}{" "}
      {captureDeletionCanRetry(job.state) && (
        <form className="capture-deletion-retry" onSubmit={retry}>
          <label>
            Administrator password
            <input name="password" type="password" autoComplete="current-password" required />
          </label>
          <button className="danger" disabled={busy}>
            {busy ? "Retrying unfinished backends…" : "Retry unfinished backends"}
          </button>
        </form>
      )}
      {captureDeletionCanRetry(job.state) && (
        <form className="capture-deletion-retry" onSubmit={supersede}>
          <p>
            Use a fresh preview only when retry cannot pass stale or expired evidence. Completed acknowledgements remain
            immutable.
          </p>
          <label>
            Administrator password
            <input name="password" type="password" autoComplete="current-password" required />
          </label>
          <button className="quiet" disabled={busy}>
            {busy ? "Refreshing authoritative evidence…" : "Supersede with fresh preview"}
          </button>
        </form>
      )}
      {captureDeletionCanCancel(job) && (
        <form className="capture-deletion-retry" onSubmit={cancel}>
          <button className="quiet" disabled={busy}>
            {busy ? "Cancelling…" : "Cancel this deletion"}
          </button>
        </form>
      )}
      {message && <p role="status">{message}</p>}
    </article>
  )
}
