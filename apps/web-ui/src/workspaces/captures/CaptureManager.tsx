import React, { FormEvent, useEffect, useState } from "react"
import { withPassword } from "../../shell/passwordPrompt"
import { formatBytes, formatDataClass, idempotencyKey } from "../../lib/format"
import { useAppState } from "../../shell/AppContext"
import { authFetch, responseError } from "../../shell/authFetch"
import { ErrorBox } from "../../shell/common"
import { usePolling, useResource } from "../../shell/hooks"
import { CaptureRetentionPreview } from "./CaptureRetention"
import { CaptureDeletionControl, CaptureDeletionJobs } from "./CaptureDeletion"
import { captureArtifactsWereDeleted } from "../../lib/captureDeletion"
import { api, describeError, downloadBlob } from "../../api"
import type { CaptureDeletionJob, CaptureExportRecord, CaptureFile, CaptureView, CaseRecord } from "../../types"

type CaseChoice = { id: string; name: string; revision: number }

// useOpenCases lists open cases for the case pickers on this page.
function useOpenCases(): CaseChoice[] {
  const cases = useResource(
    async (signal) => {
      const result = await api<{ cases: CaseRecord[] }>("/api/v1/cases", { signal })
      return (Array.isArray(result.cases) ? result.cases : [])
        .filter((item) => item.status === "OPEN")
        .map((item) => ({ id: item.id, name: item.name, revision: item.revision }))
    },
    [],
    { intervalMs: 60_000 },
  )
  return cases.data ?? []
}

export function CaptureManager({ canStart, blockedReason }: { canStart: boolean; blockedReason: string }) {
  const { refreshStatus } = useAppState()
  const [captures, setCaptures] = useState<CaptureView[]>([])
  const [loaded, setLoaded] = useState(false)
  const [deletionJobs, setDeletionJobs] = useState<CaptureDeletionJob[]>([])
  const [error, setError] = useState("")
  const [deletionError, setDeletionError] = useState("")
  const [busy, setBusy] = useState(false)
  // Whole packets by default: TLS and QUIC handshakes carry the domains.
  const [captureMode, setCaptureMode] = useState("FULL_PACKETS")
  const cases = useOpenCases()

  async function refresh() {
    try {
      const result = await api<{ captures: CaptureView[] }>("/api/v1/captures")
      setCaptures(Array.isArray(result.captures) ? result.captures : [])
      setError("")
    } catch (reason) {
      setError(describeError(reason, "Recordings are unavailable"))
    } finally {
      setLoaded(true)
    }
  }

  async function refreshDeletionJobs() {
    try {
      const result = await api<{ jobs: CaptureDeletionJob[] }>("/api/v1/capture-deletion-jobs")
      setDeletionJobs(Array.isArray(result.jobs) ? result.jobs : [])
      setDeletionError("")
    } catch (reason) {
      setDeletionError(describeError(reason, "Deletion history is unavailable"))
    }
  }

  // Past recordings, exports and deletion jobs are always listed, even when a
  // new recording cannot be started (audit #9). Poll fast only while
  // something is running.
  const running =
    captures.some((item) => item.active) ||
    deletionJobs.some((job) => job.state === "PENDING" || job.state === "RUNNING")
  usePolling(() => Promise.all([refresh(), refreshDeletionJobs()]), running ? 2000 : 10_000, [running])

  async function start(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setError("")
    const form = event.currentTarget
    const data = new FormData(form)
    const request = {
      name: String(data.get("name")),
      description: String(data.get("description")),
      mode: String(data.get("mode")),
      snap_length: Number(data.get("snap_length")),
      segment_size_mib: Number(data.get("segment_size_mib")),
      segment_seconds: Number(data.get("segment_seconds")),
      max_files: Number(data.get("max_files")),
      stop_after_seconds: Number(data.get("stop_after_seconds")),
      retention_lock: data.get("retention_lock") === "on",
      case_id: String(data.get("case_id") ?? ""),
      start_reason: String(data.get("start_reason")),
    }
    try {
      const result = await api<CaptureView>("/api/v1/captures", {
        method: "POST",
        headers: { "Idempotency-Key": idempotencyKey("capture") },
        body: JSON.stringify(request),
      })
      setCaptures((current) => [result, ...current.filter((item) => item.session.id !== result.session.id)])
      form.reset()
      void refreshStatus()
    } catch (reason) {
      setError(describeError(reason, "Recording could not start"))
    } finally {
      setBusy(false)
    }
  }

  async function stop(sessionID: string) {
    setBusy(true)
    setError("")
    try {
      const result = await api<CaptureView>(`/api/v1/captures/${sessionID}/stop`, {
        method: "POST",
        headers: { "Idempotency-Key": idempotencyKey("capture-stop") },
        body: JSON.stringify({}),
      })
      setCaptures((current) => current.map((item) => (item.session.id === sessionID ? result : item)))
      void refreshStatus()
    } catch (reason) {
      setError(describeError(reason, "Recording could not stop"))
    } finally {
      setBusy(false)
    }
  }

  const deleted = (job: CaptureDeletionJob) => {
    if (captureArtifactsWereDeleted(job))
      setCaptures((current) => current.filter((item) => item.session.id !== job.session_id))
    setDeletionJobs((current) => [job, ...current.filter((item) => item.id !== job.id)])
  }

  const active = captures.find((item) => item.active)
  const finished = captures.filter((item) => !item.active)
  return (
    <section className="capture-manager">
      <div className="capture-head">
        <div>
          <p className="eyebrow">Packet recording</p>
          <h2>{active ? `Recording: ${active.session.request.name}` : "Record the lab network"}</h2>
          <p>
            ShakerProxy records packets on the lab side of the network into rotating files. While a lab routes, it
            records automatically (&ldquo;Lab traffic&rdquo;). A recording stops by itself at its time limit and always
            leaves 1 GiB of disk free. While recording, analysed events appear in Traffic
            about 20–40 seconds after the traffic happens.
          </p>
        </div>
        <span className={active ? "capture-live" : canStart ? "capture-ready" : "capture-blocked"}>
          {active ? "RECORDING" : canStart ? "READY" : "NOT AVAILABLE"}
        </span>
      </div>
      {error && <ErrorBox message={error} onRetry={() => void refresh()} />}
      {deletionError && <ErrorBox message={`Deletion history: ${deletionError}`} />}
      {active && <CaptureSession view={active} onStop={() => stop(active.session.id)} busy={busy} cases={cases} />}
      {active?.session.request.automatic && canStart && (
        <p className="capture-gate">
          This is the automatic lab recording. A recording you start below replaces it until yours ends; stopping it turns
          automatic recording off.
        </p>
      )}
      {active && !active.session.request.automatic ? null : !canStart ? (
        <p className="capture-gate">{blockedReason}</p>
      ) : (
        <form className="capture-form" onSubmit={start}>
          <label>
            Name
            <input name="name" defaultValue="Investigation window" maxLength={96} required />
          </label>
          <label>
            Case
            <select name="case_id" defaultValue="">
              <option value="">No case</option>
              {cases.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            Notes
            <input name="description" maxLength={1024} placeholder="What you are testing" />
          </label>
          <label>
            What to record
            <select name="mode" value={captureMode} onChange={(event) => setCaptureMode(event.target.value)}>
              <option value="FULL_PACKETS">Whole packets: shows domains (recommended)</option>
              <option value="HEADERS_ONLY">Packet headers only: smaller files, no domains</option>
            </select>
          </label>
          <label>
            Stop after (seconds)
            <input name="stop_after_seconds" type="number" min="10" max="86400" defaultValue="3600" required />
          </label>
          <details className="capture-advanced">
            <summary>File size and rotation limits</summary>
            <label>
              Bytes kept per packet
              <input name="snap_length" type="number" value={captureMode === "FULL_PACKETS" ? 0 : 256} readOnly />
              <span className="hint">
                {captureMode === "FULL_PACKETS"
                  ? "0 captures the full packet up to dumpcap's safety maximum."
                  : "256 bytes retains link, network, and common transport headers."}
              </span>
            </label>
            <label>
              File size (MiB)
              <input name="segment_size_mib" type="number" min="1" max="1024" defaultValue="8" required />
            </label>
            <label>
              Start a new file every (seconds)
              <input name="segment_seconds" type="number" min="10" max="3600" defaultValue="30" required />
            </label>
            <label>
              Files to keep
              <input name="max_files" type="number" min="2" max="64" defaultValue="64" required />
            </label>
            <label>
              Reason (for the audit log)
              <input name="start_reason" defaultValue="Administrator investigation" maxLength={256} />
            </label>
            <label className="check">
              <input name="retention_lock" type="checkbox" />
              <span>Never delete this recording automatically</span>
            </label>
          </details>
          <button disabled={busy}>{busy ? "Starting…" : "Start recording"}</button>
        </form>
      )}
      {finished.length > 0 && (
        <div className="capture-history">
          <h3>Finished recordings</h3>
          {finished.map((item) => (
            <CaptureSession key={item.session.id} view={item} busy={busy} onDeleted={deleted} cases={cases} />
          ))}
        </div>
      )}
      {loaded && finished.length === 0 && !active && <p className="capture-empty">No finished recordings yet.</p>}
      {deletionJobs.length > 0 && <CaptureDeletionJobs jobs={deletionJobs} onUpdated={deleted} />}
      <CaptureRetentionPreview />
    </section>
  )
}

// AddToCase attaches a finished recording to an open case.
function AddToCase({ view, cases }: { view: CaptureView; cases: CaseChoice[] }) {
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState("")
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = event.currentTarget
    const data = new FormData(form)
    const target = cases.find((item) => item.id === data.get("case_id"))
    if (!target) return
    setBusy(true)
    setMessage("")
    try {
      // Re-read the case so a concurrent change does not fail the revision check.
      const current = await api<CaseRecord>(`/api/v1/cases/${target.id}`)
      await api<CaseRecord>(`/api/v1/cases/${target.id}/evidence`, {
        method: "POST",
        body: JSON.stringify({
          expected_revision: current.revision,
          kind: "CAPTURE",
          artifact_id: view.session.id,
          label: view.session.request.name,
          reason: data.get("reason"),
        }),
      })
      form.reset()
      setMessage(`Added to “${target.name}”.`)
    } catch (reason) {
      setMessage(describeError(reason, "Could not add the recording to the case"))
    } finally {
      setBusy(false)
    }
  }
  if (cases.length === 0) {
    return (
      <p className="capture-add-case-empty">
        To keep this recording with other evidence, <a href="#/cases">create a case</a> first.
      </p>
    )
  }
  return (
    <details className="capture-add-case">
      <summary>Add to case</summary>
      <form onSubmit={submit}>
        <label>
          Case
          <select name="case_id" required defaultValue="">
            <option value="" disabled>
              Choose a case
            </option>
            {cases.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Reason (for the audit log)
          <input name="reason" maxLength={512} required />
        </label>
        <button className="quiet" disabled={busy}>
          {busy ? "Adding…" : "Add to case"}
        </button>
        {message && <small role="status">{message}</small>}
      </form>
    </details>
  )
}

export function CaptureSession({
  view,
  onStop,
  busy,
  onDeleted,
  cases = [],
}: {
  view: CaptureView
  onStop?: () => void
  busy: boolean
  onDeleted?: (job: CaptureDeletionJob) => void
  cases?: CaseChoice[]
}) {
  const [exports, setExports] = useState<CaptureExportRecord[]>([])
  const packets = view.worker?.packets_captured ?? view.manifest?.packets_captured ?? 0
  const drops =
    (view.worker?.kernel_drops ?? view.manifest?.kernel_drops ?? 0) +
    (view.worker?.dumpcap_drops ?? view.manifest?.dumpcap_drops ?? 0)
  async function refreshExports() {
    try {
      const result = await api<{ exports: CaptureExportRecord[] }>(`/api/v1/captures/${view.session.id}/exports`)
      setExports(result.exports)
    } catch {
      /* File delivery still works if the history panel cannot refresh. */
    }
  }
  useEffect(() => {
    if (view.manifest) void refreshExports()
  }, [view.session.id, view.manifest?.created_at])
  return (
    <article className="capture-session">
      <div className="capture-session-title">
        <div>
          <strong>{view.session.request.name}</strong>
          <code>{view.session.id}</code>
        </div>
        <span>{view.state}</span>
      </div>
      <div className="capture-stats">
        <span>
          <strong>{packets.toLocaleString()}</strong> packets
        </span>
        <span>
          <strong>{drops.toLocaleString()}</strong> drops
        </span>
        <span>
          <strong>{formatBytes(view.current_bytes)}</strong> stored
        </span>
        <span>
          <strong>{view.current_files}</strong> files
        </span>
      </div>
      <p>
        {view.session.source.interface_name} · snap {view.session.request.snap_length || "full"} · stops{" "}
        {new Date(view.session.stop_at).toLocaleString()}
      </p>
      {view.evidence_hold?.active && (
        <p className="capture-evidence-hold">
          <strong>EVIDENCE HOLD</strong> · case <code>{view.evidence_hold.case_id}</code> · deletion and automatic
          retention blocked · revision {view.evidence_hold.revision}
        </p>
      )}
      {view.storage_pressure && <ErrorBox message="Payload capture stopped to preserve the emergency disk reserve." />}
      {view.worker?.failure && <ErrorBox message={view.worker.failure} />}
      {view.worker?.analyzer_feed_error && (
        <ErrorBox message={`Analyzer rotation feed error: ${view.worker.analyzer_feed_error}`} />
      )}
      {(view.worker?.analyzer_feed_evicted ?? 0) > 0 && (
        <ErrorBox
          message={`${(view.worker?.analyzer_feed_evicted ?? 0).toLocaleString()} closed capture rotation(s) left the bounded analyzer feed before publication or consumption; finalized retained files will still be analyzed.`}
        />
      )}
      {onStop && (
        <button className="quiet" onClick={onStop} disabled={busy}>
          {busy ? "Stopping…" : view.session.request.automatic ? "Turn off automatic recording" : "Stop recording"}
        </button>
      )}
      {view.manifest && (
        <details>
          <summary>Files, fingerprints and downloads</summary>
          <p>
            Session provenance <code>{view.manifest.session_sha256}</code>
          </p>
          {view.manifest.files.map((file) => (
            <div className="capture-file" key={file.name}>
              <span>
                {file.name} · {formatBytes(file.size_bytes)}
              </span>
              <code>{file.sha256}</code>
              <small>
                {file.packet_membership?.state === "EXACT"
                  ? `Exact packet membership: ${file.packet_membership.packet_count.toLocaleString()} packets · ${((file.packet_membership.mac_addresses?.length ?? 0) + (file.packet_membership.ip_addresses?.length ?? 0)).toLocaleString()} observed identities`
                  : file.packet_membership
                    ? `Packet membership is not exact: ${formatDataClass(file.packet_membership.state).toLowerCase()}`
                    : "Legacy capture: packet membership was not indexed"}
              </small>
              <CaptureExportButton
                sessionID={view.session.id}
                file={file}
                exports={exports.filter((item) => item.file_name === file.name)}
                onExported={refreshExports}
              />
            </div>
          ))}
        </details>
      )}
      {view.manifest && <AddToCase view={view} cases={cases} />}
      {view.manifest && onDeleted && !view.evidence_hold?.active && (
        <CaptureDeletionControl view={view} onDeleted={onDeleted} />
      )}
    </article>
  )
}

export function CaptureExportButton({
  sessionID,
  file,
  exports,
  onExported,
}: {
  sessionID: string
  file: CaptureFile
  exports: CaptureExportRecord[]
  onExported: () => Promise<void>
}) {
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState("")
  const browserLimit = 256 * 2 ** 20
  async function download(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setMessage("")
    try {
      const response = await withPassword("download this recording", async (password) => {
        const result = await authFetch(`/api/v1/captures/${sessionID}/files/${encodeURIComponent(file.name)}/export`, {
          method: "POST",
          headers: { Accept: "application/octet-stream" },
          body: JSON.stringify(password ? { password } : {}),
        })
        if (!result.ok) throw await responseError(result)
        return result
      })
      if (response.headers.get("X-ShakerProxy-SHA256") !== file.sha256)
        throw new Error("The server hash did not match the final manifest.")
      const blob = await response.blob()
      const actualHash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", await blob.arrayBuffer())))
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("")
      if (actualHash !== file.sha256) throw new Error("Downloaded bytes did not match the SHA-256 manifest.")
      downloadBlob(blob, file.name)
      setMessage("Hash verified; download saved.")
      await onExported()
    } catch (reason) {
      setMessage(describeError(reason, "Download failed"))
    } finally {
      setBusy(false)
    }
  }
  const completed = exports.filter((item) => item.complete)
  return (
    <div className="capture-export">
      {file.size_bytes <= browserLimit ? (
        <form onSubmit={download}>
          <button className="quiet" disabled={busy}>
            {busy ? "Checking…" : "Download and check"}
          </button>
        </form>
      ) : (
        <p>This file exceeds the 256 MiB browser verification limit. Use the local streaming CLI.</p>
      )}
      {message && <small>{message}</small>}
      {completed.length > 0 && (
        <small>
          {completed.length} verified export{completed.length === 1 ? "" : "s"}; latest{" "}
          {new Date(completed.at(-1)!.exported_at).toLocaleString()}
        </small>
      )}
    </div>
  )
}
