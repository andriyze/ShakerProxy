import React, { FormEvent, useState } from "react"
import { withPassword } from "../../shell/passwordPrompt"
import { datetimeLocalValue, formatBytes, formatDataClass, idempotencyKey } from "../../lib/format"
import { ErrorBox } from "../../shell/common"
import {
  deviceTrafficChoiceCanExecute,
  deviceTrafficChoicePresentation,
  deviceTrafficPreviewState,
} from "../../lib/deviceDeletion"
import type { DeviceTrafficDeletionChoice } from "../../lib/deviceDeletion"
import { api } from "../../api"
import type { Device, DeviceTrafficDeletionJob, DeviceTrafficDeletionPreview } from "../../types"

export function DeviceTrafficDeletionPreviewControl({ device }: { device: Device }) {
  const initialEnd = new Date(Math.min(Date.now(), Math.max(Date.parse(device.last_seen), Date.now() - 60_000)))
  const [startAt, setStartAt] = useState(() => datetimeLocalValue(new Date(initialEnd.getTime() - 60 * 60_000)))
  const [endAt, setEndAt] = useState(() => datetimeLocalValue(initialEnd))
  const [preview, setPreview] = useState<DeviceTrafficDeletionPreview | null>(null)
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)
  const [job, setJob] = useState<DeviceTrafficDeletionJob | null>(null)
  async function loadPreview(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setError("")
    setPreview(null)
    setJob(null)
    try {
      const start = new Date(startAt)
      const end = new Date(endAt)
      if (!Number.isFinite(start.getTime()) || !Number.isFinite(end.getTime()) || start >= end)
        throw new Error("Choose an end after the start.")
      const result = await api<DeviceTrafficDeletionPreview>(`/api/v1/devices/${device.id}/traffic-deletion-preview`, {
        method: "POST",
        body: JSON.stringify({ start_at: start.toISOString(), end_at: end.toISOString() }),
      })
      setPreview(result)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Traffic deletion preview failed")
    } finally {
      setBusy(false)
    }
  }
  async function executeDeletion(event: FormEvent<HTMLFormElement>, choice: DeviceTrafficDeletionChoice) {
    event.preventDefault()
    if (!preview) return
    setBusy(true)
    setError("")
    const data = new FormData(event.currentTarget)
    try {
      const result = await api<DeviceTrafficDeletionJob>(`/api/v1/devices/${device.id}/traffic-deletion-jobs`, {
        method: "POST",
        headers: { "Idempotency-Key": idempotencyKey("device-traffic-delete") },
        body: JSON.stringify({
          password: data.get("password"),
          preview,
          choice,
          confirmation: data.get("confirmation"),
        }),
      })
      setJob(result)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Traffic deletion failed")
    } finally {
      setBusy(false)
    }
  }
  async function retryMetadata(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!job) return
    setBusy(true)
    setError("")
    const data = new FormData(event.currentTarget)
    try {
      setJob(
        await api<DeviceTrafficDeletionJob>(`/api/v1/device-traffic-deletion-jobs/${job.id}/retry`, {
          method: "POST",
          headers: { "Idempotency-Key": idempotencyKey("device-traffic-delete-retry") },
          body: JSON.stringify({ password: data.get("password") }),
        }),
      )
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Metadata deletion retry failed")
    } finally {
      setBusy(false)
    }
  }
  async function cancelMetadata() {
    if (!job) return
    setBusy(true)
    setError("")
    try {
      setJob(
        await withPassword("cancel this deletion", (password) =>
          api<DeviceTrafficDeletionJob>(`/api/v1/device-traffic-deletion-jobs/${job.id}/cancel`, {
            method: "POST",
            headers: { "Idempotency-Key": idempotencyKey("device-traffic-delete-cancel") },
            body: JSON.stringify(password ? { password } : {}),
          }),
        ),
      )
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Metadata deletion cancellation failed")
    } finally {
      setBusy(false)
    }
  }
  const state = preview ? deviceTrafficPreviewState(preview) : null
  const metadataChoice = preview?.choices.find((choice) => choice.choice === "DELETE_METADATA_ONLY")
  const derivedChoice = preview?.choices.find((choice) => choice.choice === "DELETE_DERIVED_CONTENT_ONLY")
  const wholeFileChoice = preview?.choices.find((choice) => choice.choice === "DELETE_WHOLE_CAPTURE_FILES")
  const sanitizeChoice = preview?.choices.find((choice) => choice.choice === "SANITIZE_AND_REWRITE_PCAP")
  return (
    <details className="device-deletion">
      <summary>Delete this device's stored traffic…</summary>
      <div className="device-deletion-body">
        <p>
          Nothing is deleted until you confirm. Pick a time range and ShakerProxy shows exactly which events and recorded
          packets belong to this device, and what else would be removed with them. “Metadata only” keeps the recorded
          packets; “whole files” removes every recording file that contains this device (including other devices'
          packets in those files); “sanitize” rewrites the files without this device's packets.
        </p>
        <form onSubmit={loadPreview}>
          <label>
            Start
            <input
              type="datetime-local"
              required
              value={startAt}
              onChange={(event) => setStartAt(event.target.value)}
            />
          </label>
          <label>
            End
            <input type="datetime-local" required value={endAt} onChange={(event) => setEndAt(event.target.value)} />
          </label>
          <button className="quiet" disabled={busy}>
            {busy ? "Scanning exact packet impact…" : "Preview deletion choices"}
          </button>
        </form>
        {error && <ErrorBox message={error} />}
        {preview && (
          <div className="device-deletion-preview">
            <div className="device-deletion-summary">
              <span className={state === "EXACT" ? "ready" : "blocked"}>
                {state === "EXACT" ? "EXACT FOR SELECTED IDENTITIES" : "BLOCKED / INEXACT"}
              </span>
              <strong>
                {preview.normalized_event_deletion.database.database.event_rows.toLocaleString()} normalized event rows
              </strong>
              <strong>
                {preview.normalized_event_deletion.spool.pending_records.toLocaleString()} pending spool records
              </strong>
              <strong>{preview.pcap.impacted_files.length.toLocaleString()} impacted shared PCAP files</strong>
              <small>
                {formatBytes(preview.normalized_event_deletion.estimated_immediately_reclaimable_bytes)} immediately
                reclaimable ·{" "}
                {formatBytes(preview.normalized_event_deletion.logical_bytes_reclaimable_after_maintenance)} after
                database maintenance
              </small>
              <small>
                Evidence frozen until {new Date(preview.expires_at).toLocaleString()} · digest{" "}
                {preview.preview_sha256.slice(0, 12)}…
              </small>
            </div>
            {!preview.identity_evidence_covers_range && (
              <p className="device-warning">
                The known MAC/IP evidence does not cover the entire requested time range. Packet counts are exact for
                the identities and windows shown by this preview, but this is not proof that all device traffic in the
                range was identified.
              </p>
            )}
            {preview.capability_limitations.map((limitation) => (
              <p className="device-boundary" key={limitation}>
                {limitation}
              </p>
            ))}
            {(preview.copy_boundaries ?? []).map((boundary) => (
              <p className="device-boundary" key={boundary.data_class}>
                <strong>{formatDataClass(boundary.data_class)}</strong> ·{" "}
                {boundary.count_exact ? boundary.object_count.toLocaleString() : "unknown"} ·{" "}
                {formatDataClass(boundary.disposition)}. {boundary.warning}
              </p>
            ))}
            {preview.pcap.blockers.map((blocker) => (
              <p className="device-warning" key={`${blocker.session_id}-${blocker.file_name ?? ""}-${blocker.code}`}>
                <code>{blocker.code}</code> · {blocker.reason} · {blocker.session_id}
                {blocker.file_name ? ` / ${blocker.file_name}` : ""}
              </p>
            ))}
            <div className="device-choice-grid">
              {preview.choices.map((choice) => {
                const presentation = deviceTrafficChoicePresentation(choice.choice)
                return (
                  <article
                    key={choice.choice}
                    className={deviceTrafficChoiceCanExecute(choice) ? "choice-executable" : "choice-preview-only"}
                  >
                    <h3>{presentation.title}</h3>
                    <p>{presentation.effect}</p>
                    <p className="device-boundary">{presentation.packetBoundary}</p>
                    <dl>
                      <div>
                        <dt>Eligible evidence</dt>
                        <dd>{choice.eligible ? "YES" : "NO"}</dd>
                      </div>
                      <div>
                        <dt>Execution</dt>
                        <dd>{choice.execution_available ? "AVAILABLE" : "PREVIEW ONLY"}</dd>
                      </div>
                      <div>
                        <dt>Metadata rows</dt>
                        <dd>{choice.normalized_event_rows.toLocaleString()}</dd>
                      </div>
                      {choice.collateral_event_rows > 0 && (
                        <div>
                          <dt>Collateral metadata</dt>
                          <dd>{choice.collateral_event_rows.toLocaleString()}</dd>
                        </div>
                      )}
                      {choice.analyzer_replay_barriers > 0 && (
                        <div>
                          <dt>Analyzer barriers</dt>
                          <dd>
                            {choice.analyzer_replay_barriers.toLocaleString()} (
                            {choice.analyzer_checkpoints_removed.toLocaleString()} checkpoints present)
                          </dd>
                        </div>
                      )}
                      <div>
                        <dt>Matched packets</dt>
                        <dd>{choice.matched_packets_removed.toLocaleString()}</dd>
                      </div>
                      <div>
                        <dt>Collateral packets</dt>
                        <dd>{choice.collateral_packets_removed.toLocaleString()}</dd>
                      </div>
                      <div>
                        <dt>PCAP reclaim</dt>
                        <dd>{formatBytes(choice.pcap_bytes_reclaimable)}</dd>
                      </div>
                      {choice.temporary_bytes_required > 0 && (
                        <div>
                          <dt>Temporary capacity</dt>
                          <dd>{formatBytes(choice.temporary_bytes_required)}</dd>
                        </div>
                      )}
                    </dl>
                    {choice.warnings.map((warning) => (
                      <small key={warning}>{warning}</small>
                    ))}
                  </article>
                )
              })}
            </div>
            {!job && (
              <div className="device-choice-grid">
                {metadataChoice && deviceTrafficChoiceCanExecute(metadataChoice) && (
                  <form
                    className="danger-zone"
                    onSubmit={(event) => void executeDeletion(event, "DELETE_METADATA_ONLY")}
                  >
                    <h3>Delete searchable metadata only</h3>
                    <p>
                      Sets permanent device/time replay barriers, purges matching pending events, and deletes the
                      reviewed normalized rows. Raw PCAP packet bytes remain.
                    </p>
                    <label>
                      Administrator password
                      <input name="password" type="password" autoComplete="current-password" required />
                    </label>
                    <label>
                      Type <code>{device.id}</code>
                      <input name="confirmation" required />
                    </label>
                    <button className="danger" disabled={busy}>
                      {busy ? "Persisting deletion job…" : "Delete metadata only"}
                    </button>
                  </form>
                )}
                {derivedChoice && deviceTrafficChoiceCanExecute(derivedChoice) && (
                  <form
                    className="danger-zone"
                    onSubmit={(event) => void executeDeletion(event, "DELETE_DERIVED_CONTENT_ONLY")}
                  >
                    <h3>Delete configured derived content</h3>
                    <p>
                      Deletes the exact selected normalized events and both analyzer checkpoints for every affected
                      session, then leaves permanent replay barriers. Every raw PCAP byte remains; body, key-log,
                      Arkime, and OpenSearch stores are not configured in this build.
                    </p>
                    <label>
                      Administrator password
                      <input name="password" type="password" autoComplete="current-password" required />
                    </label>
                    <label>
                      Type <code>{device.id}</code>
                      <input name="confirmation" required />
                    </label>
                    <button className="danger" disabled={busy}>
                      {busy ? "Coordinating derived deletion…" : "Delete derived content"}
                    </button>
                  </form>
                )}
                {wholeFileChoice && deviceTrafficChoiceCanExecute(wholeFileChoice) && (
                  <form
                    className="danger-zone"
                    onSubmit={(event) => void executeDeletion(event, "DELETE_WHOLE_CAPTURE_FILES")}
                  >
                    <h3>Delete whole shared PCAP files</h3>
                    <p>
                      Sets permanent replay barriers for every affected capture session, removes all of those sessions’
                      normalized metadata and analyzer checkpoints, then deletes each reviewed file including unrelated
                      packet collateral.
                    </p>
                    <label>
                      Administrator password
                      <input name="password" type="password" autoComplete="current-password" required />
                    </label>
                    <label>
                      Type <code>{device.id}</code>
                      <input name="confirmation" required />
                    </label>
                    <button className="danger" disabled={busy}>
                      {busy ? "Coordinating whole-file deletion…" : "Delete files and collateral"}
                    </button>
                  </form>
                )}
                {sanitizeChoice && deviceTrafficChoiceCanExecute(sanitizeChoice) && (
                  <form
                    className="danger-zone"
                    onSubmit={(event) => void executeDeletion(event, "SANITIZE_AND_REWRITE_PCAP")}
                  >
                    <h3>Sanitize and rewrite PCAP</h3>
                    <p>
                      Installs replay and analyzer barriers, atomically replaces every reviewed PCAP with matched
                      packets removed, and waits for both analyzers to re-index retained packets.
                    </p>
                    <label>
                      Administrator password
                      <input name="password" type="password" autoComplete="current-password" required />
                    </label>
                    <label>
                      Type <code>{device.id}</code>
                      <input name="confirmation" required />
                    </label>
                    <button className="danger" disabled={busy}>
                      {busy ? "Coordinating rewrite…" : "Remove matched packet bytes"}
                    </button>
                  </form>
                )}
              </div>
            )}
            {job && (
              <section className="deletion-job">
                <h3>
                  {job.choice === "SANITIZE_AND_REWRITE_PCAP"
                    ? "Sanitize/rewrite"
                    : job.choice === "DELETE_WHOLE_CAPTURE_FILES"
                      ? "Whole-file deletion"
                      : job.choice === "DELETE_DERIVED_CONTENT_ONLY"
                        ? "Derived-content deletion"
                        : "Metadata deletion"}{" "}
                  job · {job.state}
                </h3>
                <p>
                  {job.phase} · {job.progress_percent}%
                </p>
                <code>{job.id}</code>
                {job.failure && <p className="device-warning">{job.failure}</p>}
                <p>Retained: {job.retained_data_classes.join(" · ")}</p>
                {job.state === "RUNNING" && job.phase === "ANALYZER_REINDEXING" && (
                  <p>
                    Replacement manifests are authorized. The job will finish automatically after Zeek and Suricata
                    persist rebuilt checkpoints.
                  </p>
                )}
                {job.state === "PARTIAL" && (
                  <form onSubmit={retryMetadata}>
                    <label>
                      Administrator password
                      <input name="password" type="password" autoComplete="current-password" required />
                    </label>
                    <button disabled={busy}>{busy ? "Retrying…" : "Retry preserved operation"}</button>
                  </form>
                )}
                {job.state === "PENDING" && (
                  <form
                    onSubmit={(event) => {
                      event.preventDefault()
                      void cancelMetadata()
                    }}
                  >
                    <button className="quiet" disabled={busy}>
                      Cancel this deletion
                    </button>
                  </form>
                )}
              </section>
            )}
            {preview.pcap.impacted_files.length > 0 && (
              <details className="device-file-impact">
                <summary>Exact per-file packet evidence</summary>
                {preview.pcap.impacted_files.map((file) => (
                  <article key={`${file.session_id}-${file.file_name}`}>
                    <strong>{file.file_name}</strong>
                    <code>{file.session_id}</code>
                    <span>
                      {file.matched_packets.toLocaleString()} matched ·{" "}
                      {file.collateral_packets_in_whole_delete.toLocaleString()} unrelated packets
                    </span>
                    <span>
                      {formatBytes(file.original_bytes)} original · {formatBytes(file.sanitized_bytes)} sanitized
                    </span>
                    <small>
                      {file.retention_locked
                        ? "Retention lock blocks packet deletion."
                        : file.temporary_capacity_available
                          ? "Temporary rewrite capacity available."
                          : "Temporary rewrite capacity unavailable."}
                    </small>
                    {(file.retained_mac_sample.length > 0 || file.retained_ip_sample.length > 0) && (
                      <small>
                        Retained identity sample ·{" "}
                        {[...file.retained_mac_sample, ...file.retained_ip_sample].join(" · ")}
                      </small>
                    )}
                  </article>
                ))}
              </details>
            )}
            <p className="device-secure-boundary">
              Secure erasure is not guaranteed on SSDs, copy-on-write filesystems, snapshots, backups, or prior exports.
              Rewritten captures must be re-indexed before any future job can report completion.
            </p>
          </div>
        )}
      </div>
    </details>
  )
}
