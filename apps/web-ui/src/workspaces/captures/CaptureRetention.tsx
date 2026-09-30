import React, { FormEvent, useEffect, useState } from "react"
import { formatBytes, formatDataClass, idempotencyKey } from "../../lib/format"
import { ErrorBox } from "../../shell/common"
import { usePolling } from "../../shell/hooks"
import { coordinatedRetentionRunRequest } from "../../lib/captureRetention"
import { api } from "../../api"
import type {
  CaptureRetentionPolicy,
  CaptureRetentionPreviewResult,
  CaptureRetentionRun,
  CaptureRetentionSchedulerStatus,
} from "../../types"

export function CaptureRetentionPreview() {
  const [preview, setPreview] = useState<CaptureRetentionPreviewResult | null>(null)
  const [policy, setPolicy] = useState<CaptureRetentionPolicy | null>(null)
  const [runs, setRuns] = useState<CaptureRetentionRun[]>([])
  const [scheduler, setScheduler] = useState<CaptureRetentionSchedulerStatus | null>(null)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState("")
  async function refreshRuns() {
    try {
      const result = await api<{ runs: CaptureRetentionRun[] }>("/api/v1/capture-retention/runs")
      setRuns(Array.isArray(result.runs) ? result.runs : [])
    } catch {
      /* The policy controls remain available; run errors surface on mutation. */
    }
    try {
      setScheduler(await api<CaptureRetentionSchedulerStatus>("/api/v1/capture-retention/scheduler"))
    } catch {
      /* Policy state remains authoritative if scheduler status is temporarily unavailable. */
    }
  }
  useEffect(() => {
    void api<CaptureRetentionPolicy>("/api/v1/capture-retention/policy")
      .then(setPolicy)
      .catch((reason) => setMessage(reason instanceof Error ? reason.message : "Retention policy is unavailable"))
  }, [])
  usePolling(() => refreshRuns(), 15_000)
  async function calculate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setMessage("")
    const data = new FormData(event.currentTarget)
    try {
      const days = Number(data.get("max_age_days"))
      const mib = Number(data.get("max_pcap_mib"))
      setPreview(
        await api<CaptureRetentionPreviewResult>("/api/v1/capture-retention/preview", {
          method: "POST",
          body: JSON.stringify({
            max_age_seconds: Math.round(days * 86400),
            max_pcap_bytes: Math.round(mib * 1024 * 1024),
          }),
        }),
      )
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Retention preview is unavailable")
    } finally {
      setBusy(false)
    }
  }
  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!preview || !policy) return
    setBusy(true)
    setMessage("")
    const data = new FormData(event.currentTarget)
    const host = preview.host_retention
    try {
      const saved = await api<CaptureRetentionPolicy>("/api/v1/capture-retention/policy", {
        method: "PUT",
        headers: { "Idempotency-Key": idempotencyKey("capture-retention-policy") },
        body: JSON.stringify({
          password: data.get("password"),
          expected_revision: policy.revision,
          enabled: data.get("enabled") === "on",
          rules: host.policy,
          run_every_seconds: Math.round(Number(data.get("run_every_minutes")) * 60),
          preview_sha256: host.preview_sha256,
          preview_expires_at: host.expires_at,
        }),
      })
      setPolicy(saved)
      setPreview(null)
      setMessage(
        `Saved retention policy revision ${saved.revision}; automatic execution is ${saved.enabled ? "enabled" : "disabled"}.`,
      )
      await refreshRuns()
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Retention policy was not saved")
    } finally {
      setBusy(false)
    }
  }
  async function startRun(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!preview || !policy) return
    setBusy(true)
    setMessage("")
    const data = new FormData(event.currentTarget)
    try {
      const run = await api<CaptureRetentionRun>("/api/v1/capture-retention/runs", {
        method: "POST",
        headers: { "Idempotency-Key": idempotencyKey("capture-retention-run") },
        body: JSON.stringify(coordinatedRetentionRunRequest(preview, String(data.get("password")), policy.revision)),
      })
      setRuns((current) => [run, ...current.filter((item) => item.id !== run.id)])
      setPreview(null)
      setMessage(
        `Retention run ${run.state.toLowerCase()}: ${run.deleted_sessions} deleted, ${run.failed_sessions} failed.`,
      )
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Retention run failed")
      await refreshRuns()
    } finally {
      setBusy(false)
    }
  }
  const host = preview?.host_retention
  const analyzerCheckpointBytes =
    preview?.selected.reduce(
      (total, item) => total + item.zeek_checkpoint.checkpoint_bytes + item.suricata_checkpoint.checkpoint_bytes,
      0,
    ) ?? 0
  const previewMatchesPolicy =
    !!host &&
    !!policy &&
    policy.revision > 0 &&
    host.policy.max_age_seconds === policy.rules.max_age_seconds &&
    host.policy.max_pcap_bytes === policy.rules.max_pcap_bytes
  return (
    <details className="capture-retention">
      <summary>Clean up old recordings automatically</summary>
      <p>
        Only finished recordings are considered. Automatic clean-up is {policy?.enabled ? "on" : "off"} (settings
        revision {policy?.revision ?? "unavailable"}).
        {scheduler?.next_run_at ? ` Next automatic run ${new Date(scheduler.next_run_at).toLocaleString()}.` : ""}
      </p>
      {scheduler?.last_failure && (
        <ErrorBox
          message={`Automatic retention: ${scheduler.last_failure}${scheduler.last_failure_at ? ` at ${new Date(scheduler.last_failure_at).toLocaleString()}` : ""}.`}
        />
      )}
      <form onSubmit={calculate}>
        <label>
          Maximum age (days)
          <input
            key={`retention-age-${policy?.revision ?? "loading"}`}
            name="max_age_days"
            type="number"
            min="0"
            max="3650"
            step="0.01"
            defaultValue={policy ? policy.rules.max_age_seconds / 86400 : 7}
          />
        </label>
        <label>
          Keep at most this much recorded data (MiB)
          <input
            key={`retention-bytes-${policy?.revision ?? "loading"}`}
            name="max_pcap_mib"
            type="number"
            min="0"
            max="1073741824"
            defaultValue={policy ? policy.rules.max_pcap_bytes / (1024 * 1024) : 2048}
          />
        </label>
        <button disabled={busy}>{busy ? "Calculating…" : "Preview clean-up"}</button>
      </form>
      {message && <p role="status">{message}</p>}
      {preview && host && (
        <div className="capture-retention-result">
          <dl>
            <div>
              <dt>Evaluated</dt>
              <dd>
                {host.evaluated_sessions.toLocaleString()} · {formatBytes(host.evaluated_pcap_bytes)}
              </dd>
            </div>
            <div>
              <dt>Would delete</dt>
              <dd>
                {host.selected.length.toLocaleString()} sessions · {formatBytes(preview.immediately_recoverable_bytes)}
              </dd>
            </div>
            <div>
              <dt>Normalized events</dt>
              <dd>
                {preview.normalized_event_rows.toLocaleString()} rows ·{" "}
                {preview.exclusive_identity_rows.toLocaleString()} exclusive identities
              </dd>
            </div>
            <div>
              <dt>Analyzer checkpoints</dt>
              <dd>Zeek + Suricata · {formatBytes(analyzerCheckpointBytes)}</dd>
            </div>
            <div>
              <dt>Pending ingest spool</dt>
              <dd>
                {preview.pending_spool_records.toLocaleString()} records · {formatBytes(preview.pending_spool_bytes)}
              </dd>
            </div>
            <div>
              <dt>Projected PCAP</dt>
              <dd>{formatBytes(host.projected_pcap_bytes)}</dd>
            </div>
            <div>
              <dt>Database maintenance later</dt>
              <dd>{formatBytes(preview.logical_bytes_reclaimable_after_maintenance)}</dd>
            </div>
            <div>
              <dt>Skipped (still recording)</dt>
              <dd>
                {host.excluded_sessions.toLocaleString()} · {formatBytes(host.excluded_pcap_bytes)}
              </dd>
            </div>
          </dl>
          {!host.pcap_byte_target_met && (
            <ErrorBox message="The PCAP byte target cannot be reached without deleting retention-locked captures." />
          )}
          <p>
            Running it permanently marks these recordings as deleted (so they are never re-imported), removes their
            events and the device identities only they referenced, verifies both analyzer checkpoints absent, then
            deletes each selected capture and its whole PCAP files. Cross-device PCAP collateral remains unknown.
          </p>
          <p>
            Retained or independently managed: {preview.retained_data_classes.map(formatDataClass).join(", ")}.{" "}
            {preview.existing_export_records > 0
              ? `${preview.existing_export_records.toLocaleString()} existing export record${preview.existing_export_records === 1 ? "" : "s"} may identify copies outside this cleanup.`
              : "None of these recordings were downloaded before."}
          </p>
          {host.selected.length > 0 && (
            <ol>
              {host.selected.map((item) => (
                <li key={item.session_id}>
                  <strong>{item.name}</strong>
                  <code>{item.session_id}</code>
                  <span>
                    {item.reasons.map(formatDataClass).join(" + ")} · {formatBytes(item.footprint.capture_bytes)}
                  </span>
                </li>
              ))}
            </ol>
          )}
          {host.blocked_by_retention_lock.length > 0 && (
            <p className="capture-retention-locked">
              Locked and preserved: {host.blocked_by_retention_lock.map((item) => item.name).join(", ")}.
            </p>
          )}
          <code className="capture-retention-digest">
            Frozen preview {preview.preview_sha256} · expires {new Date(preview.expires_at).toLocaleTimeString()}
          </code>
          {policy && (
            <form className="capture-retention-apply" onSubmit={save}>
              <label>
                Run cadence (minutes)
                <input
                  name="run_every_minutes"
                  type="number"
                  min="5"
                  max="1440"
                  defaultValue={policy.run_every_seconds / 60}
                />
              </label>
              <label className="check">
                <input name="enabled" type="checkbox" defaultChecked={policy.enabled} />
                <span>Enable automatic retention after one full cadence</span>
              </label>
              <label>
                Administrator password
                <input name="password" type="password" autoComplete="current-password" required />
              </label>
              <button disabled={busy}>{busy ? "Saving verified revision…" : "Save policy revision"}</button>
            </form>
          )}
          {policy && previewMatchesPolicy && (
            <form className="capture-retention-apply" onSubmit={startRun}>
              <label>
                Administrator password
                <input name="password" type="password" autoComplete="current-password" required />
              </label>
              <button className="danger" disabled={busy || host.selected.length === 0}>
                {busy ? "Deleting…" : host.selected.length === 0 ? "Nothing selected" : "Run verified cleanup now"}
              </button>
            </form>
          )}
        </div>
      )}
      {runs.length > 0 && (
        <div className="capture-retention-runs">
          <h4>Retention runs</h4>
          {runs.slice(0, 10).map((run) => (
            <article key={run.id}>
              <strong>
                {run.trigger} · {run.state} · {run.phase}
              </strong>
              <code>{run.id}</code>
              <span>
                {run.deleted_sessions}/{run.selected_sessions} deleted · {run.failed_sessions} failed ·{" "}
                {formatBytes(run.remaining_bytes)} remains
              </span>
              {run.items
                .filter((item) => item.state === "FAILED")
                .map((item) => (
                  <small key={item.session_id}>
                    {item.name}: {item.failure}
                  </small>
                ))}
            </article>
          ))}
        </div>
      )}
    </details>
  )
}
