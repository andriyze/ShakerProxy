import React, { FormEvent, useEffect, useState } from "react"
import { api, describeError } from "../../api"
import { idempotencyKey } from "../../lib/format"
import {
  AWAITING_CONFIRMATION,
  STAGED,
  describePhase,
  formatCountdown,
  isApplying,
  isFailed,
  isFinal,
  pollInterval,
  secondsLeft,
} from "../../lib/networkTransaction"
import { isAbort } from "../../lib/errors"
import { loadHeartbeat, storeHeartbeat } from "../../shell/networkHeartbeat"
import { useAppState } from "../../shell/AppContext"
import { ErrorBox } from "../../shell/common"
import { timeoutSignal, useNow, usePolling } from "../../shell/hooks"
import type { CommitResult, PlanPreview, StageSummary, StagedPlan, Status } from "../../types"

export type Transaction = {
  summary: StageSummary
  // Present when this browser staged the plan; null after a reload.
  preview: PlanPreview | null
  restored: boolean
}

export function NetworkChange({
  transaction,
  onChange,
  onClear,
  activationAvailable,
  applyReady,
}: {
  transaction: Transaction
  onChange: (next: Transaction) => void
  onClear: () => void
  activationAvailable: boolean
  applyReady: boolean
}) {
  const { refreshStatus, reloadPreflight } = useAppState()
  const { summary } = transaction
  const phase = summary.status
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const [ended, setEnded] = useState("")
  const [commitKey] = useState(() => idempotencyKey("commit"))
  const [confirmKey] = useState(() => idempotencyKey("confirm"))
  const deadline = summary.confirm_by ?? (phase === STAGED ? summary.expires_at : undefined)
  const now = useNow(1000, Boolean(deadline) && !isFinal(phase))
  const remaining = secondsLeft(deadline, now)

  // Follow the change until it is final. The heartbeat itself is sent by the
  // shell (shell/networkHeartbeat), so it continues on other pages too.
  const interval = ended ? 0 : pollInterval(phase)
  usePolling(
    async (signal) => {
      try {
        const status = await api<Status>("/api/v1/system/status", { signal: timeoutSignal(signal, 5000) })
        const current = status.staged_network_plan
        if (!current || current.apply_id !== summary.apply_id) {
          // The appliance no longer reports this change: it was confirmed,
          // rolled back, discarded or it expired.
          storeHeartbeat(summary.apply_id, null)
          setEnded(
            status.operating_mode === "ROUTED_PASSTHROUGH"
              ? "The change is finished and the lab network is live."
              : "The change is no longer pending. It was undone, discarded or it expired; the network is as before.",
          )
          void refreshStatus()
          void reloadPreflight()
          return
        }
        if (current.status !== phase || current.confirm_by !== summary.confirm_by) {
          onChange({ ...transaction, summary: current })
          if (isFinal(current.status)) {
            storeHeartbeat(summary.apply_id, null)
            void refreshStatus()
            void reloadPreflight()
          }
        }
        setError("")
      } catch (reason) {
        // A superseded poll (the phase changed) is not an error.
        if (signal.aborted) return
        setError(
          isAbort(reason) || (reason as { name?: string })?.name === "TimeoutError"
            ? "ShakerProxy is not answering right now; still checking…"
            : describeError(reason, "Could not check the network change"),
        )
      }
    },
    interval || 60_000,
    [summary.apply_id, phase, interval],
    { enabled: interval > 0, whileHidden: true },
  )

  useEffect(() => {
    if (isFinal(phase)) storeHeartbeat(summary.apply_id, null)
  }, [phase, summary.apply_id])

  async function discard() {
    setBusy(true)
    setError("")
    try {
      await api(`/api/v1/network/staged/${summary.apply_id}/rollback`, { method: "POST", body: JSON.stringify({}) })
      storeHeartbeat(summary.apply_id, null)
      onClear()
      void refreshStatus()
    } catch (reason) {
      setError(describeError(reason, "Could not discard the change"))
    } finally {
      setBusy(false)
    }
  }

  async function commit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = event.currentTarget
    const data = new FormData(form)
    setBusy(true)
    setError("")
    try {
      const committed = await api<CommitResult>(`/api/v1/network/staged/${summary.apply_id}/commit`, {
        method: "POST",
        headers: { "Idempotency-Key": commitKey },
        body: JSON.stringify({
          plan_hash: summary.plan_hash,
          password: data.get("password"),
          rollback_window_seconds: Number(data.get("window")),
        }),
      })
      // The heartbeat is sent later by the shell, once the host has applied
      // the change and waits for health evidence — not now (audit #7).
      storeHeartbeat(summary.apply_id, { token: committed.health_token, planHash: summary.plan_hash })
      form.reset()
      onChange({
        ...transaction,
        summary: { ...summary, status: committed.status || "ACCEPTED", confirm_by: committed.health_deadline },
      })
      void refreshStatus()
    } catch (reason) {
      setError(describeError(reason, "The change could not start"))
    } finally {
      setBusy(false)
    }
  }

  async function confirm(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = event.currentTarget
    const data = new FormData(form)
    setBusy(true)
    setError("")
    try {
      const confirmed = await api<StagedPlan>(`/api/v1/network/staged/${summary.apply_id}/confirm`, {
        method: "POST",
        headers: { "Idempotency-Key": confirmKey },
        body: JSON.stringify({ plan_hash: summary.plan_hash, password: data.get("password") }),
      })
      form.reset()
      storeHeartbeat(summary.apply_id, null)
      onChange({ ...transaction, summary: { ...summary, ...confirmed, status: confirmed.status || "CONFIRMED" } })
      void refreshStatus()
      void reloadPreflight()
    } catch (reason) {
      setError(describeError(reason, "Could not keep the change"))
    } finally {
      setBusy(false)
    }
  }

  const canCommit = activationAvailable && (transaction.preview?.firewall_environment.apply_ready ?? applyReady)
  const title = ended ? "Finished" : phase === STAGED ? "Ready to apply" : phase.replaceAll("_", " ").toLowerCase()
  return (
    <section className="activation" aria-live="polite" aria-labelledby="activation-title">
      <div className="activation-title">
        <div>
          <p className="eyebrow">Network change</p>
          <h3 id="activation-title">{title}</h3>
        </div>
        <code>{summary.apply_id}</code>
      </div>
      {transaction.restored && !ended && (
        <p className="activation-restored">This change was started earlier and is still in progress.</p>
      )}
      {transaction.restored && !ended && isApplying(phase) && !loadHeartbeat(summary.apply_id) && (
        <p className="traffic-policy-warning">
          This change was started in another browser tab, so this tab cannot confirm the connection for it. If that tab
          is closed, ShakerProxy will undo the change automatically.
        </p>
      )}
      <p>{ended || describePhase(phase)}</p>
      {!ended && remaining !== null && !isFinal(phase) && (
        <p className={`activation-countdown${phase === AWAITING_CONFIRMATION ? " urgent" : ""}`}>
          {phase === STAGED
            ? "Expires in "
            : phase === AWAITING_CONFIRMATION
              ? "Undone automatically in "
              : "Automatic undo in "}
          <strong>{formatCountdown(remaining)}</strong>
          {deadline && <small> (at {new Date(deadline).toLocaleTimeString()})</small>}
        </p>
      )}
      {error && <ErrorBox message={error} />}
      {!ended && phase === STAGED && (
        <>
          {canCommit ? (
            <form className="commit-form" onSubmit={commit}>
              <label>
                Re-enter administrator password
                <input name="password" type="password" autoComplete="current-password" required />
              </label>
              <label>
                Undo automatically unless confirmed within
                <select name="window" defaultValue="180">
                  <option value="120">2 minutes</option>
                  <option value="180">3 minutes</option>
                  <option value="300">5 minutes</option>
                  <option value="600">10 minutes</option>
                </select>
              </label>
              <div className="danger-note">
                Applying may briefly interrupt connectivity. ShakerProxy checks that this browser, the internet connection
                and DNS still work, then asks you to confirm. If you do not confirm in time, it undoes the change.
              </div>
              <button disabled={busy}>{busy ? "Starting…" : "Apply with automatic undo"}</button>
            </form>
          ) : (
            <p className="blocked-copy">
              {activationAvailable
                ? "The host firewall is not ready for changes. See the firewall check below."
                : "This ShakerProxy installation cannot change the host network (development profile)."}
            </p>
          )}
          <div className="activation-actions">
            <button type="button" className="quiet" onClick={() => void discard()} disabled={busy}>
              Discard this change
            </button>
          </div>
        </>
      )}
      {!ended && isApplying(phase) && (
        <div className="transaction-progress">
          <span className="pulse" />
          Keep this browser tab open until ShakerProxy asks you to confirm. You can use other pages meanwhile.
        </div>
      )}
      {!ended && phase === AWAITING_CONFIRMATION && (
        <form className="confirm-form" onSubmit={confirm}>
          <div className="safe">
            <span>WORKING</span>
            <strong>Management, WAN, DNS, and forwarding checks passed</strong>
          </div>
          <label>
            Re-enter administrator password to keep these changes
            <input name="password" type="password" autoComplete="current-password" required />
          </label>
          <button disabled={busy}>{busy ? "Confirming…" : "Keep the new network"}</button>
        </form>
      )}
      {phase === "CONFIRMED" && (
        <div className="safe">
          <span>DONE</span>
          <strong>The lab network is live</strong>
        </div>
      )}
      {isFailed(phase) && !ended && <ErrorBox message={describePhase(phase)} />}
      {(ended || isFinal(phase)) && (
        <div className="activation-actions">
          <button type="button" className="quiet" onClick={onClear}>
            Close
          </button>
        </div>
      )}
    </section>
  )
}
