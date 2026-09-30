import React, { FormEvent, useState } from "react"
import { withPassword } from "../../shell/passwordPrompt"
import { idempotencyKey } from "../../lib/format"
import { api, describeError } from "../../api"
import { ErrorBox } from "../../shell/common"
import { usePolling } from "../../shell/hooks"
import { EvidencePicker } from "./EvidencePicker"
import type { CaseRecord } from "../../types"

export function CaseWorkspace() {
  const [cases, setCases] = useState<CaseRecord[]>([])
  const [selectedID, setSelectedID] = useState("")
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState("")
  const selected = cases.find((item) => item.id === selectedID) ?? cases[0]
  const [loadError, setLoadError] = useState("")
  const [attachKey, setAttachKey] = useState(0)
  async function load() {
    try {
      const result = await api<{ schema: number; cases: CaseRecord[] }>("/api/v1/cases")
      const next = Array.isArray(result.cases) ? result.cases : []
      setCases(next)
      setSelectedID((current) => (current && next.some((item) => item.id === current) ? current : (next[0]?.id ?? "")))
      setLoadError("")
    } catch (reason) {
      setLoadError(describeError(reason, "Cases are unavailable"))
    }
  }
  // Background refreshes never clear the result message of your last action.
  usePolling(() => load(), 10000)
  async function refresh() {
    setMessage("")
    await load()
  }
  function replace(item: CaseRecord) {
    setCases((current) => [item, ...current.filter((entry) => entry.id !== item.id)])
    setSelectedID(item.id)
  }
  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setMessage("")
    const form = event.currentTarget
    const data = new FormData(form)
    try {
      replace(
        await api<CaseRecord>("/api/v1/cases", {
          method: "POST",
          body: JSON.stringify({
            name: data.get("name"),
            description: data.get("description"),
            reason: data.get("reason"),
          }),
        }),
      )
      form.reset()
      setMessage("Case created with a hash-chained timeline.")
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Case creation failed")
    } finally {
      setBusy(false)
    }
  }
  async function attach(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!selected) return
    setBusy(true)
    setMessage("")
    const form = event.currentTarget
    const data = new FormData(form)
    try {
      replace(
        await api<CaseRecord>(`/api/v1/cases/${selected.id}/evidence`, {
          method: "POST",
          body: JSON.stringify({
            expected_revision: selected.revision,
            kind: data.get("kind"),
            artifact_id: data.get("artifact_id"),
            label: data.get("label"),
            reason: data.get("reason"),
          }),
        }),
      )
      form.reset()
      setAttachKey((current) => current + 1)
      setMessage("Added to the case. To protect recordings from deletion, apply a hold below.")
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Evidence attachment failed")
    } finally {
      setBusy(false)
    }
  }
  async function changeHold(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!selected) return
    const submitter = (event.nativeEvent as SubmitEvent).submitter as HTMLButtonElement | null
    const active = submitter?.value === "apply"
    setBusy(true)
    setMessage("")
    const form = event.currentTarget
    const data = new FormData(form)
    const key = idempotencyKey(active ? "case-hold" : "case-release")
    try {
      const item = await withPassword(active ? "protect these recordings" : "release the hold", (password) =>
        api<CaseRecord>(`/api/v1/cases/${selected.id}/hold`, {
          method: "POST",
          headers: { "Idempotency-Key": key },
          body: JSON.stringify({
            expected_revision: selected.revision,
            active,
            reason: data.get("reason"),
            ...(password ? { password } : {}),
          }),
        }),
      )
      replace(item)
      form.reset()
      setMessage(
        item.hold.state === "PARTIAL"
          ? "PARTIAL HOLD: one or more capture references are not protected. Review each result and retry."
          : active
            ? "Every referenced capture is protected from manual deletion and retention."
            : "Case hold released; start-time retention locks may still apply.",
      )
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Case hold mutation failed")
    } finally {
      setBusy(false)
    }
  }
  async function changeStatus(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!selected) return
    setBusy(true)
    setMessage("")
    const data = new FormData(event.currentTarget)
    const status = selected.status === "OPEN" ? "CLOSED" : "OPEN"
    try {
      replace(
        await withPassword(status === "CLOSED" ? "close this case" : "reopen this case", (password) =>
          api<CaseRecord>(`/api/v1/cases/${selected.id}/status`, {
            method: "PUT",
            body: JSON.stringify({
              expected_revision: selected.revision,
              status,
              reason: data.get("reason"),
              ...(password ? { password } : {}),
            }),
          }),
        ),
      )
      setMessage(`Case ${status.toLowerCase()} with a timeline entry.`)
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Case status change failed")
    } finally {
      setBusy(false)
    }
  }
  return (
    <section className="case-workspace" aria-label="Case workspaces and evidence holds">
      <header>
        <div>
          <p className="eyebrow">Evidence</p>
          <h2>Your cases</h2>
        </div>
        <span>
          {cases.length} CASE{cases.length === 1 ? "" : "S"}
        </span>
      </header>
      <p className="case-intro">
        A case points at recordings and exports without copying them. Put a hold on a case to stop its recordings from
        being deleted — by hand or by automatic clean-up. A partial hold is never shown as protected.
      </p>
      {loadError && <ErrorBox message={loadError} onRetry={() => void refresh()} />}
      {message && (
        <p className={selected?.hold.state === "PARTIAL" ? "case-message warning" : "case-message"} role="status">
          {message}
        </p>
      )}
      <div className="case-layout">
        <form className="case-create" onSubmit={create}>
          <h3>Create case</h3>
          <label>
            Name
            <input name="name" maxLength={96} required />
          </label>
          <label>
            Description
            <input name="description" maxLength={2048} />
          </label>
          <label>
            Audit reason
            <input name="reason" maxLength={512} required />
          </label>
          <button className="quiet" disabled={busy}>
            Create case
          </button>
        </form>
        <div className="case-list" role="list">
          {cases.map((item) => (
            <button
              type="button"
              key={item.id}
              className={selected?.id === item.id ? "selected" : ""}
              onClick={() => setSelectedID(item.id)}
            >
              <strong>{item.name}</strong>
              <span className={`case-hold-${item.hold.state.toLowerCase()}`}>{item.hold.state}</span>
              <small>
                {item.status} · revision {item.revision} · {item.evidence.length} evidence reference
                {item.evidence.length === 1 ? "" : "s"}
              </small>
            </button>
          ))}
          {cases.length === 0 && <p>No cases yet.</p>}
        </div>
      </div>
      {selected && (
        <article className="case-detail">
          <header>
            <div>
              <strong>{selected.name}</strong>
              <code>{selected.id}</code>
            </div>
            <span>
              {selected.status} · HOLD {selected.hold.state}
            </span>
          </header>
          {selected.hold.state === "PARTIAL" && (
            <p className="case-partial">
              Protection is incomplete. Failed capture references remain deletable until a retry succeeds.
            </p>
          )}
          <div className="case-evidence">
            {selected.evidence.map((evidence) => {
              const result = selected.hold.results.find((entry) => entry.evidence_id === evidence.id)
              return (
                <div key={evidence.id}>
                  <strong>{evidence.label}</strong>
                  <code>{evidence.artifact_id}</code>
                  {selected.hold.state === "INACTIVE" && (
                    <RemoveEvidence caseRecord={selected} evidenceID={evidence.id} onRemoved={replace} />
                  )}
                  <small>
                    {evidence.kind} ·{" "}
                    {result
                      ? result.failure
                        ? `NOT PROTECTED · ${result.failure}`
                        : result.protected
                          ? "PROTECTED"
                          : "RELEASED"
                      : "NO HOLD RESULT"}
                  </small>
                </div>
              )
            })}
            {selected.evidence.length === 0 && <p>No evidence references attached.</p>}
          </div>
          {selected.status === "OPEN" && selected.hold.state === "INACTIVE" && (
            <form key={attachKey} className="case-evidence-form" onSubmit={attach}>
              <EvidencePicker />
              <label>
                Audit reason
                <input name="reason" maxLength={512} required />
              </label>
              <button className="quiet" disabled={busy}>
                Add to case
              </button>
            </form>
          )}
          {selected.evidence.some((item) => item.kind === "CAPTURE") && (
            <form className="case-hold-form" onSubmit={changeHold}>
              <label>
                Hold or release reason
                <input name="reason" maxLength={512} required />
              </label>
              <div>
                <button name="hold_action" value="apply" disabled={busy || selected.hold.state === "ACTIVE"}>
                  Apply hold
                </button>
                <button
                  className="quiet"
                  name="hold_action"
                  value="release"
                  disabled={busy || selected.hold.state === "INACTIVE"}
                >
                  Release hold
                </button>
              </div>
            </form>
          )}
          <form className="case-status-form" onSubmit={changeStatus}>
            <label>
              Status change reason
              <input name="reason" maxLength={512} required />
            </label>
            <button className="quiet" disabled={busy}>
              {selected.status === "OPEN" ? "Close case" : "Reopen case"}
            </button>
          </form>
          {selected.hold.state === "INACTIVE" && <DeleteCase caseRecord={selected} onDeleted={() => void refresh()} />}
          <details>
            <summary>Custody timeline · {selected.timeline.length} entries</summary>
            {selected.timeline.map((event) => (
              <div className="case-event" key={event.revision}>
                <strong>{event.action.replaceAll("_", " ")}</strong>
                <span>
                  {event.actor} · {new Date(event.occurred_at).toLocaleString()}
                </span>
                <small>
                  {event.reason} · SHA-256 {event.sha256.slice(0, 16)}…
                </small>
              </div>
            ))}
          </details>
        </article>
      )}
      <button type="button" className="quiet case-refresh" onClick={() => void refresh()}>
        Refresh
      </button>
    </section>
  )
}

// RemoveEvidence detaches one item from a case; the recording or export itself is kept.
function RemoveEvidence({
  caseRecord,
  evidenceID,
  onRemoved,
}: {
  caseRecord: CaseRecord
  evidenceID: string
  onRemoved: (next: CaseRecord) => void
}) {
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState("")
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    setBusy(true)
    setMessage("")
    try {
      onRemoved(
        await api<CaseRecord>(`/api/v1/cases/${caseRecord.id}/evidence/${encodeURIComponent(evidenceID)}`, {
          method: "DELETE",
          body: JSON.stringify({ expected_revision: caseRecord.revision, reason: data.get("reason") }),
        }),
      )
    } catch (reason) {
      setMessage(describeError(reason, "Could not remove it from the case"))
    } finally {
      setBusy(false)
    }
  }
  return (
    <details className="case-remove-evidence">
      <summary>Remove from case</summary>
      <form onSubmit={submit}>
        <label>
          Reason
          <input name="reason" maxLength={512} required />
        </label>
        <button className="quiet" disabled={busy}>
          {busy ? "Removing…" : "Remove"}
        </button>
        {message && <small role="alert">{message}</small>}
      </form>
    </details>
  )
}

// DeleteCase removes the case record only; recordings and exports are kept.
function DeleteCase({ caseRecord, onDeleted }: { caseRecord: CaseRecord; onDeleted: () => void }) {
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState("")
  async function remove() {
    if (!window.confirm(`Delete the case “${caseRecord.name}”? Its recordings and exports are kept.`)) return
    setBusy(true)
    setMessage("")
    try {
      await withPassword("delete this case", (password) =>
        api(`/api/v1/cases/${caseRecord.id}`, {
          method: "DELETE",
          body: JSON.stringify({ expected_revision: caseRecord.revision, ...(password ? { password } : {}) }),
        }),
      )
      onDeleted()
    } catch (reason) {
      setMessage(describeError(reason, "The case could not be deleted"))
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="case-delete">
      <button type="button" className="quiet danger" disabled={busy} onClick={() => void remove()}>
        {busy ? "Deleting…" : "Delete case"}
      </button>
      {message && <small role="alert">{message}</small>}
    </div>
  )
}
