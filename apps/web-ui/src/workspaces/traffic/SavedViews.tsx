import React, { FormEvent, useEffect, useRef, useState } from "react"
import { api, apiBlob, describeError, downloadBlob } from "../../api"
import type {
  CaseRecord,
  EventQuerySnapshot,
  SavedView,
  SavedViewConfiguration,
  SavedViewHistory,
  SavedViewPage,
} from "../../types"

export function SavedViewsPanel({
  query,
  source,
  density,
  onApply,
  onDensity,
}: {
  query: string
  source: string
  density: "comfortable" | "compact"
  onApply: (view: SavedView) => void
  onDensity: (value: "comfortable" | "compact") => void
}) {
  const [views, setViews] = useState<SavedView[]>([])
  const [selectedID, setSelectedID] = useState("")
  const [history, setHistory] = useState<SavedViewHistory | null>(null)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState("")
  const selected = views.find((view) => view.id === selectedID)
  const currentCanonical = source ? (query ? `source:${source} AND (${query})` : `source:${source}`) : query
  const refresh = async (select?: string) => {
    const result = await api<SavedViewPage>("/api/v1/saved-views?page=live-traffic")
    setViews(result.views)
    setSelectedID(
      select ?? (result.views.some((view) => view.id === selectedID) ? selectedID : (result.views[0]?.id ?? "")),
    )
  }
  useEffect(() => {
    let mounted = true
    api<SavedViewPage>("/api/v1/saved-views?page=live-traffic")
      .then((result) => {
        if (mounted) {
          setViews(result.views)
          setSelectedID(result.views[0]?.id ?? "")
        }
      })
      .catch((reason) => {
        if (mounted) setMessage(reason instanceof Error ? reason.message : "Saved views are unavailable")
      })
    return () => {
      mounted = false
    }
  }, [])
  const configuration = (
    name: string,
    scope: "personal" | "shared",
    description = "",
    base?: SavedView,
  ): SavedViewConfiguration => ({
    scope,
    name,
    description,
    page: "live-traffic",
    canonical_query: currentCanonical,
    time_behavior: base?.time_behavior ?? { mode: "query" },
    sort: base?.sort ?? [{ field: "occurred_at", direction: "desc" }],
    columns: base?.columns ?? ["source", "occurred_at", "device", "network"],
    pinned_columns: base?.pinned_columns ?? ["source"],
    density,
    chart: base?.chart ?? { visible: false },
  })
  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setMessage("")
    const form = event.currentTarget
    const data = new FormData(form)
    try {
      const created = await api<SavedView>("/api/v1/saved-views", {
        method: "POST",
        body: JSON.stringify(
          configuration(
            String(data.get("name")),
            data.get("scope") === "shared" ? "shared" : "personal",
            String(data.get("description") ?? ""),
          ),
        ),
      })
      await refresh(created.id)
      form.reset()
      setMessage("Saved. Pick it from the list to use this filter again.")
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Could not save view")
    } finally {
      setBusy(false)
    }
  }
  async function update() {
    if (!selected) return
    setBusy(true)
    setMessage("")
    try {
      const next = await api<SavedView>(`/api/v1/saved-views/${selected.id}`, {
        method: "PUT",
        body: JSON.stringify({
          expected_revision: selected.revision,
          configuration: configuration(selected.name, selected.scope, selected.description ?? "", selected),
        }),
      })
      setViews((current) => current.map((view) => (view.id === next.id ? next : view)))
      setMessage(`Updated revision ${next.revision}.`)
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Could not update view")
    } finally {
      setBusy(false)
    }
  }
  async function duplicate() {
    if (!selected) return
    setBusy(true)
    setMessage("")
    try {
      const copy = await api<SavedView>(`/api/v1/saved-views/${selected.id}/duplicate`, {
        method: "POST",
        body: JSON.stringify({ name: `${selected.name} copy`, scope: "personal" }),
      })
      await refresh(copy.id)
      setMessage("Created a personal duplicate.")
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Could not duplicate view")
    } finally {
      setBusy(false)
    }
  }
  async function remove() {
    if (!selected || !window.confirm(`Delete saved view “${selected.name}”?`)) return
    setBusy(true)
    setMessage("")
    try {
      await api(`/api/v1/saved-views/${selected.id}?expected_revision=${selected.revision}`, { method: "DELETE" })
      await refresh("")
      setHistory(null)
      setMessage("Deleted the saved view.")
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Could not delete view")
    } finally {
      setBusy(false)
    }
  }
  async function showHistory() {
    if (!selected) return
    setBusy(true)
    setMessage("")
    try {
      setHistory(await api<SavedViewHistory>(`/api/v1/saved-views/${selected.id}/history`))
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Could not load view history")
    } finally {
      setBusy(false)
    }
  }
  async function exportView() {
    if (!selected) return
    setBusy(true)
    setMessage("")
    try {
      const blob = await apiBlob(`/api/v1/saved-views/${selected.id}/export`, {
        headers: { Accept: "application/json" },
      })
      downloadBlob(blob, `shakerproxy-${selected.id}.json`)
      setMessage("Exported without owner or editor metadata.")
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Could not export view")
    } finally {
      setBusy(false)
    }
  }
  async function importView(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    if (!file) return
    setBusy(true)
    setMessage("")
    try {
      if (file.size > 32768) throw new Error("Saved view import exceeds 32 KiB")
      const document = JSON.parse(await file.text())
      const imported = await api<SavedView>("/api/v1/saved-views/import", {
        method: "POST",
        body: JSON.stringify(document),
      })
      await refresh(imported.id)
      setMessage("Imported as a new owned saved view.")
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Could not import view")
    } finally {
      event.target.value = ""
      setBusy(false)
    }
  }
  return (
    <section className="saved-views" aria-label="Saved traffic views">
      <header>
        <div>
          <strong>Saved views</strong>
          <span>Reuse or share a filter</span>
        </div>
        <label>
          Density
          <select
            value={density}
            onChange={(event) => onDensity(event.target.value === "compact" ? "compact" : "comfortable")}
          >
            <option value="comfortable">Comfortable</option>
            <option value="compact">Compact</option>
          </select>
        </label>
      </header>
      <div className="saved-view-toolbar">
        <select
          aria-label="Saved traffic view"
          value={selectedID}
          onChange={(event) => {
            setSelectedID(event.target.value)
            setHistory(null)
          }}
        >
          <option value="">No saved view selected</option>
          {views.map((view) => (
            <option key={view.id} value={view.id}>
              {view.scope === "shared" ? "Shared" : "Mine"} · {view.name} · r{view.revision}
            </option>
          ))}
        </select>
        <button
          type="button"
          className="quiet"
          disabled={!selected || busy}
          onClick={() => selected && onApply(selected)}
        >
          Apply
        </button>
        <button type="button" className="quiet" disabled={!selected || busy} onClick={update}>
          Update
        </button>
        <button type="button" className="quiet" disabled={!selected || busy} onClick={duplicate}>
          Duplicate
        </button>
        <button type="button" className="quiet" disabled={!selected || busy} onClick={showHistory}>
          History
        </button>
        <button type="button" className="quiet" disabled={!selected || busy} onClick={exportView}>
          Export
        </button>
        <button type="button" className="quiet danger" disabled={!selected || busy} onClick={remove}>
          Delete
        </button>
        <label className="saved-view-import">
          Import
          <input type="file" accept="application/json,.json" disabled={busy} onChange={importView} />
        </label>
      </div>
      <form onSubmit={save}>
        <label>
          Name
          <input name="name" maxLength={96} required placeholder="Camera investigation" />
        </label>
        <label>
          Description
          <input name="description" maxLength={512} />
        </label>
        <label>
          Scope
          <select name="scope" defaultValue="personal">
            <option value="personal">Personal</option>
            <option value="shared">Shared</option>
          </select>
        </label>
        <button disabled={busy}>{busy ? "Saving…" : "Save current view"}</button>
      </form>
      {selected && (
        <small>
          {selected.owner} · last edited by {selected.last_editor} · {new Date(selected.updated_at).toLocaleString()} ·
          filter {selected.canonical_query || "(all traffic)"}
        </small>
      )}
      {history && (
        <details open>
          <summary>
            {history.versions.length} retained revision{history.versions.length === 1 ? "" : "s"}
          </summary>
          {history.versions.map((version) => (
            <small key={version.revision}>
              r{version.revision} · {version.editor} · {new Date(version.changed_at).toLocaleString()}
            </small>
          ))}
        </details>
      )}
      {message && <p role="status">{message}</p>}
    </section>
  )
}

export function EventQuerySnapshotControl({ query, source }: { query: string; source: string }) {
  const [snapshot, setSnapshot] = useState<EventQuerySnapshot | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const selectionKey = `${source}\u0000${query}`
  const currentSelection = useRef(selectionKey)
  const requestVersion = useRef(0)
  currentSelection.current = selectionKey
  useEffect(() => {
    requestVersion.current += 1
    setSnapshot(null)
    setError("")
    setBusy(false)
  }, [selectionKey])
  const freeze = async () => {
    const version = requestVersion.current + 1
    requestVersion.current = version
    setBusy(true)
    setError("")
    try {
      const combined = source ? (query ? `source:${source} AND (${query})` : `source:${source}`) : query
      const created = await api<EventQuerySnapshot>("/api/v1/event-query-snapshots", {
        method: "POST",
        body: JSON.stringify({
          query: combined,
          sort: [
            { field: "occurred_at", direction: "desc" },
            { field: "record_id", direction: "desc" },
          ],
          expires_in_seconds: 900,
        }),
      })
      if (requestVersion.current === version && currentSelection.current === selectionKey) setSnapshot(created)
    } catch (reason) {
      if (requestVersion.current === version && currentSelection.current === selectionKey)
        setError(reason instanceof Error ? reason.message : "Could not freeze query")
    } finally {
      if (requestVersion.current === version && currentSelection.current === selectionKey) setBusy(false)
    }
  }
  return (
    <section className="query-snapshot" aria-label="Freeze this result">
      <div>
        <strong>Freeze this result</strong>
        <small>
          Lock the events that match right now for 15 minutes — for example before exporting or deleting them. New
          traffic is not added to a frozen result.
        </small>
      </div>
      <button type="button" className="quiet" disabled={busy} onClick={freeze}>
        {busy ? "Freezing…" : "Freeze these events"}
      </button>
      {snapshot && (
        <dl>
          <div>
            <dt>Selected</dt>
            <dd>
              {snapshot.matched_count.toLocaleString()}
              {snapshot.count_relation === "gte" ? "+" : ""} rows
            </dd>
          </div>
          <div>
            <dt>As of</dt>
            <dd>{new Date(snapshot.created_at).toLocaleTimeString()}</dd>
          </div>
          <div>
            <dt>Expires</dt>
            <dd>{new Date(snapshot.expires_at).toLocaleTimeString()}</dd>
          </div>
          <div>
            <dt>Snapshot ID</dt>
            <dd>
              <code>{snapshot.query_snapshot_id}</code>
            </dd>
          </div>
        </dl>
      )}
      {snapshot && <SnapshotToCase snapshotID={snapshot.query_snapshot_id} query={snapshot.canonical_query} />}
      {error && <p>{error}</p>}
    </section>
  )
}

// SnapshotToCase keeps a frozen result as case evidence (QUERY_SNAPSHOT).
function SnapshotToCase({ snapshotID, query }: { snapshotID: string; query: string }) {
  const [cases, setCases] = useState<CaseRecord[] | null>(null)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState("")
  useEffect(() => {
    api<{ cases: CaseRecord[] }>("/api/v1/cases")
      .then((result) => setCases((result.cases ?? []).filter((item) => item.status === "OPEN")))
      .catch(() => setCases([]))
  }, [])
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const caseID = String(data.get("case_id") ?? "")
    if (!caseID) return
    setBusy(true)
    setMessage("")
    try {
      const current = await api<CaseRecord>(`/api/v1/cases/${caseID}`)
      await api<CaseRecord>(`/api/v1/cases/${caseID}/evidence`, {
        method: "POST",
        body: JSON.stringify({
          expected_revision: current.revision,
          kind: "QUERY_SNAPSHOT",
          artifact_id: snapshotID,
          label: String(data.get("label") || query || "Frozen traffic result"),
          reason: data.get("reason"),
        }),
      })
      setMessage(`Added to “${current.name}”. The frozen result is kept with the case.`)
    } catch (reason) {
      setMessage(describeError(reason, "Could not add the result to the case"))
    } finally {
      setBusy(false)
    }
  }
  if (cases === null) return null
  if (cases.length === 0) {
    return (
      <small>
        To keep this result as evidence, <a href="#/cases">create a case</a> first.
      </small>
    )
  }
  return (
    <form className="snapshot-to-case" onSubmit={submit}>
      <label>
        Add to case
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
        Label
        <input
          name="label"
          maxLength={256}
          defaultValue={query ? `Traffic: ${query}`.slice(0, 256) : "Traffic result"}
        />
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
  )
}
