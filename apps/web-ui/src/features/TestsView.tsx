// Tests workspace (§5): start, stop, rename, annotate and delete test runs,
// open a run's report, and compare two runs (§4 compare).
import { useEffect, useId, useMemo, useState, type FormEvent } from "react"
import { api, describeError } from "../api"
import { navigate } from "./registry"
import { registerView } from "./register"
import { formatBytes, formatCount, formatDateTime, formatDuration, plural } from "./format"
import { canCompare, comparePath, compareSummary, diffTotals, orderForCompare, sessionsFromResponse, sortSessions, testSessionsPath } from "./tests-model"
import { DeviceReportView, FindingCard } from "./DeviceReport"
import { StartTestRunForm } from "./StartTestRun"
import { Badge, Empty, ErrorNotice, Loading, useResource } from "./shared"
import type { DeviceCompare, TestSession } from "./types"
import "./features.css"

type Detail = { kind: "report"; session: TestSession } | { kind: "compare"; base: TestSession; compare: TestSession } | null

function SessionEditor({ session, onSaved, onCancel }: { session: TestSession; onSaved: (next: TestSession) => void; onCancel: () => void }) {
  const [name, setName] = useState(session.name)
  const [notes, setNotes] = useState(session.notes)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const nameID = useId()
  const notesID = useId()
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!name.trim()) {
      setError("A test run needs a name.")
      return
    }
    setBusy(true)
    setError("")
    try {
      onSaved(await api<TestSession>(`/api/v1/test-sessions/${encodeURIComponent(session.id)}`, { method: "PATCH", body: JSON.stringify({ name: name.trim(), notes }) }))
    } catch (reason) {
      setError(describeError(reason, "Could not save the changes."))
    } finally {
      setBusy(false)
    }
  }
  return (
    <form className="lgf-form lgf-session-editor" onSubmit={submit}>
      <div className="lgf-field">
        <label className="lgf-label" htmlFor={nameID}>
          Name
        </label>
        <input id={nameID} className="lgf-input" type="text" maxLength={128} value={name} onChange={(event) => setName(event.target.value)} />
      </div>
      <div className="lgf-field">
        <label className="lgf-label" htmlFor={notesID}>
          Notes
        </label>
        <textarea id={notesID} className="lgf-textarea" maxLength={4000} value={notes} placeholder="Firmware version, what you did, anything unusual…" onChange={(event) => setNotes(event.target.value)} />
      </div>
      {error && (
        <p className="lgf-inline-error" role="alert">
          {error}
        </p>
      )}
      <div className="lgf-actions">
        <button type="submit" className="lgf-button" disabled={busy}>
          {busy ? "Saving…" : "Save"}
        </button>
        <button type="button" className="lgf-button lgf-secondary" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  )
}

function SessionCard({ session, selected, onSelect, onChanged, onRemoved, onOpenReport }: { session: TestSession; selected: boolean; onSelect: (next: boolean) => void; onChanged: (next: TestSession) => void; onRemoved: () => void; onOpenReport: () => void }) {
  const [mode, setMode] = useState<"" | "edit" | "confirm-delete">("")
  const [busy, setBusy] = useState<"" | "stop" | "delete">("")
  const [error, setError] = useState("")
  const running = session.state === "RUNNING"
  const checkboxID = useId()

  const stop = async () => {
    setBusy("stop")
    setError("")
    try {
      onChanged(await api<TestSession>(`/api/v1/test-sessions/${encodeURIComponent(session.id)}/stop`, { method: "POST" }))
    } catch (reason) {
      setError(describeError(reason, "Could not stop the test run."))
    } finally {
      setBusy("")
    }
  }
  const remove = async () => {
    setBusy("delete")
    setError("")
    try {
      await api<unknown>(`/api/v1/test-sessions/${encodeURIComponent(session.id)}`, { method: "DELETE" })
      onRemoved()
    } catch (reason) {
      setError(describeError(reason, "Could not delete the test run."))
      setBusy("")
    }
  }

  return (
    <li className={`lgf-session${running ? " lgf-running" : ""}${selected ? " lgf-picked" : ""}`}>
      <div className="lgf-session-main">
        <input id={checkboxID} type="checkbox" className="lgf-session-check" checked={selected} onChange={(event) => onSelect(event.target.checked)} aria-label={`Select “${session.name}” to compare`} />
        <div className="lgf-session-text">
          <div className="lgf-session-title">
            <strong>{session.name}</strong>
            {running ? (
              <Badge tone="good" title="This run is recording now.">
                <span className="lgf-pulse" aria-hidden="true" /> Running
              </Badge>
            ) : (
              <Badge tone="muted">Stopped</Badge>
            )}
            {session.capture_session_id && (
              <Badge tone="info" title="Packets are recorded for this run.">
                Packets
              </Badge>
            )}
          </div>
          <small>
            <button type="button" className="lgf-link" onClick={() => navigate("devices", { device_id: session.device_id })}>
              {session.device_name || session.device_id}
            </button>{" "}
            · started {formatDateTime(session.started_at)} · {running ? `running for ${formatDuration(session.started_at, null)}` : `lasted ${formatDuration(session.started_at, session.ended_at)}`}
            {session.created_by ? ` · by ${session.created_by}` : ""}
          </small>
          {session.notes && mode !== "edit" && <p className="lgf-session-notes">{session.notes}</p>}
        </div>
      </div>
      {mode === "edit" ? (
        <SessionEditor
          session={session}
          onCancel={() => setMode("")}
          onSaved={(next) => {
            setMode("")
            onChanged(next)
          }}
        />
      ) : mode === "confirm-delete" ? (
        <div className="lgf-confirm" role="alertdialog" aria-label="Confirm delete">
          <p>Delete the record of “{session.name}”? Captured traffic and packet recordings are kept; only the run's name, notes and time range are removed.</p>
          <div className="lgf-actions">
            <button type="button" className="lgf-button lgf-danger" disabled={busy === "delete"} onClick={() => void remove()}>
              {busy === "delete" ? "Deleting…" : "Delete run"}
            </button>
            <button type="button" className="lgf-button lgf-secondary" onClick={() => setMode("")}>
              Keep it
            </button>
          </div>
        </div>
      ) : (
        <div className="lgf-actions lgf-session-actions">
          <button type="button" className="lgf-button lgf-small" onClick={onOpenReport}>
            Open report
          </button>
          {running && (
            <button type="button" className="lgf-button lgf-secondary lgf-small" disabled={busy === "stop"} onClick={() => void stop()}>
              {busy === "stop" ? "Stopping…" : "Stop"}
            </button>
          )}
          <button type="button" className="lgf-button lgf-secondary lgf-small" onClick={() => setMode("edit")}>
            Rename or add notes
          </button>
          <button type="button" className="lgf-button lgf-secondary lgf-small" onClick={() => setMode("confirm-delete")}>
            Delete
          </button>
        </div>
      )}
      {error && (
        <p className="lgf-inline-error" role="alert">
          {error}
        </p>
      )}
    </li>
  )
}

function ListDiff({ title, added, removed, addedLabel, removedLabel, signs = true }: { title: string; added: string[]; removed: string[]; addedLabel: string; removedLabel: string; signs?: boolean }) {
  if (added.length === 0 && removed.length === 0) {
    return (
      <section className="lgf-report-section">
        <h3>{title}</h3>
        <p className="lgf-hint">No change.</p>
      </section>
    )
  }
  return (
    <section className="lgf-report-section">
      <h3>{title}</h3>
      <div className="lgf-diff-columns">
        <div>
          <h4 className="lgf-diff-added">
            {addedLabel} ({added.length})
          </h4>
          {added.length === 0 ? (
            <p className="lgf-hint">None</p>
          ) : (
            <ul className="lgf-diff-list lgf-diff-added">
              {added.map((item) => (
                <li key={item}>
                  {signs && <span aria-hidden="true">+</span>} <code>{item}</code>
                </li>
              ))}
            </ul>
          )}
        </div>
        <div>
          <h4 className="lgf-diff-removed">
            {removedLabel} ({removed.length})
          </h4>
          {removed.length === 0 ? (
            <p className="lgf-hint">None</p>
          ) : (
            <ul className="lgf-diff-list lgf-diff-removed">
              {removed.map((item) => (
                <li key={item}>
                  {signs && <span aria-hidden="true">−</span>} <code>{item}</code>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </section>
  )
}

export function CompareView({ base, compare, onSwap }: { base: TestSession; compare: TestSession; onSwap: () => void }) {
  const result = useResource<DeviceCompare>(comparePath(base.device_id, base.id, compare.id))
  const data = result.data
  const summary = data ? compareSummary(data) : undefined
  const totals = data ? diffTotals(data.base.totals, data.compare.totals) : []
  return (
    <section className="lgf-report lgf-compare" aria-label="Compare test runs">
      <header className="lgf-report-head">
        <div>
          <p className="lgf-eyebrow">Compare test runs</p>
          <h3 className="lgf-report-title">
            {base.name} <span className="lgf-vs">→</span> {compare.name}
          </h3>
          <p className="lgf-hint">
            {base.device_name} · “Before” is {base.name} ({formatDateTime(base.started_at)}); “after” is {compare.name} ({formatDateTime(compare.started_at)}).
          </p>
        </div>
        <button type="button" className="lgf-button lgf-secondary" onClick={onSwap}>
          Swap before / after
        </button>
      </header>
      {result.loading && !data && <Loading label="Comparing runs…" />}
      {result.error && <ErrorNotice message={result.error} onRetry={result.reload} />}
      {data && summary && (
        <>
          <div className={`lgf-report-summary ${data.findings.new.length ? "lgf-sev-high" : summary.changes ? "lgf-sev-info" : ""}`}>
            <strong>{summary.headline}</strong>
            <ul className="lgf-summary-chips">
              {summary.sections
                .filter((section) => section.count > 0)
                .map((section) => (
                  <li key={section.key} className={`lgf-diff-chip lgf-diff-${section.tone}`}>
                    {section.label}: {section.count}
                  </li>
                ))}
            </ul>
          </div>
          <section className="lgf-report-section">
            <h3>Findings</h3>
            {data.findings.new.length === 0 && data.findings.resolved.length === 0 ? (
              <p className="lgf-hint">Same findings in both runs.</p>
            ) : (
              <div className="lgf-diff-columns">
                <div>
                  <h4 className="lgf-diff-bad">New in “{compare.name}” ({data.findings.new.length})</h4>
                  {data.findings.new.length === 0 ? <p className="lgf-hint">None</p> : data.findings.new.map((finding) => <FindingCard key={`new-${finding.id}`} finding={finding} />)}
                </div>
                <div>
                  <h4 className="lgf-diff-good">Resolved since “{base.name}” ({data.findings.resolved.length})</h4>
                  {data.findings.resolved.length === 0 ? <p className="lgf-hint">None</p> : data.findings.resolved.map((finding) => <FindingCard key={`resolved-${finding.id}`} finding={finding} />)}
                </div>
              </div>
            )}
          </section>
          <ListDiff title="Domains" added={data.domains.added} removed={data.domains.removed} addedLabel="Newly contacted" removedLabel="No longer contacted" />
          <ListDiff title="Protocols" added={data.protocols.added} removed={data.protocols.removed} addedLabel="Newly used" removedLabel="No longer used" />
          <ListDiff title="HTTPS decryption" added={data.tls.newly_intercepted_hosts} removed={data.tls.newly_failed_hosts} addedLabel="Now decrypted" removedLabel="Now refusing ShakerProxy's certificate" signs={false} />
          <section className="lgf-report-section">
            <h3>Activity</h3>
            <table className="lgf-table lgf-totals-table">
              <thead>
                <tr>
                  <th scope="col">Measure</th>
                  <th scope="col" className="lgf-num">Before</th>
                  <th scope="col" className="lgf-num">After</th>
                  <th scope="col" className="lgf-num">Change</th>
                </tr>
              </thead>
              <tbody>
                {totals.map((row) => {
                  const format = row.bytes ? formatBytes : formatCount
                  const sign = row.delta > 0 ? "+" : row.delta < 0 ? "−" : ""
                  return (
                    <tr key={row.key}>
                      <th scope="row">{row.label}</th>
                      <td className="lgf-num">{format(row.base)}</td>
                      <td className="lgf-num">{format(row.compare)}</td>
                      <td className={`lgf-num ${row.delta > 0 ? "lgf-diff-added" : row.delta < 0 ? "lgf-diff-removed" : ""}`}>{row.delta === 0 ? "—" : `${sign}${format(Math.abs(row.delta))}`}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </section>
        </>
      )}
    </section>
  )
}

export function TestsView() {
  const sessions = useResource<unknown>(testSessionsPath({ limit: 200 }), 10000)
  const [overrides, setOverrides] = useState<Record<string, TestSession | null>>({})
  const [selected, setSelected] = useState<string[]>([])
  const [detail, setDetail] = useState<Detail>(null)
  const [filter, setFilter] = useState<"" | "RUNNING" | "STOPPED">("")
  const [search, setSearch] = useState("")
  const [startOpen, setStartOpen] = useState(false)
  const [started, setStarted] = useState<TestSession | null>(null)
  const headingID = useId()
  const searchID = useId()

  const all = useMemo(() => {
    const list = sessionsFromResponse(sessions.data)
      .filter((session) => overrides[session.id] !== null)
      .map((session) => overrides[session.id] ?? session)
    for (const [id, session] of Object.entries(overrides)) if (session && !list.some((item) => item.id === id)) list.push(session)
    return sortSessions(list)
  }, [sessions.data, overrides])
  const visible = all.filter((session) => (!filter || session.state === filter) && (!search.trim() || `${session.name} ${session.device_name} ${session.notes}`.toLowerCase().includes(search.trim().toLowerCase())))
  const picked = all.filter((session) => selected.includes(session.id))
  const compareCheck = canCompare(picked)
  const running = all.filter((session) => session.state === "RUNNING").length

  // Optimistic changes bridge the gap until the next list response arrives.
  useEffect(() => setOverrides({}), [sessions.data])
  const update = (session: TestSession) => {
    setOverrides((current) => ({ ...current, [session.id]: session }))
    sessions.reload()
  }
  const removeSession = (id: string) => {
    setOverrides((current) => ({ ...current, [id]: null }))
    setSelected((current) => current.filter((item) => item !== id))
    sessions.reload()
  }

  if (detail) {
    return (
      <section className="lgf-view lgf-tests" aria-label="Test run detail">
        <div className="lgf-actions">
          <button type="button" className="lgf-button lgf-secondary" onClick={() => setDetail(null)}>
            ← All test runs
          </button>
        </div>
        {detail.kind === "report" ? (
          <DeviceReportView deviceID={detail.session.device_id} deviceName={detail.session.device_name} sessionID={detail.session.id} />
        ) : (
          <CompareView base={detail.base} compare={detail.compare} onSwap={() => setDetail({ kind: "compare", base: detail.compare, compare: detail.base })} />
        )}
      </section>
    )
  }

  const showStart = startOpen || (sessions.data !== undefined && all.length === 0)
  return (
    <section className="lgf-view lgf-tests" aria-labelledby={headingID}>
      <header className="lgf-view-head">
        <div>
          <p className="lgf-eyebrow">Tests</p>
          <h2 id={headingID}>Test runs</h2>
          <p className="lgf-lede">A test run records a device's activity for a period you choose, for example one firmware version's first boot. Each run gets its own report, and two runs can be compared.</p>
        </div>
        {!showStart && (
          <button type="button" className="lgf-button" onClick={() => setStartOpen(true)}>
            Start test run
          </button>
        )}
      </header>

      {started && (
        <div className="lgf-callout lgf-tone-good" role="status">
          <strong>Started “{started.name}”.</strong> Use the device now and press Stop when you're done.
          {started.warnings && started.warnings.length > 0 && (
            <ul>
              {started.warnings.map((warning) => (
                <li key={warning}>{warning}</li>
              ))}
            </ul>
          )}
        </div>
      )}

      {showStart && (
        <div className="lgf-panel lgf-start-panel">
          <div className="lgf-section-head">
            <h3>Start a test run</h3>
            {all.length > 0 && (
              <button type="button" className="lgf-button lgf-secondary lgf-small" onClick={() => setStartOpen(false)}>
                Cancel
              </button>
            )}
          </div>
          <StartTestRunForm
            onStarted={(session) => {
              update(session)
              setStarted(session)
              setStartOpen(false)
            }}
          />
        </div>
      )}

      {sessions.loading && !sessions.data && <Loading label="Loading test runs…" />}
      {sessions.error && !sessions.data && <ErrorNotice message={sessions.error} onRetry={sessions.reload} />}
      {sessions.data !== undefined && all.length === 0 && (
        <Empty title="No test runs yet.">
          <p>Pick the device you are testing above and press Start. Then use the device the way you want to test it (first boot, sign-in, an update) and press Stop.</p>
          <p>
            New to ShakerProxy?{" "}
            <button type="button" className="lgf-link" onClick={() => navigate("start")}>
              Inspect a device step by step
            </button>
            .
          </p>
        </Empty>
      )}

      {all.length > 0 && (
        <>
          <div className="lgf-toolbar" role="group" aria-label="Filter test runs">
            <div className="lgf-segmented" role="radiogroup" aria-label="State">
              {(
                [
                  ["", `All (${all.length})`],
                  ["RUNNING", `Running (${running})`],
                  ["STOPPED", `Stopped (${all.length - running})`],
                ] as const
              ).map(([value, label]) => (
                <button key={value} type="button" role="radio" aria-checked={filter === value} className={filter === value ? "lgf-selected" : undefined} onClick={() => setFilter(value)}>
                  {label}
                </button>
              ))}
            </div>
            <div className="lgf-field lgf-grow">
              <label className="lgf-label lgf-visually-hidden" htmlFor={searchID}>
                Search test runs
              </label>
              <input id={searchID} className="lgf-input" type="search" placeholder="Search by name, device or notes" value={search} onChange={(event) => setSearch(event.target.value)} />
            </div>
          </div>

          <div className="lgf-compare-bar" role="status" aria-live="polite">
            <span>{picked.length === 0 ? "Tick two runs of the same device to compare them (for example firmware A and B)." : compareCheck.ok ? `Ready to compare “${picked[0].name}” and “${picked[1].name}”.` : compareCheck.reason}</span>
            <div className="lgf-actions">
              <button
                type="button"
                className="lgf-button lgf-small"
                disabled={!compareCheck.ok}
                onClick={() => {
                  const [base, compare] = orderForCompare(picked[0], picked[1])
                  setDetail({ kind: "compare", base, compare })
                }}
              >
                Compare
              </button>
              {picked.length > 0 && (
                <button type="button" className="lgf-button lgf-secondary lgf-small" onClick={() => setSelected([])}>
                  Clear selection
                </button>
              )}
            </div>
          </div>

          {visible.length === 0 ? (
            <Empty title="No test runs match." />
          ) : (
            <ul className="lgf-sessions">
              {visible.map((session) => (
                <SessionCard
                  key={session.id}
                  session={session}
                  selected={selected.includes(session.id)}
                  onSelect={(next) => setSelected((current) => (next ? [...current.filter((id) => id !== session.id), session.id].slice(-2) : current.filter((id) => id !== session.id)))}
                  onChanged={update}
                  onRemoved={() => removeSession(session.id)}
                  onOpenReport={() => setDetail({ kind: "report", session })}
                />
              ))}
            </ul>
          )}
          <p className="lgf-hint">
            {plural(all.length, "test run")} · updates every 10 seconds while this page is open.
          </p>
        </>
      )}
    </section>
  )
}

registerView({ id: "test-runs", workspace: "tests", title: "Test runs", order: 10, Component: TestsView })
