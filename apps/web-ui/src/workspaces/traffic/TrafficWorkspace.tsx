import React, { FormEvent, useEffect, useRef, useState } from "react"
import { formatBytes } from "../../lib/format"
import { completeTypedQuery, formatTypedQueryValue, typedQueryValueContext } from "../../lib/trafficQuery"
import { ErrorBox, FeatureViews } from "../../shell/common"
import { usePolling } from "../../shell/hooks"
import { LabRecordingBanner } from "../../shell/LabRecordingBanner"
import { TRAFFIC_PRESETS, TIME_WINDOWS, activeTimeWindow, deviceQuery, withTimeWindow } from "../../lib/trafficPresets"
import { TrafficOverview } from "./TrafficOverview"
import { HTTPActivity } from "./HTTPActivity"
import { TrafficExport } from "./TrafficExport"
import { EventQuerySnapshotControl, SavedViewsPanel } from "./SavedViews"
import { WindowedTrafficTable } from "./TrafficTable"
import { consumeLiveEventStream } from "./liveStream"
import { MAX_PENDING_LIVE_ROWS, MAX_VISIBLE_LIVE_ROWS, promoteLiveRows, queueLiveRows } from "../../lib/liveRows"
import { api, describeError } from "../../api"
import type {
  Device,
  IngestStats,
  QueryMetadata,
  QuerySuggestion,
  QueryValueCompletionPage,
  RecentEvent,
  RecentEventPage,
  SavedView,
} from "../../types"

const SOURCES: [string, string][] = [
  ["", "All sources"],
  ["MITMPROXY", "Decrypted HTTPS (mitmproxy)"],
  ["ZEEK", "Network analysis (Zeek)"],
  ["SURICATA", "Alerts (Suricata)"],
  ["HOST", "ShakerProxy host"],
]

const OLDER_PAGE_LIMIT = 100

export function TrafficWorkspace() {
  const [traffic, setTraffic] = useState<{ page: RecentEventPage | null; pending: RecentEvent[]; dropped: number }>({
    page: null,
    pending: [],
    dropped: 0,
  })
  const page = traffic.page
  const [selectedRecordID, setSelectedRecordID] = useState("")
  const [manualPaused, setManualPaused] = useState(false)
  const manualPausedRef = useRef(false)
  const activeStreamController = useRef<AbortController | null>(null)
  const resumeStream = useRef<(() => void) | null>(null)
  const [status, setStatus] = useState<IngestStats | null>(null)
  const [streamState, setStreamState] = useState<"CONNECTING" | "LIVE" | "RECONNECTING" | "PAUSED">("CONNECTING")
  const [source, setSource] = useState(() => new URLSearchParams(window.location.search).get("traffic_source") || "")
  const [query, setQuery] = useState(() => new URLSearchParams(window.location.search).get("traffic_q") || "")
  const [draftQuery, setDraftQuery] = useState(query)
  const [density, setDensity] = useState<"comfortable" | "compact">(() =>
    new URLSearchParams(window.location.search).get("traffic_density") === "compact" ? "compact" : "comfortable",
  )
  const [queryMetadata, setQueryMetadata] = useState<QueryMetadata | null>(null)
  const [dynamicQuerySuggestions, setDynamicQuerySuggestions] = useState<QuerySuggestion[]>([])
  const [error, setError] = useState("")
  const [statusError, setStatusError] = useState("")
  useEffect(() => {
    const controller = new AbortController()
    api<QueryMetadata>("/api/v1/events/query-metadata", { signal: controller.signal })
      .then((metadata) => {
        if (metadata.schema === 1 && metadata.fields.length <= 64) setQueryMetadata(metadata)
      })
      .catch(() => {})
    return () => controller.abort()
  }, [])
  useEffect(() => {
    const completion = typedQueryValueContext(draftQuery)
    if (!completion) {
      setDynamicQuerySuggestions([])
      return
    }
    setDynamicQuerySuggestions([])
    const controller = new AbortController()
    const timer = window.setTimeout(() => {
      const parameters = new URLSearchParams({ field: completion.field, prefix: completion.prefix, limit: "12" })
      api<QueryValueCompletionPage>(`/api/v1/events/query-completions?${parameters}`, { signal: controller.signal })
        .then((result) => {
          if (
            result.schema !== 1 ||
            result.field !== completion.field ||
            result.prefix !== completion.prefix ||
            !Array.isArray(result.values) ||
            result.values.length > 12 ||
            result.values.some(
              (item) =>
                typeof item.value !== "string" ||
                item.value.length < 1 ||
                item.value.length > 128 ||
                !Number.isSafeInteger(item.device_count) ||
                item.device_count < 1 ||
                item.device_count > 50000 ||
                typeof item.includes_historical !== "boolean",
            )
          ) {
            setDynamicQuerySuggestions([])
            return
          }
          setDynamicQuerySuggestions(
            result.values.map((item) => ({
              value:
                completion.before + completion.typedField + ":" + formatTypedQueryValue(item.value, completion.field),
              label: `${item.includes_historical ? "Includes historical alias" : completion.field === "device.tag" ? "Current tag" : "Current alias"} · ${item.device_count} device${item.device_count === 1 ? "" : "s"}`,
            })),
          )
        })
        .catch((reason) => {
          if (!(reason instanceof DOMException && reason.name === "AbortError")) setDynamicQuerySuggestions([])
        })
    }, 180)
    return () => {
      window.clearTimeout(timer)
      controller.abort()
    }
  }, [draftQuery])
  useEffect(() => {
    let active = true
    let streamController: AbortController | null = null
    const visibilityChanged = () => {
      if (document.hidden) streamController?.abort()
      else if (!manualPausedRef.current) {
        resumeStream.current?.()
        resumeStream.current = null
      }
    }
    document.addEventListener("visibilitychange", visibilityChanged)
    setTraffic({ page: null, pending: [], dropped: 0 })
    setSelectedRecordID("")
    const waitUntilVisible = async () => {
      if (!document.hidden && !manualPausedRef.current) return
      setStreamState("PAUSED")
      let resume: (() => void) | null = null
      await new Promise<void>((resolve) => {
        resume = resolve
        resumeStream.current = resolve
      })
      // Only clear our own resolver: after a filter change the next stream
      // loop may already have installed a new one.
      if (resumeStream.current === resume) resumeStream.current = null
    }
    const waitForRetry = (milliseconds: number) =>
      new Promise<void>((resolve) => window.setTimeout(resolve, milliseconds))
    const run = async () => {
      let retryMilliseconds = 500
      let cursor = ""
      while (active && !cursor) {
        await waitUntilVisible()
        const parameters = new URLSearchParams({ limit: "30" })
        if (source) parameters.set("source", source)
        if (query) parameters.set("q", query)
        try {
          const result = await api<RecentEventPage>(`/api/v1/events?${parameters}`)
          if (!result.live_cursor) throw new Error("The event service did not provide a live resume cursor")
          if (!active) return
          cursor = result.live_cursor
          setTraffic({ page: result, pending: [], dropped: 0 })
          setError("")
          retryMilliseconds = 500
        } catch (reason) {
          if (!active) return
          setStreamState("RECONNECTING")
          setError(reason instanceof Error ? reason.message : "Traffic events are unavailable")
          await waitForRetry(retryMilliseconds)
          retryMilliseconds = Math.min(retryMilliseconds * 2, 10000)
        }
      }
      while (active) {
        await waitUntilVisible()
        if (!active) return
        const liveParameters = new URLSearchParams({ limit: "100", cursor })
        if (source) liveParameters.set("source", source)
        if (query) liveParameters.set("q", query)
        streamController = new AbortController()
        activeStreamController.current = streamController
        setStreamState(retryMilliseconds === 500 ? "CONNECTING" : "RECONNECTING")
        try {
          await consumeLiveEventStream(
            `/api/v1/events/live?${liveParameters}`,
            streamController.signal,
            () => {
              setStreamState("LIVE")
              setError("")
            },
            (batch) => {
              if (!active) return
              cursor = batch.next_cursor
              retryMilliseconds = 500
              setStreamState("LIVE")
              setError("")
              setTraffic((current) => {
                if (!current.page) return current
                const queued = queueLiveRows(
                  current.pending,
                  batch.events,
                  new Set(current.page.events.map((event) => event.record_id)),
                  MAX_PENDING_LIVE_ROWS,
                )
                return {
                  page: {
                    ...current.page,
                    generated_at: batch.generated_at,
                    live_cursor: batch.next_cursor,
                    query_anchor: batch.query_anchor ?? current.page.query_anchor,
                    device_labels_available: current.page.device_labels_available && batch.device_labels_available,
                  },
                  pending: queued.rows,
                  dropped: current.dropped + queued.dropped,
                }
              })
            },
          )
          if (active) throw new Error("The live event stream closed")
        } catch (reason) {
          if (!active) return
          if (document.hidden || manualPausedRef.current) continue
          setStreamState("RECONNECTING")
          setError(reason instanceof Error ? reason.message : "The live event stream is reconnecting")
          await waitForRetry(retryMilliseconds)
          retryMilliseconds = Math.min(retryMilliseconds * 2, 10000)
        } finally {
          if (activeStreamController.current === streamController) activeStreamController.current = null
        }
      }
    }
    void run()
    return () => {
      active = false
      streamController?.abort()
      if (activeStreamController.current === streamController) activeStreamController.current = null
      resumeStream.current?.()
      resumeStream.current = null
      document.removeEventListener("visibilitychange", visibilityChanged)
    }
  }, [source, query])
  usePolling(async () => {
    try {
      setStatus(await api<IngestStats>("/api/v1/ingest/status"))
      setStatusError("")
    } catch (reason) {
      setStatusError(describeError(reason, "Event storage health is unavailable"))
    }
  }, 10_000)
  const [olderBusy, setOlderBusy] = useState(false)
  const [olderError, setOlderError] = useState("")
  const [showSyntax, setShowSyntax] = useState(false)
  const [copied, setCopied] = useState(false)
  const queryInput = useRef<HTMLInputElement>(null)
  const setAppliedQuery = (next: string) => {
    setDraftQuery(next)
    setQuery(next)
    updateTrafficURL(next, source, density)
  }
  const filterDevice = (deviceID: string) => {
    setSelectedRecordID("")
    setAppliedQuery(deviceQuery(deviceID, activeTimeWindow(query)))
  }
  // "/" focuses the filter box (a typed character, so event.key is correct).
  useEffect(() => {
    const keydown = (event: KeyboardEvent) => {
      if (event.defaultPrevented || event.metaKey || event.ctrlKey || event.altKey || event.key !== "/") return
      const target = event.target as HTMLElement | null
      if (
        target instanceof HTMLInputElement ||
        target instanceof HTMLTextAreaElement ||
        target instanceof HTMLSelectElement ||
        target?.isContentEditable
      )
        return
      event.preventDefault()
      queryInput.current?.focus()
    }
    document.addEventListener("keydown", keydown)
    return () => document.removeEventListener("keydown", keydown)
  }, [])
  // Load older events through the server cursor (next_cursor), appended below
  // the current rows and bounded like the live view.
  // The filter the older page was requested for; results for an earlier
  // filter are dropped.
  const selection = `${source}\u0000${query}`
  const selectionRef = useRef(selection)
  selectionRef.current = selection
  const loadOlder = async () => {
    const cursor = traffic.page?.next_cursor
    if (!cursor || olderBusy) return
    const requested = selection
    setOlderBusy(true)
    setOlderError("")
    try {
      const parameters = new URLSearchParams({ limit: String(OLDER_PAGE_LIMIT), cursor })
      if (source) parameters.set("source", source)
      if (query) parameters.set("q", query)
      const older = await api<RecentEventPage>(`/api/v1/events?${parameters}`)
      if (selectionRef.current !== requested) return
      setTraffic((current) => {
        if (!current.page) return current
        const known = new Set(current.page.events.map((event) => event.record_id))
        const room = Math.max(0, MAX_VISIBLE_LIVE_ROWS - current.page.events.length)
        const added = (Array.isArray(older.events) ? older.events : []).filter((event) => !known.has(event.record_id))
        return {
          ...current,
          page: {
            ...current.page,
            events: [...current.page.events, ...added.slice(0, room)],
            next_cursor: added.length > room ? current.page.next_cursor : older.next_cursor,
          },
        }
      })
    } catch (reason) {
      setOlderError(describeError(reason, "Older events could not be loaded"))
    } finally {
      setOlderBusy(false)
    }
  }
  const applyQuery = (event: React.FormEvent) => {
    event.preventDefault()
    const next = draftQuery.trim()
    setQuery(next)
    updateTrafficURL(next, source, density)
  }
  const toggleLivePause = () => {
    const next = !manualPausedRef.current
    manualPausedRef.current = next
    setManualPaused(next)
    if (next) {
      activeStreamController.current?.abort()
      setStreamState("PAUSED")
    } else if (!document.hidden) {
      resumeStream.current?.()
      resumeStream.current = null
      setStreamState("CONNECTING")
    }
  }
  const selectSource = (next: string) => {
    setSource(next)
    updateTrafficURL(query, next, density)
  }
  const applyAlias = (device: Device) => {
    const rename = (item: RecentEvent) =>
      item.device_id === device.id
        ? {
            ...item,
            device_friendly_name: device.friendly_name,
            device_alias_revision: device.alias_revision,
            device_friendly_name_conflict: device.friendly_name_conflict,
          }
        : item
    setTraffic((current) => ({
      ...current,
      page: current.page ? { ...current.page, events: current.page.events.map(rename) } : null,
      pending: current.pending.map(rename),
    }))
  }
  const applyFacet = (field: string, value: string) => {
    const predicate = value ? `${field}:${value}` : `${field}!=*`
    const next = query ? `${query} AND ${predicate}` : predicate
    setAppliedQuery(next)
  }
  const applySavedView = (view: SavedView) => {
    const next = view.canonical_query ?? ""
    setDraftQuery(next)
    setQuery(next)
    setSource("")
    setDensity(view.density)
    updateTrafficURL(next, "", view.density)
  }
  const baseQuerySuggestions =
    queryMetadata?.fields
      .flatMap((field) => [
        `${field.name}:*`,
        ...(field.aliases ?? []).map((alias) => `${alias}:*`),
        ...field.suggestions,
      ])
      .slice(0, 160) ?? []
  const querySuggestionMap = new Map<string, QuerySuggestion>()
  for (const suggestion of dynamicQuerySuggestions) querySuggestionMap.set(suggestion.value, suggestion)
  for (const value of completeTypedQuery(draftQuery, baseQuerySuggestions))
    if (!querySuggestionMap.has(value)) querySuggestionMap.set(value, { value })
  const querySuggestions = Array.from(querySuggestionMap.values()).slice(0, 128)
  const showPendingEvents = () => {
    setTraffic((current) => {
      if (!current.page || current.pending.length === 0) return current
      const promoted = promoteLiveRows(
        current.page.events,
        current.pending,
        new Set(selectedRecordID ? [selectedRecordID] : []),
        MAX_VISIBLE_LIVE_ROWS,
      )
      return {
        page: { ...current.page, events: promoted.rows },
        pending: [],
        dropped: current.dropped + promoted.dropped,
      }
    })
  }
  const activeWindow = activeTimeWindow(query)
  const selectedEvent = page?.events.find((event) => event.record_id === selectedRecordID)
  const ingestDegraded =
    status !== null &&
    (!status.database_connected ||
      status.storage_pressure ||
      status.quarantined_records > 0 ||
      status.ingest_lag_seconds > 60)
  return (
    <>
      <section className={`event-feed ${density}`}>
        <div className="event-feed-head">
          <div>
            <p className="eyebrow">Live</p>
            <h2>Traffic events</h2>
            <p>
              New events appear as ShakerProxy analyses the lab network. Pausing, or switching to another tab, stops the
              live view; it picks up where it left off when you come back.
            </p>
            <LabRecordingBanner />
          </div>
          <div>
            <span className={`event-feed-state ${streamState.toLowerCase()}`}>
              {streamState === "LIVE"
                ? "LIVE"
                : streamState === "PAUSED"
                  ? "PAUSED"
                  : streamState === "RECONNECTING"
                    ? "RECONNECTING…"
                    : "CONNECTING…"}
            </span>
            <button type="button" className="quiet event-stream-toggle" onClick={toggleLivePause}>
              {manualPaused ? "Resume live" : "Pause live"}
            </button>
            <label>
              Source
              <select value={source} onChange={(event) => selectSource(event.target.value)}>
                {SOURCES.map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </select>
            </label>
          </div>
        </div>
        <div className="traffic-workspace-controls">
          <section className="traffic-workspace-group">
            <strong>Quick views</strong>
            <div className="traffic-workspace-chips">
              {TRAFFIC_PRESETS.map((preset) => (
                <button
                  key={preset.id}
                  type="button"
                  className={`traffic-workspace-chip ${preset.tone ?? ""}${preset.query === query ? " active" : ""}`}
                  title={preset.description}
                  aria-pressed={preset.query === query}
                  onClick={() => setAppliedQuery(preset.query)}
                >
                  {preset.label}
                </button>
              ))}
            </div>
          </section>
          <section className="traffic-workspace-group traffic-workspace-time">
            <strong>Time</strong>
            <div className="traffic-workspace-chips">
              {TIME_WINDOWS.map(([label, value]) => (
                <button
                  key={value}
                  type="button"
                  className={`traffic-workspace-chip subtle${activeWindow === value ? " active" : ""}`}
                  aria-pressed={activeWindow === value}
                  onClick={() => setAppliedQuery(withTimeWindow(query, value))}
                >
                  {label}
                </button>
              ))}
            </div>
          </section>
          <section className="traffic-workspace-group traffic-workspace-actions">
            <strong>Focus</strong>
            <div className="traffic-workspace-chips">
              <button
                type="button"
                className="traffic-workspace-chip selected-device"
                disabled={!selectedEvent?.device_id}
                title={
                  selectedEvent?.device_id
                    ? `Show only ${selectedEvent.device_friendly_name || selectedEvent.device_id}`
                    : "Click a row first"
                }
                onClick={() => selectedEvent?.device_id && filterDevice(selectedEvent.device_id)}
              >
                {selectedEvent?.device_id
                  ? `Only ${selectedEvent.device_friendly_name || "this device"}`
                  : "Only the selected device"}
              </button>
              <button
                type="button"
                className="traffic-workspace-chip subtle"
                disabled={!query}
                onClick={async () => {
                  try {
                    await navigator.clipboard.writeText(query)
                    setCopied(true)
                    window.setTimeout(() => setCopied(false), 1000)
                  } catch {
                    setCopied(false)
                  }
                }}
              >
                {copied ? "Copied" : "Copy filter"}
              </button>
            </div>
          </section>
        </div>
        <form className="event-query" onSubmit={applyQuery}>
          <label htmlFor="traffic-query">Filter</label>
          <div>
            <input
              id="traffic-query"
              ref={queryInput}
              list="traffic-query-suggestions"
              value={draftQuery}
              onChange={(event) => setDraftQuery(event.target.value)}
              placeholder="Search: netflix.com, proto:mqtt, device.name:tv"
              spellCheck={false}
              aria-describedby="traffic-query-help"
            />
            <datalist id="traffic-query-suggestions">
              {querySuggestions.map((suggestion) => (
                <option value={suggestion.value} label={suggestion.label} key={suggestion.value} />
              ))}
            </datalist>
            <button type="submit">Apply filter</button>
            {query && (
              <button type="button" className="quiet" onClick={() => setAppliedQuery("")}>
                Clear
              </button>
            )}
            <button
              type="button"
              className="quiet"
              aria-expanded={showSyntax}
              onClick={() => setShowSyntax((current) => !current)}
            >
              {showSyntax ? "Hide help" : "Filter help"}
            </button>
          </div>
          {draftQuery.trim() !== query && (
            <small className="event-query-draft">Press Apply filter to use this filter.</small>
          )}
          {showSyntax && (
            <small id="traffic-query-help">
              A bare word such as netflix.com searches DNS names, HTTPS server names and web hosts. Fields: source,
              kind, device.id, device.name (also name or device), device.tag (also tag), capture.id, src.ip, dst.ip,
              src.port, dst.port, protocol, service, app.protocol (also proto or app), protocol.category,
              protocol.visibility, protocol.exotic, bytes, confidence, time. Use time:last_15m (s, m, h, or d; up to
              30d) or compare time with an RFC3339 timestamp. Friendly-name matches include current and retained old
              aliases; alias and tag values complete from the current inventory. Supports AND, OR, NOT, parentheses,
              comparisons, CIDR, wildcards, and byte units.
              {queryMetadata
                ? ` Suggestions are loaded from ${queryMetadata.fields.length} server-validated fields.`
                : ""}
            </small>
          )}
          {showSyntax && page?.canonical_query && <code>As understood by ShakerProxy: {page.canonical_query}</code>}
          {page?.query_anchor && new Date(page.query_anchor).getUTCFullYear() > 2000 && (
            <small>
              Time window measured from {new Date(page.query_anchor).toLocaleString()}; it stays fixed while this view
              resumes.
            </small>
          )}
        </form>
        {page?.facets && (
          <section className="event-facets" aria-label="Server-computed event facets">
            <header>
              <strong>Filter this result</strong>
              <span>
                {page.facets.matched_count.toLocaleString()}
                {page.facets.count_relation === "gte" ? "+" : ""} matches ·{" "}
                {page.facets.exact ? "exact counts" : "newest 10,000 sampled"}
              </span>
            </header>
            <div>
              {page.facets.fields.map((facet) => (
                <fieldset key={facet.field}>
                  <legend>{facet.field}</legend>
                  {facet.values.map((value) => (
                    <button
                      type="button"
                      key={value.value || "missing"}
                      onClick={() => applyFacet(facet.field, value.value)}
                      title={`Add ${facet.field} filter`}
                    >
                      <span>{value.value || "Missing"}</span>
                      <strong>{value.count.toLocaleString()}</strong>
                    </button>
                  ))}
                  {facet.other_count > 0 && <small>{facet.other_count.toLocaleString()} other</small>}
                </fieldset>
              ))}
            </div>
          </section>
        )}
        {status && ingestDegraded && (
          <div
            className={`event-health ${status.storage_pressure || !status.database_connected ? "degraded" : "healthy"}`}
          >
            <div>
              <span>Event database</span>
              <strong>
                {status.database_connected
                  ? "CONNECTED"
                  : status.database_configured
                    ? "UNAVAILABLE"
                    : "NOT CONFIGURED"}
              </strong>
            </div>
            <div>
              <span>Durable queue</span>
              <strong>
                {status.pending_records.toLocaleString()} events · {formatBytes(status.pending_bytes)}
              </strong>
            </div>
            <div>
              <span>Oldest lag</span>
              <strong>{status.pending_records ? `${status.ingest_lag_seconds.toFixed(1)} seconds` : "CURRENT"}</strong>
            </div>
            <div>
              <span>Quarantine</span>
              <strong>
                {status.quarantined_records.toLocaleString()} events · {formatBytes(status.quarantined_bytes)}
              </strong>
            </div>
          </div>
        )}
        {statusError && <div className="event-health-error">Ingestion health unavailable · {statusError}</div>}
        {page && !page.device_labels_available && (
          <div className="event-health-error">
            Device names are temporarily unavailable. Immutable device IDs and event evidence remain visible.
          </div>
        )}
        {error && <ErrorBox message={error} />}
        {!error && page?.events.length === 0 && (
          <div className="event-empty">
            {query || source
              ? "No events match this filter. Try a longer time window or press Clear."
              : "No traffic yet. Connect a device to the lab network and use it; events appear here within a minute."}
          </div>
        )}
        {traffic.pending.length > 0 && (
          <div className="event-new-rows" role="status">
            <button type="button" onClick={showPendingEvents}>
              Show {traffic.pending.length.toLocaleString()} new event{traffic.pending.length === 1 ? "" : "s"}
            </button>
            <span>Current rows stay fixed until you choose to update the view.</span>
          </div>
        )}
        {traffic.dropped > 0 && (
          <div className="event-browser-drop" role="status">
            {traffic.dropped.toLocaleString()} older event{traffic.dropped === 1 ? " was" : "s were"} removed from this
            page to keep it fast. They are still stored; use Load older events or Export to get them.
          </div>
        )}
        {page && page.events.length > 0 && (
          <WindowedTrafficTable
            events={page.events}
            density={density}
            labelsAvailable={page.device_labels_available}
            selectedRecordID={selectedRecordID}
            onSelect={setSelectedRecordID}
            onRenamed={applyAlias}
            onFilterDevice={filterDevice}
          />
        )}
        {page && page.next_cursor && (
          <div className="event-older">
            <button
              type="button"
              className="quiet"
              disabled={olderBusy || page.events.length >= MAX_VISIBLE_LIVE_ROWS}
              onClick={() => void loadOlder()}
            >
              {olderBusy ? "Loading…" : "Load older events"}
            </button>
            {page.events.length >= MAX_VISIBLE_LIVE_ROWS && (
              <small>
                This page holds {MAX_VISIBLE_LIVE_ROWS.toLocaleString()} events at most. Narrow the filter or use
                Export.
              </small>
            )}
            {olderError && <small className="event-health-error">{olderError}</small>}
          </div>
        )}
        {page && <p className="event-generated">Updated {new Date(page.generated_at).toLocaleString()}</p>}
        <TrafficExport query={query} source={source} />
        <details className="traffic-save">
          <summary>Save, share or freeze this view</summary>
          <SavedViewsPanel
            query={query}
            source={source}
            density={density}
            onApply={applySavedView}
            onDensity={(next) => {
              setDensity(next)
              updateTrafficURL(query, source, next)
            }}
          />
          <EventQuerySnapshotControl query={page?.canonical_query ?? query} source={source} />
        </details>
      </section>
      <TrafficOverview onDevice={filterDevice} />
      <HTTPActivity />
      <FeatureViews workspace="traffic" />
    </>
  )
}

export function updateTrafficURL(query: string, source: string, density: "comfortable" | "compact" = "comfortable") {
  const next = new URL(window.location.href)
  if (query) next.searchParams.set("traffic_q", query)
  else next.searchParams.delete("traffic_q")
  if (source) next.searchParams.set("traffic_source", source)
  else next.searchParams.delete("traffic_source")
  if (density === "compact") next.searchParams.set("traffic_density", density)
  else next.searchParams.delete("traffic_density")
  window.history.replaceState({}, "", next)
}
