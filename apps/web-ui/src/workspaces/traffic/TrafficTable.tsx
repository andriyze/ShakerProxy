import React, { FormEvent, useEffect, useRef, useState } from "react"
import { withPassword } from "../../shell/passwordPrompt"
import { formatBytes, formatNetworkEndpoint, idempotencyKey } from "../../lib/format"
import { MAX_VISIBLE_LIVE_ROWS, virtualRowWindow } from "../../lib/liveRows"
import { tlsOutcomeExplanation } from "../../lib/tlsTrust"
import { eventSummary, eventTone, eventTypeLabel, foldSplitConnections, isAnalyzerDuplicate } from "../../lib/eventSummary"
import { EventDetailDrawer } from "./EventDetailDrawer"
import { api, describeError } from "../../api"
import type { Device, DeviceMutationResult, RecentEvent } from "../../types"

export function WindowedTrafficTable({
  events: allEvents,
  density,
  labelsAvailable,
  selectedRecordID,
  onSelect,
  onRenamed,
  onFilterDevice,
}: {
  events: RecentEvent[]
  density: "comfortable" | "compact"
  labelsAvailable: boolean
  selectedRecordID: string
  onSelect: (recordID: string) => void
  onFilterDevice: (deviceID: string) => void
  onRenamed: (device: Device) => void
}) {
  const viewport = useRef<HTMLDivElement | null>(null)
  // One row per connection and lookup by default; the analyzers' duplicate
  // records stay one click away.
  const [showDuplicates, setShowDuplicates] = useState(false)
  const events = showDuplicates ? allEvents : foldSplitConnections(allEvents.filter((event) => !isAnalyzerDuplicate(event)))
  const hiddenDuplicates = allEvents.length - events.length
  const rowHeight = density === "compact" ? 54 : 72
  const preferredHeight = Math.min(560, Math.max(rowHeight, events.length * rowHeight))
  const [viewportHeight, setViewportHeight] = useState(preferredHeight)
  const [scrollTop, setScrollTop] = useState(0)
  useEffect(() => {
    const element = viewport.current
    if (!element) return
    const measure = () => setViewportHeight(element.clientHeight || preferredHeight)
    measure()
    const observer = new ResizeObserver(measure)
    observer.observe(element)
    return () => observer.disconnect()
  }, [preferredHeight])
  const windowed = virtualRowWindow(events.length, scrollTop, viewportHeight, rowHeight)
  const visible = events.slice(windowed.start, windowed.end)
  const selectedIndex = events.findIndex((event) => event.record_id === selectedRecordID)
  const selected = selectedIndex >= 0 ? events[selectedIndex] : undefined
  const activeDescendant =
    selectedIndex >= windowed.start && selectedIndex < windowed.end ? `traffic-row-${selectedRecordID}` : undefined
  const selectIndex = (index: number) => {
    const bounded = Math.max(0, Math.min(events.length - 1, index))
    const event = events[bounded]
    if (!event) return
    onSelect(event.record_id)
    const element = viewport.current
    if (!element) return
    const top = bounded * rowHeight
    if (top < element.scrollTop) element.scrollTo({ top })
    else if (top + rowHeight > element.scrollTop + element.clientHeight)
      element.scrollTo({ top: top + rowHeight - element.clientHeight })
  }
  const keyboard = (event: React.KeyboardEvent<HTMLDivElement>) => {
    const current = events.findIndex((item) => item.record_id === selectedRecordID)
    if (event.key === "ArrowDown") {
      event.preventDefault()
      selectIndex(current < 0 ? 0 : current + 1)
    } else if (event.key === "ArrowUp") {
      event.preventDefault()
      selectIndex(current < 0 ? 0 : current - 1)
    } else if (event.key === "Home") {
      event.preventDefault()
      selectIndex(0)
    } else if (event.key === "End") {
      event.preventDefault()
      selectIndex(events.length - 1)
    } else if (event.key === "Escape" && selectedRecordID) {
      event.preventDefault()
      onSelect("")
    }
  }
  return (
    <section className="traffic-table-shell" aria-label="Bounded live traffic table">
      <div className="traffic-table-summary">
        <strong>{events.length.toLocaleString()} events shown</strong>
        {(hiddenDuplicates > 0 || showDuplicates) && (
          <button type="button" className="quiet traffic-duplicates-toggle" onClick={() => setShowDuplicates((value) => !value)}>
            {showDuplicates ? "Hide analyzer duplicates" : `Show ${hiddenDuplicates.toLocaleString()} analyzer duplicates`}
          </button>
        )}
        <span>
          Up to {MAX_VISIBLE_LIVE_ROWS.toLocaleString()} at a time · click a row or use the arrow keys for details
        </span>
      </div>
      <div
        className="traffic-table"
        role="table"
        aria-label="Traffic events"
        aria-rowcount={events.length + 1}
        aria-colcount={4}
      >
        <div className="traffic-table-header" role="row" aria-rowindex={1}>
          <span role="columnheader">When</span>
          <span role="columnheader">Device</span>
          <span role="columnheader">What happened</span>
          <span role="columnheader">Connection</span>
        </div>
        <div
          className="traffic-table-viewport"
          ref={viewport}
          role="rowgroup"
          tabIndex={0}
          aria-label="Traffic events. Use the up and down arrow keys to open details."
          aria-activedescendant={activeDescendant}
          onKeyDown={keyboard}
          onScroll={(event) => setScrollTop(Math.max(0, event.currentTarget.scrollTop))}
          style={{ height: preferredHeight }}
        >
          <div className="traffic-table-spacer" style={{ height: windowed.totalSize }}>
            {visible.map((item, offset) => {
              const index = windowed.start + offset
              const endpoint =
                item.source_ip || item.destination_ip
                  ? `${formatNetworkEndpoint(item.source_ip, item.source_port)} → ${formatNetworkEndpoint(item.destination_ip, item.destination_port)}`
                  : "Endpoints unavailable"
              const device = item.device_friendly_name || item.device_id || "Unknown device"
              const summary = eventSummary(item)
              const tone = eventTone(item)
              return (
                <div
                  id={`traffic-row-${item.record_id}`}
                  className={`traffic-table-row${item.record_id === selectedRecordID ? " selected" : ""}${tone ? ` tw-row-${tone}` : ""}`}
                  role="row"
                  aria-rowindex={index + 2}
                  aria-selected={item.record_id === selectedRecordID}
                  aria-label={`${summary}, ${device}, ${new Date(item.occurred_at).toLocaleString()}`}
                  key={item.record_id}
                  onClick={() => onSelect(item.record_id)}
                  style={{ height: rowHeight, transform: `translateY(${index * rowHeight}px)` }}
                >
                  <span role="cell">
                    <strong>{new Date(item.occurred_at).toLocaleTimeString()}</strong>
                    <small title={`${new Date(item.occurred_at).toLocaleString()} · ${item.source.toLowerCase()} ${item.kind}`}>
                      {eventTypeLabel(item)}
                    </small>
                  </span>
                  <span role="cell">
                    <strong>{device}</strong>
                    <small>{item.source_ip || `${item.confidence}% sure`}</small>
                  </span>
                  <span role="cell" className="traffic-summary-cell">
                    <strong title={summary}>{summary}</strong>
                    <small>{(item.app_protocol || item.service || "").toUpperCase()}</small>
                  </span>
                  <span role="cell">
                    <strong title={endpoint}>{endpoint}</strong>
                    <small>
                      {[item.protocol?.toUpperCase(), item.network_bytes ? formatBytes(item.network_bytes) : ""]
                        .filter(Boolean)
                        .join(" · ") || "—"}
                    </small>
                  </span>
                </div>
              )
            })}
          </div>
        </div>
      </div>
      {selected && (
        <EventDetailDrawer
          event={selected}
          labelsAvailable={labelsAvailable}
          onClose={() => onSelect("")}
          onRenamed={onRenamed}
          onFilterDevice={onFilterDevice}
        />
      )}
    </section>
  )
}

export function TrafficEventInspector({
  event,
  labelsAvailable,
  onClose,
  onRenamed,
}: {
  event: RecentEvent
  labelsAvailable: boolean
  onClose?: () => void
  onRenamed: (device: Device) => void
}) {
  const evidence = event.attribution_evidence
  return (
    <section className="traffic-inspector" aria-labelledby="traffic-inspector-title">
      <header>
        <div>
          <span>Summary</span>
          <strong id="traffic-inspector-title">{eventSummary(event)}</strong>
        </div>
        {onClose && (
          <button type="button" className="quiet" onClick={onClose}>
            Close
          </button>
        )}
      </header>
      <dl>
        <div>
          <dt>Record</dt>
          <dd>
            <code>{event.record_id}</code>
          </dd>
        </div>
        <div>
          <dt>Observed</dt>
          <dd>
            {new Date(event.occurred_at).toLocaleString()}
            <small>Stored {new Date(event.received_at).toLocaleString()}</small>
          </dd>
        </div>
        {event.detection_type && (
          <div>
            <dt>Native detection</dt>
            <dd>
              <strong>{event.detection_type.replaceAll("_", " ")}</strong>
              <small>
                {event.detection_severity} · {event.detection_state} · {event.detection_scope}
              </small>
              <small>{event.detection_summary}</small>
            </dd>
          </div>
        )}
        <div>
          <dt>Traffic</dt>
          <dd>
            {event.source_ip || event.destination_ip
              ? `${formatNetworkEndpoint(event.source_ip, event.source_port)} → ${formatNetworkEndpoint(event.destination_ip, event.destination_port)}`
              : "Endpoints unavailable"}
            <small>
              {[event.protocol, event.service, event.network_bytes ? formatBytes(event.network_bytes) : ""]
                .filter(Boolean)
                .join(" · ") || "No connection details"}
            </small>
          </dd>
        </div>
        {event.tls_interception_state && (
          <div>
            <dt>TLS outcome</dt>
            <dd>
              <strong>
                {event.tls_interception_state.replaceAll("_", " ")}
                {event.tls_pinning_suspected ? " · PINNING SUSPECTED" : ""}
              </strong>
              <small>
                {event.tls_server_name || "Server name unavailable"}
                {event.tls_platform ? ` · ${event.tls_platform}` : ""}
              </small>
              <small>{tlsOutcomeExplanation(event)}</small>
              {event.tls_client_recent_success !== undefined && (
                <small>
                  Recent successful interception on this client: {event.tls_client_recent_success ? "yes" : "no"}
                </small>
              )}
            </dd>
          </div>
        )}
        {event.dns_query && (
          <div>
            <dt>DNS observation</dt>
            <dd>
              <strong>{event.dns_query}</strong>
              <small>
                {[
                  event.dns_record_type,
                  event.dns_response_code,
                  event.dns_answer_count !== undefined ? `${event.dns_answer_count} answer(s)` : "",
                ]
                  .filter(Boolean)
                  .join(" · ")}
              </small>
              <small>Observe only · no resolver policy or client outcome is inferred</small>
            </dd>
          </div>
        )}
        <div>
          <dt>Attribution</dt>
          <dd>
            {event.device_friendly_name || event.device_id || "No unambiguous device"}
            {event.device_id && <code>{event.device_id}</code>}
            {event.device_friendly_name_conflict && <small className="alias-conflict">Duplicate friendly name</small>}
            {event.device_id &&
              event.device_friendly_name_at_capture_known &&
              event.device_friendly_name_at_capture !== event.device_friendly_name && (
                <small>At capture · {event.device_friendly_name_at_capture || "Unnamed device"}</small>
              )}
            {event.device_id && labelsAvailable && !event.device_friendly_name_at_capture_known && (
              <small>Capture-time name unavailable</small>
            )}
            <small>
              {event.confidence}% confidence{event.flow_id ? ` · flow ${event.flow_id}` : ""}
            </small>
          </dd>
        </div>
        {evidence && (
          <div>
            <dt>Attribution evidence</dt>
            <dd>
              <strong>
                {evidence.endpoint.toLowerCase()} address {evidence.address}
              </strong>
              <small>
                {evidence.source} · {evidence.confidence}% address confidence
              </small>
              <small>
                Valid {new Date(evidence.valid_from).toLocaleString()} →{" "}
                {new Date(evidence.valid_until).toLocaleString()} (exclusive)
              </small>
              <small>
                {evidence.interface
                  ? `${evidence.interface}${evidence.vlan_id ? ` · VLAN ${evidence.vlan_id}` : ""}`
                  : "Legacy interface/VLAN scope unknown"}
                {evidence.scope_plan_sha256 ? ` · plan ${evidence.scope_plan_sha256.slice(0, 12)}…` : ""}
              </small>
            </dd>
          </div>
        )}
        {event.device_id && !evidence && (
          <div>
            <dt>Attribution evidence</dt>
            <dd>
              Unavailable for this stored event
              <small>Explicit MITM policy association or legacy event; no DHCP interval is inferred.</small>
            </dd>
          </div>
        )}
        {event.capture_session_id && (
          <div>
            <dt>Capture</dt>
            <dd>
              <code>{event.capture_session_id}</code>
            </dd>
          </div>
        )}
        <div>
          <dt>Parser</dt>
          <dd>
            {event.source_version}
            <small>{event.parser_version}</small>
          </dd>
        </div>
      </dl>
      {event.device_id && labelsAvailable && <EventDeviceAliasForm event={event} onRenamed={onRenamed} />}
    </section>
  )
}

export function EventDeviceAliasForm({
  event,
  onRenamed,
}: {
  event: RecentEvent
  onRenamed: (device: Device) => void
}) {
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState("")
  async function submit(formEvent: FormEvent<HTMLFormElement>) {
    formEvent.preventDefault()
    setBusy(true)
    setMessage("")
    const form = formEvent.currentTarget
    const data = new FormData(form)
    try {
      const key = idempotencyKey("traffic-alias")
      const result = await withPassword("rename this device", (password) =>
        api<DeviceMutationResult>(`/api/v1/devices/${event.device_id}/alias`, {
          method: "PUT",
          headers: { "Idempotency-Key": key },
          body: JSON.stringify({
            ...(password ? { password } : {}),
            friendly_name: data.get("friendly_name"),
            reason: data.get("reason"),
            expected_revision: event.device_alias_revision ?? 0,
          }),
        }),
      )
      const device = result.devices[0]
      if (!device) throw new Error("Alias response did not include the device")
      onRenamed(device)
      form.reset()
      setMessage(result.replayed ? "Rename was already saved." : "Renamed with revision history.")
    } catch (reason) {
      setMessage(describeError(reason, "The device could not be renamed"))
    } finally {
      setBusy(false)
    }
  }
  return (
    <details className="event-alias">
      <summary>Rename device</summary>
      <form onSubmit={submit}>
        <label>
          Friendly name
          <input name="friendly_name" defaultValue={event.device_friendly_name} maxLength={128} required />
        </label>
        <label>
          Reason
          <input name="reason" maxLength={256} required placeholder="Why this name is correct" />
        </label>
        <button className="quiet" disabled={busy}>
          {busy ? "Renaming…" : "Save rename"}
        </button>
        {message && <small>{message}</small>}
      </form>
    </details>
  )
}
