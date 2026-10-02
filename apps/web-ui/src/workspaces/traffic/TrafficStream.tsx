import React, { useEffect, useMemo, useRef, useState } from "react"
import { foldSplitConnections, forwardedLookups, isAnalyzerDuplicate } from "../../lib/eventSummary"
import { eventDeviceTitle, splitDeviceTitle, type DeviceDirectory } from "../../lib/deviceTitle"
import { collapseRepeats, mergeInstantConnections, ownerLine, streamEnds, streamLine, transferLine } from "../../lib/liveTraffic"
import type { RecentEvent } from "../../types"

// TrafficStream lists events newest first, one line each. Rows that arrive
// while the list is shown fade in so new traffic is easy to spot.
export function TrafficStream({
  events: allEvents,
  directory,
  selectedRecordID,
  onSelect,
  onHoldChange,
}: {
  events: RecentEvent[]
  directory?: DeviceDirectory
  selectedRecordID: string
  onSelect: (recordID: string) => void
  onHoldChange: (holding: boolean) => void
}) {
  const [showDuplicates, setShowDuplicates] = useState(false)
  const forwarded = useMemo(() => forwardedLookups(allEvents), [allEvents])
  const events = useMemo(
    () =>
      showDuplicates
        ? allEvents
        : mergeInstantConnections(foldSplitConnections(allEvents.filter((event) => !isAnalyzerDuplicate(event, forwarded)))),
    [allEvents, forwarded, showDuplicates],
  )
  const hidden = allEvents.length - events.length
  const rows = useMemo(
    () =>
      collapseRepeats(events, (event) => {
        const line = streamLine(event)
        return [event.device_id ?? event.source_ip ?? "", line.kind, line.name, line.detail].join("\u0000")
      }),
    [events],
  )
  // Rows already on screen; anything new after the first render is fresh.
  const seen = useRef<Set<string> | null>(null)
  const fresh = useMemo(() => {
    const previous = seen.current
    const next = new Set<string>()
    if (previous) for (const event of events) if (!previous.has(event.record_id)) next.add(event.record_id)
    return next
  }, [events])
  useEffect(() => {
    seen.current = new Set(events.map((event) => event.record_id))
  }, [events])
  const select = (recordID: string) => onSelect(recordID === selectedRecordID ? "" : recordID)
  return (
    <div className="stream" onMouseEnter={() => onHoldChange(true)} onMouseLeave={() => onHoldChange(false)}>
      <div className="stream-head" role="row">
        <span>Time</span>
        <span>Type</span>
        <span>From</span>
        <span aria-hidden="true" />
        <span>To</span>
        <span>What</span>
        <span>Details</span>
      </div>
      <div className="stream-rows" role="rowgroup">
        {rows.map(({ event, count }) => {
          const line = streamLine(event)
          const [client] = splitDeviceTitle(eventDeviceTitle(event, directory))
          const ends = streamEnds(event, client)
          const transfer = transferLine(event)
          const flags = [
            line.kind === "http" && event.source !== "MITMPROXY" ? "cleartext" : "",
            event.tls_interception_state === "INTERCEPTED" ? "decrypted" : "",
            event.blocked ? "blocked" : "",
          ]
            .filter(Boolean)
            .join(" · ")
          const at = new Date(event.occurred_at)
          return (
            <div
              key={event.record_id}
              role="row"
              tabIndex={0}
              aria-selected={event.record_id === selectedRecordID}
              className={`stream-row ${line.kind}${fresh.has(event.record_id) ? " fresh" : ""}${line.problem ? " problem" : ""}${line.pending ? " pending" : ""}${event.record_id === selectedRecordID ? " selected" : ""}`}
              onClick={() => select(event.record_id)}
              onKeyDown={(keyboard) => {
                if (keyboard.key === "Enter" || keyboard.key === " ") {
                  keyboard.preventDefault()
                  select(event.record_id)
                }
              }}
            >
              <time dateTime={event.occurred_at} title={at.toLocaleString()}>
                {at.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" })}
              </time>
              <span className={`stream-badge ${line.kind}`}>{line.badge}</span>
              <Cell primary={ends.from.primary} secondary={ends.from.secondary} className="stream-from" />
              <span className="stream-arrow" aria-label={ends.inbound ? "to the device" : "to"}>
                {ends.inbound ? "←" : "→"}
              </span>
              <Cell primary={ends.to.primary} secondary={ends.to.secondary} className="stream-to" />
              <Cell
                primary={
                  <>
                    {line.name}
                    {count > 1 && <span className="stream-count">×{count}</span>}
                  </>
                }
                title={count > 1 ? `${line.name} · ${count} times within a minute` : line.name}
                secondary={ownerLine(event)}
                className="stream-what"
              />
              <Cell
                primary={line.pending ? "opened" : line.detail || transfer}
                secondary={line.pending ? "details follow from the recording" : line.detail && transfer && line.detail !== transfer ? transfer : flags}
                className="stream-detail"
              />
            </div>
          )
        })}
      </div>
      {hidden > 0 || showDuplicates ? (
        <button type="button" className="quiet stream-duplicates" onClick={() => setShowDuplicates((current) => !current)}>
          {showDuplicates ? "Hide analyzer duplicates" : `Show ${hidden.toLocaleString()} analyzer duplicate${hidden === 1 ? "" : "s"}`}
        </button>
      ) : null}
    </div>
  )
}

// Cell is a two-line stream cell: the value, and a smaller line under it.
function Cell({
  primary,
  secondary,
  className,
  title,
}: {
  primary: React.ReactNode
  secondary?: string
  className: string
  title?: string
}) {
  return (
    <span className={`stream-cell ${className}`} title={title ?? (typeof primary === "string" ? [primary, secondary].filter(Boolean).join(" · ") : undefined)}>
      <span className="stream-primary">{primary}</span>
      {secondary ? <span className="stream-secondary">{secondary}</span> : null}
    </span>
  )
}
