import React, { useEffect, useMemo, useRef, useState } from "react"
import { foldSplitConnections, forwardedLookups, isAnalyzerDuplicate } from "../../lib/eventSummary"
import { eventDeviceTitle, splitDeviceTitle, type DeviceDirectory } from "../../lib/deviceTitle"
import { collapseRepeats, mergeInstantConnections, ownerLine, streamEnds, streamLine, transferLine } from "../../lib/liveTraffic"
import type { RecentEvent } from "../../types"

// TrafficStream lists events newest first, one line each. Rows that arrive
// while the list is shown fade in so new traffic is easy to spot.
export type RowAction = "only-device" | "hide-device" | "only-domain" | "hide-domain" | "conversation" | "copy"
export type GroupBy = "none" | "device" | "domain"

export function TrafficStream({
  events: allEvents,
  directory,
  selectedRecordID,
  onSelect,
  onHoldChange,
  groupBy = "none",
  onRowAction,
}: {
  events: RecentEvent[]
  directory?: DeviceDirectory
  selectedRecordID: string
  onSelect: (recordID: string) => void
  onHoldChange: (holding: boolean) => void
  groupBy?: GroupBy
  onRowAction?: (action: RowAction, event: RecentEvent) => void
}) {
  const [menu, setMenu] = useState<{ x: number; y: number; event: RecentEvent } | null>(null)
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set())
  useEffect(() => {
    if (!menu) return
    const close = (event: Event) => {
      if (event instanceof KeyboardEvent && event.key !== "Escape") return
      setMenu(null)
    }
    window.addEventListener("click", close)
    window.addEventListener("keydown", close)
    window.addEventListener("scroll", close, true)
    return () => {
      window.removeEventListener("click", close)
      window.removeEventListener("keydown", close)
      window.removeEventListener("scroll", close, true)
    }
  }, [menu])
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
  const clientOf = (event: RecentEvent) => splitDeviceTitle(eventDeviceTitle(event, directory))[0] || event.source_ip || "Unknown device"
  // Groups (after Little Snitch and Proxyman): by device, or device and domain.
  const groups = useMemo(() => {
    if (groupBy === "none") return [{ key: "", label: "", rows, bytes: 0 }]
    const map = new Map<string, { key: string; label: string; rows: typeof rows; bytes: number }>()
    for (const row of rows) {
      const client = clientOf(row.event)
      const line = streamLine(row.event)
      const domain = groupBy === "domain" ? line.name : ""
      const key = groupBy === "domain" ? `${client}\u0000${domain}` : client
      const group = map.get(key) ?? { key, label: groupBy === "domain" ? `${client} → ${domain}` : client, rows: [], bytes: 0 }
      group.rows.push(row)
      group.bytes += row.event.network_bytes ?? 0
      map.set(key, group)
    }
    return Array.from(map.values()).sort((a, b) => b.rows.length - a.rows.length)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows, groupBy, directory])
  const visibleIDs = groups.flatMap((group) => (collapsed.has(group.key) ? [] : group.rows.map((row) => row.event.record_id)))
  // Arrow keys move the selection, like DevTools and Wireshark.
  const moveSelection = (step: number) => {
    if (visibleIDs.length === 0) return
    const index = visibleIDs.indexOf(selectedRecordID)
    const next = visibleIDs[Math.min(visibleIDs.length - 1, Math.max(0, index < 0 ? 0 : index + step))]
    onSelect(next)
    document.querySelector(`[data-record="${next}"]`)?.scrollIntoView({ block: "nearest" })
  }
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
      <div
        className="stream-rows"
        role="rowgroup"
        tabIndex={-1}
        onKeyDown={(keyboard) => {
          if (keyboard.key === "ArrowDown" || keyboard.key === "j") {
            keyboard.preventDefault()
            moveSelection(1)
          } else if (keyboard.key === "ArrowUp" || keyboard.key === "k") {
            keyboard.preventDefault()
            moveSelection(-1)
          }
        }}
      >
        {groups.map((group) => (
          <React.Fragment key={group.key || "all"}>
            {group.label && (
              <button
                type="button"
                className="stream-group"
                aria-expanded={!collapsed.has(group.key)}
                onClick={() =>
                  setCollapsed((current) => {
                    const next = new Set(current)
                    if (next.has(group.key)) next.delete(group.key)
                    else next.add(group.key)
                    return next
                  })
                }
              >
                <span>{collapsed.has(group.key) ? "▸" : "▾"}</span>
                <strong>{group.label}</strong>
                <span>
                  {group.rows.length.toLocaleString()} event{group.rows.length === 1 ? "" : "s"}
                  {group.bytes ? ` · ${transferLine({ network_bytes: group.bytes } as RecentEvent)}` : ""}
                </span>
              </button>
            )}
            {!collapsed.has(group.key) &&
              group.rows.map(({ event, count }) => (
                <StreamRow
                  key={event.record_id}
                  event={event}
                  count={count}
                  client={clientOf(event) === event.source_ip ? "" : clientOf(event)}
                  fresh={fresh.has(event.record_id)}
                  selected={event.record_id === selectedRecordID}
                  onSelect={() => select(event.record_id)}
                  onMenu={onRowAction ? (x, y) => setMenu({ x, y, event }) : undefined}
                />
              ))}
          </React.Fragment>
        ))}
      </div>
      {menu && onRowAction && (
        <RowMenu
          x={menu.x}
          y={menu.y}
          event={menu.event}
          client={clientOf(menu.event)}
          onPick={(action) => {
            onRowAction(action, menu.event)
            setMenu(null)
          }}
        />
      )}
      {hidden > 0 || showDuplicates ? (
        <button type="button" className="quiet stream-duplicates" onClick={() => setShowDuplicates((current) => !current)}>
          {showDuplicates ? "Hide analyzer duplicates" : `Show ${hidden.toLocaleString()} analyzer duplicate${hidden === 1 ? "" : "s"}`}
        </button>
      ) : null}
    </div>
  )
}

function StreamRow({
  event,
  count,
  client,
  fresh,
  selected,
  onSelect,
  onMenu,
}: {
  event: RecentEvent
  count: number
  client: string
  fresh: boolean
  selected: boolean
  onSelect: () => void
  onMenu?: (x: number, y: number) => void
}) {
  const line = streamLine(event)
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
      role="row"
      tabIndex={0}
      data-record={event.record_id}
      aria-selected={selected}
      className={`stream-row ${line.kind}${fresh ? " fresh" : ""}${line.problem ? " problem" : ""}${line.pending ? " pending" : ""}${line.kind === "http" && event.source !== "MITMPROXY" ? " cleartext" : ""}${selected ? " selected" : ""}`}
      onClick={onSelect}
      onContextMenu={
        onMenu
          ? (mouse) => {
              mouse.preventDefault()
              onMenu(mouse.clientX, mouse.clientY)
            }
          : undefined
      }
      onKeyDown={(keyboard) => {
        if (keyboard.key === "Enter" || keyboard.key === " ") {
          keyboard.preventDefault()
          onSelect()
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
}

// RowMenu is the right-click menu on a row, after Wireshark's "Apply as
// filter" and "Follow stream".
function RowMenu({ x, y, event, client, onPick }: { x: number; y: number; event: RecentEvent; client: string; onPick: (action: RowAction) => void }) {
  const domain = streamLine(event).name
  const items: [RowAction, string][] = [
    ["only-device", `Only ${client}`],
    ["hide-device", `Hide ${client}`],
    ...(domain ? ([["only-domain", `Only ${domain}`], ["hide-domain", `Hide ${domain}`]] as [RowAction, string][]) : []),
    ["conversation", "Follow this conversation"],
    ["copy", "Copy this line"],
  ]
  return (
    <div className="stream-menu" role="menu" style={{ left: Math.min(x, window.innerWidth - 260), top: Math.min(y, window.innerHeight - 220) }} onClick={(click) => click.stopPropagation()}>
      {items.map(([action, label]) => (
        <button key={action} type="button" role="menuitem" onClick={() => onPick(action)}>
          {label}
        </button>
      ))}
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
