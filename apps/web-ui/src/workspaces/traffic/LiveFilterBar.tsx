import React, { FormEvent, useEffect, useState } from "react"
import { deviceTitle, type DeviceDirectory } from "../../lib/deviceTitle"
import { ALL_STREAM_KINDS, STREAM_KINDS, STREAM_TIMES, type LiveFilters, type StreamKind } from "../../lib/liveTraffic"
import type { Device } from "../../types"

const MAX_CLIENT_CHIPS = 12

function recentDevices(directory?: DeviceDirectory): { device: Device; title: string }[] {
  if (!directory) return []
  const unique = new Map<string, { device: Device; title: string }>()
  for (const entry of directory.values()) unique.set(entry.device.id, { device: entry.device, title: deviceTitle(entry.device, "", entry.hint) })
  return Array.from(unique.values()).sort((a, b) =>
    a.device.online !== b.device.online ? (a.device.online ? -1 : 1) : Date.parse(b.device.last_seen) - Date.parse(a.device.last_seen),
  )
}

// LiveFilterBar narrows the stream by client, kind, time and a search term.
export function LiveFilterBar({
  filters,
  directory,
  onChange,
}: {
  filters: LiveFilters
  directory?: DeviceDirectory
  onChange: (next: LiveFilters) => void
}) {
  const [search, setSearch] = useState(filters.search)
  useEffect(() => setSearch(filters.search), [filters.search])
  const devices = recentDevices(directory)
  const shown = devices.slice(0, MAX_CLIENT_CHIPS)
  for (const id of filters.clients) {
    const extra = devices.find((entry) => entry.device.id === id)
    if (extra && !shown.includes(extra)) shown.push(extra)
  }
  const everyKind = filters.kinds.length === ALL_STREAM_KINDS.length
  const toggleKind = (id: StreamKind) => {
    // From "all", a click shows only that kind; further clicks add or remove.
    const kinds = everyKind ? [id] : filters.kinds.includes(id) ? filters.kinds.filter((kind) => kind !== id) : [...filters.kinds, id]
    onChange({ ...filters, kinds: kinds.length ? kinds : ALL_STREAM_KINDS })
  }
  const toggleClient = (id: string) =>
    onChange({ ...filters, clients: filters.clients.includes(id) ? filters.clients.filter((client) => client !== id) : [...filters.clients, id] })
  const submitSearch = (event: FormEvent) => {
    event.preventDefault()
    onChange({ ...filters, search: search.trim() })
  }
  return (
    <div className="live-filters" role="group" aria-label="Filter the live traffic">
      <div className="live-filter-row">
        <span className="live-filter-label">Clients</span>
        <button type="button" className={`live-chip${filters.clients.length === 0 ? " on" : ""}`} aria-pressed={filters.clients.length === 0} onClick={() => onChange({ ...filters, clients: [] })}>
          All
        </button>
        {shown.map(({ device, title }) => (
          <button
            key={device.id}
            type="button"
            className={`live-chip${filters.clients.includes(device.id) ? " on" : ""}`}
            aria-pressed={filters.clients.includes(device.id)}
            title={`${title}${device.online ? " · online" : ""}`}
            onClick={() => toggleClient(device.id)}
          >
            <span className={device.online ? "live-dot online" : "live-dot"} aria-hidden="true" />
            {title}
          </button>
        ))}
        {devices.length === 0 && <span className="live-filter-hint">Devices appear here once they use the lab.</span>}
      </div>
      <div className="live-filter-row">
        <span className="live-filter-label">Type</span>
        <button type="button" className={`live-chip${everyKind ? " on" : ""}`} aria-pressed={everyKind} onClick={() => onChange({ ...filters, kinds: ALL_STREAM_KINDS })}>
          All
        </button>
        {STREAM_KINDS.map((kind) => {
          const on = !everyKind && filters.kinds.includes(kind.id)
          return (
            <button key={kind.id} type="button" className={`live-chip kind ${kind.id}${on ? " on" : ""}`} aria-pressed={on} title={kind.description} onClick={() => toggleKind(kind.id)}>
              {kind.label}
            </button>
          )
        })}
        {filters.kinds.length === 0 && <span className="live-filter-hint">Any event, including analyzer records (advanced filter)</span>}
      </div>
      <div className="live-filter-row">
        <span className="live-filter-label">Time</span>
        {STREAM_TIMES.map(([label, value]) => (
          <button key={label} type="button" className={`live-chip${filters.time === value ? " on" : ""}`} aria-pressed={filters.time === value} onClick={() => onChange({ ...filters, time: value })}>
            {label}
          </button>
        ))}
        <form className="live-search" onSubmit={submitSearch}>
          <input
            type="search"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            onBlur={() => search.trim() !== filters.search && onChange({ ...filters, search: search.trim() })}
            placeholder="Search a domain or IP: github, 142.250.1.1"
            aria-label="Search a domain or IP address"
            maxLength={128}
            spellCheck={false}
          />
        </form>
      </div>
    </div>
  )
}
