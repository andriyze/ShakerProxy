// Protocols workspace (§2): which application protocols devices speak, how
// much of the traffic ShakerProxy can see into, and what is new or exotic.
import { Fragment, useEffect, useId, useMemo, useState } from "react"
import { navigate } from "./registry"
import { registerView } from "./register"
import { formatBytes, formatCount, formatDateTime, formatRelative, humanize, isTimeWindow, plural, windowLabel } from "./format"
import {
  EVIDENCE_INFO,
  VISIBILITY_INFO,
  coverageSegments,
  coverageSentence,
  filterCatalog,
  portSummary,
  protocolChips,
  protocolsPath,
  sortProtocols,
  trafficQueryForProtocol,
  type ProtocolFilters,
  type ProtocolSort,
} from "./protocols-model"
import { Badge, DevicePicker, Empty, ErrorNotice, Loading, WindowSelect, useResource, type Resource } from "./shared"
import type { DeviceChoice, ProtocolCatalogResponse, ProtocolCoverage, ProtocolsResponse, ProtocolUsage } from "./types"
import "./features.css"

const URL_KEYS = { window: "proto_window", device: "proto_device", category: "proto_category", exotic: "proto_exotic" } as const

function filtersFromURL(): ProtocolFilters {
  const params = new URLSearchParams(window.location.search)
  const windowValue = params.get(URL_KEYS.window)
  return {
    window: isTimeWindow(windowValue) ? windowValue : "24h",
    device: params.get(URL_KEYS.device) ?? "",
    category: params.get(URL_KEYS.category) ?? "",
    exotic: params.get(URL_KEYS.exotic) === "true",
  }
}

function writeFiltersToURL(filters: ProtocolFilters): void {
  const url = new URL(window.location.href)
  const set = (key: string, value: string) => (value ? url.searchParams.set(key, value) : url.searchParams.delete(key))
  set(URL_KEYS.window, filters.window === "24h" ? "" : filters.window)
  set(URL_KEYS.device, filters.device)
  set(URL_KEYS.category, filters.category)
  set(URL_KEYS.exotic, filters.exotic ? "true" : "")
  if (url.href !== window.location.href) window.history.replaceState(window.history.state, "", url)
}

export function CoverageBar({ coverage, compact }: { coverage: ProtocolCoverage; compact?: boolean }) {
  const segments = coverageSegments(coverage)
  const total = segments.reduce((sum, segment) => sum + segment.bytes, 0)
  return (
    <figure className={`lgf-coverage${compact ? " lgf-compact" : ""}`}>
      <div className="lgf-coverage-bar" role="img" aria-label={coverageSentence(coverage)}>
        {total === 0 ? (
          <span className="lgf-coverage-empty" />
        ) : (
          segments
            .filter((segment) => segment.percent > 0)
            .map((segment) => <span key={segment.key} className={`lgf-seg lgf-seg-${segment.key}`} style={{ width: `${Math.max(segment.percent, 0.75)}%` }} title={`${segment.label}: ${formatBytes(segment.bytes)}`} />)
        )}
      </div>
      <figcaption>
        <p className="lgf-coverage-sentence">{coverageSentence(coverage)}</p>
        {!compact && (
          <ul className="lgf-legend">
            {segments.map((segment) => (
              <li key={segment.key} title={segment.explanation}>
                <span className={`lgf-swatch lgf-seg-${segment.key}`} aria-hidden="true" />
                {segment.label} <b>{total ? `${Math.round(segment.percent)}%` : "—"}</b>
                <small>{formatBytes(segment.bytes)}</small>
              </li>
            ))}
          </ul>
        )}
      </figcaption>
    </figure>
  )
}

export function VisibilityBadge({ visibility }: { visibility: ProtocolUsage["visibility"] }) {
  const info = VISIBILITY_INFO[visibility] ?? VISIBILITY_INFO.OPAQUE
  return (
    <Badge tone={info.tone} title={info.explanation}>
      {info.short}
    </Badge>
  )
}

export function EvidenceBadge({ evidence }: { evidence: ProtocolUsage["evidence"] }) {
  const info = EVIDENCE_INFO[evidence] ?? EVIDENCE_INFO.UNCLASSIFIED
  return (
    <Badge tone={evidence === "ANALYZER" ? "good" : "muted"} title={info.explanation}>
      {info.label}
    </Badge>
  )
}

function ProtocolDetail({ protocol }: { protocol: ProtocolUsage }) {
  return (
    <div className="lgf-proto-detail">
      <p>{protocol.description || "No description in the catalog."}</p>
      <p className="lgf-hint">
        {VISIBILITY_INFO[protocol.visibility]?.explanation} {EVIDENCE_INFO[protocol.evidence]?.explanation}
      </p>
      <div className="lgf-proto-detail-grid">
        <div>
          <h4>Devices</h4>
          {protocol.devices.length === 0 ? (
            <p className="lgf-hint">No device could be identified for these connections.</p>
          ) : (
            <ul className="lgf-plain-list">
              {protocol.devices.map((device) => (
                <li key={device.device_id}>
                  <button type="button" className="lgf-link" onClick={() => navigate("devices", { device_id: device.device_id })}>
                    {device.device_name || device.device_id}
                  </button>
                  <small>
                    {plural(device.flows, "connection")} · {formatBytes(device.bytes)} · {formatRelative(device.last_seen)}
                  </small>
                </li>
              ))}
            </ul>
          )}
          {protocol.unattributed_flows > 0 && <p className="lgf-hint">{plural(protocol.unattributed_flows, "connection")} could not be linked to a device.</p>}
        </div>
        <div>
          <h4>Ports</h4>
          {protocol.ports.length === 0 ? (
            <p className="lgf-hint">No port information.</p>
          ) : (
            <ul className="lgf-plain-list">
              {protocol.ports.map((port) => (
                <li key={`${port.transport}-${port.port}`}>
                  <code>
                    {port.transport.toUpperCase()} {port.port}
                  </code>
                  <small>{plural(port.flows, "connection")}</small>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
      <div className="lgf-actions">
        <button type="button" className="lgf-button" onClick={() => navigate("traffic", { traffic_q: trafficQueryForProtocol(protocol.protocol) })}>
          View traffic
        </button>
      </div>
    </div>
  )
}

const SORT_OPTIONS: { value: ProtocolSort; label: string }[] = [
  { value: "bytes", label: "Most data" },
  { value: "flows", label: "Most connections" },
  { value: "devices", label: "Most devices" },
  { value: "last_seen", label: "Most recent" },
  { value: "label", label: "Name" },
]

function ProtocolTable({ protocols }: { protocols: ProtocolUsage[] }) {
  const [expanded, setExpanded] = useState<string>("")
  const [sort, setSort] = useState<ProtocolSort>("bytes")
  const sorted = useMemo(() => sortProtocols(protocols, sort), [protocols, sort])
  const baseID = useId()
  return (
    <div className="lgf-table-wrap">
      <div className="lgf-table-tools">
        <span>{plural(protocols.length, "protocol")}</span>
        <label className="lgf-inline-label">
          Sort by
          <select className="lgf-select" aria-label="Sort protocols by" value={sort} onChange={(event) => setSort(event.target.value as ProtocolSort)}>
            {SORT_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
      </div>
      <table className="lgf-table lgf-responsive">
        <thead>
          <tr>
            <th scope="col">Protocol</th>
            <th scope="col">Category</th>
            <th scope="col">Visibility</th>
            <th scope="col">Identified by</th>
            <th scope="col" className="lgf-num">Devices</th>
            <th scope="col" className="lgf-num">Connections</th>
            <th scope="col" className="lgf-num">Data</th>
            <th scope="col">First seen</th>
            <th scope="col">Last seen</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((protocol) => {
            const open = expanded === protocol.protocol
            const detailID = `${baseID}-${protocol.protocol}`
            return (
              <Fragment key={protocol.protocol}>
                <tr className={open ? "lgf-row-open" : undefined}>
                  <th scope="row" data-label="Protocol">
                    <button type="button" className="lgf-expander" aria-expanded={open} aria-controls={detailID} onClick={() => setExpanded(open ? "" : protocol.protocol)}>
                      <span className="lgf-chevron" aria-hidden="true" />
                      <span className="lgf-proto-name">{protocol.label || protocol.protocol}</span>
                    </button>
                    {protocolChips(protocol).map((chip) => (
                      <span key={chip.label} className={`lgf-chip lgf-chip-${chip.label.toLowerCase()}`} title={chip.title}>
                        {chip.label}
                      </span>
                    ))}
                  </th>
                  <td data-label="Category">{humanize(protocol.category)}</td>
                  <td data-label="Visibility">
                    <VisibilityBadge visibility={protocol.visibility} />
                  </td>
                  <td data-label="Identified by">
                    <EvidenceBadge evidence={protocol.evidence} />
                  </td>
                  <td data-label="Devices" className="lgf-num">
                    {formatCount(protocol.device_count)}
                  </td>
                  <td data-label="Connections" className="lgf-num">
                    {formatCount(protocol.flows)}
                  </td>
                  <td data-label="Data" className="lgf-num">
                    {formatBytes(protocol.bytes)}
                  </td>
                  <td data-label="First seen" title={formatDateTime(protocol.first_seen)}>
                    {formatRelative(protocol.first_seen)}
                  </td>
                  <td data-label="Last seen" title={formatDateTime(protocol.last_seen)}>
                    {formatRelative(protocol.last_seen)}
                  </td>
                </tr>
                {open && (
                  <tr className="lgf-detail-row" id={detailID}>
                    <td colSpan={9}>
                      <ProtocolDetail protocol={protocol} />
                      <p className="lgf-hint lgf-ports-inline">Ports: {portSummary(protocol.ports, 8)}</p>
                    </td>
                  </tr>
                )}
              </Fragment>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function CatalogExplorer({ catalog }: { catalog: Resource<ProtocolCatalogResponse> }) {
  const [open, setOpen] = useState(false)
  const [text, setText] = useState("")
  const [category, setCategory] = useState("")
  const searchID = useId()
  const categoryID = useId()
  const items = useMemo(() => filterCatalog(catalog.data?.protocols ?? [], text, category), [catalog.data, text, category])
  return (
    <details className="lgf-catalog" open={open} onToggle={(event) => setOpen((event.currentTarget as HTMLDetailsElement).open)}>
      <summary>
        Protocol catalog
        <small>{catalog.data ? ` — ${plural(catalog.data.protocols.length, "protocol")} ShakerProxy can recognise` : ""}</small>
      </summary>
      {open && (
        <div className="lgf-catalog-body">
          {catalog.loading && !catalog.data && <Loading label="Loading catalog…" />}
          {catalog.error && <ErrorNotice message={catalog.error} onRetry={catalog.reload} />}
          {catalog.data && (
            <>
              <div className="lgf-toolbar">
                <div className="lgf-field">
                  <label className="lgf-label" htmlFor={searchID}>
                    Search
                  </label>
                  <input id={searchID} className="lgf-input" type="search" value={text} placeholder="Name, description or port" onChange={(event) => setText(event.target.value)} />
                </div>
                <div className="lgf-field">
                  <label className="lgf-label" htmlFor={categoryID}>
                    Category
                  </label>
                  <select id={categoryID} className="lgf-select" value={category} onChange={(event) => setCategory(event.target.value)}>
                    <option value="">All categories</option>
                    {catalog.data.categories.map((item) => (
                      <option key={item} value={item}>
                        {humanize(item)}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
              {items.length === 0 ? (
                <Empty title="No catalog entry matches.">Try a different word or port number.</Empty>
              ) : (
                <ul className="lgf-catalog-list">
                  {items.map((item) => (
                    <li key={item.id}>
                      <div>
                        <strong>{item.label}</strong> <code>{item.id}</code>
                        {item.exotic && <span className="lgf-chip lgf-chip-exotic">Exotic</span>}
                      </div>
                      <p>{item.description}</p>
                      <small>
                        {humanize(item.category)} · <VisibilityBadge visibility={item.visibility} /> · {item.ports?.length ? portSummary(item.ports, 6) : "identified by analyzers only"}
                      </small>
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}
        </div>
      )}
    </details>
  )
}

export function ProtocolsView() {
  const [filters, setFilters] = useState<ProtocolFilters>(filtersFromURL)
  const [device, setDevice] = useState<DeviceChoice | null>(null)
  const result = useResource<ProtocolsResponse>(protocolsPath(filters), 30000)
  const catalog = useResource<ProtocolCatalogResponse>("/api/v1/protocols/catalog")
  const windowID = useId()
  const categoryID = useId()

  useEffect(() => writeFiltersToURL(filters), [filters])
  const update = (change: Partial<ProtocolFilters>) => setFilters((current) => ({ ...current, ...change }))
  const categories = catalog.data?.categories ?? []
  const filtered = filters.device !== "" || filters.category !== "" || filters.exotic

  return (
    <section className="lgf-view lgf-protocols" aria-labelledby={`${windowID}-title`}>
      <header className="lgf-view-head">
        <div>
          <p className="lgf-eyebrow">Protocols</p>
          <h2 id={`${windowID}-title`}>What are your devices speaking?</h2>
          <p className="lgf-lede">Every connection is identified by ShakerProxy's traffic analyzers or, if they can't tell, guessed from its port. New and unusual protocols are flagged so you can look closer.</p>
        </div>
        <button type="button" className="lgf-button lgf-secondary" onClick={result.reload} disabled={result.loading}>
          {result.loading ? "Refreshing…" : "Refresh"}
        </button>
      </header>

      <div className="lgf-toolbar" role="group" aria-label="Protocol filters">
        <div className="lgf-field">
          <label className="lgf-label" htmlFor={windowID}>
            Time window
          </label>
          <WindowSelect id={windowID} value={filters.window} onChange={(value) => update({ window: value })} />
        </div>
        <div className="lgf-field lgf-grow">
          {filters.device && !device ? (
            <div className="lgf-field">
              <span className="lgf-label">Device</span>
              <div className="lgf-device-chosen">
                <div>
                  <strong>{filters.device}</strong>
                </div>
                <button type="button" className="lgf-button lgf-secondary lgf-small" onClick={() => update({ device: "" })}>
                  All devices
                </button>
              </div>
            </div>
          ) : (
            <DevicePicker
              label="Device (optional)"
              value={device}
              onChange={(choice) => {
                setDevice(choice)
                update({ device: choice?.device_id ?? "" })
              }}
            />
          )}
        </div>
        <div className="lgf-field">
          <label className="lgf-label" htmlFor={categoryID}>
            Category
          </label>
          <select id={categoryID} className="lgf-select" value={filters.category} onChange={(event) => update({ category: event.target.value })}>
            <option value="">All categories</option>
            {categories.map((item) => (
              <option key={item} value={item}>
                {humanize(item)}
              </option>
            ))}
          </select>
        </div>
        <label className="lgf-checkbox">
          <input type="checkbox" checked={filters.exotic} onChange={(event) => update({ exotic: event.target.checked })} />
          Exotic only
        </label>
      </div>

      {result.error && !result.data && <ErrorNotice message={result.error} onRetry={result.reload} />}
      {result.loading && !result.data && <Loading label="Classifying traffic…" />}
      {result.data && (
        <>
          <CoverageBar coverage={result.data.coverage} />
          {result.error && <p className="lgf-hint lgf-warn-text">Showing earlier results: {result.error}</p>}
          {result.data.protocols.length === 0 ? (
            filtered ? (
              <Empty
                title="No protocols match these filters."
                action={
                  <button type="button" className="lgf-button lgf-secondary" onClick={() => { setDevice(null); setFilters((current) => ({ ...current, device: "", category: "", exotic: false })) }}>
                    Clear filters
                  </button>
                }
              >
                Nothing matched in the {windowLabel(filters.window).toLowerCase()}. Try a longer time window or clear the filters.
              </Empty>
            ) : (
              <Empty
                title="No traffic analyzed yet."
                action={
                  <button type="button" className="lgf-button" onClick={() => navigate("start")}>
                    Connect a device
                  </button>
                }
              >
                <p>ShakerProxy identifies protocols from traffic that passes through it. Connect a device to ShakerProxy's Wi-Fi or lab port and use it for a minute; the analyzers (Zeek and Suricata) classify each connection and it appears here.</p>
                <p>If devices are connected but nothing shows up, check that the analyzers are healthy in System.</p>
              </Empty>
            )
          ) : (
            <ProtocolTable protocols={result.data.protocols} />
          )}
          {result.data.truncated && <p className="lgf-hint">Only the top protocols are listed. Narrow the time window or pick a device to see the rest.</p>}
        </>
      )}

      <CatalogExplorer catalog={catalog} />
    </section>
  )
}

registerView({ id: "protocols", workspace: "protocols", title: "Protocols", order: 10, Component: ProtocolsView })
