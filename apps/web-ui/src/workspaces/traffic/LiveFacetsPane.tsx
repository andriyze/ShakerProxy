import React from "react"
import { ALL_STREAM_KINDS, MAX_FIELD_FILTERS, type FacetValue, type LiveFacets, type LiveFilters, type StreamKind } from "../../lib/liveTraffic"

// LiveFacetsPane is the left sidebar of the Live view, after Kibana's and
// Datadog's field lists: what the shown traffic consists of, with counts.
// Clicking a value shows only it; the minus excludes it.
export function LiveFacetsPane({
  facets,
  filters,
  sampled,
  onChange,
}: {
  facets: LiveFacets
  filters: LiveFilters
  sampled: string
  onChange: (next: LiveFilters) => void
}) {
  const include = filters.include ?? []
  const exclude = filters.exclude ?? []
  const add = (list: "include" | "exclude", value: string) => {
    if (!value) return
    const current = list === "include" ? include : exclude
    if (current.includes(value) || current.length >= MAX_FIELD_FILTERS) return
    const other = list === "include" ? exclude : include
    onChange({ ...filters, [list]: [...current, value], [list === "include" ? "exclude" : "include"]: other.filter((item) => item !== value) })
  }
  const remove = (list: "include" | "exclude", value: string) =>
    onChange({ ...filters, [list]: (list === "include" ? include : exclude).filter((item) => item !== value) })
  const clientChoice = (value: FacetValue) => {
    if (value.filter.startsWith("device.id:")) {
      const id = value.filter.slice("device.id:".length)
      onChange({ ...filters, clients: filters.clients.includes(id) ? filters.clients.filter((client) => client !== id) : [...filters.clients, id] })
    } else add("include", value.filter)
  }
  const kindChoice = (kind: string) => {
    const only = [kind as StreamKind]
    const already = filters.kinds.length === 1 && filters.kinds[0] === kind
    onChange({ ...filters, kinds: already ? ALL_STREAM_KINDS : only })
  }
  return (
    <aside className="live-facets" aria-label="What this traffic consists of">
      {(include.length > 0 || exclude.length > 0) && (
        <div className="live-facets__active">
          {include.map((value) => (
            <button key={`in-${value}`} type="button" className="live-chip on" onClick={() => remove("include", value)} title="Remove this filter">
              {value} ✕
            </button>
          ))}
          {exclude.map((value) => (
            <button key={`ex-${value}`} type="button" className="live-chip excluded" onClick={() => remove("exclude", value)} title="Remove this exclusion">
              not {value} ✕
            </button>
          ))}
        </div>
      )}
      <FacetGroup title="Clients" values={facets.clients} active={(value) => value.filter.startsWith("device.id:") && filters.clients.includes(value.filter.slice(10))} onPick={clientChoice} onExclude={(value) => add("exclude", value.filter)} />
      <FacetGroup
        title="Type"
        values={facets.kinds}
        active={(value) => filters.kinds.length === 1 && filters.kinds[0] === value.key}
        onPick={(value) => kindChoice(value.key)}
      />
      <FacetGroup title="Owner" values={facets.owners} active={(value) => include.includes(value.filter)} onPick={(value) => add("include", value.filter)} onExclude={(value) => add("exclude", value.filter)} />
      <FacetGroup title="Domain" values={facets.domains} active={(value) => include.includes(value.filter)} onPick={(value) => add("include", value.filter)} onExclude={(value) => add("exclude", value.filter)} />
      <FacetGroup title="Port" values={facets.ports} active={(value) => include.includes(value.filter)} onPick={(value) => add("include", value.filter)} onExclude={(value) => add("exclude", value.filter)} />
      <p className="live-facets__note">{sampled}</p>
    </aside>
  )
}

function FacetGroup({
  title,
  values,
  active,
  onPick,
  onExclude,
}: {
  title: string
  values: FacetValue[]
  active: (value: FacetValue) => boolean
  onPick: (value: FacetValue) => void
  onExclude?: (value: FacetValue) => void
}) {
  if (values.length === 0) return null
  const max = Math.max(...values.map((value) => value.count))
  return (
    <section className="live-facet">
      <h3>{title}</h3>
      <ul>
        {values.map((value) => (
          <li key={value.key} className={active(value) ? "on" : undefined}>
            <button type="button" className="live-facet__pick" onClick={() => onPick(value)} title={`Show only ${value.label}`}>
              <span className="live-facet__bar" style={{ width: `${Math.max(4, (value.count / max) * 100)}%` }} aria-hidden="true" />
              <span className="live-facet__label">{value.label}</span>
              <span className="live-facet__count">{value.count.toLocaleString()}</span>
            </button>
            {onExclude && (
              <button type="button" className="live-facet__exclude" onClick={() => onExclude(value)} title={`Hide ${value.label}`} aria-label={`Hide ${value.label}`}>
                −
              </button>
            )}
          </li>
        ))}
      </ul>
    </section>
  )
}
