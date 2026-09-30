// Device report (§4): findings first, then domains, protocols, TLS and HTTP,
// with a printable view, JSON/HTML export and the CA-trust selector.
// Registered as a device extension and reused by the Tests workspace.
import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react"
import { createPortal } from "react-dom"
import { api, describeError, downloadBlob } from "../api"
import { navigate } from "./registry"
import { registerDeviceExtension } from "./register"
import { formatBytes, formatCount, formatDateTime, formatRelative, isTimeWindow, plural, safeFileName, windowLabel, TIME_WINDOWS } from "./format"
import { deviceProtocolsPath, trafficQueryForProtocol } from "./protocols-model"
import {
  CA_TRUST_OPTIONS,
  SEVERITY_INFO,
  domainKind,
  findingsHeadline,
  groupDomains,
  reportPath,
  reportTitle,
  sortFindings,
  tlsSummaryLines,
  trackerDomainCount,
  windowCovering,
  type ReportScope,
} from "./report-model"
import { ReportDocument, standaloneReportHTML } from "./ReportDocument"
import { sessionsFromResponse, testSessionsPath } from "./tests-model"
import { CoverageBar, EvidenceBadge, VisibilityBadge } from "./ProtocolsView"
import { Badge, Empty, ErrorNotice, Loading, useResource, type Resource } from "./shared"
import type { CATrust, CATrustResponse, DeviceReport, Finding, ProtocolsResponse, ReportDomain, TimeWindow } from "./types"
import "./features.css"
import "./report-print.css"
import reportCSS from "./report-print.css?raw"

// ---------------------------------------------------------------------------
// Findings

export function FindingCard({ finding }: { finding: Finding }) {
  const [showAll, setShowAll] = useState(false)
  const info = SEVERITY_INFO[finding.severity] ?? SEVERITY_INFO.INFO
  const evidence = showAll ? finding.evidence : finding.evidence.slice(0, 5)
  return (
    <article className={`lgf-finding lgf-sev-${info.tone}`}>
      <header>
        <Badge tone={info.tone} title={info.meaning}>
          {info.label}
        </Badge>
        <h4>{finding.title}</h4>
      </header>
      <p>{finding.detail}</p>
      {finding.recommendation && (
        <p className="lgf-recommendation">
          <strong>What to do: </strong>
          {finding.recommendation}
        </p>
      )}
      {finding.evidence.length > 0 && (
        <div className="lgf-evidence">
          <span className="lgf-label">Evidence</span>
          <ul>
            {evidence.map((item, index) => (
              <li key={`${index}-${item}`}>
                <code>{item}</code>
              </li>
            ))}
          </ul>
          {finding.evidence.length > 5 && (
            <button type="button" className="lgf-link" onClick={() => setShowAll(!showAll)}>
              {showAll ? "Show less" : `Show all ${finding.evidence.length}`}
            </button>
          )}
        </div>
      )}
    </article>
  )
}

function FindingsSection({ findings }: { findings: Finding[] }) {
  const sorted = useMemo(() => sortFindings(findings), [findings])
  return (
    <section className="lgf-report-section" aria-label="Findings">
      <h3>Findings</h3>
      {sorted.length === 0 ? (
        <Empty title="No security findings.">Findings only cover what ShakerProxy observed. Use every feature of the device (setup, sign-in, updates, casting) during the test so its traffic is checked.</Empty>
      ) : (
        <div className="lgf-findings">
          {sorted.map((finding) => (
            <FindingCard key={finding.id} finding={finding} />
          ))}
        </div>
      )}
    </section>
  )
}

// ---------------------------------------------------------------------------
// Domains

function DomainRow({ domain }: { domain: ReportDomain }) {
  const kind = domainKind(domain.category)
  return (
    <li className={`lgf-domain lgf-domain-${kind}`}>
      <div>
        <strong>{domain.domain}</strong>
        {kind === "tracker" && <span className="lgf-chip lgf-chip-tracker">Tracker</span>}
        {kind === "telemetry" && <span className="lgf-chip lgf-chip-telemetry">Telemetry</span>}
        <small>{domain.organization || domain.registrable_domain}</small>
      </div>
      <div className="lgf-domain-meta">
        {domain.sources.map((source) => (
          <span key={source} className="lgf-source">
            {source.toUpperCase()}
          </span>
        ))}
        <span title="Events">{formatCount(domain.events)}</span>
        <span title={formatDateTime(domain.last_seen)}>{formatRelative(domain.last_seen)}</span>
      </div>
    </li>
  )
}

function DomainsSection({ domains }: { domains: ReportDomain[] }) {
  const [by, setBy] = useState<"category" | "organization">("category")
  const [expanded, setExpanded] = useState<Record<string, boolean>>({})
  const groups = useMemo(() => groupDomains(domains, by), [domains, by])
  const trackers = trackerDomainCount(domains)
  const groupID = useId()
  return (
    <section className="lgf-report-section" aria-label="Domains">
      <div className="lgf-section-head">
        <h3>Domains contacted {domains.length > 0 && <small>({domains.length})</small>}</h3>
        <div className="lgf-segmented" role="radiogroup" aria-label="Group domains by">
          {(["category", "organization"] as const).map((option) => (
            <button key={option} type="button" role="radio" aria-checked={by === option} className={by === option ? "lgf-selected" : undefined} onClick={() => setBy(option)}>
              {option === "category" ? "By purpose" : "By company"}
            </button>
          ))}
        </div>
      </div>
      {trackers > 0 && (
        <p className="lgf-callout lgf-tone-warn">
          {plural(trackers, "domain")} {trackers === 1 ? "is" : "are"} used for analytics or advertising. The device reports usage data to third parties.
        </p>
      )}
      {groups.length === 0 ? (
        <Empty title="No domains observed.">The device made no DNS lookups, TLS connections or HTTP requests that ShakerProxy saw in this period.</Empty>
      ) : (
        <div className="lgf-domain-groups">
          {groups.map((group) => {
            const open = expanded[group.key] ?? false
            const shown = open ? group.domains : group.domains.slice(0, 8)
            return (
              <div key={group.key} className={`lgf-domain-group lgf-domain-${group.kind}`}>
                <h4 id={`${groupID}-${group.key}`}>
                  {group.label} <small>{plural(group.domains.length, "domain")}</small>
                </h4>
                <ul aria-labelledby={`${groupID}-${group.key}`}>
                  {shown.map((domain) => (
                    <DomainRow key={domain.domain} domain={domain} />
                  ))}
                </ul>
                {group.domains.length > 8 && (
                  <button type="button" className="lgf-link" onClick={() => setExpanded({ ...expanded, [group.key]: !open })}>
                    {open ? "Show fewer" : `Show ${group.domains.length - 8} more`}
                  </button>
                )}
              </div>
            )
          })}
        </div>
      )}
    </section>
  )
}

// ---------------------------------------------------------------------------
// Protocols, TLS, HTTP

function ProtocolsSection({ protocols, window }: { protocols: Resource<ProtocolsResponse>; window: TimeWindow }) {
  return (
    <section className="lgf-report-section" aria-label="Protocols">
      <div className="lgf-section-head">
        <h3>Protocols</h3>
        <small className="lgf-hint">{windowLabel(window)}</small>
      </div>
      {protocols.loading && !protocols.data && <Loading label="Loading protocols…" />}
      {protocols.error && !protocols.data && <ErrorNotice message={protocols.error} onRetry={protocols.reload} />}
      {protocols.data &&
        (protocols.data.protocols.length === 0 ? (
          <Empty title="No protocols observed in this window." />
        ) : (
          <>
            <CoverageBar coverage={protocols.data.coverage} compact />
            <ul className="lgf-proto-list">
              {protocols.data.protocols.slice(0, 20).map((protocol) => (
                <li key={protocol.protocol}>
                  <button type="button" className="lgf-link" onClick={() => navigate("traffic", { traffic_q: trafficQueryForProtocol(protocol.protocol) })} title="View this traffic">
                    {protocol.label || protocol.protocol}
                  </button>
                  {protocol.novel && <span className="lgf-chip lgf-chip-new">New</span>}
                  {protocol.exotic && <span className="lgf-chip lgf-chip-exotic">Exotic</span>}
                  <VisibilityBadge visibility={protocol.visibility} />
                  <EvidenceBadge evidence={protocol.evidence} />
                  <small>
                    {plural(protocol.flows, "connection")} · {formatBytes(protocol.bytes)}
                  </small>
                </li>
              ))}
            </ul>
            {protocols.data.protocols.length > 20 && <p className="lgf-hint">Showing the top 20 of {protocols.data.protocols.length}. Open Protocols for the full list.</p>}
          </>
        ))}
    </section>
  )
}

function HostList({ hosts, limit = 8 }: { hosts: string[]; limit?: number }) {
  const [all, setAll] = useState(false)
  const shown = all ? hosts : hosts.slice(0, limit)
  return (
    <>
      <ul className="lgf-host-list">
        {shown.map((host) => (
          <li key={host}>
            <code>{host}</code>
          </li>
        ))}
      </ul>
      {hosts.length > limit && (
        <button type="button" className="lgf-link" onClick={() => setAll(!all)}>
          {all ? "Show fewer" : `Show all ${hosts.length}`}
        </button>
      )}
    </>
  )
}

function TLSSection({ report }: { report: DeviceReport }) {
  const { tls } = report
  return (
    <section className="lgf-report-section" aria-label="HTTPS and TLS">
      <h3>HTTPS / TLS</h3>
      <div className="lgf-stats">
        <div>
          <span>Decrypted</span>
          <strong>{formatCount(tls.intercepted)}</strong>
        </div>
        <div>
          <span>Refused certificate</span>
          <strong>{formatCount(tls.failed)}</strong>
        </div>
        <div>
          <span>Passed through</span>
          <strong>{formatCount(tls.bypassed)}</strong>
        </div>
        <div>
          <span>Pinning suspected</span>
          <strong>{formatCount(tls.pinning_suspected)}</strong>
        </div>
      </div>
      <ul className="lgf-plain-list lgf-explain">
        {tlsSummaryLines(report).map((line) => (
          <li key={line}>{line}</li>
        ))}
      </ul>
      {tls.failed_hosts.length > 0 && (
        <>
          <h4>Hosts that refused ShakerProxy's certificate</h4>
          <HostList hosts={tls.failed_hosts} />
        </>
      )}
      {tls.old_versions.map((old) => (
        <div key={old.version}>
          <h4>
            Outdated {old.version} used with {plural(old.hosts.length, "host")}
          </h4>
          <HostList hosts={old.hosts} />
        </div>
      ))}
    </section>
  )
}

function HTTPSection({ report }: { report: DeviceReport }) {
  const { http } = report
  const classes = ["2xx", "3xx", "4xx", "5xx"] as const
  const total = classes.reduce((sum, key) => sum + (http.status_classes[key] ?? 0), 0)
  return (
    <section className="lgf-report-section" aria-label="HTTP">
      <h3>HTTP</h3>
      <div className="lgf-stats">
        <div>
          <span>Requests</span>
          <strong>{formatCount(http.requests)}</strong>
        </div>
        <div>
          <span>Hosts</span>
          <strong>{formatCount(http.hosts)}</strong>
        </div>
        <div className={http.cleartext_requests > 0 ? "lgf-stat-warn" : undefined}>
          <span>Unencrypted</span>
          <strong>{formatCount(http.cleartext_requests)}</strong>
        </div>
      </div>
      {total > 0 && (
        <ul className="lgf-status-classes" aria-label="Responses by status">
          {classes.map((key) => (
            <li key={key} className={`lgf-status-${key}`}>
              <span>{key}</span> <b>{formatCount(http.status_classes[key] ?? 0)}</b>
            </li>
          ))}
        </ul>
      )}
      {http.cleartext_requests > 0 && <p className="lgf-hint">Unencrypted HTTP can be read and changed by anyone on the network path.</p>}
    </section>
  )
}

// ---------------------------------------------------------------------------
// CA trust

export function CATrustSelector({ deviceID, value, onSaved }: { deviceID: string; value: CATrust; onSaved: (next: CATrust) => void }) {
  const [saving, setSaving] = useState<CATrust | "">("")
  const [error, setError] = useState("")
  const name = useId()
  const save = async (state: CATrust) => {
    if (state === value) return
    setSaving(state)
    setError("")
    try {
      const response = await api<CATrustResponse>(`/api/v1/devices/${encodeURIComponent(deviceID)}/ca-trust`, { method: "PUT", body: JSON.stringify({ state }) })
      onSaved(response.ca_trust ?? state)
    } catch (reason) {
      setError(describeError(reason, "Could not save the certificate state."))
    } finally {
      setSaving("")
    }
  }
  return (
    <fieldset className="lgf-ca-trust" disabled={saving !== ""}>
      <legend>Is ShakerProxy's certificate installed on this device?</legend>
      <div className="lgf-radio-cards">
        {CA_TRUST_OPTIONS.map((option) => (
          <label key={option.value} className={value === option.value ? "lgf-selected" : undefined}>
            <input type="radio" name={name} value={option.value} checked={value === option.value} onChange={() => void save(option.value)} />
            <span>
              <strong>{saving === option.value ? "Saving…" : option.label}</strong>
              <small>{option.explanation}</small>
            </span>
          </label>
        ))}
      </div>
      {error && (
        <p className="lgf-inline-error" role="alert">
          {error}
        </p>
      )}
    </fieldset>
  )
}

// ---------------------------------------------------------------------------
// Printable view

function PrintSheet({ report, protocols, fileStem, onClose }: { report: DeviceReport; protocols?: ProtocolsResponse | null; fileStem: string; onClose: () => void }) {
  const printButton = useRef<HTMLButtonElement>(null)
  const documentRef = useRef<HTMLDivElement>(null)
  const [error, setError] = useState("")
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null
    printButton.current?.focus()
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose()
    }
    document.addEventListener("keydown", onKey)
    return () => {
      document.removeEventListener("keydown", onKey)
      previous?.focus?.()
    }
  }, [onClose])
  const downloadHTML = () => {
    const markup = documentRef.current?.outerHTML
    if (!markup) return
    try {
      downloadBlob(new Blob([standaloneReportHTML(markup, reportTitle(report), reportCSS)], { type: "text/html" }), `${fileStem}.html`)
    } catch (reason) {
      setError(describeError(reason, "Could not create the download."))
    }
  }
  return createPortal(
    <div className="lgf-print-sheet" role="dialog" aria-modal="true" aria-label="Printable report">
      <div className="lgf-print-bar">
        <span>To share a PDF, choose Print, then “Save as PDF”.</span>
        <div className="lgf-actions">
          <button ref={printButton} type="button" className="lgf-button" onClick={() => window.print()}>
            Print
          </button>
          <button type="button" className="lgf-button lgf-secondary" onClick={downloadHTML}>
            Download HTML
          </button>
          <button type="button" className="lgf-button lgf-secondary" onClick={onClose}>
            Close
          </button>
        </div>
        {error && (
          <p className="lgf-inline-error" role="alert">
            {error}
          </p>
        )}
      </div>
      <div className="lgf-print-paper">
        <ReportDocument ref={documentRef} report={report} protocols={protocols} />
      </div>
    </div>,
    document.body,
  )
}

// ---------------------------------------------------------------------------
// Report

type ScopeValue = { kind: "window"; window: TimeWindow } | { kind: "session"; id: string }

function scopeKey(scope: ScopeValue): string {
  return scope.kind === "window" ? `window:${scope.window}` : `session:${scope.id}`
}

function parseScopeKey(key: string): ScopeValue {
  const [kind, value] = key.split(":", 2)
  if (kind === "session" && value) return { kind: "session", id: value }
  return { kind: "window", window: isTimeWindow(value) ? value : "24h" }
}

export type DeviceReportViewProps = { deviceID: string; deviceName?: string; sessionID?: string; heading?: boolean }

export function DeviceReportView({ deviceID, deviceName, sessionID, heading = true }: DeviceReportViewProps) {
  const [scope, setScope] = useState<ScopeValue>(sessionID ? { kind: "session", id: sessionID } : { kind: "window", window: "24h" })
  const [printing, setPrinting] = useState(false)
  const [exportError, setExportError] = useState("")
  useEffect(() => {
    setScope(sessionID ? { kind: "session", id: sessionID } : { kind: "window", window: "24h" })
  }, [deviceID, sessionID])
  const reportScope: ReportScope = scope.kind === "session" ? { session: scope.id } : { window: scope.window }
  const report = useResource<DeviceReport>(reportPath(deviceID, reportScope))
  const sessions = useResource<unknown>(testSessionsPath({ device: deviceID, limit: 50 }))
  const sessionList = useMemo(() => sessionsFromResponse(sessions.data), [sessions.data])
  // The protocols endpoint takes a window; for a test run, wait until the
  // run's start is known and use the smallest window that covers it.
  const sessionStart = scope.kind === "session" ? (report.data?.session?.started_at ?? sessionList.find((item) => item.id === scope.id)?.started_at) : undefined
  const protocolWindow: TimeWindow = scope.kind === "window" ? scope.window : windowCovering(sessionStart)
  const protocols = useResource<ProtocolsResponse>(scope.kind === "window" || sessionStart ? deviceProtocolsPath(deviceID, protocolWindow) : null)
  const scopeID = useId()
  const data = report.data
  const name = data?.device.friendly_name || deviceName || deviceID
  const fileStem = safeFileName(`shakerproxy-report-${name}-${new Date().toISOString().slice(0, 10)}`)

  const closePrint = useCallback(() => setPrinting(false), [])
  const downloadJSON = () => {
    if (!data) return
    try {
      downloadBlob(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }), `${fileStem}.json`)
    } catch (reason) {
      setExportError(describeError(reason, "Could not create the download."))
    }
  }
  return (
    <section className="lgf-report" aria-label={`Report for ${name}`}>
      <header className="lgf-report-head">
        <div>
          {heading && <p className="lgf-eyebrow">Security report</p>}
          <h3 className="lgf-report-title">{name}</h3>
          {data && (
            <p className="lgf-hint">
              {[data.device.vendor, data.device.addresses.join(", "), data.device.online ? "online" : "offline"].filter(Boolean).join(" · ")}
            </p>
          )}
        </div>
        <div className="lgf-report-controls">
          <div className="lgf-field">
            <label className="lgf-label" htmlFor={scopeID}>
              Report covers
            </label>
            <select id={scopeID} className="lgf-select" value={scopeKey(scope)} onChange={(event) => setScope(parseScopeKey(event.target.value))}>
              <optgroup label="Time window">
                {TIME_WINDOWS.map((window) => (
                  <option key={window.value} value={`window:${window.value}`}>
                    {window.label}
                  </option>
                ))}
              </optgroup>
              {sessionList.length > 0 && (
                <optgroup label="Test runs">
                  {sessionList.map((session) => (
                    <option key={session.id} value={`session:${session.id}`}>
                      {session.state === "RUNNING" ? "● " : ""}
                      {session.name}
                    </option>
                  ))}
                </optgroup>
              )}
              {scope.kind === "session" && !sessionList.some((session) => session.id === scope.id) && (
                <option value={scopeKey(scope)}>{data?.session?.name ?? "Selected test run"}</option>
              )}
            </select>
          </div>
          <div className="lgf-actions" role="group" aria-label="Export report">
            <button type="button" className="lgf-button lgf-secondary" disabled={!data} onClick={() => setPrinting(true)}>
              Printable report
            </button>
            <button type="button" className="lgf-button lgf-secondary" disabled={!data} onClick={downloadJSON}>
              Download JSON
            </button>
          </div>
        </div>
      </header>
      {exportError && (
        <p className="lgf-inline-error" role="alert">
          {exportError}
        </p>
      )}

      {report.loading && !data && <Loading label="Building the report…" />}
      {report.error && (
        <ErrorNotice message={report.error} onRetry={report.reload}>
          <button type="button" className="lgf-button lgf-secondary" onClick={() => navigate("devices")}>
            Open Devices
          </button>
        </ErrorNotice>
      )}
      {data && (
        <>
          <div className={`lgf-report-summary lgf-sev-${data.findings.length ? SEVERITY_INFO[sortFindings(data.findings)[0].severity]?.tone ?? "info" : "ok"}`}>
            <strong>{findingsHeadline(data.findings)}</strong>
            <span>
              {data.session ? `Test run “${data.session.name}”` : windowLabel(scope.kind === "window" ? scope.window : "24h")} · {formatDateTime(data.window_start)} – {formatDateTime(data.window_end)}
            </span>
            <span>
              {plural(data.totals.flows, "connection")} · {formatBytes(data.totals.bytes)} · {plural(data.totals.dns_queries, "DNS lookup")} · {plural(data.totals.alerts, "IDS alert")}
            </span>
          </div>
          <CATrustSelector
            deviceID={deviceID}
            value={data.ca_trust}
            onSaved={(next) => {
              report.setData({ ...data, ca_trust: next })
              report.reload()
            }}
          />
          <FindingsSection findings={data.findings} />
          <DomainsSection domains={data.domains} />
          <ProtocolsSection protocols={protocols} window={protocolWindow} />
          <TLSSection report={data} />
          <HTTPSection report={data} />
          {data.truncated && <p className="lgf-hint">Some lists were shortened because the device was very busy. Download JSON for everything in the report.</p>}
        </>
      )}
      {printing && data && <PrintSheet report={data} protocols={protocols.data} fileStem={fileStem} onClose={closePrint} />}
    </section>
  )
}

function DeviceReportExtension({ deviceID, deviceName }: { deviceID: string; deviceName?: string }) {
  return <DeviceReportView deviceID={deviceID} deviceName={deviceName} />
}

registerDeviceExtension({ id: "device-report", title: "Security report", order: 30, Component: DeviceReportExtension })
