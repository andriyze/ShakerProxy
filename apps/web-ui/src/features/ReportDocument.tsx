// Printable device report. Rendered by React (so every API value is escaped)
// inside the print sheet; "Download HTML" serialises the rendered markup.
import { forwardRef } from "react"
import { escapeHTML, formatBytes, formatCount, formatDateTime, humanize } from "./format"
import { VISIBILITY_INFO, coverageSentence } from "./protocols-model"
import { SEVERITY_INFO, caTrustInfo, domainKind, findingsHeadline, groupDomains, reportTitle, sortFindings, tlsSummaryLines } from "./report-model"
import type { DeviceReport, ProtocolsResponse } from "./types"

function List({ items, empty = "None" }: { items: readonly string[]; empty?: string }) {
  if (!items.length) return <p className="muted">{empty}</p>
  return (
    <ul>
      {items.map((item, index) => (
        <li key={`${index}-${item}`}>{item}</li>
      ))}
    </ul>
  )
}

export const ReportDocument = forwardRef<HTMLDivElement, { report: DeviceReport; protocols?: ProtocolsResponse | null }>(function ReportDocument({ report, protocols }, ref) {
  const device = report.device
  const findings = sortFindings(report.findings)
  const groups = groupDomains(report.domains, "category")
  const { tls, http, totals } = report
  return (
    <div className="lgf-report-doc" ref={ref}>
      <header className="rpt-head">
        <p className="rpt-eyebrow">ShakerProxy device report</p>
        <h1>{reportTitle(report)}</h1>
        <p className="rpt-meta">{[device.friendly_name || device.device_id, device.vendor, device.category ? humanize(device.category) : ""].filter(Boolean).join(" · ")}</p>
        <p className="rpt-meta">{[device.addresses.join(", ") || "No current address", device.hardware_addresses.join(", ")].filter(Boolean).join(" · ")}</p>
        <p className="rpt-meta">
          Covers:{" "}
          {report.session
            ? `Test run “${report.session.name}” · ${formatDateTime(report.session.started_at)} – ${report.session.ended_at ? formatDateTime(report.session.ended_at) : "still running"}`
            : `${formatDateTime(report.window_start)} – ${formatDateTime(report.window_end)}`}
        </p>
        <p className="rpt-meta">
          ShakerProxy certificate: {caTrustInfo(report.ca_trust).label} · Generated {formatDateTime(report.generated_at)}
        </p>
      </header>

      <section className="rpt-summary">
        <p className="rpt-headline">{findingsHeadline(report.findings)}</p>
        <dl className="rpt-totals">
          <div><dt>Connections</dt><dd>{formatCount(totals.flows)}</dd></div>
          <div><dt>Data</dt><dd>{formatBytes(totals.bytes)}</dd></div>
          <div><dt>DNS lookups</dt><dd>{formatCount(totals.dns_queries)}</dd></div>
          <div><dt>TLS connections</dt><dd>{formatCount(totals.tls_connections)}</dd></div>
          <div><dt>HTTP requests</dt><dd>{formatCount(totals.http_requests)}</dd></div>
          <div><dt>IDS alerts</dt><dd>{formatCount(totals.alerts)}</dd></div>
        </dl>
      </section>

      <section>
        <h2>Findings</h2>
        {findings.length === 0 ? (
          <p className="muted">No findings. Findings only cover behaviour ShakerProxy observed, so exercise every feature of the device during a test run.</p>
        ) : (
          findings.map((finding) => {
            const info = SEVERITY_INFO[finding.severity] ?? SEVERITY_INFO.INFO
            return (
              <article key={finding.id} className={`rpt-finding sev-${info.tone}`}>
                <p className="rpt-sev">{info.label}</p>
                <h3>{finding.title}</h3>
                <p>{finding.detail}</p>
                {finding.recommendation && (
                  <p>
                    <strong>What to do:</strong> {finding.recommendation}
                  </p>
                )}
                {finding.evidence.length > 0 && (
                  <details open>
                    <summary>Evidence ({finding.evidence.length})</summary>
                    <List items={finding.evidence.slice(0, 50)} />
                  </details>
                )}
              </article>
            )
          })
        )}
      </section>

      <section>
        <h2>Domains contacted ({report.domains.length})</h2>
        {groups.length === 0 ? (
          <p className="muted">No domains observed.</p>
        ) : (
          groups.map((group) => (
            <div key={group.key} className={`rpt-group ${group.kind}`}>
              <h3>
                {group.label}
                {group.kind === "tracker" ? " — tracking" : ""} <span className="muted">({group.domains.length})</span>
              </h3>
              <table>
                <thead>
                  <tr><th>Domain</th><th>Organization</th><th>Seen via</th><th className="num">Events</th><th>Last seen</th></tr>
                </thead>
                <tbody>
                  {group.domains.map((domain) => (
                    <tr key={domain.domain} className={domainKind(domain.category)}>
                      <td>{domain.domain}</td>
                      <td>{domain.organization || domain.registrable_domain || "—"}</td>
                      <td>{domain.sources.map((source) => source.toUpperCase()).join(", ")}</td>
                      <td className="num">{formatCount(domain.events)}</td>
                      <td>{formatDateTime(domain.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))
        )}
      </section>

      {protocols && (
        <section>
          <h2>Protocols</h2>
          <p>{coverageSentence(protocols.coverage)}</p>
          {protocols.protocols.length === 0 ? (
            <p className="muted">No protocols observed.</p>
          ) : (
            <table>
              <thead>
                <tr><th>Protocol</th><th>Category</th><th>Visibility</th><th className="num">Connections</th><th className="num">Data</th></tr>
              </thead>
              <tbody>
                {protocols.protocols.map((protocol) => (
                  <tr key={protocol.protocol}>
                    <td>
                      {protocol.label || protocol.protocol}
                      {protocol.exotic ? " (exotic)" : ""}
                      {protocol.novel ? " (new)" : ""}
                    </td>
                    <td>{humanize(protocol.category)}</td>
                    <td>{VISIBILITY_INFO[protocol.visibility]?.label ?? protocol.visibility}</td>
                    <td className="num">{formatCount(protocol.flows)}</td>
                    <td className="num">{formatBytes(protocol.bytes)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      )}

      <section>
        <h2>HTTPS / TLS</h2>
        <List items={tlsSummaryLines(report)} />
        {tls.failed_hosts.length > 0 && (
          <>
            <h3>Hosts that refused ShakerProxy's certificate</h3>
            <List items={tls.failed_hosts} />
          </>
        )}
        {tls.old_versions.map((old) => (
          <div key={old.version}>
            <h3>{old.version} used with</h3>
            <List items={old.hosts} />
          </div>
        ))}
      </section>

      <section>
        <h2>HTTP</h2>
        <dl className="rpt-totals">
          <div><dt>Requests</dt><dd>{formatCount(http.requests)}</dd></div>
          <div><dt>Hosts</dt><dd>{formatCount(http.hosts)}</dd></div>
          <div><dt>Unencrypted requests</dt><dd>{formatCount(http.cleartext_requests)}</dd></div>
          <div><dt>2xx / 3xx / 4xx / 5xx</dt><dd>{(["2xx", "3xx", "4xx", "5xx"] as const).map((key) => formatCount(http.status_classes[key] ?? 0)).join(" / ")}</dd></div>
        </dl>
      </section>

      {report.truncated && <p className="muted">Some lists were shortened because the device produced a lot of activity. Export JSON for the full data.</p>}
      <footer className="rpt-foot">Generated by ShakerProxy from traffic it observed. Absence of a finding is not proof of absence.</footer>
    </div>
  )
})

// standaloneReportHTML wraps serialised report markup (produced by the
// browser from the rendered ReportDocument, so already escaped) in a
// self-contained document with the report stylesheet inlined.
export function standaloneReportHTML(renderedMarkup: string, title: string, css: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHTML(title)}</title>
<style>${css.replace(/<\/style/gi, "<\\/style")}</style></head>
<body class="lgf-report-standalone">${renderedMarkup}</body></html>`
}
