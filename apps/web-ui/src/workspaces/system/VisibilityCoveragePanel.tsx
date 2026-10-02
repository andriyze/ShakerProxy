import React, { useState } from "react"
import { withPassword } from "../../shell/passwordPrompt"
import { api, describeError } from "../../api"
import { usePolling } from "../../shell/hooks"
import { coverageDelay, coverageHeadline } from "../../lib/coverage"
import type { CoverageOverview, CoverageReport } from "../../types"

// Visibility coverage: proves, one traffic type at a time, what ShakerProxy
// really records (probes from virtual clients through the real recording and
// analyzers), and lists every way devices could get around ShakerProxy.

function ResultTable({ run }: { run: CoverageReport }) {
  if (!run.results.length) return null
  return (
    <table className="coverage-table">
      <thead>
        <tr>
          <th>Traffic</th>
          <th>Result</th>
          <th>Seen as</th>
          <th>Delay</th>
          <th>What is missing</th>
        </tr>
      </thead>
      <tbody>
        {run.results.slice(0, 32).map((result) => (
          <tr key={result.id} className={result.status.toLowerCase()}>
            <td>{result.name}</td>
            <td>
              <span className={`testlab-result-badge ${result.status.toLowerCase()}`}>{result.status}</span>
            </td>
            <td>{result.event_kinds.length ? result.event_kinds.slice(0, 3).join(", ") : "—"}</td>
            <td>{coverageDelay(result)}</td>
            <td>{result.status === "SKIP" ? result.summary : result.status === "FAIL" ? result.summary : ""}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

export function VisibilityCoveragePanel() {
  const [overview, setOverview] = useState<CoverageOverview | null>(null)
  const [message, setMessage] = useState<{ text: string; tone: "" | "error" }>({ text: "", tone: "" })
  const [starting, setStarting] = useState(false)
  const run = overview?.last_run ?? null
  const running = starting || run?.state === "RUNNING"

  async function refresh() {
    try {
      setOverview(await api<CoverageOverview>("/api/v1/coverage"))
    } catch (reason) {
      setMessage({ text: describeError(reason, "Visibility coverage is unavailable"), tone: "error" })
    }
  }

  // Poll quickly while a check runs, slowly otherwise.
  usePolling(() => refresh(), running ? 3_000 : 30_000, [running])

  async function start() {
    if (running) return
    setStarting(true)
    setMessage({ text: "", tone: "" })
    try {
      await withPassword("run the visibility coverage check", (password) =>
        api<CoverageReport>("/api/v1/coverage/runs", { method: "POST", body: JSON.stringify(password ? { password } : {}) }),
      )
      await refresh()
    } catch (reason) {
      setMessage({ text: describeError(reason, "The coverage check could not start"), tone: "error" })
    } finally {
      setStarting(false)
    }
  }

  const routing = overview?.routing ?? []
  return (
    <section className="panel coverage-panel" aria-labelledby="coverage-title">
      <header className="coverage-head">
        <div>
          <p className="eyebrow">Visibility coverage</p>
          <h2 id="coverage-title">What ShakerProxy is proven to see</h2>
          <p>
            Sends one of each kind of traffic — DNS, DoH, DoT, DoQ, HTTP, HTTPS, QUIC, TCP, UDP, ICMP, SSH, NTP, mDNS,
            SSDP — from virtual clients through the real recording and analyzers, then checks what was stored and how
            fast. Takes 1–3 minutes; lab recording pauses for a few seconds.
          </p>
        </div>
        <button type="button" onClick={() => void start()} disabled={running}>
          {running ? "Checking…" : "Run coverage check"}
        </button>
      </header>
      <p className={`coverage-headline${run?.state === "FAILED" ? " error" : ""}`}>{coverageHeadline(run)}</p>
      {message.text && <p className={message.tone === "error" ? "error" : ""}>{message.text}</p>}
      {run && <ResultTable run={run} />}
      <h3>
        Ways around ShakerProxy in this lab
        {overview ? <span className={`coverage-gaps${overview.gap_count ? " has-gaps" : ""}`}>{overview.gap_count} gaps</span> : null}
      </h3>
      <ul className="coverage-findings">
        {routing.slice(0, 16).map((finding) => (
          <li key={finding.id} className={finding.status.toLowerCase()}>
            <span className={`coverage-finding-badge ${finding.status.toLowerCase()}`}>{finding.status}</span>
            <div>
              <strong>{finding.title}</strong>
              <p>{finding.detail}</p>
              {finding.status !== "OK" && finding.fix && <p className="coverage-fix">Fix: {finding.fix}</p>}
            </div>
          </li>
        ))}
      </ul>
      {run && run.limitations.length > 0 && (
        <details className="testlab-limitations">
          <summary>What this check does not prove</summary>
          {run.limitations.slice(0, 8).map((limitation) => (
            <p key={limitation}>{limitation}</p>
          ))}
        </details>
      )}
    </section>
  )
}
