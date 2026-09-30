import React, { FormEvent, useRef, useState } from "react"
import { withPassword } from "../../shell/passwordPrompt"
import { api, describeError } from "../../api"
import { usePolling } from "../../shell/hooks"
import type { TestLabProfile, TestLabRun, TestLabStatus, TestLabStatusValue } from "../../types"

// Virtual Test Lab: disposable network namespaces that act as test clients.
// Mounted only inside the signed-in dashboard (System workspace).
const PROFILES: { profile: TestLabProfile; title: string; detail: string }[] = [
  { profile: "quick", title: "Quick", detail: "Virtual topology + IPv4 routed HTTP" },
  { profile: "dns", title: "DNS", detail: "UDP DNS + isolated DoT block mechanic" },
  { profile: "tls", title: "TLS", detail: "TLS/pinning readiness without fabricated proof" },
  { profile: "full", title: "Full", detail: "Run every virtual profile and report remaining external gates" },
]

function Badge({ status }: { status: TestLabStatusValue }) {
  return <span className={`testlab-result-badge ${status.toLowerCase()}`}>{status}</span>
}

function RunResults({ run }: { run?: TestLabRun }) {
  if (!run) return <p className="testlab-empty">No virtual test run has been completed on this installation yet.</p>
  return (
    <>
      <div className="testlab-run-summary">
        <div>
          <strong>
            {run.profile.toUpperCase()} · {run.state}
          </strong>
          <small>
            {run.run_id} · {new Date(run.started_at).toLocaleString()}
          </small>
        </div>
        <div className="testlab-counters">
          <span className="pass">{run.pass_count} PASS</span>
          <span className="fail">{run.fail_count} FAIL</span>
          <span className="skip">{run.skip_count} SKIP</span>
        </div>
      </div>
      <div className="testlab-result-grid">
        {(run.results ?? []).slice(0, 32).map((result) => (
          <article key={result.id} className={`testlab-result ${result.status.toLowerCase()}`}>
            <header>
              <div>
                <strong>{result.name}</strong>
                <small>
                  {result.category} · {result.duration_ms.toLocaleString()} ms
                </small>
              </div>
              <Badge status={result.status} />
            </header>
            <p>{result.summary}</p>
            {result.observed && (
              <details>
                <summary>Observed evidence</summary>
                <pre>{result.observed}</pre>
              </details>
            )}
            {result.evidence_ref && <code className="testlab-evidence-ref">{result.evidence_ref}</code>}
          </article>
        ))}
      </div>
      {run.limitations && run.limitations.length > 0 && (
        <div className="testlab-limitations">
          <strong>What this run does not prove</strong>
          {run.limitations.slice(0, 8).map((limitation) => (
            <p key={limitation}>{limitation}</p>
          ))}
        </div>
      )}
    </>
  )
}

export function TestLabPanel() {
  const [status, setStatus] = useState<TestLabStatus | null>(null)
  const [lastRun, setLastRun] = useState<TestLabRun | undefined>(undefined)
  const [message, setMessage] = useState<{ text: string; tone: "" | "error" | "success" }>({
    text: "Loading test-lab status…",
    tone: "",
  })
  const [busy, setBusy] = useState(false)
  const refreshInFlight = useRef(false)

  async function refresh() {
    if (refreshInFlight.current) return
    refreshInFlight.current = true
    try {
      const next = await api<TestLabStatus>("/api/v1/self-test/status")
      setStatus(next)
      setLastRun(next.last_run)
      setMessage((current) =>
        !next.available
          ? { text: "Some requirements for the virtual lab are missing. See the checks below.", tone: "error" }
          : current.text === "Loading test-lab status…"
            ? { text: "Pick a profile to run.", tone: "" }
            : current,
      )
    } catch (reason) {
      setMessage({ text: describeError(reason, "Virtual test lab is unavailable"), tone: "error" })
    } finally {
      refreshInFlight.current = false
    }
  }

  // Bounded polling instead of DOM observation; pauses while the tab is hidden.
  usePolling(() => (busy ? undefined : refresh()), 10_000, [busy])

  async function run(profile: TestLabProfile) {
    if (busy) return
    setBusy(true)
    setMessage({
      text: `Running ${profile} virtual-client tests. The isolated namespaces are removed automatically when the run ends…`,
      tone: "",
    })
    try {
      const result = await withPassword("create the virtual test clients", (password) =>
        api<TestLabRun>("/api/v1/self-test/run", {
          method: "POST",
          body: JSON.stringify({ profile, ...(password ? { password } : {}) }),
        }),
      )
      setLastRun(result)
      setMessage(
        result.fail_count
          ? { text: `Run completed with ${result.fail_count} failure(s).`, tone: "error" }
          : result.skip_count
            ? {
                text: `Runtime checks passed; ${result.skip_count} capability proof(s) remain intentionally skipped.`,
                tone: "success",
              }
            : { text: "All requested virtual checks passed.", tone: "success" },
      )
    } catch (reason) {
      setMessage({ text: describeError(reason, "Virtual test run failed"), tone: "error" })
    } finally {
      setBusy(false)
    }
  }

  async function cleanup(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    try {
      await withPassword("remove the virtual test clients", (password) =>
        api("/api/v1/self-test/cleanup", { method: "POST", body: JSON.stringify(password ? { password } : {}) }),
      )
      setMessage({
        text: "Test namespaces, links, and the dedicated test nftables table were removed.",
        tone: "success",
      })
    } catch (reason) {
      setMessage({ text: describeError(reason, "Cleanup failed"), tone: "error" })
    } finally {
      setBusy(false)
    }
  }

  const running = busy || status?.busy === true
  const state = status?.busy ? "RUNNING" : (status?.state ?? "IDLE")
  return (
    <section className="testlab-panel" id="virtual-test-lab" aria-labelledby="testlab-title">
      <header className="testlab-header">
        <div>
          <p className="eyebrow">Self-test</p>
          <h2 id="testlab-title">Virtual Test Lab</h2>
          <p>
            Create disposable Linux network namespaces that behave like isolated test clients. Use them to prove routing
            and protocol mechanics before connecting a real phone or Smart TV.
          </p>
        </div>
        <span className={`testlab-state ${state.toLowerCase()}`}>{state}</span>
      </header>
      <div className="testlab-boundary">
        <strong>What the results mean</strong>
        <span>
          PASS means the named virtual runtime check actually succeeded. SKIP means ShakerProxy deliberately did not claim
          product proof. Physical Android, iOS, Wi-Fi, and Smart TV behavior still requires real-device testing.
        </span>
      </div>
      <div className="testlab-profiles">
        {PROFILES.map((item) => (
          <button
            key={item.profile}
            type="button"
            className="testlab-profile"
            disabled={running || status?.available === false}
            onClick={() => void run(item.profile)}
          >
            <strong>{item.title}</strong>
            <small>{item.detail}</small>
          </button>
        ))}
      </div>
      <form className="testlab-controls" onSubmit={cleanup}>
        <button type="button" className="quiet" onClick={() => void refresh()}>
          Refresh
        </button>
        <button type="submit" className="quiet danger" disabled={running}>
          Force cleanup
        </button>
      </form>
      <p className={`testlab-message ${message.tone}`} role="status">
        {message.text}
      </p>
      {status?.prerequisites && status.prerequisites.length > 0 && (
        <details className="testlab-prerequisites">
          <summary>Host requirements</summary>
          <div>
            {status.prerequisites.map((item) => (
              <div className="testlab-prereq-item" key={item.id}>
                <Badge status={item.status} />
                <span>{item.name}</span>
                <small>{item.summary}</small>
              </div>
            ))}
          </div>
        </details>
      )}
      <div className="testlab-results">
        <RunResults run={lastRun} />
      </div>
    </section>
  )
}
