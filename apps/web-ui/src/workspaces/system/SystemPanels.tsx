import React, { useEffect, useState } from "react"
import { api, apiBlob, describeError, downloadBlob } from "../../api"
import type {
  AnalyzerLiveStatus,
  AnalyzerStatusReport,
  CapabilityBundle,
  ConnectivityReport,
  DiagnosticReport,
  ManagementPKIStatus,
  RecoveryObjectiveRegistry,
  ServicePortPlan,
} from "../../types"

export function ManagementPKIPanel({ status }: { status: ManagementPKIStatus | null }) {
  const [message, setMessage] = useState("")
  async function download() {
    setMessage("")
    try {
      const blob = await apiBlob("/api/v1/system/management-ca.pem", { headers: { Accept: "application/x-pem-file" } })
      downloadBlob(blob, "shakerproxy-management-ca.pem")
      setMessage("Management CA downloaded. Verify its fingerprint before enrollment; download does not mean trusted.")
    } catch (reason) {
      setMessage(describeError(reason, "Management CA download failed"))
    }
  }
  return (
    <section className="management-pki" aria-label="Management TLS authority">
      <header>
        <div>
          <p className="eyebrow">Admin connection certificate</p>
          <h2>Management-only local CA</h2>
        </div>
        <strong>{status?.authority ?? "Development HTTP"}</strong>
      </header>
      <p>
        This certificate authenticates the ShakerProxy management HTTPS endpoint. It is <b>not the interception CA</b> and
        must never be enrolled for traffic decryption.
      </p>
      {status ? (
        <>
          <code>{status.sha256_fingerprint}</code>
          <small>
            Root valid until {new Date(status.not_after).toLocaleDateString()} · server leaf valid until{" "}
            {new Date(status.leaf_not_after).toLocaleDateString()} · interception authority{" "}
            {status.interception_ca_state.replaceAll("-", " ")}
          </small>
          <button type="button" onClick={() => void download()}>
            Download public management CA
          </button>
        </>
      ) : (
        <small>No management CA is projected in loopback-only development HTTP; no local trust was created.</small>
      )}
      {message && <p className="management-pki-message">{message}</p>}
    </section>
  )
}

export function CapabilityPanel({ bundle }: { bundle: CapabilityBundle | null }) {
  return (
    <section className="capability-registry" aria-label="Evidence-backed capability registry">
      <header>
        <div>
          <p className="eyebrow">What this build supports</p>
          <h2>Features and certification</h2>
        </div>
        <span>{bundle ? `Revision ${bundle.revision}` : "Loading authoritative claims…"}</span>
      </header>
      <div className="capability-grid">
        {bundle?.features.map((feature) => (
          <article key={feature.id} className={`capability-${feature.status}`}>
            <div>
              <strong>{feature.name}</strong>
              <span>{feature.badge}</span>
            </div>
            <p>{feature.summary}</p>
            <small>
              {feature.evidence.length} evidence path{feature.evidence.length === 1 ? "" : "s"} ·{" "}
              {feature.enabled_by_default ? "enabled by default" : "not enabled by default"}
            </small>
            <details>
              <summary>Promotion gate</summary>
              <p>{feature.promotion_gate}</p>
            </details>
          </article>
        )) ?? <p>Waiting for the validated registry…</p>}
      </div>
      {bundle && (
        <details className="support-matrix">
          <summary>Platform certification matrix · {bundle.support_matrix.environments.length} environments</summary>
          {bundle.support_matrix.environments.map((environment) => (
            <article key={environment.id}>
              <strong>
                {environment.os} · {environment.architecture}
              </strong>
              <span>
                {environment.docker_firewall_backend} · {environment.topology}
              </span>
              <small>
                {environment.capabilities.map((entry) => `${entry.feature_id}: ${entry.level}`).join(" · ")}
              </small>
            </article>
          ))}
        </details>
      )}
    </section>
  )
}

export function RecoveryObjectivePanel({ registry }: { registry: RecoveryObjectiveRegistry | null }) {
  return (
    <section className="capability-registry" aria-label="Recovery objectives">
      <header>
        <div>
          <p className="eyebrow">Recovery</p>
          <h2>RTO and RPO contracts</h2>
          <p className="panel-help">
            How long each kind of recovery takes (RTO) and how much recent data it can lose (RPO).
          </p>
        </div>
        <span>{registry ? `Revision ${registry.revision}` : "Loading…"}</span>
      </header>
      <div className="capability-grid">
        {registry?.objectives.map((objective) => (
          <article
            key={objective.id}
            className={`capability-${objective.status === "verified" ? "supported" : objective.status === "target" ? "experimental" : "unavailable"}`}
          >
            <div>
              <strong>{objective.name}</strong>
              <span>{objective.status.toUpperCase()}</span>
            </div>
            <p>{objective.scope}</p>
            <small>
              {objective.rto_seconds === undefined ? "RTO not offered" : `RTO ${objective.rto_seconds}s`} ·{" "}
              {objective.rpo_seconds === undefined ? "RPO not offered" : `RPO ${objective.rpo_seconds}s`} ·{" "}
              {objective.environment}
            </small>
            <details>
              <summary>Data-loss contract and limits</summary>
              <p>{objective.data_loss_contract}</p>
              {objective.limitations.map((limitation) => (
                <small key={limitation}>{limitation}</small>
              ))}
            </details>
          </article>
        )) ?? <p>Waiting for the validated recovery registry…</p>}
      </div>
    </section>
  )
}

export function DiagnosticPanel({ report, error }: { report: DiagnosticReport | null; error: string }) {
  return (
    <section className={`diagnostics ${report?.overall.toLowerCase() ?? "unknown"}`}>
      <header>
        <div>
          <p className="eyebrow">Health check</p>
          <h2>{report ? report.overall : error ? "UNAVAILABLE" : "LOADING"}</h2>
        </div>
        <span>
          {report
            ? `Updated ${new Date(report.generated_at).toLocaleTimeString()} · 30s normal / 60s under pressure`
            : "Checking…"}
        </span>
      </header>
      {report?.resource_pressure && report.resource_pressure.level !== "NORMAL" && (
        <p className="event-health-error">
          Resource mode · {report.resource_pressure.level} · new captures{" "}
          {report.resource_pressure.new_capture_allowed ? "allowed" : "blocked"} · routing and management preserved
        </p>
      )}
      {error && <p className="event-health-error">Diagnostics unavailable · {error}</p>}
      <div>
        {report?.checks.map((check) => (
          <article key={check.name} className={check.status.toLowerCase()}>
            <span>{check.name.replaceAll("_", " ")}</span>
            <strong>{check.status}</strong>
            <p>{check.summary}</p>
            {check.observations.map((item) => (
              <small key={item}>{item}</small>
            ))}
          </article>
        )) ?? <p>Waiting for the privileged read-only diagnostic report…</p>}
      </div>
    </section>
  )
}

export function ServicePortPanel() {
  const [plan, setPlan] = useState<ServicePortPlan | null>(null)
  const [probe, setProbe] = useState<ConnectivityReport | null>(null)
  const [message, setMessage] = useState("")
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    api<ServicePortPlan>("/api/v1/system/ports")
      .then(setPlan)
      .catch((reason) => setMessage(reason instanceof Error ? reason.message : "Port ownership is unavailable"))
  }, [])
  async function runProbe() {
    setBusy(true)
    setMessage("")
    try {
      setProbe(await api<ConnectivityReport>("/api/v1/system/connectivity-probe", { method: "POST", body: "{}" }))
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Connectivity probe failed")
    } finally {
      setBusy(false)
    }
  }
  return (
    <section className="diagnostics" aria-label="Service and port ownership planner">
      <header>
        <div>
          <p className="eyebrow">Ports</p>
          <h2>Which programs use the DNS and proxy ports</h2>
        </div>
        <span>{plan?.systemd_resolved_stub ? "SYSTEMD-RESOLVED STUB PRESERVED" : "NO RESOLVED STUB DETECTED"}</span>
      </header>
      <p>
        {plan?.resolver_handling?.replaceAll("_", " ") ?? "Inspecting fixed local listeners…"}. These results do not
        enable DNS or rewrite the host.
      </p>
      {message && <p role="status">{message}</p>}
      <div>
        {plan?.reservations.map((item) => (
          <article
            key={`${item.transport}-${item.port}`}
            className={item.state === "POTENTIAL_CONFLICT" ? "warning" : "pass"}
          >
            <span>
              {item.transport.toUpperCase()}/{item.port} · {item.purpose}
            </span>
            <strong>{item.state.replaceAll("_", " ")}</strong>
            <p>{item.action.replaceAll("_", " ")}</p>
            {item.listeners.map((listener) => (
              <small key={`${listener.address}-${listener.process}`}>
                {listener.address}:{listener.port} · {listener.process || "owner unavailable"}
              </small>
            ))}
          </article>
        ))}
      </div>
      <button type="button" className="quiet" disabled={busy} onClick={() => void runProbe()}>
        {busy ? "Testing fixed IP paths…" : "Run explicit connectivity probe"}
      </button>
      {probe && (
        <p className={probe.restricted_port_53 ? "event-health-error" : ""}>
          HTTPS by fixed IP: {probe.dns_independent_https ? "reachable" : "unreachable"} · TCP/53:{" "}
          {probe.plain_dns_port_53 ? "reachable" : "blocked/unreachable"}
          {probe.restricted_port_53 ? " · restricted VPS behavior confirmed" : ""}
        </p>
      )}
    </section>
  )
}

function liveAnalysisLine(live: AnalyzerLiveStatus, recording = "lab"): string {
  const counts = `${live.events_delivered.toLocaleString()} events · ${live.segments_handed_off.toLocaleString()} segments left to segment analysis`
  switch (live.state) {
    case "FOLLOWING":
      return `Live analysis following the ${recording} recording${live.lag_millis > 0 ? ` · ${Math.round(live.lag_millis / 1000)}s behind` : ""} · ${counts}`
    case "RECOVERING":
      return `Live analysis of the ${recording} recording restarting · ${counts}${live.last_error ? ` · ${live.last_error}` : ""}`
    case "IDLE":
      return `Live analysis waiting for a ${recording} recording · ${counts}`
    default:
      return "Live analysis off · segments are analyzed as they close"
  }
}

export function AnalyzerHealthPanel({ report, error }: { report: AnalyzerStatusReport | null; error: string }) {
  return (
    <section className="analyzer-health">
      <header>
        <div>
          <p className="eyebrow">Traffic analyzers</p>
          <h2>Zeek and Suricata</h2>
        </div>
        <span>
          {report
            ? `Updated ${new Date(report.generated_at).toLocaleTimeString()} · refreshes every 30 seconds`
            : "Reading authenticated broker state…"}
        </span>
      </header>
      {error && <p className="event-health-error">Analyzer health unavailable · {error}</p>}
      <div className="analyzer-health-grid">
        {report?.analyzers.map((entry) => {
          const health = entry.health
          const state = entry.available && health ? health.state : "UNAVAILABLE"
          return (
            <article key={entry.engine} className={state.toLowerCase()}>
              <div>
                <span>{entry.engine}</span>
                <strong>{state}</strong>
              </div>
              {health ? (
                <>
                  <p>
                    Engine {health.source_version} · {health.completed_captures.toLocaleString()} completed captures ·{" "}
                    {health.delivered_events.toLocaleString()} delivered events
                  </p>
                  <small>
                    Heartbeat {Math.max(0, Math.round(health.heartbeat_age_millis / 1000))}s old
                    {health.last_success_at
                      ? ` · last success ${new Date(health.last_success_at).toLocaleString()}`
                      : ""}
                  </small>
                  {entry.engine === "SURICATA" && (
                    <small>
                      Rules {health.ruleset_version ?? "unknown"} ·{" "}
                      {health.ruleset_sha256?.slice(0, 12) ?? "identity unavailable"}
                    </small>
                  )}
                  {health.last_error && <small className="analyzer-error">Last error · {health.last_error}</small>}
                  {health.live && <small>{liveAnalysisLine(health.live)}</small>}
                  {health.live_vpn && <small>{liveAnalysisLine(health.live_vpn, "VPN")}</small>}
                </>
              ) : (
                <p>{entry.failure ?? "Analyzer status is not configured"}</p>
              )}
            </article>
          )
        }) ?? <p>Waiting for analyzer broker evidence…</p>}
      </div>
    </section>
  )
}
