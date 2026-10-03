import React, { FormEvent, useState } from "react"
import { withPassword } from "../../shell/passwordPrompt"
import { api } from "../../api"
import { usePolling } from "../../shell/hooks"

// The network-gear (UniFi) log collector turns the lab router's own syslog
// into events and device identity. In single-arm and inline-bridge labs the
// router serves DHCP and Wi-Fi, so this is how ShakerProxy sees devices that
// never route through it.

type SyslogStatus = {
  received: number
  parsed: number
  unparsed: number
  delivered: number
  dropped_rate_limited: number
  rejected_not_allowed: number
}

type SyslogCollectorView = {
  available: boolean
  enabled: boolean
  bind_address: string
  tcp: boolean
  udp: boolean
  allowed_sources: string[]
  revision: number
  updated_by?: string
  setup: string
  status?: SyslogStatus
}

export function SyslogCollector() {
  const [view, setView] = useState<SyslogCollectorView | null>(null)
  const [unavailable, setUnavailable] = useState(false)
  const [message, setMessage] = useState("")
  const [busy, setBusy] = useState(false)

  async function refresh() {
    try {
      const next = await api<SyslogCollectorView>("/api/v1/integrations/syslog-collector")
      setView(next)
      setUnavailable(false)
    } catch {
      setUnavailable(true)
    }
  }
  usePolling(refresh, 10_000, [])

  if (unavailable) return null
  if (!view) return null

  async function submit(enable: boolean, event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!view) return
    const data = new FormData(event.currentTarget)
    const sources = String(data.get("sources") ?? "")
      .split(/[\s,]+/)
      .map((value) => value.trim())
      .filter(Boolean)
    const bind = String(data.get("bind") ?? "").trim() || view.bind_address
    setBusy(true)
    setMessage("")
    try {
      const next = await withPassword(enable ? "turn the log collector on" : "turn the log collector off", (password) =>
        api<SyslogCollectorView>("/api/v1/integrations/syslog-collector", {
          method: "PUT",
          body: JSON.stringify({
            enabled: enable,
            bind_address: bind,
            tcp: true,
            udp: data.get("udp") === "on",
            allowed_sources: enable ? sources : view.allowed_sources,
            expected_revision: view.revision,
            ...(password ? { password } : {}),
          }),
        }),
      )
      setView(next)
      setMessage(enable ? "Collector enabled." : "Collector turned off.")
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The change could not be saved.")
    } finally {
      setBusy(false)
    }
  }

  const status = view.status
  return (
    <section className="integration-card" aria-label="Network-gear log collector">
      <header>
        <h2>Router logs (UniFi)</h2>
        <span className={view.enabled ? "integration-on" : "integration-off"}>{view.enabled ? "On" : "Off"}</span>
      </header>
      <p>
        Receive the lab router's own logs and turn its DHCP leases, Wi-Fi associations, firewall and IDS lines into
        events and device names — so you see devices that use the router as their gateway and never reach ShakerProxy.
      </p>

      {view.enabled ? (
        <>
          <dl className="integration-facts">
            <div>
              <dt>Listening</dt>
              <dd>
                {view.bind_address} ({view.udp ? "TCP and UDP" : "TCP"})
              </dd>
            </div>
            <div>
              <dt>Accepting logs from</dt>
              <dd>{view.allowed_sources.length ? view.allowed_sources.join(", ") : "no sources"}</dd>
            </div>
            {status && (
              <div>
                <dt>Messages</dt>
                <dd>
                  {status.received.toLocaleString()} received · {status.parsed.toLocaleString()} became events ·{" "}
                  {status.delivered.toLocaleString()} delivered · {status.unparsed.toLocaleString()} unparsed ·{" "}
                  {status.dropped_rate_limited.toLocaleString()} rate-limited · {status.rejected_not_allowed.toLocaleString()} from a stranger
                </dd>
              </div>
            )}
          </dl>
          <form onSubmit={(event) => submit(false, event)}>
            <button type="submit" className="danger" disabled={busy}>
              Turn off
            </button>
          </form>
        </>
      ) : (
        <form onSubmit={(event) => submit(true, event)} className="integration-form">
          <label>
            Allowed sources (the router's IP)
            <input name="sources" placeholder="192.168.10.1" required />
          </label>
          <label>
            Listen address
            <input name="bind" placeholder={view.bind_address || ":1514"} />
          </label>
          <label className="check">
            <input name="udp" type="checkbox" /> Also accept UDP (spoofable; prefer TCP)
          </label>
          <button type="submit" disabled={busy}>
            Turn on
          </button>
        </form>
      )}

      <details className="integration-help">
        <summary>How to point UniFi at ShakerProxy</summary>
        <ol>
          <li>UniFi Network → Settings → System → enable Remote Logging.</li>
          <li>
            Set the host to ShakerProxy's lab address and the port to <code>{view.bind_address.replace(/^.*:/, "") || "1514"}</code>; use TCP if offered.
          </li>
          <li>Enable "include all device logs" so DHCP, Wi-Fi and firewall lines are sent.</li>
          <li>Restrict the allowed sources above to the router's IP.</li>
        </ol>
        <p className="integration-note">{view.setup}</p>
      </details>

      {message && <p className="integration-message">{message}</p>}
    </section>
  )
}
