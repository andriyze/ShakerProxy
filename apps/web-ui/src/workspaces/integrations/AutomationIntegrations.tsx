import React, { FormEvent, useState } from "react"
import { withPassword } from "../../shell/passwordPrompt"
import { api } from "../../api"
import { usePolling } from "../../shell/hooks"
import type { APITokenRecord, ForwarderStatus } from "../../types"

export function AutomationIntegrations() {
  const [tokens, setTokens] = useState<APITokenRecord[]>([])
  const [forwarders, setForwarders] = useState<ForwarderStatus[]>([])
  const [allowedScopes, setAllowedScopes] = useState<string[]>([])
  const [allowedClasses, setAllowedClasses] = useState<string[]>([])
  const [transport, setTransport] = useState<"JSONL" | "WEBHOOK" | "SYSLOG_TLS">("JSONL")
  const [tokenSecret, setTokenSecret] = useState("")
  const [forwarderSecret, setForwarderSecret] = useState("")
  const [message, setMessage] = useState("")
  const [busy, setBusy] = useState(false)
  async function refresh() {
    try {
      const [tokenPage, forwarderPage] = await Promise.all([
        api<{ tokens: APITokenRecord[]; allowed_scopes: string[] }>("/api/v1/auth/tokens"),
        api<{ forwarders: ForwarderStatus[]; allowed_classes: string[] }>("/api/v1/integrations/forwarders"),
      ])
      setTokens(Array.isArray(tokenPage.tokens) ? tokenPage.tokens : [])
      setAllowedScopes(Array.isArray(tokenPage.allowed_scopes) ? tokenPage.allowed_scopes : [])
      setForwarders(Array.isArray(forwarderPage.forwarders) ? forwarderPage.forwarders : [])
      setAllowedClasses(Array.isArray(forwarderPage.allowed_classes) ? forwarderPage.allowed_classes : [])
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Automation settings are unavailable")
    }
  }
  usePolling(() => refresh(), 15000)
  async function createToken(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setMessage("")
    setTokenSecret("")
    const form = event.currentTarget
    const data = new FormData(form)
    try {
      const created = await api<{ token: APITokenRecord; secret: string }>("/api/v1/auth/tokens", {
        method: "POST",
        body: JSON.stringify({
          name: data.get("name"),
          scopes: data.getAll("scope").map(String),
          expires_in_seconds: Number(data.get("expires_hours")) * 3600,
          sensitive_scope_acknowledged: data.get("sensitive_ack") === "on",
          password: data.get("password"),
        }),
      })
      setTokens((current) => [created.token, ...current])
      setTokenSecret(created.secret)
      form.reset()
      setMessage("API token created. Its cleartext is shown once and is not stored by ShakerProxy.")
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "API token creation failed")
    } finally {
      setBusy(false)
    }
  }
  async function revokeToken(event: FormEvent<HTMLFormElement>, id: string) {
    event.preventDefault()
    setBusy(true)
    setMessage("")
    const form = event.currentTarget
    const data = new FormData(form)
    try {
      const result = await withPassword("revoke this token", (password) =>
        api<{ token: APITokenRecord }>(`/api/v1/auth/tokens/${id}`, {
          method: "DELETE",
          body: JSON.stringify({ reason: data.get("reason"), ...(password ? { password } : {}) }),
        }),
      )
      setTokens((current) => current.map((item) => (item.id === id ? result.token : item)))
      form.reset()
      setMessage("Token revoked immediately.")
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Token revocation failed")
    } finally {
      setBusy(false)
    }
  }
  async function createForwarder(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setMessage("")
    setForwarderSecret("")
    const form = event.currentTarget
    const data = new FormData(form)
    try {
      const created = await withPassword("create this forwarder", (password) =>
        api<{ integration: ForwarderStatus["integration"]; hmac_secret?: string }>("/api/v1/integrations/forwarders", {
          method: "POST",
          body: JSON.stringify({
            name: data.get("name"),
            kind: transport,
            destination: transport === "JSONL" ? "" : data.get("destination"),
            classes: data.getAll("class").map(String),
            ...(password ? { password } : {}),
          }),
        }),
      )
      setForwarders((current) => [
        { integration: created.integration, queued: 0, dropped: 0, delivered: 0 },
        ...current,
      ])
      setForwarderSecret(created.hmac_secret ?? "")
      form.reset()
      setTransport("JSONL")
      setMessage("Forwarder created disabled. Review the destination, then enable it explicitly.")
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Forwarder creation failed")
    } finally {
      setBusy(false)
    }
  }
  async function toggleForwarder(event: FormEvent<HTMLFormElement>, item: ForwarderStatus) {
    event.preventDefault()
    setBusy(true)
    setMessage("")
    const form = event.currentTarget
    const data = new FormData(form)
    try {
      const integration = await withPassword(
        item.integration.enabled ? "turn this forwarder off" : "turn this forwarder on",
        (password) =>
          api<ForwarderStatus["integration"]>(`/api/v1/integrations/forwarders/${item.integration.id}/enabled`, {
            method: "PUT",
            body: JSON.stringify({
              expected_revision: item.integration.revision,
              enabled: !item.integration.enabled,
              reason: data.get("reason"),
              ...(password ? { password } : {}),
            }),
          }),
      )
      setForwarders((current) =>
        current.map((entry) => (entry.integration.id === integration.id ? { ...entry, integration } : entry)),
      )
      form.reset()
      setMessage(`Forwarder ${integration.enabled ? "enabled" : "disabled"}.`)
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Forwarder activation failed")
    } finally {
      setBusy(false)
    }
  }
  return (
    <section className="automation-integrations" aria-label="Scoped API tokens and safe event forwarding">
      <header>
        <div>
          <p className="eyebrow">API tokens and forwarding</p>
          <h2>Scripts and log collectors</h2>
        </div>
        <span>
          {tokens.filter((item) => item.state === "active").length} ACTIVE TOKENS ·{" "}
          {forwarders.filter((item) => item.integration.enabled).length} ENABLED FORWARDERS
        </span>
      </header>
      <p className="integration-intro">
        Tokens expire, carry exact scopes, and are rate-limited and audited per successful use. Forwarders emit only the
        fixed metadata schema—never event bodies, packet bytes, TLS key logs, CA material, or administrator credentials.
      </p>
      {message && (
        <p className="integration-message" role="status">
          {message}
        </p>
      )}
      {(tokenSecret || forwarderSecret) && (
        <div className="display-once" role="alert">
          <strong>Display-once secret</strong>
          <code>{tokenSecret || forwarderSecret}</code>
          <span>Copy this now. It disappears on reload and cannot be recovered.</span>
          <button
            type="button"
            className="quiet"
            onClick={() => {
              setTokenSecret("")
              setForwarderSecret("")
            }}
          >
            I have stored it
          </button>
        </div>
      )}
      <div className="integration-columns">
        <div>
          <h3>API tokens</h3>
          <form className="integration-create" onSubmit={createToken}>
            <label>
              Name
              <input name="name" maxLength={64} required />
            </label>
            <label>
              Expires after (hours)
              <input name="expires_hours" type="number" min="1" max="2160" defaultValue="24" required />
            </label>
            <fieldset>
              <legend>Exact scopes</legend>
              {allowedScopes.map((scope) => (
                <label className="check" key={scope}>
                  <input name="scope" value={scope} type="checkbox" />
                  <span>{scope}</span>
                </label>
              ))}
            </fieldset>
            <label className="check">
              <input name="sensitive_ack" type="checkbox" />
              <span>
                I explicitly authorize the sensitive scopes selected above: capture/case writes, and traffic:content (HTTP
                headers and bodies, credentials redacted).
              </span>
            </label>
            <label>
              Administrator password
              <input name="password" type="password" autoComplete="current-password" required />
            </label>
            <button disabled={busy}>Create display-once token</button>
          </form>
          <div className="integration-list">
            {tokens.map((token) => (
              <article key={token.id}>
                <header>
                  <strong>{token.name}</strong>
                  <span className={`integration-${token.state}`}>{token.state}</span>
                </header>
                <code>{token.id}</code>
                <small>
                  {token.scopes.join(" · ")} · expires {new Date(token.expires_at).toLocaleString()} · {token.use_count}{" "}
                  uses
                </small>
                {token.state === "active" && (
                  <form onSubmit={(event) => revokeToken(event, token.id)}>
                    <label>
                      Reason
                      <input name="reason" minLength={3} maxLength={256} required />
                    </label>
                    <button className="quiet" disabled={busy}>
                      Revoke
                    </button>
                  </form>
                )}
              </article>
            ))}
          </div>
        </div>
        <div>
          <h3>Event forwarders</h3>
          <form className="integration-create" onSubmit={createForwarder}>
            <label>
              Name
              <input name="name" maxLength={64} required />
            </label>
            <label>
              Transport
              <select value={transport} onChange={(event) => setTransport(event.target.value as typeof transport)}>
                <option value="JSONL">Bounded local JSONL</option>
                <option value="WEBHOOK">HTTPS webhook + HMAC</option>
                <option value="SYSLOG_TLS">Syslog over TLS</option>
              </select>
            </label>
            {transport !== "JSONL" && (
              <label>
                Destination
                <input
                  name="destination"
                  type="url"
                  required
                  placeholder={
                    transport === "WEBHOOK" ? "https://hooks.example.com/events" : "tls://syslog.example.com:6514"
                  }
                />
              </label>
            )}
            <fieldset>
              <legend>Event classes</legend>
              {allowedClasses.map((eventClass) => (
                <label className="check" key={eventClass}>
                  <input name="class" value={eventClass} type="checkbox" />
                  <span>{eventClass.replaceAll("_", " ")}</span>
                </label>
              ))}
            </fieldset>
            <button disabled={busy}>Create disabled forwarder</button>
          </form>
          <div className="integration-list">
            {forwarders.map((item) => (
              <article key={item.integration.id}>
                <header>
                  <strong>{item.integration.name}</strong>
                  <span className={item.integration.enabled ? "integration-active" : "integration-disabled"}>
                    {item.integration.enabled ? "enabled" : "disabled"}
                  </span>
                </header>
                <code>{item.integration.destination}</code>
                <small>
                  {item.integration.kind} · queued {item.queued} · delivered {item.delivered} · dropped {item.dropped}
                </small>
                {item.last_error && (
                  <small className="integration-error">Last delivery error · {item.last_error}</small>
                )}
                <form onSubmit={(event) => toggleForwarder(event, item)}>
                  <label>
                    Reason
                    <input name="reason" minLength={3} maxLength={256} required />
                  </label>
                  <button className="quiet" disabled={busy}>
                    {item.integration.enabled ? "Disable" : "Enable"}
                  </button>
                </form>
              </article>
            ))}
          </div>
        </div>
      </div>
    </section>
  )
}
