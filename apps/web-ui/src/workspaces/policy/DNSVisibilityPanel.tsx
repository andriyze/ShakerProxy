import React, { useEffect, useState } from "react"
import { api, describeError } from "../../api"

// DNSVisibility mirrors GET /api/v1/dns-visibility.
export type DNSVisibility = {
  schema: number
  policy_revision: number
  force_plain_dns: boolean
  block_encrypted_dns: boolean
  mode: string
  upstream_servers: string[]
  blocked_resolvers: { id: string; provider: string; hostnames: string[]; ipv4: string[]; ipv6: string[] }[]
  blocked_addresses: number
  blocked_names: string[]
  canaries: string[]
  notes: string[]
}

// DNSVisibilityPanel holds the two switches that decide whether every lookup
// on the lab is visible: plain DNS forced through ShakerProxy, and encrypted
// DNS blocked so devices fall back to it.
export function DNSVisibilityPanel({ available, onChanged }: { available: boolean; onChanged: () => void }) {
  const [view, setView] = useState<DNSVisibility | null>(null)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState("")
  useEffect(() => {
    if (!available) return
    let mounted = true
    api<DNSVisibility>("/api/v1/dns-visibility")
      .then((next) => mounted && setView(next))
      .catch((reason) => mounted && setMessage(describeError(reason, "DNS visibility is unavailable")))
    return () => {
      mounted = false
    }
  }, [available])
  async function change(update: { force_plain_dns?: boolean; block_encrypted_dns?: boolean }) {
    setBusy(true)
    setMessage("")
    try {
      const next = await api<DNSVisibility>("/api/v1/dns-visibility", { method: "PUT", body: JSON.stringify(update) })
      setView(next)
      onChanged()
    } catch (reason) {
      setMessage(describeError(reason, "The DNS setting could not be changed"))
    } finally {
      setBusy(false)
    }
  }
  if (!available) return null
  return (
    <section className="panel dns-visibility" aria-labelledby="dns-visibility-title">
      <p className="eyebrow">DNS</p>
      <h2 id="dns-visibility-title">See every lookup</h2>
      <p>
        Both switches apply to every device on the lab network. Plain DNS is forced through ShakerProxy by default;
        encrypted DNS (DoH, DoT, DoQ) is identified and labelled in Traffic but not blocked unless you turn blocking on.
      </p>
      <label className="dns-switch">
        <input
          type="checkbox"
          role="switch"
          checked={view?.force_plain_dns ?? false}
          disabled={!view || busy}
          onChange={(event) => void change({ force_plain_dns: event.target.checked })}
        />
        <span>
          <strong>Force plain DNS through ShakerProxy</strong>
          <small>Every device's DNS, to any server (8.8.8.8 included), is answered by ShakerProxy, so each lookup is recorded.</small>
        </span>
      </label>
      <label className="dns-switch">
        <input
          type="checkbox"
          role="switch"
          checked={view?.block_encrypted_dns ?? false}
          disabled={!view || busy}
          onChange={(event) => void change({ block_encrypted_dns: event.target.checked })}
        />
        <span>
          <strong>Block encrypted DNS (DoH, DoT, DoQ)</strong>
          <small>
            Devices that try DNS over HTTPS, TLS or QUIC are refused and fall back to plain DNS. Each blocked attempt shows in
            Traffic.
          </small>
        </span>
      </label>
      {view?.block_encrypted_dns && (
        <p className="dns-warning" role="note">
          Android Private DNS set to a specific provider (strict) will lose internet while this is on: set Private DNS to
          Automatic or Off.
        </p>
      )}
      {view && (
        <details className="dns-resolvers">
          <summary>
            Blocked resolvers: {view.blocked_resolvers.length} providers, {view.blocked_addresses} addresses,{" "}
            {view.blocked_names.length} names
          </summary>
          <ul>
            {view.blocked_resolvers.map((resolver) => (
              <li key={resolver.id}>
                <strong>{resolver.provider}</strong> {[...resolver.ipv4, ...resolver.ipv6].join(", ")}
                <small> {resolver.hostnames.join(", ")}</small>
              </li>
            ))}
          </ul>
          <p>
            Also refused by name: {view.canaries.join(", ")} (these tell Firefox and Apple devices to use the network's DNS).
          </p>
        </details>
      )}
      {message && <p className="error">{message}</p>}
    </section>
  )
}
