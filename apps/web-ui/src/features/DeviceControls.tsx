// Device lab controls (§6): Decrypt HTTPS, Block internet and blocked domains.
import { useId, useState } from "react"
import { api, describeError } from "../api"
import { navigate } from "./registry"
import { registerDeviceExtension } from "./register"
import { formatRelative } from "./format"
import { MAX_BLOCKED_DOMAINS, controlsPath, controlsUpdate, mergeDomains, parseDomainList } from "./controls-model"
import { ErrorNotice, Loading, Toggle, useResource } from "./shared"
import type { DeviceControls, DeviceControlsUpdate } from "./types"
import "./features.css"

// workspaceForReason guesses which workspace fixes an error or unavailable
// reason ("Apply a routed network plan first" → Network).
export function workspaceForReason(reason: string): { workspace: "network" | "policy"; label: string } {
  return /network|route|routed|plan|interface/i.test(reason) ? { workspace: "network", label: "Open Network" } : { workspace: "policy", label: "Open DNS & HTTPS" }
}

export function DeviceControlsPanel({ deviceID, deviceName }: { deviceID: string; deviceName?: string }) {
  const controls = useResource<DeviceControls>(controlsPath(deviceID))
  const [saving, setSaving] = useState<"" | "decrypt" | "internet" | "domains">("")
  const [error, setError] = useState("")
  const [domainText, setDomainText] = useState("")
  const [domainMessage, setDomainMessage] = useState("")
  const inputID = useId()
  const hintID = useId()
  const data = controls.data
  const name = deviceName || "this device"

  const save = async (kind: "decrypt" | "internet" | "domains", change: Partial<DeviceControlsUpdate>): Promise<boolean> => {
    if (!data) return false
    setSaving(kind)
    setError("")
    try {
      const next = await api<DeviceControls>(controlsPath(deviceID), { method: "PUT", body: JSON.stringify(controlsUpdate(data, change)) })
      controls.setData(next)
      return true
    } catch (reason) {
      setError(describeError(reason, "Could not change the setting."))
      return false
    } finally {
      setSaving("")
    }
  }

  const addDomains = async () => {
    if (!data) return
    const parsed = parseDomainList(domainText)
    if (parsed.valid.length === 0) {
      setDomainMessage(parsed.invalid.length ? `Not a domain: ${parsed.invalid.join(", ")}. Enter names like ads.example.com.` : "Enter a domain such as ads.example.com.")
      return
    }
    const merged = mergeDomains(data.blocked_domains, parsed.valid)
    if (merged.added.length === 0) {
      setDomainMessage(merged.skipped.length ? `The list is full (${MAX_BLOCKED_DOMAINS} domains). Remove some first.` : "Already blocked.")
      return
    }
    if (await save("domains", { blocked_domains: merged.domains })) {
      const notes: string[] = [`Blocked ${merged.added.join(", ")}.`]
      if (parsed.invalid.length) notes.push(`Skipped (not domains): ${parsed.invalid.join(", ")}.`)
      if (merged.skipped.length) notes.push(`List is full; not added: ${merged.skipped.join(", ")}.`)
      setDomainMessage(notes.join(" "))
      setDomainText("")
    }
  }

  const removeDomain = async (domain: string) => {
    if (!data) return
    if (await save("domains", { blocked_domains: data.blocked_domains.filter((item) => item !== domain) })) setDomainMessage(`Unblocked ${domain}.`)
  }

  if (controls.loading && !data) return <Loading label="Loading lab controls…" />
  if (controls.errorCode === "traffic_policy_unavailable" && !data)
    return (
      <div className="lgf-state" role="note">
        <p>
          <strong>Lab controls for {name}</strong> (decrypt HTTPS, block internet, block domains) need an installed ShakerProxy
          appliance. {controls.error}
        </p>
      </div>
    )
  if (controls.error && !data) return <ErrorNotice message={controls.error} onRetry={controls.reload} />
  if (!data) return null
  const fix = workspaceForReason(error)

  return (
    <section className="lgf-controls" aria-label="Lab controls">
      <div className="lgf-section-head">
        <h3>Lab controls</h3>
        <small className="lgf-hint">{data.updated_at ? `Changed ${formatRelative(data.updated_at)}` : ""}</small>
      </div>

      {!data.effective && (
        <div className="lgf-callout lgf-tone-warn" role="status">
          <strong>Not fully in effect.</strong> Some of these settings are saved but ShakerProxy cannot enforce them right now.
          {data.notes.length > 0 && (
            <ul>
              {data.notes.map((note) => (
                <li key={note}>{note}</li>
              ))}
            </ul>
          )}
        </div>
      )}
      {data.effective && data.notes.length > 0 && (
        <ul className="lgf-callout lgf-tone-info lgf-notes">
          {data.notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      )}

      {error && (
        <div className="lgf-state lgf-error" role="alert">
          <p>{error}</p>
          <div className="lgf-actions">
            <button type="button" className="lgf-button lgf-secondary lgf-small" onClick={() => navigate(fix.workspace)}>
              {fix.label}
            </button>
          </div>
        </div>
      )}

      <Toggle
        label="Decrypt HTTPS"
        checked={data.decrypt_https}
        busy={saving === "decrypt"}
        disabled={saving !== ""}
        onChange={(next) => void save("decrypt", { decrypt_https: next })}
        description={`ShakerProxy decrypts ${name}'s HTTPS so you can read its requests. The device must trust ShakerProxy's certificate, otherwise its connections fail (which is how you test certificate validation). QUIC is blocked so apps fall back to regular HTTPS.`}
      />
      <Toggle
        label="Block internet"
        checked={data.internet === "BLOCK"}
        busy={saving === "internet"}
        disabled={saving !== ""}
        onChange={(next) => void save("internet", { internet: next ? "BLOCK" : "ALLOW" })}
        description={`Cuts ${name} off from the internet. It can still reach ShakerProxy (addresses, DNS), so you can watch how it behaves when its cloud is unreachable.`}
      />

      <div className="lgf-blocked">
        <div className="lgf-field">
          <label className="lgf-label" htmlFor={inputID}>
            Block domains
          </label>
          <div className="lgf-inline-form">
            <input
              id={inputID}
              className="lgf-input"
              type="text"
              value={domainText}
              placeholder="ads.example.com"
              autoComplete="off"
              spellCheck={false}
              aria-describedby={hintID}
              disabled={saving !== ""}
              onChange={(event) => {
                setDomainText(event.target.value)
                setDomainMessage("")
              }}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  event.preventDefault()
                  void addDomains()
                }
              }}
            />
            <button type="button" className="lgf-button" disabled={saving !== "" || !domainText.trim()} onClick={() => void addDomains()}>
              {saving === "domains" ? "Saving…" : "Block"}
            </button>
          </div>
          <p id={hintID} className="lgf-hint" aria-live="polite">
            {domainMessage || `The device gets "no such domain" for these names and all their subdomains. You can paste several at once. ${data.blocked_domains.length} of ${MAX_BLOCKED_DOMAINS} used.`}
          </p>
        </div>
        {data.blocked_domains.length === 0 ? (
          <p className="lgf-hint">No domains are blocked for this device.</p>
        ) : (
          <ul className="lgf-domain-chips" aria-label="Blocked domains">
            {data.blocked_domains.map((domain) => (
              <li key={domain}>
                <code>{domain}</code>
                <button type="button" aria-label={`Unblock ${domain}`} title={`Unblock ${domain}`} disabled={saving !== ""} onClick={() => void removeDomain(domain)}>
                  ×
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  )
}

registerDeviceExtension({ id: "device-controls", title: "Lab controls", order: 20, Component: DeviceControlsPanel })
