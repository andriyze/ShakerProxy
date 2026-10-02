import React, { useEffect, useState } from "react"
import { api, describeError } from "../../api"
import { isUnavailableEndpoint } from "../../lib/errors"
import type { WiFiVisibility } from "../../types"

type Change = {
  enabled?: boolean
  adapter?: string
  channel_mode?: "auto" | "fixed" | "hop"
  channel?: number
  nearby?: boolean
  acknowledge_nearby?: boolean
}

function headline(view: WiFiVisibility): string {
  if (view.active) {
    const where =
      view.channel_mode === "hop"
        ? `hopping over channels ${(view.hop_channels ?? []).join(", ")}`
        : view.channel_mode === "access-point"
          ? `channel ${view.channel}, on the lab access point's radio`
          : `channel ${view.channel}`
    return `Listening with ${view.adapter} (${where}).`
  }
  if (view.settings.enabled) return "On, but not running."
  return "Off."
}

// WiFiVisibilityPanel turns ShakerProxy's passive Wi-Fi monitor on and off:
// which networks lab devices search for, when they join, roam and leave.
export function WiFiVisibilityPanel() {
  const [view, setView] = useState<WiFiVisibility | null>(null)
  const [unsupported, setUnsupported] = useState(false)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState("")
  const [confirmNearby, setConfirmNearby] = useState(false)
  const [channel, setChannel] = useState("6")
  useEffect(() => {
    let mounted = true
    api<WiFiVisibility>("/api/v1/wifi-visibility")
      .then((next) => {
        if (!mounted) return
        setView(next)
        if (next.settings.channel) setChannel(String(next.settings.channel))
      })
      .catch((reason) => {
        if (!mounted) return
        if (isUnavailableEndpoint(reason)) setUnsupported(true)
        else setMessage(describeError(reason, "Wi-Fi visibility is unavailable"))
      })
    return () => {
      mounted = false
    }
  }, [])
  async function change(update: Change) {
    setBusy(true)
    setMessage("")
    try {
      const next = await api<WiFiVisibility>("/api/v1/wifi-visibility", { method: "PUT", body: JSON.stringify(update) })
      setView(next)
      setConfirmNearby(false)
    } catch (reason) {
      setMessage(describeError(reason, "The Wi-Fi setting could not be changed"))
    } finally {
      setBusy(false)
    }
  }
  if (unsupported) return null
  const mode = view?.settings.channel_mode ?? "auto"
  return (
    <section className="panel wifi-visibility" aria-labelledby="wifi-visibility-title">
      <p className="eyebrow">Wi-Fi</p>
      <h2 id="wifi-visibility-title">See what devices do on the radio</h2>
      <p>
        With a Wi-Fi adapter that supports monitor mode, ShakerProxy listens (it never transmits) and records which networks lab
        devices search for, when they join, roam and disconnect, and why. Events appear in Traffic under Wi-Fi.
      </p>
      {view && (
        <>
          <p className={`wifi-visibility__state${view.active ? " on" : ""}`} role="status">
            {headline(view)}
            {!view.available && view.reason ? ` ${view.reason}` : ""}
            {view.last_error && !view.active ? ` Last attempt: ${view.last_error}` : ""}
          </p>
          <label className="dns-switch">
            <input
              type="checkbox"
              role="switch"
              checked={view.settings.enabled}
              disabled={busy || (!view.available && !view.settings.enabled)}
              onChange={(event) => void change({ enabled: event.target.checked })}
            />
            <span>
              <strong>Listen on Wi-Fi</strong>
              <small>
                {view.lab_ssid ? `Lab network “${view.lab_ssid}”. ` : ""}
                {view.lab_devices} lab device addresses are known; only their frames and the lab network's are recorded.
              </small>
            </span>
          </label>
          <div className="wifi-visibility__channel">
            <label>
              Channel
              <select
                value={mode}
                disabled={busy || view.shared_with_access_point}
                onChange={(event) => {
                  const next = event.target.value as Change["channel_mode"]
                  void change(next === "fixed" ? { channel_mode: "fixed", channel: Number(channel) || 6 } : { channel_mode: next })
                }}
              >
                <option value="auto">Automatic (the lab access point's, else hop)</option>
                <option value="fixed">One channel</option>
                <option value="hop">Hop across common channels</option>
              </select>
            </label>
            {mode === "fixed" && (
              <label>
                Number
                <input
                  type="number"
                  min={1}
                  max={177}
                  value={channel}
                  disabled={busy}
                  onChange={(event) => setChannel(event.target.value)}
                  onBlur={() => Number(channel) !== view.settings.channel && void change({ channel_mode: "fixed", channel: Number(channel) })}
                />
              </label>
            )}
          </div>
          {mode === "hop" && <p className="wifi-visibility__note">Hopping misses frames sent while the radio listens elsewhere; one channel follows a device closely.</p>}
          <label className="dns-switch">
            <input
              type="checkbox"
              role="switch"
              checked={view.settings.nearby}
              disabled={busy}
              onChange={(event) => (event.target.checked ? setConfirmNearby(true) : void change({ nearby: false }))}
            />
            <span>
              <strong>Also record nearby devices and networks</strong>
              <small>Off by default. Nearby data is deleted after {view.nearby_retention_hours} hours.</small>
            </span>
          </label>
          {confirmNearby && (
            <div className="dns-warning" role="alertdialog" aria-labelledby="wifi-nearby-warning">
              <p id="wifi-nearby-warning">
                Phones and laptops nearby announce the networks they have saved. Recording them records people who are not part of
                your test. Only do this where you are allowed to.
              </p>
              <button type="button" disabled={busy} onClick={() => void change({ nearby: true, acknowledge_nearby: true })}>
                I understand, record nearby devices
              </button>{" "}
              <button type="button" className="quiet" onClick={() => setConfirmNearby(false)}>
                Cancel
              </button>
            </div>
          )}
          <details className="dns-resolvers">
            <summary>Wi-Fi adapters ({view.adapters.length})</summary>
            {view.adapters.length === 0 ? (
              <p>No Wi-Fi adapter is connected. A USB adapter with monitor mode (MediaTek MT7612U or MT7921AU, Atheros AR9271) works best.</p>
            ) : (
              <ul>
                {view.adapters.map((adapter) => (
                  <li key={adapter.interface}>
                    <strong>{adapter.interface}</strong>{" "}
                    {[
                      adapter.monitor_supported ? "monitor mode" : "no monitor mode",
                      adapter.access_point ? "serves the lab Wi-Fi" : "",
                      adapter.in_use ? "carries this host's connection" : "",
                      adapter.bands.join("/"),
                    ]
                      .filter(Boolean)
                      .join(" · ")}
                  </li>
                ))}
              </ul>
            )}
            <ul>
              {view.notes.map((note) => (
                <li key={note}>{note}</li>
              ))}
            </ul>
          </details>
        </>
      )}
      {message && <p className="error">{message}</p>}
    </section>
  )
}
