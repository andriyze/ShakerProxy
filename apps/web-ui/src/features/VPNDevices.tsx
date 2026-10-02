import React, { FormEvent, useCallback, useId, useState } from "react"
import { api, describeError } from "../api"
import { PasswordCancelled, withPassword } from "../lib/passwordConfirm"
import {
  type VPNAdded,
  type VPNPeer,
  type VPNStatus,
  validVPNName,
  vpnByteText,
  vpnHeadline,
  vpnNeverConnectedHint,
  vpnPeerState,
  vpnSettingsChange,
} from "../lib/vpn"
import { QRCodeSVG } from "./QRCodeSVG"
import { registerView } from "./register"
import { usePolling } from "./shared"

// VPNDevices is VPN mode on the Network page: a phone or laptop on any
// network scans a QR code with the WireGuard app and from then on sends all
// of its traffic through ShakerProxy, where it shows under its name.
export function VPNDevices() {
  const [status, setStatus] = useState<VPNStatus | null>(null)
  const [unavailable, setUnavailable] = useState("")
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState("")
  const [added, setAdded] = useState<VPNAdded | null>(null)
  const [now, setNow] = useState(() => Date.now())

  const reload = useCallback(async () => {
    try {
      setStatus(await api<VPNStatus>("/api/v1/vpn"))
      setUnavailable("")
      setNow(Date.now())
    } catch (reason) {
      setUnavailable(describeError(reason, "VPN mode is unavailable"))
    }
  }, [])
  // Connected states change when a device turns its tunnel on.
  usePolling(() => void reload(), 10_000)
  const nameID = useId()

  async function change(action: string, path: string, init: RequestInit, body: Record<string, unknown>) {
    setBusy(true)
    setMessage("")
    try {
      return await withPassword(action, (password) =>
        api<unknown>(path, { ...init, body: JSON.stringify({ ...(password ? { password } : {}), ...body }) }),
      )
    } catch (reason) {
      if (!(reason instanceof PasswordCancelled)) setMessage(describeError(reason, `Could not ${action}`))
      return undefined
    } finally {
      setBusy(false)
    }
  }

  async function setEnabled(enabled: boolean) {
    const next = (await change(enabled ? "turn on VPN mode" : "turn off VPN mode", "/api/v1/vpn", { method: "PUT" }, { enabled })) as VPNStatus | undefined
    if (next) setStatus(next)
  }

  async function addDevice(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = event.currentTarget
    const name = String(new FormData(form).get("name") ?? "").trim()
    if (!validVPNName(name)) {
      setMessage("Give the device a name of 1-64 characters.")
      return
    }
    const result = (await change("add a VPN device", "/api/v1/vpn/devices", { method: "POST" }, { name })) as VPNAdded | undefined
    if (result) {
      setAdded(result)
      form.reset()
      void reload()
    }
  }

  async function revoke(peer: VPNPeer) {
    const result = await change(`revoke ${peer.name}`, `/api/v1/vpn/devices/${encodeURIComponent(peer.id)}`, { method: "DELETE" }, {})
    if (result) {
      setMessage(`Revoked ${peer.name}. It is disconnected; its traffic history stays under its name.`)
      void reload()
    }
  }

  if (unavailable && !status) {
    return (
      <section className="inventory vpn-devices" aria-labelledby="vpn-title">
        <p className="eyebrow">VPN mode</p>
        <h2 id="vpn-title">VPN devices</h2>
        <p className="error">{unavailable}</p>
      </section>
    )
  }
  return (
    <section className="inventory vpn-devices" aria-labelledby="vpn-title">
      <p className="eyebrow">VPN mode · WireGuard</p>
      <h2 id="vpn-title">VPN devices</h2>
      <p>
        Route a phone or laptop through ShakerProxy from any network: add it here and scan the QR code with the WireGuard app.
        All of its traffic, IPv4, IPv6 and local networks, then appears in Traffic under its name.
      </p>
      {!status ? (
        <p>Reading VPN mode…</p>
      ) : (
        <>
          <p className={`vpn-headline ${status.enabled && !status.up ? "warning" : ""}`} role="status">
            {vpnHeadline(status)}
          </p>
          {!status.enabled ? (
            <button type="button" disabled={busy} onClick={() => void setEnabled(true)}>
              {busy ? "Turning on…" : "Turn on VPN mode"}
            </button>
          ) : (
            <>
              {added && <AddedDevice added={added} onDone={() => setAdded(null)} />}
              {!added && (
                <form className="vpn-add" onSubmit={addDevice}>
                  <label htmlFor={nameID}>
                    Device name
                    <input id={nameID} name="name" required maxLength={64} placeholder="Pixel" autoComplete="off" />
                  </label>
                  <button type="submit" disabled={busy}>
                    {busy ? "Adding…" : "Add device"}
                  </button>
                </form>
              )}
              {status.peers.length > 0 && (
                <ul className="vpn-peers">
                  {status.peers.map((peer) => (
                    <PeerRow key={peer.id} peer={peer} now={now} busy={busy} onRevoke={() => void revoke(peer)} />
                  ))}
                </ul>
              )}
              {vpnNeverConnectedHint(status) && <p className="vpn-hint">{vpnNeverConnectedHint(status)}</p>}
              <VPNSettings status={status} busy={busy} onSave={async (update) => {
                const next = (await change("change the VPN settings", "/api/v1/vpn", { method: "PUT" }, update)) as VPNStatus | undefined
                if (next) setStatus(next)
              }} onTurnOff={() => void setEnabled(false)} />
            </>
          )}
          {status.enabled && status.notes.length > 0 && (
            <ul className="vpn-notes">
              {status.notes.map((note) => (
                <li key={note}>{note}</li>
              ))}
            </ul>
          )}
        </>
      )}
      {message && (
        <p className="vpn-message" role="status">
          {message}
        </p>
      )}
    </section>
  )
}

function PeerRow({ peer, now, busy, onRevoke }: { peer: VPNPeer; now: number; busy: boolean; onRevoke: () => void }) {
  const [confirming, setConfirming] = useState(false)
  const state = vpnPeerState(peer, now)
  const bytes = vpnByteText(peer)
  return (
    <li className={`vpn-peer ${state.tone}`}>
      <span className="vpn-dot" aria-hidden="true" />
      <span className="vpn-peer-name">
        <strong>{peer.name}</strong> <small>(VPN) · {peer.ipv4}</small>
      </span>
      <span className="vpn-peer-state">
        {state.label}
        {peer.remote_address && <small> from {peer.remote_address}</small>}
        {bytes && <small> · {bytes}</small>}
      </span>
      {confirming ? (
        <span className="vpn-confirm">
          <button type="button" className="danger" disabled={busy} onClick={onRevoke}>
            Revoke {peer.name}
          </button>
          <button type="button" className="quiet" onClick={() => setConfirming(false)}>
            Keep
          </button>
        </span>
      ) : (
        <button type="button" className="quiet" onClick={() => setConfirming(true)}>
          Revoke
        </button>
      )}
    </li>
  )
}

// AddedDevice shows the new device's configuration once: the QR code for the
// WireGuard app on a phone, or a file for a laptop.
function AddedDevice({ added, onDone }: { added: VPNAdded; onDone: () => void }) {
  function download() {
    const url = URL.createObjectURL(new Blob([added.config], { type: "text/plain" }))
    const link = document.createElement("a")
    link.href = url
    link.download = added.file_name
    link.click()
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
  }
  return (
    <div className="vpn-added" role="region" aria-label={`Set up ${added.device_name}`}>
      <QRCodeSVG text={added.config} size={280} label={`WireGuard configuration for ${added.device_name}`} />
      <div>
        <h3>Set up {added.device_name}</h3>
        <ol>
          <li>Install the WireGuard app (App Store or Google Play).</li>
          <li>
            Tap <strong>+</strong> and choose <strong>Scan from QR code</strong>, then scan this code.
          </li>
          <li>Turn the tunnel on. Everything the device does appears in Traffic as “{added.device_name}”.</li>
        </ol>
        <p className="vpn-once">
          This code holds the device's private key and is shown only now. ShakerProxy keeps only the public key; if it is lost,
          revoke the device and add it again.
        </p>
        {added.warnings.map((warning) => (
          <p key={warning} className="vpn-hint">
            {warning}
          </p>
        ))}
        <div className="vpn-added-actions">
          <button type="button" className="quiet" onClick={download}>
            Download {added.file_name}
          </button>
          <button type="button" onClick={onDone}>
            Done
          </button>
        </div>
      </div>
    </div>
  )
}

function VPNSettings({
  status,
  busy,
  onSave,
  onTurnOff,
}: {
  status: VPNStatus
  busy: boolean
  onSave: (update: { endpoint?: string; listen_port?: number; allow_peer_to_peer?: boolean }) => Promise<void>
  onTurnOff: () => void
}) {
  const [endpoint, setEndpoint] = useState(status.endpoint_setting ?? "")
  const [port, setPort] = useState(String(status.listen_port))
  const [peerToPeer, setPeerToPeer] = useState(status.allow_peer_to_peer)
  const [error, setError] = useState("")
  const id = useId()
  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const update = vpnSettingsChange(status, { endpoint, listen_port: port, allow_peer_to_peer: peerToPeer })
    if (typeof update === "string") {
      setError(update)
      return
    }
    setError("")
    if (Object.keys(update).length > 0) await onSave(update)
  }
  return (
    <details className="vpn-settings">
      <summary>VPN settings: address, port, device-to-device</summary>
      <form onSubmit={save}>
        <label htmlFor={`${id}-endpoint`}>
          Address in device configurations
          <input
            id={`${id}-endpoint`}
            value={endpoint}
            onChange={(event) => setEndpoint(event.target.value)}
            placeholder={status.default_endpoint_host ? `${status.default_endpoint_host} (this appliance)` : "home.example.net"}
            maxLength={260}
            autoComplete="off"
            spellCheck={false}
          />
          <small>
            To connect from outside this network, forward UDP {status.listen_port} on your router to this appliance and enter your
            public address or name (add :port if the router forwards another port). Devices added before a change need adding again.
          </small>
        </label>
        <label htmlFor={`${id}-port`}>
          UDP port
          <input id={`${id}-port`} value={port} onChange={(event) => setPort(event.target.value)} inputMode="numeric" maxLength={5} />
        </label>
        <label className="vpn-switch">
          <input type="checkbox" checked={peerToPeer} onChange={(event) => setPeerToPeer(event.target.checked)} />
          <span>Let VPN devices reach each other</span>
        </label>
        {error && <p className="error">{error}</p>}
        <div className="vpn-settings-actions">
          <button type="submit" disabled={busy}>
            Save settings
          </button>
          <button type="button" className="danger quiet" disabled={busy} onClick={onTurnOff}>
            Turn off VPN mode
          </button>
        </div>
        <p className="vpn-hint">
          Turning VPN mode off disconnects every VPN device; they reconnect when it is turned on again. VPN devices never reach
          ShakerProxy's management page.
        </p>
      </form>
    </details>
  )
}

registerView({ id: "vpn-devices", workspace: "network", title: "VPN devices", order: 10, Component: VPNDevices })
