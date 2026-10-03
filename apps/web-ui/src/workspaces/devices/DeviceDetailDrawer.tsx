import React, { FormEvent, useEffect, useRef, useState } from "react"
import { uniqueAddresses } from "../../lib/deviceAddresses"
import { deviceTitle, dhcpIdentityParts } from "../../lib/deviceTitle"
import { withPassword } from "../../shell/passwordPrompt"
import { idempotencyKey } from "../../lib/format"
import { ErrorBox, FeatureBoundary } from "../../shell/common"
import { api, describeError } from "../../api"
import { sortedDeviceExtensions } from "../../features"
import { DeviceAuditEntries } from "./DeviceHistory"
import type { Device, DeviceMutationResult, DevicePlatformHint, DeviceServiceHint } from "../../types"
import { PinnedAddressControls } from "./NamedDevices"
import { DeviceWiFiPanel } from "./DeviceWiFiPanel"

export function DeviceDetailDrawer({
  deviceID,
  onClose,
  onChanged,
  onViewTraffic,
  platformHint,
  serviceHint,
}: {
  deviceID: string
  onClose: () => void
  onChanged: () => Promise<void>
  onViewTraffic: () => void
  platformHint?: DevicePlatformHint
  serviceHint?: DeviceServiceHint
}) {
  const extensions = sortedDeviceExtensions()
  const [device, setDevice] = useState<Device | null>(null)
  const [friendlyName, setFriendlyName] = useState("")
  const [error, setError] = useState("")
  const [message, setMessage] = useState("")
  const [busy, setBusy] = useState(false)
  const closeButton = useRef<HTMLButtonElement>(null)
  const drawer = useRef<HTMLElement>(null)
  const onCloseRef = useRef(onClose)
  onCloseRef.current = onClose
  useEffect(() => {
    let mounted = true
    const load = () =>
      api<Device>(`/api/v1/devices/${deviceID}`)
        .then((result) => {
          if (mounted) {
            setDevice(result)
            setFriendlyName(result.friendly_name ?? "")
            setError("")
          }
        })
        .catch((reason) => {
          if (mounted) setError(describeError(reason, "This device could not be loaded"))
        })
    void load()
    return () => {
      mounted = false
    }
  }, [deviceID])
  useEffect(() => {
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null
    const keydown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onCloseRef.current()
        return
      }
      if (event.key !== "Tab" || !drawer.current) return
      const focusable = Array.from(
        drawer.current.querySelectorAll<HTMLElement>(
          'button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),a[href],[tabindex]:not([tabindex="-1"])',
        ),
      ).filter((element) => element.offsetParent !== null)
      if (focusable.length === 0) return
      const first = focusable[0]
      const last = focusable.at(-1)!
      if (event.shiftKey && (document.activeElement === first || !drawer.current.contains(document.activeElement))) {
        event.preventDefault()
        last.focus()
      } else if (
        !event.shiftKey &&
        (document.activeElement === last || !drawer.current.contains(document.activeElement))
      ) {
        event.preventDefault()
        first.focus()
      }
    }
    document.addEventListener("keydown", keydown)
    closeButton.current?.focus()
    return () => {
      document.removeEventListener("keydown", keydown)
      previous?.focus()
    }
  }, [])
  async function rename(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!device) return
    setBusy(true)
    setMessage("")
    setError("")
    const form = event.currentTarget
    const data = new FormData(form)
    try {
      const key = idempotencyKey("device-detail-alias")
      const result = await withPassword("rename this device", (password) =>
        api<DeviceMutationResult>(`/api/v1/devices/${device.id}/alias`, {
          method: "PUT",
          headers: { "Idempotency-Key": key },
          body: JSON.stringify({
            ...(password ? { password } : {}),
            friendly_name: friendlyName,
            reason: data.get("reason"),
            expected_revision: device.alias_revision ?? 0,
          }),
        }),
      )
      const updated = result.devices[0]
      if (updated) {
        setDevice(updated)
        setFriendlyName(updated.friendly_name ?? "")
      }
      setMessage("Name revision saved with an audit record.")
      form.reset()
      await onChanged()
    } catch (reason) {
      setError(describeError(reason, "The device could not be renamed"))
    } finally {
      setBusy(false)
    }
  }
  return (
    <div
      className="device-drawer-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose()
      }}
    >
      <aside
        ref={drawer}
        className="device-drawer"
        role="dialog"
        aria-modal="true"
        aria-labelledby="device-drawer-title"
      >
        <header>
          <div>
            <p className="eyebrow">Device</p>
            <h2 id="device-drawer-title">{device ? deviceTitle(device, "", platformHint, serviceHint) : deviceID}</h2>
            <code>{deviceID}</code>
          </div>
          <button ref={closeButton} type="button" className="quiet" onClick={onClose} aria-label="Close device detail">
            Close
          </button>
        </header>
        {error && <ErrorBox message={error} />} {!device && !error && <p>Loading…</p>}
        {device && (
          <div className="device-drawer-body">
            <section className="device-drawer-facts">
              <article>
                <span>Status</span>
                <strong>{device.online ? "ONLINE" : "OFFLINE"}</strong>
                <small>Last seen {new Date(device.last_seen).toLocaleString()}</small>
              </article>
              <article>
                <span>Attribution</span>
                <strong>{device.attribution_confidence}% confidence</strong>
                <small>First seen {new Date(device.first_seen).toLocaleString()}</small>
              </article>
              <article>
                <span>Metadata</span>
                <strong>{device.category || "Uncategorized"}</strong>
                <small>
                  {device.owner || "No owner"}
                  {device.location ? ` · ${device.location}` : ""}
                </small>
              </article>
              {device.observed_dhcp && (
                <article title="From the DHCP exchanges the lab recording saw, when the network's router, not ShakerProxy, gave the device its address.">
                  <span>DHCP</span>
                  <strong>{device.observed_dhcp.host_name || device.observed_dhcp.vendor_class || "Asked for an address"}</strong>
                  <small>
                    {dhcpIdentityParts(device).join(" · ")} · last {new Date(device.observed_dhcp.last_seen).toLocaleString()}
                  </small>
                </article>
              )}
              {serviceHint && serviceHint.services.length > 0 && (
                <article title="From the mDNS/Bonjour the device broadcasts on the network — what it offers and looks for.">
                  <span>Discovery</span>
                  <strong>{serviceHint.type || "Network services"}</strong>
                  <small>{serviceHint.services.map((service) => service.label || service.service).join(" · ")}</small>
                </article>
              )}
            </section>
            <div className="device-drawer-actions">
              <button type="button" onClick={onViewTraffic}>
                View traffic
              </button>
            </div>
            <PinnedAddressControls
              device={device}
              onChanged={(updated) => {
                if (updated) {
                  setDevice(updated)
                  setFriendlyName(updated.friendly_name ?? "")
                } else {
                  onClose()
                }
                void onChanged()
              }}
            />
            {device.attribution_warnings?.map((warning) => (
              <p className="device-warning" key={warning}>
                {warning}
              </p>
            ))}
            <DeviceWiFiPanel deviceID={device.id} formerIDs={device.former_ids} />
            {extensions.map((extension) => (
              <section
                key={extension.id}
                className="device-extension"
                aria-label={extension.title}
                data-feature={extension.id}
              >
                <FeatureBoundary title={extension.title}>
                  <extension.Component
                    deviceID={device.id}
                    deviceName={device.friendly_name || device.suggested_names?.[0]?.name}
                  />
                </FeatureBoundary>
              </section>
            ))}
            <details className="device-drawer-more">
              <summary>How ShakerProxy recognises this device</summary>
              <section className="device-drawer-evidence">
                <h3>Identity evidence</h3>
                {device.identities.map((identity) => (
                  <article key={`${identity.kind}-${identity.value}`}>
                    <strong>
                      {identity.kind} · {identity.value}
                    </strong>
                    <small>
                      {identity.source} · {identity.confidence}% · {new Date(identity.first_seen).toLocaleString()} →{" "}
                      {new Date(identity.last_seen).toLocaleString()}
                    </small>
                  </article>
                ))}
              </section>
              {device.observed_dhcp && (
                <section className="device-drawer-evidence">
                  <h3>DHCP request seen on the lab</h3>
                  <article>
                    <strong>
                      {device.observed_dhcp.host_name || "No name"} · {device.observed_dhcp.hardware_addr}
                    </strong>
                    <small>
                      {[
                        device.observed_dhcp.client_fqdn && `FQDN ${device.observed_dhcp.client_fqdn}`,
                        device.observed_dhcp.vendor_class && `vendor class ${device.observed_dhcp.vendor_class}`,
                        device.observed_dhcp.parameter_list && `options ${device.observed_dhcp.parameter_list}`,
                        device.observed_dhcp.server && `server ${device.observed_dhcp.server}`,
                        device.observed_dhcp.router && `gateway ${device.observed_dhcp.router}`,
                        `last ${new Date(device.observed_dhcp.last_seen).toLocaleString()}`,
                      ]
                        .filter(Boolean)
                        .join(" · ")}
                    </small>
                  </article>
                </section>
              )}
              <section className="device-drawer-evidence">
                <h3>Address history</h3>
                {uniqueAddresses(device.addresses).map((address) => (
                  <article key={`${address.address}-${address.interface ?? "unknown"}-${address.vlan_id ?? "none"}`}>
                    <strong>
                      {address.address} · {address.active ? "active" : "historical"}
                    </strong>
                    <small>
                      {address.interface ?? "scope unknown"}
                      {address.vlan_id ? ` · VLAN ${address.vlan_id}` : ""} · {new Date(address.first_seen).toLocaleString()}{" "}
                      → {new Date(address.last_seen).toLocaleString()}
                    </small>
                  </article>
                ))}
              </section>
              <section className="device-drawer-evidence">
                <h3>Hostname evidence</h3>
                {device.hostnames?.length ? (
                  device.hostnames.map((hostname) => (
                    <article key={`${hostname.hostname}-${hostname.source}`}>
                      <strong>{hostname.hostname}</strong>
                      <small>
                        {hostname.source} · {hostname.confidence}% · last seen{" "}
                        {new Date(hostname.last_seen).toLocaleString()}
                      </small>
                    </article>
                  ))
                ) : (
                  <p>No hostname evidence.</p>
                )}
              </section>
            </details>
            <DeviceAuditEntries deviceID={device.id} />
            <section className="device-drawer-evidence">
              <h3>Name revision history</h3>
              {device.alias_history?.length ? (
                device.alias_history
                  .slice()
                  .reverse()
                  .map((change) => (
                    <article key={change.revision}>
                      <strong>
                        r{change.revision} · {change.friendly_name || "Unnamed"}
                      </strong>
                      <small>
                        {change.reason} · {change.actor} · {new Date(change.changed_at).toLocaleString()}
                      </small>
                    </article>
                  ))
              ) : (
                <p>No administrator name revisions.</p>
              )}
            </section>
            <form className="device-drawer-rename" onSubmit={rename}>
              <h3>Rename from device detail</h3>
              <p>
                Suggestions are review-only. Saving creates a revisioned audit record and rejects stale detail state.
              </p>
              {device.suggested_names?.length ? (
                <div className="device-drawer-suggestions">
                  {device.suggested_names.map((suggestion) => (
                    <button
                      type="button"
                      className="quiet"
                      key={suggestion.name}
                      onClick={() => setFriendlyName(suggestion.name)}
                    >
                      {suggestion.name} · {suggestion.confidence}%
                    </button>
                  ))}
                </div>
              ) : null}
              <label>
                Friendly name
                <input
                  name="friendly_name"
                  value={friendlyName}
                  onChange={(event) => setFriendlyName(event.target.value)}
                  maxLength={128}
                  required
                />
              </label>
              <label>
                Reason
                <input name="reason" maxLength={256} required />
              </label>
              <button disabled={busy}>{busy ? "Saving revision…" : "Save name revision"}</button>
              {message && <p role="status">{message}</p>}
            </form>
          </div>
        )}
      </aside>
    </div>
  )
}
