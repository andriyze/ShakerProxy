import React, { FormEvent, useRef, useState } from "react"
import { uniqueAddresses } from "../../lib/deviceAddresses"
import { deviceMAC, deviceTitle, dhcpIdentityParts, locallyAdministered, platformEvidence } from "../../lib/deviceTitle"
import { withPassword } from "../../shell/passwordPrompt"
import { timeAgo, idempotencyKey } from "../../lib/format"
import { DeviceTrafficDeletionPreviewControl } from "./DeviceTrafficDeletion"
import { api, describeError } from "../../api"
import type { Device, DevicePlatformHint, LabRoutingDevice } from "../../types"

export function DeviceRow({
  device,
  devices,
  onChanged,
  onInspect,
  onViewTraffic,
  platformHint,
  routing,
}: {
  device: Device
  devices: Device[]
  onChanged: () => Promise<void>
  onInspect: () => void
  onViewTraffic: () => void
  platformHint?: DevicePlatformHint
  routing?: LabRoutingDevice
}) {
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState("")
  const controls = useRef<HTMLDetailsElement>(null)
  const nameInput = useRef<HTMLInputElement>(null)
  const mac = deviceMAC(device)
  function openRename() {
    if (controls.current) controls.current.open = true
    nameInput.current?.focus()
    nameInput.current?.select()
  }
  const addresses = uniqueAddresses(device.addresses)
  const activeAddresses = addresses.filter((address) => address.active)
  const vendorLabel =
    device.vendor?.name ||
    (
      {
        LOCALLY_ADMINISTERED: "Locally administered MAC",
        AMBIGUOUS: "Ambiguous IEEE assignment",
        NO_MATCH: "No IEEE assignment",
      } as Record<string, string>
    )[device.vendor_state ?? ""] ||
    "Vendor not evaluated"
  async function mutate(path: string, method: string, body: Record<string, unknown>, prefix: string) {
    setBusy(true)
    setMessage("")
    try {
      const key = idempotencyKey(prefix)
      await withPassword("save this change", (password) =>
        api(path, {
          method,
          headers: { "Idempotency-Key": key },
          body: JSON.stringify({ ...body, ...(password ? { password } : {}) }),
        }),
      )
      setMessage("Correction saved with an audit record.")
      await onChanged()
    } catch (reason) {
      setMessage(describeError(reason, "The change could not be saved"))
    } finally {
      setBusy(false)
    }
  }
  async function saveMetadata(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    await mutate(
      `/api/v1/devices/${device.id}/metadata`,
      "PUT",
      {
        friendly_name: device.friendly_name ?? "",
        owner: data.get("owner"),
        location: data.get("location"),
        category: data.get("category"),
        icon: data.get("icon"),
        tags: String(data.get("tags") ?? "")
          .split(",")
          .map((item) => item.trim())
          .filter(Boolean),
        notes: data.get("notes"),
      },
      "device-metadata",
    )
  }
  async function saveAlias(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    await mutate(
      `/api/v1/devices/${device.id}/alias`,
      "PUT",
      {
        friendly_name: data.get("friendly_name"),
        reason: data.get("reason"),
        expected_revision: device.alias_revision ?? 0,
      },
      "device-alias",
    )
  }
  async function merge(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    await mutate(
      `/api/v1/devices/${device.id}/merge`,
      "POST",
      { source_device_id: data.get("source_device_id") },
      "device-merge",
    )
  }
  async function split(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const identityIndexes = data.getAll("identity").map(Number)
    if (identityIndexes.length === 0 || identityIndexes.length >= device.identities.length) {
      setMessage("Select at least one identity to move and leave at least one on the original device.")
      return
    }
    const addressIndexes = data.getAll("address").map(Number)
    const hostnameIndexes = data.getAll("hostname").map(Number)
    const selection = {
      identities: identityIndexes.map((index) => ({
        kind: device.identities[index].kind,
        value: device.identities[index].value,
        source: device.identities[index].source,
      })),
      addresses: addressIndexes.map((index) => ({
        address: device.addresses[index].address,
        source: device.addresses[index].source,
        valid_from: device.addresses[index].valid_from,
        valid_until: device.addresses[index].valid_until,
        interface: device.addresses[index].interface,
        vlan_id: device.addresses[index].vlan_id,
        scope_plan_sha256: device.addresses[index].scope_plan_sha256,
      })),
      hostnames: hostnameIndexes.map((index) => ({
        hostname: (device.hostnames ?? [])[index].hostname,
        source: (device.hostnames ?? [])[index].source,
      })),
      metadata: {
        friendly_name: data.get("friendly_name"),
        owner: data.get("owner"),
        location: data.get("location"),
        category: data.get("category"),
        icon: data.get("icon"),
        tags: String(data.get("tags") ?? "")
          .split(",")
          .map((item) => item.trim())
          .filter(Boolean),
        notes: data.get("notes"),
      },
    }
    await mutate(`/api/v1/devices/${device.id}/split`, "POST", { selection }, "device-split")
  }
  const otherDevices = devices.filter((candidate) => candidate.id !== device.id)
  return (
    <article className="device-row">
      <div className="device-primary">
        <span className={device.online ? "online-dot" : "offline-dot"} />
        <div>
          <strong>
            {deviceTitle(device, "", platformHint)}
            {routing?.routing === "BYPASSING" && (
              <span className="device-routing-badge" title={routing.reason ?? "Its traffic does not go through ShakerProxy."}>
                Not through ShakerProxy
              </span>
            )}
          </strong>
          {mac && (
            <small className="device-mac">
              MAC <code>{mac}</code>
              {locallyAdministered(mac) ? " · private Wi-Fi address, changes when the device reconnects" : ""}
            </small>
          )}
          {platformHint && !device.friendly_name && (
            <small
              className="device-platform"
              title={
                platformHint.source === "dhcp"
                  ? "Only this kind of device's DHCP client asks for an address this way."
                  : "Only this kind of device contacts this server: a connectivity check, time, location or update service of its operating system."
              }
            >
              {platformEvidence(platformHint)}
            </small>
          )}
          {device.observed_dhcp && (
            <small className="device-dhcp" title="From the DHCP exchanges the lab recording saw, when the network's router, not ShakerProxy, gave the device its address.">
              DHCP · {dhcpIdentityParts(device).join(" · ")} · {timeAgo(device.observed_dhcp.last_seen)}
            </small>
          )}
          <code>{device.id}</code>
          <small className={device.online ? "device-seen online" : "device-seen"}>
            {device.online
              ? "Online now"
              : device.identities.length === 0
                ? "Not seen yet"
                : `Offline · last seen ${timeAgo(device.last_seen)}`}
            {device.pinned_address ? ` · named by IP ${device.pinned_address}` : ""}
          </small>
          <span className="device-row-actions">
            <button type="button" className="quiet device-inspect" onClick={onInspect}>
              Report &amp; controls
            </button>
            <button type="button" className="quiet device-inspect" onClick={onViewTraffic}>
              View traffic
            </button>
            <button type="button" className="quiet device-inspect" onClick={openRename}>
              Rename
            </button>
          </span>
          {device.friendly_name_conflict && <small className="alias-conflict">Duplicate friendly name</small>}
          {!device.friendly_name && device.suggested_names?.length ? (
            <small>
              Review suggested name · {device.suggested_names[0].name} ({device.suggested_names[0].confidence}% DHCP
              evidence)
            </small>
          ) : null}
          {deviceSummaryLine(device) && <small className="device-summary-line">{deviceSummaryLine(device)}</small>}
          {device.alias_history?.length ? (
            <details className="alias-history">
              <summary>Name history · revision {device.alias_revision}</summary>
              {device.alias_history
                .slice()
                .reverse()
                .map((change) => (
                  <small key={change.revision}>
                    <strong>{change.friendly_name || "Unnamed"}</strong> · {change.reason} · {change.actor} ·{" "}
                    {new Date(change.changed_at).toLocaleString()}
                  </small>
                ))}
              {device.alias_history_truncated && (
                <small>Earlier name revisions were pruned at the bounded history limit.</small>
              )}
            </details>
          ) : null}
        </div>
      </div>
      <div>
        <span className="device-label">Current address evidence</span>
        <strong>
          {activeAddresses
            .map(
              (item) =>
                `${item.address}${item.interface ? ` on ${item.interface}${item.vlan_id ? ` VLAN ${item.vlan_id}` : ""}` : " · scope unknown"}`,
            )
            .join(" · ") || "No active mapping"}
        </strong>
        <small>
          {addresses.length} address{addresses.length === 1 ? "" : "es"}
        </small>
        {addresses.length > 0 && (
          <details>
            <summary>Address history and scope</summary>
            {addresses.map((item) => (
              <small key={`${item.address}-${item.interface ?? "unknown"}-${item.vlan_id ?? "none"}`}>
                <strong>{item.address}</strong> · {item.active ? "current" : "earlier"} ·{" "}
                {item.interface ?? "legacy scope unknown"}
                {item.vlan_id ? ` · VLAN ${item.vlan_id}` : ""} · {new Date(item.first_seen).toLocaleString()} →{" "}
                {new Date(item.last_seen).toLocaleString()}
              </small>
            ))}
          </details>
        )}
      </div>
      <div>
        <span className="device-label">Attribution</span>
        <strong>{device.attribution_confidence}% confidence</strong>
        <small>
          {vendorLabel}
          {device.vendor ? ` · ${device.vendor.registry} ${device.vendor.assignment}` : ""}
        </small>
        <small>{device.identities.map((item) => `${item.kind} · ${item.source}`).join(" / ")}</small>
      </div>
      {device.attribution_warnings?.map((warning) => (
        <p className="device-warning" key={warning}>
          {warning}
        </p>
      ))}
      <DeviceTrafficDeletionPreviewControl device={device} />
      <details className="device-controls" ref={controls}>
        <summary>Rename, tag or correct this device</summary>
        <div className="device-control-grid">
          <form onSubmit={saveAlias}>
            <h3>Friendly name</h3>
            <p>
              Duplicate names are allowed and visibly flagged. DHCP hostnames are review-only suggestions and are never
              applied silently.
            </p>
            {device.suggested_names?.map((suggestion) => (
              <small key={suggestion.name}>
                Suggested · <strong>{suggestion.name}</strong> · {suggestion.confidence}% {suggestion.source} · last
                seen {new Date(suggestion.last_seen).toLocaleString()}
              </small>
            ))}
            <label>
              Friendly name
              <input
                ref={nameInput}
                name="friendly_name"
                defaultValue={device.friendly_name}
                list={`device-suggestions-${device.id}`}
                maxLength={128}
                required
              />
              <datalist id={`device-suggestions-${device.id}`}>
                {device.suggested_names?.map((suggestion) => (
                  <option key={suggestion.name} value={suggestion.name} />
                ))}
              </datalist>
            </label>
            <label>
              Reason
              <input name="reason" maxLength={256} required placeholder="Why this name is correct" />
            </label>
            <button className="quiet" disabled={busy}>
              {busy ? "Saving…" : "Save name revision"}
            </button>
          </form>
          <form onSubmit={saveMetadata}>
            <h3>Administrator metadata</h3>
            <label>
              Owner
              <input name="owner" defaultValue={device.owner} maxLength={128} />
            </label>
            <label>
              Location
              <input name="location" defaultValue={device.location} maxLength={128} />
            </label>
            <label>
              Category
              <input
                name="category"
                defaultValue={device.category}
                maxLength={64}
                pattern="[a-z0-9][a-z0-9_-]{0,63}"
                placeholder="camera"
              />
            </label>
            <label>
              Icon
              <select name="icon" defaultValue={device.icon ?? ""}>
                <option value="">Default device</option>
                {[
                  "device",
                  "camera",
                  "sensor",
                  "tv",
                  "speaker",
                  "phone",
                  "tablet",
                  "computer",
                  "console",
                  "router",
                  "appliance",
                ].map((icon) => (
                  <option key={icon} value={icon}>
                    {icon}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Tags
              <input
                name="tags"
                defaultValue={device.tags?.join(", ")}
                maxLength={512}
                placeholder="comma, separated"
              />
            </label>
            <label>
              Notes
              <textarea name="notes" defaultValue={device.notes} maxLength={4096} />
            </label>
            <button className="quiet" disabled={busy}>
              {busy ? "Saving…" : "Save metadata"}
            </button>
          </form>
          <form onSubmit={merge}>
            <h3>Merge another device here</h3>
            <p>
              The selected device is removed after its evidence is merged. Conflicting target metadata is retained and
              flagged.
            </p>
            <label>
              Source device
              <select name="source_device_id" required defaultValue="">
                <option value="" disabled>
                  Select a device
                </option>
                {otherDevices.map((candidate) => (
                  <option key={candidate.id} value={candidate.id}>
                    {candidate.friendly_name || candidate.hostnames?.at(-1)?.hostname || candidate.id}
                  </option>
                ))}
              </select>
            </label>
            <label className="check">
              <input name="confirm" type="checkbox" required />
              <span>I reviewed both device identities.</span>
            </label>
            <button className="quiet" disabled={busy || otherDevices.length === 0}>
              {busy ? "Merging…" : "Merge with audit"}
            </button>
          </form>
          <form onSubmit={split}>
            <h3>Split exact evidence</h3>
            <p>Move selected records into a new device. At least one identity must remain here.</p>
            <fieldset>
              <legend>Identities</legend>
              {device.identities.map((identity, index) => (
                <label className="check" key={`${identity.kind}-${identity.value}`}>
                  <input name="identity" type="checkbox" value={index} />
                  <span>
                    {identity.kind} · {identity.value}
                  </span>
                </label>
              ))}
            </fieldset>
            {device.addresses.length > 0 && (
              <fieldset>
                <legend>Address observations</legend>
                {device.addresses.map((address, index) => (
                  <label
                    className="check"
                    key={`${address.address}-${address.valid_from}-${address.interface ?? "unknown"}-${address.vlan_id ?? "none"}-${address.scope_plan_sha256 ?? "unknown"}`}
                  >
                    <input name="address" type="checkbox" value={index} />
                    <span>
                      {address.address} · {address.interface ?? "scope unknown"}
                      {address.vlan_id ? ` VLAN ${address.vlan_id}` : ""} · from{" "}
                      {new Date(address.valid_from).toLocaleString()}
                    </span>
                  </label>
                ))}
              </fieldset>
            )}
            {(device.hostnames?.length ?? 0) > 0 && (
              <fieldset>
                <legend>Hostnames</legend>
                {device.hostnames.map((hostname, index) => (
                  <label className="check" key={`${hostname.source}-${hostname.hostname}`}>
                    <input name="hostname" type="checkbox" value={index} />
                    <span>
                      {hostname.hostname} · {hostname.source}
                    </span>
                  </label>
                ))}
              </fieldset>
            )}
            <label>
              New device name
              <input name="friendly_name" maxLength={128} />
            </label>
            <label>
              New owner
              <input name="owner" maxLength={128} />
            </label>
            <label>
              New location
              <input name="location" maxLength={128} />
            </label>
            <label>
              New category
              <input name="category" maxLength={64} pattern="[a-z0-9][a-z0-9_-]{0,63}" />
            </label>
            <label>
              New icon
              <select name="icon" defaultValue="">
                <option value="">Default device</option>
                {[
                  "device",
                  "camera",
                  "sensor",
                  "tv",
                  "speaker",
                  "phone",
                  "tablet",
                  "computer",
                  "console",
                  "router",
                  "appliance",
                ].map((icon) => (
                  <option key={icon} value={icon}>
                    {icon}
                  </option>
                ))}
              </select>
            </label>
            <label>
              New tags
              <input name="tags" maxLength={512} placeholder="comma, separated" />
            </label>
            <label>
              New notes
              <textarea name="notes" maxLength={4096} />
            </label>
            <label className="check">
              <input name="confirm" type="checkbox" required />
              <span>I selected exact evidence records.</span>
            </label>
            <button className="quiet" disabled={busy}>
              {busy ? "Splitting…" : "Split with audit"}
            </button>
          </form>
        </div>
        {message && <p className="device-message">{message}</p>}
      </details>
    </article>
  )
}

// deviceSummaryLine joins what an operator recorded about a device into one
// readable line: category · location · owner · #tags.
function deviceSummaryLine(device: Device): string {
  const parts = [device.category, device.location, device.owner ? `owner ${device.owner}` : ""]
  for (const tag of device.tags ?? []) parts.push(`#${tag}`)
  return parts.filter(Boolean).join(" · ")
}
