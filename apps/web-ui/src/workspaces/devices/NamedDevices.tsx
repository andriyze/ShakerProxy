import React, { FormEvent, useState } from "react"
import { api, describeError } from "../../api"
import { idempotencyKey } from "../../lib/format"
import { PasswordCancelled, withPassword } from "../../lib/passwordConfirm"
import type { Device, DeviceMutationResult } from "../../types"

// Naming a device by its IP address works like a router's client alias: the
// address becomes the device's identity, so a phone that changes its private
// Wi-Fi MAC stays one named device.

function nameAddress(body: { name: string; address: string; device_id?: string }) {
  const key = idempotencyKey("device-name")
  return withPassword("name this device", (password) =>
    api<DeviceMutationResult>("/api/v1/devices", {
      method: "POST",
      headers: { "Idempotency-Key": key },
      body: JSON.stringify({ ...(password ? { password } : {}), ...body }),
    }),
  )
}

// AddDeviceByAddress adds a device by name and IP address before or after
// ShakerProxy has seen it.
export function AddDeviceByAddress({ onAdded }: { onAdded: () => void }) {
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState("")
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = event.currentTarget
    const data = new FormData(form)
    const name = String(data.get("name") ?? "").trim()
    const address = String(data.get("address") ?? "").trim()
    setBusy(true)
    setMessage("")
    try {
      const result = await nameAddress({ name, address })
      const device = result.devices?.[0]
      setMessage(device && device.identities.length > 0 ? `${name} is ${address}.` : `Added ${name}. It shows as online once ${address} sends traffic.`)
      form.reset()
      onAdded()
    } catch (reason) {
      if (!(reason instanceof PasswordCancelled)) setMessage(describeError(reason, "Could not add the device"))
    } finally {
      setBusy(false)
    }
  }
  return (
    <form className="device-add" onSubmit={submit}>
      <strong>Add a device</strong>
      <span>Name a device by its IP address. Every MAC address it uses there, such as a phone's changing private Wi-Fi address, counts as this device.</span>
      <label>
        Name
        <input name="name" required maxLength={64} placeholder="Pixel 9" autoComplete="off" />
      </label>
      <label>
        IP address
        <input name="address" required maxLength={45} placeholder="192.168.10.201" inputMode="decimal" autoComplete="off" spellCheck={false} />
      </label>
      <button type="submit" disabled={busy}>
        {busy ? "Adding…" : "Add device"}
      </button>
      {message && (
        <p className="device-add-message" role="status">
          {message}
        </p>
      )}
    </form>
  )
}

function currentIPv4(device: Device): string {
  const active = device.addresses.filter((address) => address.active && address.address.includes("."))
  return (active.at(-1) ?? device.addresses.filter((address) => address.address.includes(".")).at(-1))?.address ?? ""
}

// PinnedAddressControls names an existing device by its IP address, or stops.
export function PinnedAddressControls({ device, onChanged }: { device: Device; onChanged: (updated?: Device) => void }) {
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState("")
  async function pin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    setBusy(true)
    setMessage("")
    try {
      const result = await nameAddress({ name: String(data.get("name") ?? "").trim(), address: String(data.get("address") ?? "").trim(), device_id: device.id })
      onChanged(result.devices?.[0])
    } catch (reason) {
      if (!(reason instanceof PasswordCancelled)) setMessage(describeError(reason, "Could not name the device"))
    } finally {
      setBusy(false)
    }
  }
  async function unpin() {
    setBusy(true)
    setMessage("")
    const key = idempotencyKey("device-unpin")
    try {
      const result = await withPassword("stop naming this device by its IP address", (password) =>
        api<DeviceMutationResult>(`/api/v1/devices/${device.id}/pinned-address`, {
          method: "DELETE",
          headers: { "Idempotency-Key": key },
          body: JSON.stringify(password ? { password } : {}),
        }),
      )
      onChanged(result.devices?.[0])
    } catch (reason) {
      if (!(reason instanceof PasswordCancelled)) setMessage(describeError(reason, "Could not change the device"))
    } finally {
      setBusy(false)
    }
  }
  if (device.pinned_address) {
    return (
      <div className="device-pinned-controls">
        <p>
          Named by its IP address <code>{device.pinned_address}</code>: every MAC address seen there counts as this device.
        </p>
        <button type="button" className="quiet" disabled={busy} onClick={() => void unpin()}>
          {device.identities.length === 0 ? "Remove this device" : "Stop naming by IP address"}
        </button>
        {message && <p className="error">{message}</p>}
      </div>
    )
  }
  return (
    <form className="device-add device-pin" onSubmit={pin}>
      <strong>Name by IP address</strong>
      <span>Keep this device together when it changes its MAC address, as phones do.</span>
      <label>
        Name
        <input name="name" required maxLength={64} defaultValue={device.friendly_name ?? ""} placeholder="Pixel 9" autoComplete="off" />
      </label>
      <label>
        IP address
        <input name="address" required maxLength={45} defaultValue={currentIPv4(device)} autoComplete="off" spellCheck={false} />
      </label>
      <button type="submit" disabled={busy}>
        {busy ? "Saving…" : "Save"}
      </button>
      {message && <p className="error">{message}</p>}
    </form>
  )
}
