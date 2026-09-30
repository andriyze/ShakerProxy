import React, { FormEvent, useState } from "react"
import { withPassword } from "../../shell/passwordPrompt"
import { datetimeLocalValue, idempotencyKey } from "../../lib/format"
import { api, apiBlob, describeError, downloadBlob } from "../../api"
import type { AddressAlias, AliasTagImportPreview, Interface } from "../../types"

export function DeviceAliasExportControls() {
  const [busy, setBusy] = useState<"json" | "csv" | null>(null)
  const [message, setMessage] = useState("")
  async function download(format: "json" | "csv") {
    setBusy(format)
    setMessage("")
    try {
      const blob = await apiBlob(`/api/v1/device-aliases/export?format=${format}`)
      downloadBlob(blob, `shakerproxy-device-aliases.${format}`)
      setMessage(`${format.toUpperCase()} alias/tag export downloaded.`)
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Alias/tag export failed")
    } finally {
      setBusy(null)
    }
  }
  return (
    <div className="device-export">
      <div>
        <strong>Portable alias and tag snapshot</strong>
        <small>Contains immutable device IDs, current friendly names, alias revisions, and tags only.</small>
      </div>
      <button type="button" className="quiet" disabled={busy !== null} onClick={() => void download("json")}>
        {busy === "json" ? "Preparing JSON…" : "Export JSON"}
      </button>
      <button type="button" className="quiet" disabled={busy !== null} onClick={() => void download("csv")}>
        {busy === "csv" ? "Preparing CSV…" : "Export CSV"}
      </button>
      {message && <small role="status">{message}</small>}
    </div>
  )
}

export function DeviceAliasImportControls({ onChanged }: { onChanged: () => Promise<void> }) {
  const [preview, setPreview] = useState<AliasTagImportPreview | null>(null)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState("")
  async function loadPreview(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setMessage("")
    setPreview(null)
    try {
      const data = new FormData(event.currentTarget)
      const file = data.get("file")
      if (!(file instanceof File) || file.size === 0 || file.size > 1 << 20)
        throw new Error("Choose a non-empty JSON or CSV export no larger than 1 MiB.")
      const result = await api<AliasTagImportPreview>("/api/v1/device-aliases/import-preview", {
        method: "POST",
        body: JSON.stringify({ format: data.get("format"), content: await file.text(), reason: data.get("reason") }),
      })
      setPreview(result)
      setMessage(
        result.ready
          ? `Review ${result.changes.length} changed device${result.changes.length === 1 ? "" : "s"}. No data has been changed yet.`
          : "Import is blocked or contains no changes.",
      )
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Import preview failed")
    } finally {
      setBusy(false)
    }
  }
  async function apply(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!preview) return
    setBusy(true)
    setMessage("")
    const key = idempotencyKey("device-alias-import")
    try {
      const result = await withPassword("apply this import", (password) =>
        api<{ updated_devices: number; replayed: boolean }>("/api/v1/device-aliases/import", {
          method: "POST",
          headers: { "Idempotency-Key": key },
          body: JSON.stringify({ preview, ...(password ? { password } : {}) }),
        }),
      )
      setMessage(
        `${result.updated_devices} device${result.updated_devices === 1 ? "" : "s"} updated atomically with an audit record.`,
      )
      setPreview(null)
      await onChanged()
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Alias/tag import failed")
    } finally {
      setBusy(false)
    }
  }
  return (
    <details className="device-import">
      <summary>Validate and import aliases/tags</summary>
      <div className="device-import-body">
        <p>
          Imports at most 256 rows from ShakerProxy’s JSON or CSV export. Preview is read-only. Apply may ask for your
          password and rejects the whole batch if any alias revision or tag set changed.
        </p>
        <form onSubmit={loadPreview}>
          <label>
            Format
            <select name="format" defaultValue="json">
              <option value="json">JSON export</option>
              <option value="csv">CSV export</option>
            </select>
          </label>
          <label>
            Export file
            <input name="file" type="file" accept=".json,.csv,application/json,text/csv" required />
          </label>
          <label>
            Audit reason
            <input name="reason" maxLength={256} required placeholder="Reviewed asset worksheet" />
          </label>
          <button className="quiet" disabled={busy}>
            {busy ? "Validating exact revisions…" : "Preview import"}
          </button>
        </form>
        {message && <p role="status">{message}</p>}
        {preview && (
          <section className="device-import-preview">
            <header>
              <strong>{preview.ready ? "READY FOR ATOMIC APPLY" : "BLOCKED"}</strong>
              <small>
                Expires {new Date(preview.expires_at).toLocaleString()} · {preview.preview_sha256.slice(0, 12)}…
              </small>
            </header>
            {preview.blockers.map((blocker) => (
              <p className="device-warning" key={`${blocker.device_id}-${blocker.code}`}>
                <code>{blocker.code}</code> · {blocker.device_id} · {blocker.message}
              </p>
            ))}
            {preview.changes.map((change) => (
              <article key={change.device_id}>
                <code>{change.device_id}</code>
                <strong>
                  {change.current_friendly_name || "Unnamed"} → {change.proposed_friendly_name || "Unnamed"}
                </strong>
                <small>
                  Tags · {change.current_tags.join(", ") || "none"} → {change.proposed_tags.join(", ") || "none"}
                </small>
                {change.warnings.map((warning) => (
                  <small className="device-warning" key={warning}>
                    {warning}
                  </small>
                ))}
              </article>
            ))}
            {preview.ready && (
              <form onSubmit={apply}>
                <button disabled={busy}>{busy ? "Applying atomically…" : "Apply reviewed import"}</button>
              </form>
            )}
          </section>
        )}
      </div>
    </details>
  )
}

export function addressAliasPayload(data: FormData, expectedRevision?: number) {
  const validFrom = new Date(String(data.get("valid_from")))
  const validUntilValue = String(data.get("valid_until") ?? "")
  const validUntil = validUntilValue ? new Date(validUntilValue) : null
  const vlanValue = String(data.get("vlan_id") ?? "")
  if (
    !Number.isFinite(validFrom.getTime()) ||
    (validUntil && !Number.isFinite(validUntil.getTime())) ||
    (validUntil && validUntil <= validFrom)
  )
    throw new Error("Choose a valid start and an optional end after it.")
  return {
    name: data.get("name"),
    prefix: data.get("prefix"),
    interface: data.get("interface"),
    ...(vlanValue ? { vlan_id: Number(vlanValue) } : {}),
    valid_from: validFrom.toISOString(),
    ...(validUntil ? { valid_until: validUntil.toISOString() } : {}),
    priority: Number(data.get("priority")),
    confidence: Number(data.get("confidence")),
    reason: data.get("reason"),
    ...(expectedRevision === undefined ? {} : { expected_revision: expectedRevision }),
  }
}

export function AddressAliasManager({
  aliases,
  onChanged,
}: {
  aliases: AddressAlias[]
  onChanged: () => Promise<void>
}) {
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState("")
  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setMessage("")
    const form = event.currentTarget
    try {
      const data = new FormData(form)
      const key = idempotencyKey("address-alias")
      await withPassword("save this address name", (password) =>
        api("/api/v1/address-aliases", {
          method: "POST",
          headers: { "Idempotency-Key": key },
          body: JSON.stringify({ ...addressAliasPayload(data), ...(password ? { password } : {}) }),
        }),
      )
      setMessage("Address alias saved with an audit record.")
      form.reset()
      await onChanged()
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Address alias creation failed")
    } finally {
      setBusy(false)
    }
  }
  return (
    <details className="address-aliases">
      <summary>Advanced address aliases · {aliases.length}</summary>
      <div className="address-alias-body">
        <p>
          Use a manual address or CIDR name only when no reliable device identity exists. DHCP reuse and IPv6 privacy
          addresses can make it inaccurate; every alias is limited by interface, optional VLAN, and time.
        </p>
        <form className="address-alias-form" onSubmit={create}>
          <h3>Create address alias</h3>
          <label>
            Name
            <input name="name" maxLength={128} required placeholder="Temporary bench camera" />
          </label>
          <label>
            IPv4/IPv6 or CIDR
            <input name="prefix" required placeholder="10.77.0.44 or 2001:db8:20::/64" />
          </label>
          <label>
            Interface
            <input
              name="interface"
              maxLength={15}
              pattern="[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}"
              required
              placeholder="enp2s0"
            />
          </label>
          <label>
            VLAN ID (optional)
            <input name="vlan_id" type="number" min="1" max="4094" />
          </label>
          <label>
            Valid from
            <input name="valid_from" type="datetime-local" defaultValue={datetimeLocalValue(new Date())} required />
          </label>
          <label>
            Valid until (optional)
            <input name="valid_until" type="datetime-local" />
          </label>
          <label>
            Priority
            <input name="priority" type="number" min="0" max="1000" defaultValue="100" required />
          </label>
          <label>
            Confidence
            <input name="confidence" type="number" min="1" max="100" defaultValue="50" required />
          </label>
          <label>
            Reason
            <input name="reason" maxLength={256} required placeholder="Why this override is necessary" />
          </label>
          <button className="quiet" disabled={busy}>
            {busy ? "Saving…" : "Create scoped alias"}
          </button>
        </form>
        {message && <p role="status">{message}</p>}
        <div className="address-alias-list">
          {aliases.map((alias) => (
            <AddressAliasEditor key={`${alias.id}-${alias.revision}`} alias={alias} onChanged={onChanged} />
          ))}
        </div>
      </div>
    </details>
  )
}

export function AddressAliasEditor({ alias, onChanged }: { alias: AddressAlias; onChanged: () => Promise<void> }) {
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState("")
  async function update(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setMessage("")
    try {
      const data = new FormData(event.currentTarget)
      const key = idempotencyKey("address-alias-update")
      await withPassword("save this address name", (password) =>
        api(`/api/v1/address-aliases/${alias.id}`, {
          method: "PUT",
          headers: { "Idempotency-Key": key },
          body: JSON.stringify({ ...addressAliasPayload(data, alias.revision), ...(password ? { password } : {}) }),
        }),
      )
      setMessage("Address alias revision saved.")
      await onChanged()
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Address alias update failed")
    } finally {
      setBusy(false)
    }
  }
  async function remove(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    setBusy(true)
    setMessage("")
    try {
      await withPassword("delete this address name", (password) =>
        api(`/api/v1/address-aliases/${alias.id}`, {
          method: "DELETE",
          body: JSON.stringify({
            expected_revision: alias.revision,
            reason: data.get("reason"),
            ...(password ? { password } : {}),
          }),
        }),
      )
      await onChanged()
    } catch (reason) {
      setMessage(describeError(reason, "The address name could not be deleted"))
    } finally {
      setBusy(false)
    }
  }
  return (
    <article className={alias.conflict ? "address-alias-card conflict" : "address-alias-card"}>
      <header>
        <div>
          <strong>{alias.name}</strong>
          <code>{alias.prefix}</code>
        </div>
        <span>revision {alias.revision}</span>
      </header>
      <p>
        {alias.interface}
        {alias.vlan_id ? ` · VLAN ${alias.vlan_id}` : " · all VLANs on interface"} · {alias.confidence}% confidence ·
        priority {alias.priority}
      </p>
      <small>
        {new Date(alias.valid_from).toLocaleString()} →{" "}
        {alias.valid_until ? new Date(alias.valid_until).toLocaleString() : "no scheduled end"}
      </small>
      {alias.conflict_warnings?.map((warning) => (
        <p className="device-warning" key={warning}>
          {warning}
        </p>
      ))}
      <details>
        <summary>Edit exact scope</summary>
        <form className="address-alias-form" onSubmit={update}>
          <label>
            Name
            <input name="name" defaultValue={alias.name} maxLength={128} required />
          </label>
          <label>
            IPv4/IPv6 or CIDR
            <input name="prefix" defaultValue={alias.prefix} required />
          </label>
          <label>
            Interface
            <input
              name="interface"
              defaultValue={alias.interface}
              maxLength={15}
              pattern="[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}"
              required
            />
          </label>
          <label>
            VLAN ID (optional)
            <input name="vlan_id" type="number" min="1" max="4094" defaultValue={alias.vlan_id} />
          </label>
          <label>
            Valid from
            <input
              name="valid_from"
              type="datetime-local"
              defaultValue={datetimeLocalValue(new Date(alias.valid_from))}
              required
            />
          </label>
          <label>
            Valid until (optional)
            <input
              name="valid_until"
              type="datetime-local"
              defaultValue={alias.valid_until ? datetimeLocalValue(new Date(alias.valid_until)) : ""}
            />
          </label>
          <label>
            Priority
            <input name="priority" type="number" min="0" max="1000" defaultValue={alias.priority} required />
          </label>
          <label>
            Confidence
            <input name="confidence" type="number" min="1" max="100" defaultValue={alias.confidence} required />
          </label>
          <label>
            Reason
            <input name="reason" defaultValue={alias.reason} maxLength={256} required />
          </label>
          <button className="quiet" disabled={busy}>
            {busy ? "Saving…" : "Save revision"}
          </button>
          {message && <small>{message}</small>}
        </form>
      </details>
      <details>
        <summary>Delete this address name</summary>
        <form className="address-alias-form" onSubmit={remove}>
          <label>
            Reason
            <input name="reason" maxLength={256} required />
          </label>
          <button className="quiet danger" disabled={busy}>
            {busy ? "Deleting…" : "Delete"}
          </button>
        </form>
      </details>
    </article>
  )
}
