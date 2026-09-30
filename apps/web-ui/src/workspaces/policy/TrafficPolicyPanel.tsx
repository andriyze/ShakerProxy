import React, { FormEvent, useEffect, useMemo, useState } from "react"
import { withPassword } from "../../shell/passwordPrompt"
import { api, describeError } from "../../api"
import { isUnavailableEndpoint } from "../../lib/errors"
import {
  MAX_SELECTED_DEVICES,
  parseMobileClients,
  splitList,
  tlsModeFromPolicy,
  tlsSelection,
  validSelectedDevices,
  type TLSMode,
} from "../../lib/trafficPolicy"
import { useAppState } from "../../shell/AppContext"
import { useResource } from "../../shell/hooks"
import type {
  Device,
  EncryptedDNSMode,
  InventorySnapshot,
  TrafficPolicy,
  TrafficPolicyDocument,
  TrafficPolicyPreview,
} from "../../types"

type ResolverCatalog = {
  schema: number
  revision: string
  resolvers: { id: string; provider: string; hostnames: string[] }[]
}

function deviceLabel(device: Device): string {
  return device.friendly_name?.trim() || device.suggested_names?.[0]?.name || device.vendor?.name?.trim() || device.id
}

function activeAddress(device: Device): string {
  return (
    device.addresses.find((item) => item.active && item.family === "ipv4")?.address ??
    device.addresses.find((item) => item.active)?.address ??
    ""
  )
}

// TrafficPolicyPanel edits the one traffic policy document: which devices
// ShakerProxy decrypts (off / all / selected devices) and how devices use DNS.
// There is a single editor, so a change made here can never be overwritten
// by a stale copy elsewhere on the page (audit #5).
export function TrafficPolicyPanel({
  available,
  routed,
  emergencyBypass,
}: {
  available: boolean
  routed: boolean
  emergencyBypass: boolean
}) {
  const { refreshStatus } = useAppState()
  const [document, setDocument] = useState<TrafficPolicyDocument | null>(null)
  const [mode, setMode] = useState<EncryptedDNSMode>("OBSERVE")
  const [name, setName] = useState("Local DNS policy")
  const [upstreams, setUpstreams] = useState("1.1.1.1:53\n8.8.8.8:53")
  const [blockDoT, setBlockDoT] = useState(false)
  const [blockDoQ, setBlockDoQ] = useState(false)
  const [blockDoH, setBlockDoH] = useState(false)
  const [blockDoH3, setBlockDoH3] = useState(false)
  const [resolverExclusions, setResolverExclusions] = useState<string[]>([])
  const [tlsMode, setTLSMode] = useState<TLSMode>("off")
  const [selectedDevices, setSelectedDevices] = useState<Set<string>>(new Set())
  const [deviceFilter, setDeviceFilter] = useState("")
  const [tlsPort, setTLSPort] = useState("8085")
  const [tlsExcludeHosts, setTLSExcludeHosts] = useState("")
  const [tlsExcludeCIDRs, setTLSExcludeCIDRs] = useState("")
  const [tlsMobileClients, setTLSMobileClients] = useState("")
  const [autoBypassPinned, setAutoBypassPinned] = useState(true)
  const [autoBypassTTL, setAutoBypassTTL] = useState("86400")
  const [maxDynamicBypasses, setMaxDynamicBypasses] = useState("1024")
  const [preview, setPreview] = useState<TrafficPolicyPreview | null>(null)
  const [message, setMessage] = useState("")
  const [busy, setBusy] = useState(false)

  const devices = useResource(
    async (signal) => {
      const snapshot = await api<InventorySnapshot>("/api/v1/devices?sort=name&direction=asc", { signal })
      return Array.isArray(snapshot.devices) ? snapshot.devices : []
    },
    [available],
    { enabled: available, intervalMs: 30_000 },
  )
  const catalog = useResource(
    async (signal) => {
      try {
        return await api<ResolverCatalog>("/api/v1/traffic-policy/catalog", { signal })
      } catch (reason) {
        if (isUnavailableEndpoint(reason)) return null
        throw reason
      }
    },
    [available],
    { enabled: available },
  )

  function loadDocument(next: TrafficPolicyDocument) {
    const dns = next.policy.encrypted_dns
    const tls = next.policy.tls_interception
    setDocument(next)
    setMode(dns.mode)
    setName(next.policy.name)
    setUpstreams((dns.upstream_servers ?? []).join("\n") || "1.1.1.1:53\n8.8.8.8:53")
    setBlockDoT(dns.block_dot)
    setBlockDoQ(dns.block_doq)
    setBlockDoH(dns.block_known_doh)
    setBlockDoH3(dns.block_known_doh3)
    setResolverExclusions(dns.resolver_exclusions ?? [])
    setTLSMode(tlsModeFromPolicy(tls))
    setSelectedDevices(new Set(validSelectedDevices(tls.selected_device_ids)))
    setTLSPort(String(tls.transparent_port))
    setTLSExcludeHosts((tls.exclude_hosts ?? []).join("\n"))
    setTLSExcludeCIDRs((tls.exclude_cidrs ?? []).join("\n"))
    setTLSMobileClients((tls.mobile_clients ?? []).map((client) => `${client.cidr} ${client.platform}`).join("\n"))
    setAutoBypassPinned(tls.auto_bypass_pinned)
    setAutoBypassTTL(String(tls.auto_bypass_ttl_seconds))
    setMaxDynamicBypasses(String(tls.max_dynamic_bypasses))
  }

  useEffect(() => {
    let mounted = true
    if (!available) {
      setDocument(null)
      setMessage("")
      return () => {
        mounted = false
      }
    }
    api<TrafficPolicyDocument>("/api/v1/traffic-policy")
      .then((next) => {
        if (mounted) {
          loadDocument(next)
          setMessage("")
        }
      })
      .catch((reason) => {
        if (mounted) setMessage(describeError(reason, "The DNS & HTTPS settings are unavailable"))
      })
    return () => {
      mounted = false
    }
  }, [available])

  function candidate(): TrafficPolicy {
    if (!document) throw new Error("The current settings have not loaded yet.")
    const selection = tlsSelection(tlsMode, selectedDevices)
    return {
      ...document.policy,
      revision: document.policy.revision + 1,
      name: name.trim(),
      encrypted_dns: {
        ...document.policy.encrypted_dns,
        mode,
        redirect_plain_dns: mode === "ENFORCE_LOCAL",
        upstream_servers: splitList(upstreams),
        block_dot: blockDoT,
        block_doq: blockDoQ,
        block_known_doh: blockDoH,
        block_known_doh3: blockDoH3,
        resolver_exclusions: resolverExclusions,
      },
      tls_interception: {
        ...document.policy.tls_interception,
        enabled: selection.enabled,
        selected_device_ids: selection.selected_device_ids,
        transparent_port: Number(tlsPort),
        exclude_hosts: splitList(tlsExcludeHosts),
        exclude_cidrs: splitList(tlsExcludeCIDRs),
        auto_bypass_pinned: autoBypassPinned,
        auto_bypass_ttl_seconds: Number(autoBypassTTL),
        max_dynamic_bypasses: Number(maxDynamicBypasses),
        mobile_clients: parseMobileClients(tlsMobileClients),
      },
    }
  }

  function changed() {
    setPreview(null)
    setMessage("")
  }

  async function previewPolicy(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setMessage("")
    try {
      const next = await api<TrafficPolicyPreview>("/api/v1/traffic-policy/preview", {
        method: "POST",
        body: JSON.stringify(candidate()),
      })
      setPreview(next)
      setMessage("Review the changes below, then enter your password to apply them.")
    } catch (reason) {
      setPreview(null)
      setMessage(describeError(reason, "The preview failed"))
    } finally {
      setBusy(false)
    }
  }

  async function applyPolicy(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!document || !preview) return
    // Keep the form element: React clears event.currentTarget after an await.
    const form = event.currentTarget
    const data = new FormData(form)
    const typedPassword = String(data.get("password") ?? "")
    setBusy(true)
    setMessage("")
    try {
      const next = await withPassword(
        "apply these settings",
        (password) =>
          api<TrafficPolicyDocument>("/api/v1/traffic-policy", {
            method: "PUT",
            body: JSON.stringify({
              expected_revision: document.policy.revision,
              policy: preview.policy,
              ...(password ? { password } : {}),
            }),
          }),
        typedPassword,
      )
      loadDocument(next)
      setPreview(null)
      form.reset()
      setMessage(`Saved. These settings are now active (revision ${next.policy.revision}).`)
      void refreshStatus()
    } catch (reason) {
      setMessage(describeError(reason, "The settings could not be applied"))
    } finally {
      setBusy(false)
    }
  }

  async function rollbackPolicy(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!document?.previous) return
    setBusy(true)
    setMessage("")
    try {
      const next = await withPassword("restore the previous settings", (password) =>
        api<TrafficPolicyDocument>("/api/v1/traffic-policy/rollback", {
          method: "POST",
          body: JSON.stringify({ expected_revision: document.policy.revision, ...(password ? { password } : {}) }),
        }),
      )
      loadDocument(next)
      setPreview(null)
      setMessage(`Restored the previous settings (now revision ${next.policy.revision}).`)
      void refreshStatus()
    } catch (reason) {
      setMessage(describeError(reason, "Could not restore the previous settings"))
    } finally {
      setBusy(false)
    }
  }

  function toggleDevice(id: string, on: boolean) {
    if (on && !selectedDevices.has(id) && selectedDevices.size >= MAX_SELECTED_DEVICES) return
    setSelectedDevices((current) => {
      const next = new Set(current)
      if (on) next.add(id)
      else next.delete(id)
      return next
    })
  }

  const tlsEnabled = tlsMode !== "off"
  // Turning on decryption for every device always needs the password.
  const decryptsEveryDevice =
    preview !== null &&
    tlsModeFromPolicy(preview.policy.tls_interception) === "all" &&
    (!document || tlsModeFromPolicy(document.policy.tls_interception) !== "all")
  const enforcementBlocked = (mode !== "OBSERVE" || tlsEnabled) && (!routed || emergencyBypass)
  const enabled = document !== null && available
  const knownDevices = devices.data ?? []
  const listedDevices = useMemo(() => {
    const needle = deviceFilter.trim().toLowerCase()
    const known = new Set(knownDevices.map((device) => device.id))
    const rows = knownDevices
      .map((device) => ({
        id: device.id,
        label: deviceLabel(device),
        online: device.online,
        detail: [device.category, device.vendor?.name, activeAddress(device)].filter(Boolean).join(" · "),
      }))
      // Selected devices that are no longer in the inventory stay visible so
      // they are never dropped from the policy silently.
      .concat(
        [...selectedDevices]
          .filter((id) => !known.has(id))
          .map((id) => ({ id, label: id, online: false, detail: "Not in the device list any more" })),
      )
      .filter((row) => !needle || `${row.label} ${row.id} ${row.detail}`.toLowerCase().includes(needle))
    rows.sort((left, right) => Number(right.online) - Number(left.online) || left.label.localeCompare(right.label))
    return rows.slice(0, MAX_SELECTED_DEVICES)
  }, [knownDevices, selectedDevices, deviceFilter])

  return (
    <section className="traffic-policy" aria-labelledby="traffic-policy-title">
      <header>
        <div>
          <p className="eyebrow">Step 2 · Decryption and DNS</p>
          <h2 id="traffic-policy-title">Choose what ShakerProxy decrypts</h2>
        </div>
        <span>
          {document
            ? `HTTPS: ${tlsModeFromPolicy(document.policy.tls_interception) === "off" ? "not decrypted" : tlsModeFromPolicy(document.policy.tls_interception) === "all" ? "all devices" : `${document.policy.tls_interception.selected_device_ids?.length ?? 0} device(s)`} · DNS: ${document.policy.encrypted_dns.mode.replaceAll("_", " ").toLowerCase()}`
            : available
              ? "LOADING"
              : "NOT AVAILABLE"}
        </span>
      </header>
      <p className="traffic-policy-intro">
        For an authorized test client, set both its default gateway and DNS server to the ShakerProxy client-side IP (a
        device on the lab network gets this automatically). ShakerProxy redirects UDP and TCP port 53 when “Send all DNS
        through ShakerProxy” is selected. HTTPS can be decrypted only after the certificate from step 1 is installed on the
        device.
      </p>
      {!available && (
        <p className="traffic-policy-warning">
          Decryption and DNS control need the installed ShakerProxy appliance (host profile). They are not available in this
          setup.
        </p>
      )}
      {available && !routed && (
        <p className="traffic-policy-warning">
          Confirm a routed or single-arm network plan before enabling DNS enforcement or TLS interception.{" "}
          <a href="#/network">Set up the network</a>.
        </p>
      )}
      {emergencyBypass && (
        <p className="traffic-policy-warning">
          Emergency bypass is on, so decryption and DNS control cannot be turned on.
        </p>
      )}
      {message && (
        <p className="traffic-policy-message" role="status">
          {message}
        </p>
      )}
      <form className="traffic-policy-editor" onSubmit={previewPolicy} onChange={changed}>
        <fieldset className="tls-mode">
          <legend>Decrypt HTTPS</legend>
          <div className="device-interception-modes">
            {(
              [
                ["off", "Pass through all", "Don't decrypt anything. Devices work normally."],
                [
                  "all",
                  "Decrypt all eligible",
                  "Decrypt eligible TCP TLS traffic from every device on the lab network.",
                ],
                [
                  "selected",
                  "Decrypt selected clients",
                  "Decrypt only the devices you tick below; everything else passes through.",
                ],
              ] as const
            ).map(([value, title, description]) => (
              <label className="device-interception-mode" key={value}>
                <input
                  type="radio"
                  name="tls-mode"
                  value={value}
                  checked={tlsMode === value}
                  onChange={() => setTLSMode(value)}
                  disabled={!enabled || busy}
                />
                <span>
                  <strong>{title}</strong>
                  <small>{description}</small>
                </span>
              </label>
            ))}
          </div>
          {tlsMode === "selected" && (
            <div className="tls-device-picker">
              <div className="device-interception-toolbar">
                <label className="visually-hidden" htmlFor="tls-device-filter">
                  Search devices
                </label>
                <input
                  id="tls-device-filter"
                  type="search"
                  value={deviceFilter}
                  onChange={(event) => setDeviceFilter(event.target.value)}
                  placeholder="Search name, vendor, IP or device ID"
                />
                <span className="device-interception-count">{selectedDevices.size} selected</span>
              </div>
              {devices.error && <p className="traffic-policy-warning">{devices.error}</p>}
              <div className="device-interception-list">
                {listedDevices.map((row) => (
                  <label className="device-interception-device" key={row.id}>
                    <input
                      type="checkbox"
                      checked={selectedDevices.has(row.id)}
                      onChange={(event) => toggleDevice(row.id, event.target.checked)}
                      disabled={!enabled || busy}
                    />
                    <span className="device-interception-device-copy">
                      <strong>
                        {row.label}
                        {!row.online && <small> · offline</small>}
                      </strong>
                      <small>{row.detail || row.id}</small>
                    </span>
                  </label>
                ))}
                {listedDevices.length === 0 && (
                  <div className="device-interception-empty">
                    {deviceFilter ? "No devices match." : "No devices yet. Connect a device to the lab network first."}
                  </div>
                )}
              </div>
              <div className="device-interception-safety">
                <strong>If ShakerProxy is unsure which device it is</strong>
                <span>
                  Devices are matched by their ShakerProxy device ID using current address evidence. Missing, expired, or
                  ambiguous identity is passed through, never guessed. Existing TLS sessions can remain on their
                  previous interception decision until the device opens a new connection.
                </span>
              </div>
            </div>
          )}
        </fieldset>
        <label>
          DNS
          <select
            value={mode}
            onChange={(event) => setMode(event.target.value as EncryptedDNSMode)}
            disabled={!enabled || busy}
          >
            <option value="OBSERVE">Just watch DNS (change nothing)</option>
            <option value="BLOCK_KNOWN">Block the encrypted DNS options ticked below</option>
            <option value="ENFORCE_LOCAL">Send all DNS through ShakerProxy</option>
          </select>
        </label>
        <label>
          Settings name
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            maxLength={120}
            required
            disabled={!enabled || busy}
          />
        </label>
        <fieldset>
          <legend>Encrypted DNS (hides lookups from ShakerProxy)</legend>
          <label className="check">
            <input
              type="checkbox"
              checked={blockDoT}
              onChange={(event) => setBlockDoT(event.target.checked)}
              disabled={!enabled || busy}
            />
            <span>Block DNS over TLS (TCP/853)</span>
          </label>
          <label className="check">
            <input
              type="checkbox"
              checked={blockDoQ}
              onChange={(event) => setBlockDoQ(event.target.checked)}
              disabled={!enabled || busy}
            />
            <span>Block DNS over QUIC (UDP/853)</span>
          </label>
          <label className="check">
            <input
              type="checkbox"
              checked={blockDoH}
              onChange={(event) => setBlockDoH(event.target.checked)}
              disabled={!enabled || busy}
            />
            <span>Block known DNS over HTTPS services</span>
          </label>
          <label className="check">
            <input
              type="checkbox"
              checked={blockDoH3}
              onChange={(event) => setBlockDoH3(event.target.checked)}
              disabled={!enabled || busy}
            />
            <span>Block known DNS over HTTP/3 services</span>
          </label>
        </fieldset>
        {catalog.data && catalog.data.resolvers.length > 0 && (
          <details className="traffic-policy-upstreams resolver-catalog">
            <summary>
              Known encrypted DNS services ({catalog.data.resolvers.length}) · {resolverExclusions.length} allowed
            </summary>
            <p>Tick a service to keep it working even when blocking is on.</p>
            <div className="resolver-catalog-list">
              {catalog.data.resolvers.map((resolver) => (
                <label className="check" key={resolver.id}>
                  <input
                    type="checkbox"
                    checked={resolverExclusions.includes(resolver.id)}
                    onChange={(event) =>
                      setResolverExclusions((current) =>
                        event.target.checked ? [...current, resolver.id] : current.filter((id) => id !== resolver.id),
                      )
                    }
                    disabled={!enabled || busy}
                  />
                  <span>
                    {resolver.provider} <small>{resolver.hostnames.slice(0, 3).join(", ")}</small>
                  </span>
                </label>
              ))}
            </div>
          </details>
        )}
        <label className="traffic-policy-upstreams">
          Upstream DNS servers · one IP:53 per line
          <textarea
            value={upstreams}
            onChange={(event) => setUpstreams(event.target.value)}
            rows={3}
            spellCheck={false}
            disabled={!enabled || busy}
          />
          <small>Example: 1.1.1.1:53. Hostnames are rejected to avoid bootstrap loops.</small>
        </label>
        <details className="traffic-policy-upstreams traffic-policy-advanced">
          <summary>Advanced HTTPS options (exclusions, pinned apps, proxy port)</summary>
          <fieldset>
            <legend>Pinned apps</legend>
            <label className="check">
              <input
                type="checkbox"
                checked={autoBypassPinned}
                onChange={(event) => setAutoBypassPinned(event.target.checked)}
                disabled={!enabled || busy || !tlsEnabled}
              />
              <span>Automatically stop decrypting apps that seem to pin certificates (listed mobile clients only)</span>
            </label>
            <label>
              Proxy port
              <input
                type="number"
                min="1024"
                max="65535"
                value={tlsPort}
                onChange={(event) => setTLSPort(event.target.value)}
                disabled={!enabled || busy || !tlsEnabled}
              />
            </label>
            <label>
              Stop decrypting a pinned app for (seconds)
              <input
                type="number"
                min="300"
                max="2592000"
                value={autoBypassTTL}
                onChange={(event) => setAutoBypassTTL(event.target.value)}
                disabled={!enabled || busy || !tlsEnabled || !autoBypassPinned}
              />
            </label>
            <label>
              Maximum automatic exceptions
              <input
                type="number"
                min="16"
                max="10000"
                value={maxDynamicBypasses}
                onChange={(event) => setMaxDynamicBypasses(event.target.value)}
                disabled={!enabled || busy || !tlsEnabled || !autoBypassPinned}
              />
            </label>
          </fieldset>
          <label className="traffic-policy-upstreams">
            TLS host exclusions · never decrypt these hostnames, one per line
            <textarea
              value={tlsExcludeHosts}
              onChange={(event) => setTLSExcludeHosts(event.target.value)}
              rows={3}
              spellCheck={false}
              disabled={!enabled || busy || !tlsEnabled}
            />
            <small>Use exclusions for known pinned or custom-trust apps, for example *.example.test.</small>
          </label>
          <label className="traffic-policy-upstreams">
            TLS destination exclusions · never decrypt traffic to these IPv4 ranges (CIDR), one per line
            <textarea
              value={tlsExcludeCIDRs}
              onChange={(event) => setTLSExcludeCIDRs(event.target.value)}
              rows={3}
              spellCheck={false}
              disabled={!enabled || busy || !tlsEnabled}
            />
          </label>
          <label className="traffic-policy-upstreams">
            Mobile clients that may get automatic pinning exceptions · one “IPv4/CIDR platform” per line
            <textarea
              value={tlsMobileClients}
              onChange={(event) => setTLSMobileClients(event.target.value)}
              rows={3}
              spellCheck={false}
              placeholder="192.0.2.40/32 android-tv"
              disabled={!enabled || busy || !tlsEnabled || !autoBypassPinned}
            />
            <small>Platforms: android, android-tv, ios, tvos. Desktop clients never receive automatic bypasses.</small>
          </label>
        </details>
        <button disabled={!enabled || busy || enforcementBlocked}>
          {busy ? "Checking…" : "Preview traffic policy"}
        </button>
      </form>
      {preview && (
        <section className="traffic-policy-preview" aria-label="Changes to apply">
          <header>
            <strong>Ready to apply</strong>
            <code>{preview.digest.slice(0, 16)}…</code>
          </header>
          <small>
            DNS service {preview.firewall.needs_dns_service ? "needed" : "not needed"} · HTTPS proxy{" "}
            {preview.firewall.needs_mitm_service ? "needed" : "not needed"} · traffic redirect{" "}
            {preview.firewall.needs_nat_prerouting_hook ? "needed" : "not needed"}
          </small>
          <ul>
            {preview.changed_objects.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
          {preview.warnings.map((warning) => (
            <small key={warning}>{warning}</small>
          ))}
          <form onSubmit={applyPolicy}>
            {decryptsEveryDevice && (
              <label>
                Administrator password (always needed to decrypt every device)
                <input name="password" type="password" autoComplete="current-password" required />
              </label>
            )}
            <button disabled={busy || enforcementBlocked}>{busy ? "Applying…" : "Apply traffic policy"}</button>
          </form>
        </section>
      )}
      {document?.previous && (
        <details className="traffic-policy-rollback">
          <summary>Go back to the previous settings</summary>
          <p>This saves the previous settings as a new revision; the history is kept.</p>
          <form onSubmit={rollbackPolicy}>
            <button className="quiet" disabled={busy}>
              Restore previous settings
            </button>
          </form>
        </details>
      )}
    </section>
  )
}
