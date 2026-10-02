import React, { FormEvent, useEffect, useState } from "react"
import { ErrorBox } from "../../shell/common"
import { usePolling } from "../../shell/hooks"
import { navigate } from "../../features"
import { deviceQuery } from "../../lib/trafficPresets"
import { DeviceAuditLog, DeviceTrafficDeletionJobs } from "./DeviceHistory"
import { DeviceRow } from "./DeviceRow"
import { DeviceDetailDrawer } from "./DeviceDetailDrawer"
import { AddressAliasManager, DeviceAliasExportControls, DeviceAliasImportControls } from "./DeviceAliases"
import {
  applyDeviceListFiltersToURL,
  defaultDeviceListFilters,
  deviceListAPIPath,
  parseDeviceListFilters,
} from "../../lib/deviceFilters"
import type { DeviceListFilters } from "../../lib/deviceFilters"
import { applySelectedDeviceToURL, selectedDeviceFromURL } from "../../lib/deviceDetailURL"
import { api, describeError } from "../../api"
import type { Device, Interface, InventorySnapshot } from "../../types"

export function deviceListFiltersFromURL(): DeviceListFilters {
  return parseDeviceListFilters(new URL(window.location.href).searchParams)
}

export function updateDeviceListURL(filters: DeviceListFilters) {
  window.history.replaceState({}, "", applyDeviceListFiltersToURL(new URL(window.location.href), filters))
}

export function DeviceInventory() {
  const [snapshot, setSnapshot] = useState<InventorySnapshot | null>(null)
  const [error, setError] = useState("")
  const [filters, setFilters] = useState<DeviceListFilters>(deviceListFiltersFromURL)
  const [selectedDeviceID, setSelectedDeviceID] = useState(() =>
    selectedDeviceFromURL(new URL(window.location.href).searchParams),
  )
  // The open device drawer is part of this page's URL. When you leave the
  // page (for example "Inspect this device"), drop it from the new page's URL
  // so coming back does not reopen the drawer; Back still restores it.
  useEffect(
    () => () => {
      const url = new URL(window.location.href)
      if (!url.searchParams.has("device_id")) return
      window.history.replaceState(window.history.state, "", applySelectedDeviceToURL(url, ""))
    },
    [],
  )
  const refresh = async () => {
    try {
      const result = await api<InventorySnapshot>(deviceListAPIPath(filters))
      setSnapshot({ ...result, devices: Array.isArray(result.devices) ? result.devices : [] })
      setError("")
    } catch (reason) {
      setError(describeError(reason, "The device list is unavailable"))
    }
  }
  usePolling(() => refresh(), 10_000, [filters])
  function applyFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const next: DeviceListFilters = {
      view: data.get("view") as DeviceListFilters["view"],
      q: String(data.get("q") ?? "").trim(),
      interface: String(data.get("interface") ?? ""),
      vlan_id: String(data.get("vlan_id") ?? ""),
      vendor: String(data.get("vendor") ?? "").trim(),
      category: String(data.get("category") ?? ""),
      tag: String(data.get("tag") ?? ""),
      ip_family: data.get("ip_family") as DeviceListFilters["ip_family"],
      min_confidence: String(data.get("min_confidence") ?? ""),
      warnings: data.get("warnings") as DeviceListFilters["warnings"],
      sort: data.get("sort") as DeviceListFilters["sort"],
      direction: data.get("direction") as DeviceListFilters["direction"],
    }
    updateDeviceListURL(next)
    setFilters(next)
  }
  function resetFilters() {
    updateDeviceListURL(defaultDeviceListFilters)
    setFilters(defaultDeviceListFilters)
  }
  function viewDeviceTraffic(deviceID: string) {
    const formerIDs = snapshot?.devices.find((device) => device.id === deviceID)?.former_ids ?? []
    navigate("traffic", { traffic_q: deviceQuery(deviceID, "", formerIDs), traffic_source: "" })
  }
  function selectDevice(deviceID: string) {
    window.history.replaceState({}, "", applySelectedDeviceToURL(new URL(window.location.href), deviceID))
    setSelectedDeviceID(deviceID)
  }
  return (
    <section className="device-inventory">
      <div className="device-head">
        <div>
          <p className="eyebrow">Devices</p>
          <h2>Everything ShakerProxy has seen</h2>
          <p>
            ShakerProxy recognises devices from the lab network's address assignments (DHCP) and from the addresses it
            sees them use (ARP and IPv6 neighbors), so devices with a fixed IP appear too. Each device is shown by name
            and IP; until you name it, the name says what it is when its traffic shows that. The confidence shows how sure
            it is about which device is which. Corrections need your password and are recorded in the change history.
          </p>
        </div>
        <span>{snapshot ? `${snapshot.devices.filter((device) => device.online).length} ONLINE` : "LOADING"}</span>
      </div>
      {error && <ErrorBox message={error} onRetry={() => void refresh()} />}
      <form className="device-filters" key={JSON.stringify(filters)} onSubmit={applyFilters}>
        <label>
          View
          <select name="view" defaultValue={filters.view}>
            <option value="all">All devices</option>
            <option value="online">Online now</option>
            <option value="recent">Seen in 24 hours</option>
          </select>
        </label>
        <label className="device-filter-search">
          Search
          <input
            name="q"
            defaultValue={filters.q}
            maxLength={128}
            placeholder="name, owner, MAC, IP, hostname, vendor, notes"
          />
        </label>
        <div className="device-filter-actions">
          <button type="submit" className="quiet">
            Search
          </button>
          <button type="button" className="quiet" onClick={resetFilters}>
            Reset
          </button>
        </div>
        <details className="device-filters-more">
          <summary>More filters and sorting</summary>
          <div className="device-filters-more-grid">
            <label>
              Interface
              <input
                name="interface"
                defaultValue={filters.interface}
                maxLength={15}
                pattern="[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}"
                placeholder="enp2s0.20"
              />
            </label>
            <label>
              VLAN
              <input name="vlan_id" defaultValue={filters.vlan_id} type="number" min={1} max={4094} />
            </label>
            <label>
              Vendor
              <input name="vendor" defaultValue={filters.vendor} maxLength={256} />
            </label>
            <label>
              Category
              <input
                name="category"
                defaultValue={filters.category}
                maxLength={64}
                pattern="[a-z0-9][a-z0-9_-]{0,63}"
              />
            </label>
            <label>
              Tag
              <input name="tag" defaultValue={filters.tag} maxLength={64} />
            </label>
            <label>
              IP family
              <select name="ip_family" defaultValue={filters.ip_family}>
                <option value="">Any family</option>
                <option value="ipv4">IPv4 evidence</option>
                <option value="ipv6">IPv6 evidence</option>
              </select>
            </label>
            <label>
              Minimum confidence
              <input name="min_confidence" defaultValue={filters.min_confidence} type="number" min={0} max={100} />
            </label>
            <label>
              Warnings
              <select name="warnings" defaultValue={filters.warnings}>
                <option value="">Any warning state</option>
                <option value="present">Warnings present</option>
                <option value="none">No warnings</option>
              </select>
            </label>
            <label>
              Sort
              <select name="sort" defaultValue={filters.sort}>
                <option value="last_seen">Last seen</option>
                <option value="first_seen">First seen</option>
                <option value="name">Name</option>
                <option value="confidence">Confidence</option>
              </select>
            </label>
            <label>
              Direction
              <select name="direction" defaultValue={filters.direction}>
                <option value="desc">Descending</option>
                <option value="asc">Ascending</option>
              </select>
            </label>
          </div>
          <button type="submit" className="quiet">
            Apply filters
          </button>
        </details>
      </form>
      {snapshot?.devices.length === 0 && (
        <div className="device-empty">
          {filters.q || filters.view !== "all"
            ? "No devices match. Press Reset to see every device."
            : "No devices yet. Connect a device to the lab port or lab Wi-Fi; it appears here within a minute."}
        </div>
      )}
      {snapshot?.devices.map((device) => (
        <DeviceRow
          key={device.id}
          device={device}
          devices={snapshot.devices}
          onChanged={refresh}
          onInspect={() => selectDevice(device.id)}
          onViewTraffic={() => viewDeviceTraffic(device.id)}
          platformHint={snapshot.platform_hints?.[device.id]}
        />
      ))}
      {snapshot && (
        <p className="evidence-time">
          {new Date(snapshot.evidence_as_of).getUTCFullYear() > 1970
            ? `Evidence reconciled ${new Date(snapshot.evidence_as_of).toLocaleString()}`
            : "No lease evidence source has been reconciled."}
        </p>
      )}
      <details className="device-advanced">
        <summary>Import, export and name devices by address</summary>
        <DeviceAliasExportControls />
        <DeviceAliasImportControls onChanged={refresh} />
        {snapshot && <AddressAliasManager aliases={snapshot.address_aliases ?? []} onChanged={refresh} />}
      </details>
      <DeviceAuditLog devices={snapshot?.devices ?? []} />
      <DeviceTrafficDeletionJobs />
      {selectedDeviceID && (
        <DeviceDetailDrawer
          deviceID={selectedDeviceID}
          onChanged={refresh}
          onClose={() => selectDevice("")}
          onViewTraffic={() => viewDeviceTraffic(selectedDeviceID)}
          platformHint={snapshot?.platform_hints?.[selectedDeviceID]}
        />
      )}
    </section>
  )
}
