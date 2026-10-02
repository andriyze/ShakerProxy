import type { AddressObservation } from "../types"

// DeviceAddress is one address of a device as people think of it: the
// inventory keeps a time-bounded observation per sighting window (traffic
// attribution needs them), but the page shows each address once.
export type DeviceAddress = {
  address: string
  interface?: string
  vlan_id?: number
  active: boolean
  first_seen: string
  last_seen: string
  windows: number
}

function scopeKey(item: AddressObservation): string {
  return `${item.address}\u0000${item.interface ?? ""}\u0000${item.vlan_id ?? ""}`
}

// uniqueAddresses merges the observations of each address on the same
// interface and VLAN. An address is active when any of its windows is, so an
// expired sighting never shows next to the current one. Active addresses come
// first, then the most recently seen.
export function uniqueAddresses(addresses: AddressObservation[] | null | undefined): DeviceAddress[] {
  const merged = new Map<string, DeviceAddress>()
  for (const item of addresses ?? []) {
    const key = scopeKey(item)
    const current = merged.get(key)
    if (!current) {
      merged.set(key, {
        address: item.address,
        interface: item.interface,
        vlan_id: item.vlan_id,
        active: item.active,
        first_seen: item.valid_from,
        last_seen: item.valid_until,
        windows: 1,
      })
      continue
    }
    current.active ||= item.active
    current.windows += 1
    if (Date.parse(item.valid_from) < Date.parse(current.first_seen)) current.first_seen = item.valid_from
    if (Date.parse(item.valid_until) > Date.parse(current.last_seen)) current.last_seen = item.valid_until
  }
  return Array.from(merged.values()).sort((left, right) => {
    if (left.active !== right.active) return left.active ? -1 : 1
    return Date.parse(right.last_seen) - Date.parse(left.last_seen) || left.address.localeCompare(right.address)
  })
}
