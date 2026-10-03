import type { Device, DevicePlatformHint, DeviceServiceHint } from "../types"

// A device is shown as "<name> · <IPv4>" everywhere, so testers can tell
// devices apart by what they are and find them by address. Private Wi-Fi MACs
// change on every connection, so a MAC is never the name.

export type DeviceNameSource = "friendly" | "broadcast" | "platform" | "services" | "vendor" | "private" | ""

const PRIVATE_ADDRESS_NAME = "Device with a private Wi-Fi address"

function newest<T>(items: readonly T[], at: (item: T) => string): T | undefined {
  let best: T | undefined
  for (const item of items) {
    if (!best || Date.parse(at(item)) > Date.parse(at(best))) best = item
  }
  return best
}

function isIPv4(value: string | undefined): value is string {
  return !!value && /^\d{1,3}(\.\d{1,3}){3}$/.test(value)
}

// deviceIPv4 is the address to show: the one pinned to the device, else its
// current IPv4, else the fallback (the address an event was attributed by),
// else the last IPv4 it had.
export function deviceIPv4(device: Device, fallback = ""): string {
  if (isIPv4(device.pinned_address)) return device.pinned_address
  const ipv4 = (device.addresses ?? []).filter((address) => isIPv4(address.address))
  const current = newest(
    ipv4.filter((address) => address.active),
    (address) => address.observed_at,
  )
  if (current) return current.address
  if (isIPv4(fallback)) return fallback
  return newest(ipv4, (address) => address.observed_at)?.address ?? ""
}

// locallyAdministered reports a private ("randomized") MAC address.
export function locallyAdministered(mac: string): boolean {
  const first = Number.parseInt(mac.slice(0, 2), 16)
  return Number.isFinite(first) && (first & 0x02) !== 0
}

export function deviceMAC(device: Device): string {
  return newest(
    (device.identities ?? []).filter((identity) => identity.kind === "MAC"),
    (identity) => identity.last_seen,
  )?.value ?? ""
}

// deviceName picks the best name, in order: the name the administrator set,
// the name the device broadcasts about itself (its DHCP hostname), what its
// connectivity checks say it is, its MAC vendor, or that it uses a private
// Wi-Fi address.
export function deviceName(device: Device, hint?: DevicePlatformHint, serviceHint?: DeviceServiceHint): { name: string; source: DeviceNameSource } {
  const friendly = device.friendly_name?.trim()
  if (friendly) return { name: friendly, source: "friendly" }
  const broadcast = newest(device.hostnames ?? [], (hostname) => hostname.last_seen)?.hostname?.trim()
  if (broadcast) {
    // Hostname evidence is lower-cased; the DHCP request keeps the device's
    // own spelling ("iPad").
    const spelled = device.observed_dhcp?.host_name?.trim()
    return { name: spelled && spelled.toLowerCase() === broadcast.toLowerCase() ? spelled : broadcast, source: "broadcast" }
  }
  if (hint?.platform) return { name: hint.platform, source: "platform" }
  if (serviceHint?.type) return { name: serviceHint.type, source: "services" }
  if (device.vendor?.name) return { name: device.vendor.name, source: "vendor" }
  const macs = (device.identities ?? []).filter((identity) => identity.kind === "MAC")
  if (macs.length > 0 && macs.every((identity) => locallyAdministered(identity.value))) {
    return { name: PRIVATE_ADDRESS_NAME, source: "private" }
  }
  return { name: "", source: "" }
}

// platformEvidence says how a platform hint was found, for the line under a
// device's title.
export function platformEvidence(hint: DevicePlatformHint): string {
  if (hint.source === "dhcp") return `Identified from its DHCP request: ${hint.detail ?? ""}`.trim()
  return `Identified from its system traffic to ${hint.domain ?? ""}`.trim()
}

// dhcpIdentityParts is what a device's DHCP request on the lab said, for the
// Devices page: its own name, its DHCP client and the server that answered.
export function dhcpIdentityParts(device: Device): string[] {
  const observed = device.observed_dhcp
  if (!observed) return []
  const parts: string[] = []
  if (observed.host_name) parts.push(`calls itself ${observed.host_name}`)
  if (observed.vendor_class) parts.push(observed.vendor_class)
  if (observed.parameter_list) parts.push(`asks for options ${observed.parameter_list}`)
  if (observed.server) parts.push(`answered by ${observed.server}${observed.router && observed.router !== observed.server ? ` (gateway ${observed.router})` : ""}`)
  return parts
}

// deviceTitle is "<name> · <IPv4>", or whichever of the two is known, or the
// MAC or ID as a last resort.
export function deviceTitle(device: Device, ip = "", hint?: DevicePlatformHint, serviceHint?: DeviceServiceHint): string {
  const { name } = deviceName(device, hint, serviceHint)
  const address = deviceIPv4(device, ip)
  if (name && address) return `${name} · ${address}`
  return name || address || deviceMAC(device) || device.id
}

// eventDeviceTitle titles an event's device: from the inventory when it is
// known (including records merged into it), else the event's own name and
// address.
export function eventDeviceTitle(
  event: { device_id?: string; device_friendly_name?: string; attribution_evidence?: { address: string } },
  directory?: DeviceDirectory,
): string {
  const ip = event.attribution_evidence?.address ?? ""
  const known = event.device_id ? directory?.get(event.device_id) : undefined
  if (known) return deviceTitle(known.device, ip, known.hint, known.services)
  const name = event.device_friendly_name?.trim() ?? ""
  if (name && isIPv4(ip)) return `${name} · ${ip}`
  return name || event.device_id || ""
}

export type DeviceDirectory = Map<string, { device: Device; hint?: DevicePlatformHint; services?: DeviceServiceHint }>

// deviceDirectory indexes devices by their ID and the IDs of records merged
// into them, so traffic recorded before a merge finds the device.
export function deviceDirectory(
  devices: readonly Device[],
  hints: Record<string, DevicePlatformHint> = {},
  services: Record<string, DeviceServiceHint> = {},
): DeviceDirectory {
  const directory: DeviceDirectory = new Map()
  for (const device of devices) {
    const entry = { device, hint: hints[device.id], services: services[device.id] }
    for (const id of device.former_ids ?? []) directory.set(id, entry)
  }
  for (const device of devices) directory.set(device.id, { device, hint: hints[device.id], services: services[device.id] })
  return directory
}

// serviceSummary is a short "AirPlay, HomeKit, printing" line of the service
// labels a device uses, for a device row.
export function serviceSummary(hint: DeviceServiceHint | undefined, max = 4): string {
  if (!hint) return ""
  const labels: string[] = []
  // Guarded: a hint from an older or partial response may have no list.
  for (const service of hint.services ?? []) {
    const label = service.label || service.service
    if (label && !labels.includes(label)) labels.push(label)
    if (labels.length >= max) break
  }
  return labels.join(", ")
}

// splitDeviceTitle separates "name · IP" so a narrow column can show the name
// and the IP on separate lines.
export function splitDeviceTitle(title: string): [string, string] {
  const at = title.lastIndexOf(" · ")
  if (at < 0) return [title, ""]
  const ip = title.slice(at + 3)
  return isIPv4(ip) ? [title.slice(0, at), ip] : [title, ""]
}
