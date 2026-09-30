// Helpers for the single DNS & HTTPS policy editor. Pure.

export const MAX_SELECTED_DEVICES = 512

export type TLSMode = "off" | "all" | "selected"

const DEVICE_ID = /^device-[a-f0-9]{32}$/

export function tlsModeFromPolicy(tls: { enabled: boolean; selected_device_ids?: string[] | null }): TLSMode {
  if (!tls.enabled) return "off"
  return Array.isArray(tls.selected_device_ids) && tls.selected_device_ids.length > 0 ? "selected" : "all"
}

export function validSelectedDevices(ids: readonly string[] | null | undefined): string[] {
  return Array.isArray(ids) ? ids.filter((id) => DEVICE_ID.test(id)) : []
}

// tlsSelection maps the three-way choice onto the policy fields. "all" and
// "off" send an empty list; "selected" sends a sorted, bounded list.
export function tlsSelection(
  mode: TLSMode,
  selected: Iterable<string>,
): { enabled: boolean; selected_device_ids: string[] } {
  if (mode === "off") return { enabled: false, selected_device_ids: [] }
  if (mode === "all") return { enabled: true, selected_device_ids: [] }
  const ids = [...new Set(validSelectedDevices([...selected]))].sort()
  if (ids.length === 0) throw new Error("Pick at least one device to decrypt, or choose “Decrypt all devices”.")
  if (ids.length > MAX_SELECTED_DEVICES) {
    throw new Error(`You can pick at most ${MAX_SELECTED_DEVICES} devices. Choose “Decrypt all devices” instead.`)
  }
  return { enabled: true, selected_device_ids: ids }
}

export function splitList(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((item) => item.trim())
    .filter(Boolean)
}

export type MobileClient = { cidr: string; platform: "android" | "android-tv" | "ios" | "tvos" }
const PLATFORMS = new Set(["android", "android-tv", "ios", "tvos"])

export function parseMobileClients(text: string): MobileClient[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line, index) => {
      const fields = line.split(/\s+/)
      if (fields.length !== 2) throw new Error(`Mobile client line ${index + 1} must be: IPv4/CIDR platform`)
      const platform = fields[1].toLowerCase()
      if (!PLATFORMS.has(platform)) {
        throw new Error(`Mobile client line ${index + 1}: platform must be android, android-tv, ios or tvos`)
      }
      return { cidr: fields[0], platform: platform as MobileClient["platform"] }
    })
}
