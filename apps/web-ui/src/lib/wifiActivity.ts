import type { RecentEvent } from "../types"

// A device's Wi-Fi activity, from ShakerProxy's passive Wi-Fi monitor: the
// networks it searched for by name (often its saved networks), when it
// joined, roamed and left, and the hardware addresses it used.

export type WiFiNetworkSearch = { ssid: string; count: number; last: string }
export type WiFiMoment = { at: string; text: string; problem: boolean }
export type WiFiAddress = { mac: string; randomized: boolean; possible: boolean; last: string }
export type WiFiActivity = { networks: WiFiNetworkSearch[]; moments: WiFiMoment[]; addresses: WiFiAddress[] }

// The query for a device's Wi-Fi events (beacons are about networks, not
// devices).
export function wifiActivityQuery(deviceIDs: readonly string[], time = "last_7d"): string {
  const ids = deviceIDs.filter((id) => /^device-[a-f0-9]{32}$/.test(id)).slice(0, 12)
  const device = ids.length === 1 ? `device.id:${ids[0]}` : `(${ids.map((id) => `device.id:${id}`).join(" OR ")})`
  return `time:${time} AND kind:wifi.* AND NOT kind:wifi.beacon_summary AND ${device}`
}

function name(ssid?: string, bssid?: string): string {
  return ssid ? `“${ssid}”` : bssid ?? "a network"
}

export function summarizeWiFi(events: readonly RecentEvent[]): WiFiActivity {
  const networks = new Map<string, WiFiNetworkSearch>()
  const addresses = new Map<string, WiFiAddress>()
  const moments: WiFiMoment[] = []
  for (const event of events) {
    const wifi = event.wifi
    if (!wifi || !event.kind.startsWith("wifi.")) continue
    if (wifi.client_mac) {
      const current = addresses.get(wifi.client_mac)
      if (!current) addresses.set(wifi.client_mac, { mac: wifi.client_mac, randomized: Boolean(wifi.randomized_mac), possible: Boolean(wifi.possible_mac), last: event.occurred_at })
      else if (event.occurred_at > current.last) current.last = event.occurred_at
    }
    switch (event.kind) {
      case "wifi.probe": {
        if (!wifi.ssid) break
        const current = networks.get(wifi.ssid)
        if (!current) networks.set(wifi.ssid, { ssid: wifi.ssid, count: 1, last: event.occurred_at })
        else {
          current.count++
          if (event.occurred_at > current.last) current.last = event.occurred_at
        }
        break
      }
      case "wifi.assoc": {
        const failed = wifi.success === false
        const text = wifi.no_response
          ? `Tried to join ${name(wifi.ssid, wifi.bssid)}: no answer`
          : failed
            ? `Refused by ${name(wifi.ssid, wifi.bssid)}: ${wifi.status ?? "unknown reason"}`
            : wifi.reassociation && wifi.previous_bssid
              ? `Roamed to ${wifi.bssid ?? name(wifi.ssid)} on ${name(wifi.ssid, wifi.bssid)}`
              : `Joined ${name(wifi.ssid, wifi.bssid)}`
        moments.push({ at: event.occurred_at, text, problem: failed || Boolean(wifi.no_response) })
        break
      }
      case "wifi.auth":
        if (wifi.success === false) moments.push({ at: event.occurred_at, text: `Authentication with ${name(wifi.ssid, wifi.bssid)} failed: ${wifi.status ?? "unknown"}`, problem: true })
        break
      case "wifi.deauth":
      case "wifi.disassoc": {
        const reason = wifi.protected ? "reason hidden" : wifi.reason ?? ""
        const who = wifi.direction === "from_ap" ? "Dropped by" : "Left"
        moments.push({ at: event.occurred_at, text: `${who} ${name(wifi.ssid, wifi.bssid)}${reason ? ` (${reason})` : ""}`, problem: wifi.direction === "from_ap" })
        break
      }
    }
  }
  return {
    networks: [...networks.values()].sort((left, right) => right.count - left.count || left.ssid.localeCompare(right.ssid)),
    moments: moments.sort((left, right) => right.at.localeCompare(left.at)),
    addresses: [...addresses.values()].sort((left, right) => right.last.localeCompare(left.last)),
  }
}
