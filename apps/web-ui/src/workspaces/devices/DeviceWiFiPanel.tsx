import React, { useEffect, useState } from "react"
import { api } from "../../api"
import { summarizeWiFi, wifiActivityQuery, type WiFiActivity } from "../../lib/wifiActivity"
import type { RecentEventPage } from "../../types"

// DeviceWiFiPanel shows what a device did on Wi-Fi in the last week, when
// ShakerProxy's passive Wi-Fi monitor recorded any of it.
export function DeviceWiFiPanel({ deviceID, formerIDs }: { deviceID: string; formerIDs?: readonly string[] }) {
  const [activity, setActivity] = useState<WiFiActivity | null>(null)
  const ids = [deviceID, ...(formerIDs ?? [])].join(",")
  useEffect(() => {
    let mounted = true
    const parameters = new URLSearchParams({ limit: "100", q: wifiActivityQuery(ids.split(",")) })
    api<RecentEventPage>(`/api/v1/events?${parameters}`)
      .then((page) => mounted && setActivity(summarizeWiFi(page.events ?? [])))
      .catch(() => mounted && setActivity(null))
    return () => {
      mounted = false
    }
  }, [ids])
  if (!activity || (activity.networks.length === 0 && activity.moments.length === 0)) return null
  return (
    <section className="device-wifi" aria-labelledby="device-wifi-title">
      <h3 id="device-wifi-title">Wi-Fi</h3>
      {activity.networks.length > 0 && (
        <div>
          <h4>Networks it searched for</h4>
          <p className="device-wifi__hint">Devices ask by name for networks they have saved, so this often shows where a device has been.</p>
          <ul className="device-wifi__networks">
            {activity.networks.slice(0, 20).map((network) => (
              <li key={network.ssid}>
                <span>{network.ssid}</span>
                <small>
                  {network.count}× · {new Date(network.last).toLocaleString()}
                </small>
              </li>
            ))}
          </ul>
        </div>
      )}
      {activity.moments.length > 0 && (
        <div>
          <h4>Joins and disconnects</h4>
          <ul className="device-wifi__moments">
            {activity.moments.slice(0, 12).map((moment) => (
              <li key={`${moment.at}-${moment.text}`} className={moment.problem ? "problem" : undefined}>
                <time dateTime={moment.at}>{new Date(moment.at).toLocaleString()}</time> {moment.text}
              </li>
            ))}
          </ul>
        </div>
      )}
      {activity.addresses.length > 0 && (
        <div>
          <h4>Addresses it used on Wi-Fi</h4>
          <ul className="device-wifi__addresses">
            {activity.addresses.slice(0, 12).map((address) => (
              <li key={address.mac} className="mono">
                {address.mac}
                {address.randomized ? " · randomized" : ""}
                {address.possible ? " · possible match (fingerprint)" : ""}
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  )
}
