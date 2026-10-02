// Network plan extension for the Wi-Fi access point (§8, plan key "wifi").
// Rendered inside the shell's plan builder form, so it uses no <form>.
import { useId, useMemo, useState } from "react"
import type { PlanExtensionProps, PlanInterface } from "./registry"
import { registerPlanExtension } from "./register"
import { BAND_OPTIONS, DEFAULT_CHANNEL, SECURITY_OPTIONS, apSupport, bandSupported, browserCountry, channelHint, channelsFor, defaultWifiPlan, generatePassphrase, isValidCountryCode, normalizeWifiPlan, utf8Length, validateWifiPlan, wifiTopologySupport, wirelessInterfaces, type WifiFieldIssue } from "./wifi-model"
import { serverPlanIssues } from "./plan-issues"
import { Toggle } from "./shared"
import type { PlanValidationResult, WifiBand, WifiPlan } from "./types"
import "./features.css"

const AP_ROLE = "WIFI_AP"
const RELEASED_ROLE = "UNUSED"

let countryNames: { code: string; name: string }[] | undefined

// countryOptions lists ISO regions by display name, derived from Intl so no
// country table ships with the UI.
function countryOptions(): { code: string; name: string }[] {
  if (countryNames) return countryNames
  const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  const result: { code: string; name: string }[] = []
  let names: Intl.DisplayNames | undefined
  try {
    names = new Intl.DisplayNames(undefined, { type: "region", fallback: "none" })
  } catch {
    names = undefined
  }
  for (const first of letters) {
    for (const second of letters) {
      const code = first + second
      if (!isValidCountryCode(code)) continue
      const name = names?.of(code)
      if (name && name !== code) result.push({ code, name })
    }
  }
  if (result.length === 0) result.push({ code: "US", name: "United States" })
  countryNames = result.sort((a, b) => a.name.localeCompare(b.name))
  return countryNames
}

function supportLabel(iface: PlanInterface): { text: string; tone: "good" | "warn" | "bad" } {
  switch (apSupport(iface)) {
    case "supported":
      return { text: "Supports access-point mode", tone: "good" }
    case "unsupported":
      return { text: "Does not support access-point mode", tone: "bad" }
    default:
      return { text: "Access-point support unknown — it may not work", tone: "warn" }
  }
}

function issueFor(issues: WifiFieldIssue[], field: WifiFieldIssue["field"]): string | undefined {
  return issues.find((issue) => issue.field === field)?.message
}

// Fields this editor renders messages next to; server issues for any other
// wifi path are listed at the top.
const FIELDS_WITH_MESSAGES = new Set(["interface", "ssid", "country_code", "security", "passphrase", "band", "channel", "bridge_with_lab", "client_isolation", "hidden"])

// Beyond PlanExtensionProps the shell may pass the plan topology and the
// server's plan validation (preview) so problems show next to their fields.
export type WifiPlanEditorProps = PlanExtensionProps & { topology?: string; validation?: PlanValidationResult }

export function WifiPlanEditor({ value, onChange, interfaces, roles, onRoleChange, disabled, topology, validation }: WifiPlanEditorProps) {
  const country = useMemo(() => browserCountry(), [])
  const plan = useMemo(() => normalizeWifiPlan(value, country), [value, country])
  const [showPassphrase, setShowPassphrase] = useState(false)
  const baseID = useId()
  const id = (name: string) => `${baseID}-${name}`
  const candidates = useMemo(() => wirelessInterfaces(interfaces), [interfaces])
  const apInterface = interfaces.find((iface) => roles[iface.stable_id] === AP_ROLE)
  // A wired LAB port and the access point must share one bridged lab network
  // (the plan validator rejects bridge_with_lab=false in that case).
  const hasWiredLab = interfaces.some((iface) => iface.stable_id !== apInterface?.stable_id && roles[iface.stable_id] === "LAB")
  const issues = validateWifiPlan(plan, { wiredLab: hasWiredLab })
  if (plan.enabled && !apInterface) issues.unshift({ field: "interface", message: "Choose the Wi-Fi adapter that will broadcast the lab network." })
  const server = plan.enabled ? serverPlanIssues(validation, "wifi", "WIFI_") : []
  const generalServer = server.filter((issue) => !FIELDS_WITH_MESSAGES.has(issue.field))
  const topologySupport = wifiTopologySupport(topology, roles)
  const set = (change: Partial<WifiPlan>) => onChange({ ...plan, ...change })
  // Client-side problems win; otherwise show the server's errors and warnings for the field.
  const messagesFor = (field: WifiFieldIssue["field"]) => {
    const client = issueFor(issues, field)
    if (client) return [{ message: client, severity: "error" as const }]
    return server.filter((issue) => issue.field === field)
  }
  const invalid = (field: WifiFieldIssue["field"]) => (messagesFor(field).some((item) => item.severity === "error") ? { "aria-invalid": true as const, "aria-describedby": id(`${field}-error`) } : {})
  const fieldError = (field: WifiFieldIssue["field"]) => {
    const messages = messagesFor(field)
    return messages.length ? (
      <div id={id(`${field}-error`)}>
        {messages.map((item) => (
          <p key={item.message} className={item.severity === "error" ? "lgf-field-error" : "lgf-field-warning"}>
            {item.message}
          </p>
        ))}
      </div>
    ) : null
  }

  const chooseInterface = (stableID: string) => {
    if (apInterface && apInterface.stable_id !== stableID) onRoleChange(apInterface.stable_id, RELEASED_ROLE)
    onRoleChange(stableID, AP_ROLE)
  }

  const setEnabled = (enabled: boolean) => {
    if (enabled) {
      const base = value && typeof value === "object" ? plan : defaultWifiPlan(country)
      onChange({ ...base, enabled: true, passphrase: base.passphrase || generatePassphrase() })
      const best = candidates[0]
      if (!apInterface && best && apSupport(best) !== "unsupported") onRoleChange(best.stable_id, AP_ROLE)
    } else {
      onChange({ ...plan, enabled: false })
      if (apInterface) onRoleChange(apInterface.stable_id, RELEASED_ROLE)
    }
  }

  const setBand = (band: WifiBand) => set({ band, channel: DEFAULT_CHANNEL[band] })
  const channels = channelsFor(plan.band, plan.country_code)
  const bandOK = bandSupported(apInterface, plan.band)
  const countries = countryOptions()
  const ssidBytes = utf8Length(plan.ssid)

  if (!topologySupport.supported) {
    return (
      <fieldset className="lgf-plan-ext lgf-wifi" disabled={disabled}>
        <legend>Wi-Fi access point</legend>
        <p className="lgf-hint">{topologySupport.reason}</p>
        {plan.enabled && (
          <div className="lgf-callout lgf-tone-warn" role="alert">
            Wi-Fi is still turned on in this plan, so it will not validate.{" "}
            <button type="button" className="lgf-link" onClick={() => setEnabled(false)}>
              Turn Wi-Fi off
            </button>
          </div>
        )}
      </fieldset>
    )
  }

  return (
    <fieldset className="lgf-plan-ext lgf-wifi" disabled={disabled}>
      <legend>Wi-Fi access point</legend>
      <p className="lgf-hint">ShakerProxy can broadcast its own Wi-Fi network so phones, TVs and IoT devices join the lab directly. Everything they do passes through ShakerProxy.</p>
      <Toggle label="Broadcast a lab Wi-Fi network" checked={plan.enabled} onChange={setEnabled} disabled={disabled} />
      {generalServer.length > 0 && (
        <ul className="lgf-server-issues" aria-label="Wi-Fi plan check">
          {generalServer.map((issue) => (
            <li key={`${issue.code}-${issue.message}`} className={issue.severity === "error" ? "lgf-field-error" : "lgf-field-warning"}>
              {issue.message}
            </li>
          ))}
        </ul>
      )}

      {plan.enabled && (
        <>
          <div className="lgf-field" role="radiogroup" aria-labelledby={id("iface-label")} {...(issueFor(issues, "interface") ? { "aria-describedby": id("interface-error") } : {})}>
            <span className="lgf-label" id={id("iface-label")}>
              Wi-Fi adapter
            </span>
            {candidates.length === 0 ? (
              <div className="lgf-callout lgf-tone-warn">No Wi-Fi adapter was found. Plug in a USB Wi-Fi adapter that supports access-point (AP) mode, then refresh this page.</div>
            ) : (
              <div className="lgf-radio-cards">
                {candidates.map((iface) => {
                  const support = supportLabel(iface)
                  const checked = apInterface?.stable_id === iface.stable_id
                  return (
                    <label key={iface.stable_id} className={checked ? "lgf-selected" : undefined}>
                      <input type="radio" name={id("iface")} checked={checked} onChange={() => chooseInterface(iface.stable_id)} />
                      <span>
                        <strong>{iface.name}</strong>
                        <small className={`lgf-tone-${support.tone}`}>{support.text}</small>
                        {iface.wireless_bands && iface.wireless_bands.length > 0 && <small>Bands: {iface.wireless_bands.map((band) => band.replace("GHZ", " GHz")).join(", ")}</small>}
                        {iface.hardware_address && <small className="lgf-mono">{iface.hardware_address}</small>}
                      </span>
                    </label>
                  )
                })}
              </div>
            )}
            {apInterface && apSupport(apInterface) === "unsupported" && <p className="lgf-callout lgf-tone-bad">{apInterface.name} reports that it cannot run an access point. Use a different adapter.</p>}
            {apInterface && apSupport(apInterface) === "unknown" && <p className="lgf-callout lgf-tone-warn">ShakerProxy could not confirm that {apInterface.name} supports access-point mode. The plan check will fail if it does not.</p>}
            {fieldError("interface")}
          </div>

          <div className="lgf-grid-2">
            <div className="lgf-field">
              <label className="lgf-label" htmlFor={id("ssid")}>
                Network name (SSID)
              </label>
              <input id={id("ssid")} className="lgf-input" type="text" value={plan.ssid} autoComplete="off" spellCheck={false} onChange={(event) => set({ ssid: event.target.value })} {...invalid("ssid")} />
              {fieldError("ssid") ?? <p className="lgf-hint">{ssidBytes}/32 bytes. Devices will see this name.</p>}
            </div>
            <div className="lgf-field">
              <label className="lgf-label" htmlFor={id("country")}>
                Country
              </label>
              <select id={id("country")} className="lgf-select" value={plan.country_code} onChange={(event) => set({ country_code: event.target.value, channel: channelsFor(plan.band, event.target.value).includes(plan.channel) ? plan.channel : DEFAULT_CHANNEL[plan.band] })} {...invalid("country_code")}>
                {!countries.some((item) => item.code === plan.country_code) && <option value={plan.country_code}>{plan.country_code}</option>}
                {countries.map((item) => (
                  <option key={item.code} value={item.code}>
                    {item.name} ({item.code})
                  </option>
                ))}
              </select>
              {fieldError("country_code") ?? <p className="lgf-hint">Where ShakerProxy is used; it decides which channels are legal.</p>}
            </div>
          </div>

          <div className="lgf-field" role="radiogroup" aria-labelledby={id("security-label")}>
            <span className="lgf-label" id={id("security-label")}>
              Security
            </span>
            <div className="lgf-radio-cards">
              {SECURITY_OPTIONS.map((option) => (
                <label key={option.value} className={plan.security === option.value ? "lgf-selected" : undefined}>
                  <input type="radio" name={id("security")} checked={plan.security === option.value} onChange={() => set({ security: option.value, passphrase: option.value === "OPEN" ? "" : plan.passphrase || generatePassphrase() })} />
                  <span>
                    <strong>{option.label}</strong>
                    <small>{option.detail}</small>
                  </span>
                </label>
              ))}
            </div>
            {fieldError("security")}
          </div>

          {plan.security !== "OPEN" && (
            <div className="lgf-field">
              <label className="lgf-label" htmlFor={id("passphrase")}>
                Password
              </label>
              <div className="lgf-inline-form">
                <input id={id("passphrase")} className="lgf-input lgf-mono" type={showPassphrase ? "text" : "password"} value={plan.passphrase} autoComplete="new-password" spellCheck={false} onChange={(event) => set({ passphrase: event.target.value })} {...invalid("passphrase")} />
                <button type="button" className="lgf-button lgf-secondary" aria-pressed={showPassphrase} onClick={() => setShowPassphrase(!showPassphrase)}>
                  {showPassphrase ? "Hide" : "Show"}
                </button>
                <button
                  type="button"
                  className="lgf-button lgf-secondary"
                  onClick={() => {
                    set({ passphrase: generatePassphrase() })
                    setShowPassphrase(true)
                  }}
                >
                  Generate
                </button>
              </div>
              {fieldError("passphrase") ?? <p className="lgf-hint">8–63 characters. Generated passwords avoid look-alike characters so they are easy to type on a TV remote.</p>}
            </div>
          )}

          <div className="lgf-grid-2">
            <div className="lgf-field" role="radiogroup" aria-labelledby={id("band-label")}>
              <span className="lgf-label" id={id("band-label")}>
                Band
              </span>
              <div className="lgf-segmented">
                {BAND_OPTIONS.map((option) => (
                  <button key={option.value} type="button" role="radio" aria-checked={plan.band === option.value} className={plan.band === option.value ? "lgf-selected" : undefined} onClick={() => setBand(option.value)}>
                    {option.label}
                  </button>
                ))}
              </div>
              <p className="lgf-hint">{BAND_OPTIONS.find((option) => option.value === plan.band)?.detail}</p>
              {bandOK === false && <p className="lgf-field-error">{apInterface?.name} does not report {plan.band === "5GHZ" ? "5 GHz" : "2.4 GHz"} support.</p>}
              {bandOK !== false && fieldError("band")}
            </div>
            <div className="lgf-field">
              <label className="lgf-label" htmlFor={id("channel")}>
                Channel
              </label>
              <select id={id("channel")} className="lgf-select" value={plan.channel} onChange={(event) => set({ channel: Number(event.target.value) })} {...invalid("channel")}>
                {!channels.includes(plan.channel) && <option value={plan.channel}>{plan.channel} (not allowed)</option>}
                {channels.map((channel) => (
                  <option key={channel} value={channel}>
                    {channel}
                    {channel === DEFAULT_CHANNEL[plan.band] ? " (default)" : ""}
                  </option>
                ))}
              </select>
              {fieldError("channel") ?? <p className="lgf-hint">{channelHint(plan.band, plan.channel)} Radar (DFS) channels are left out so the network never switches channel mid-test.</p>}
            </div>
          </div>

          {messagesFor("bridge_with_lab").some((item) => item.severity === "error") ? (
            <div className="lgf-callout lgf-tone-warn" role="alert">
              {messagesFor("bridge_with_lab")[0].message}{" "}
              <button type="button" className="lgf-link" onClick={() => set({ bridge_with_lab: true })}>
                Share one lab network
              </button>
            </div>
          ) : (
            <p className="lgf-hint">
              {topology === "TRANSPARENT_BRIDGE"
                ? "The access point joins ShakerProxy's inline bridge beside the device port: Wi-Fi devices get their address, gateway and DNS from your router through ShakerProxy, and are recorded and controlled like the wired device."
                : hasWiredLab
                  ? "Wi-Fi and wired lab devices share one lab network (bridged), so they can see each other."
                  : "There is no wired lab port in this plan, so the Wi-Fi network is the lab network."}
            </p>
          )}
          <div className="lgf-check-list">
            <label className="lgf-checkbox">
              <input type="checkbox" checked={plan.client_isolation} onChange={(event) => set({ client_isolation: event.target.checked })} />
              Isolate Wi-Fi devices from each other
            </label>
            <p className="lgf-hint">Wi-Fi devices can still reach the internet through ShakerProxy{hasWiredLab ? " and wired lab devices" : ""}, but not each other. Casting and local discovery stop working.</p>
            {fieldError("client_isolation")}
            <label className="lgf-checkbox">
              <input type="checkbox" checked={plan.hidden} onChange={(event) => set({ hidden: event.target.checked })} />
              Hide the network name
            </label>
            <p className="lgf-hint">Devices must type the name to join. Some smart TVs and IoT devices cannot join hidden networks.</p>
            {fieldError("hidden")}
          </div>
        </>
      )}
    </fieldset>
  )
}

registerPlanExtension({ id: "wifi-ap", planKey: "wifi", title: "Wi-Fi access point", order: 10, Component: WifiPlanEditor })
