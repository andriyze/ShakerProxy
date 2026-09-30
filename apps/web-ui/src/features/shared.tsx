// Shared hooks and small components for feature modules. Everything here is
// side-effect free at import time.
import { useCallback, useEffect, useId, useMemo, useRef, useState, type ReactNode } from "react"
import { api, ApiError, describeError } from "../api"
import { NAVIGATE_EVENT, navigate, type WorkspaceID } from "./registry"
import { TIME_WINDOWS } from "./format"
import type { DeviceChoice, DeviceResolveResponse, InventoryDevice, InventorySnapshot, TimeWindow } from "./types"

// ---------------------------------------------------------------------------
// Hooks

// usePageVisible tracks document.visibilityState so polling stops in hidden tabs.
export function usePageVisible(): boolean {
  const [visible, setVisible] = useState(() => typeof document === "undefined" || document.visibilityState === "visible")
  useEffect(() => {
    const update = () => setVisible(document.visibilityState === "visible")
    document.addEventListener("visibilitychange", update)
    return () => document.removeEventListener("visibilitychange", update)
  }, [])
  return visible
}

// usePolling calls `tick` every `intervalMs` while enabled and the page is
// visible, and once immediately whenever polling restarts (for example when
// the tab becomes visible again). With immediate=false the very first start
// does not tick, for callers that already loaded on mount.
export function usePolling(tick: () => void, intervalMs: number, enabled = true, immediate = true): void {
  const visible = usePageVisible()
  const saved = useRef(tick)
  const started = useRef(false)
  saved.current = tick
  useEffect(() => {
    if (!enabled || !visible) return
    if (immediate || started.current) saved.current()
    started.current = true
    const timer = window.setInterval(() => saved.current(), Math.max(intervalMs, 1000))
    return () => window.clearInterval(timer)
  }, [enabled, visible, intervalMs, immediate])
}

export type Resource<T> = {
  data: T | undefined
  error: string
  // The API error code, e.g. "traffic_policy_unavailable", when known.
  errorCode: string
  loading: boolean
  reload: () => void
  // Replace the cached data (for example with a PUT response).
  setData: (next: T) => void
}

// useResource GETs `path` (skipped when null), aborting stale requests.
// With `pollMs`, it refreshes silently while the page is visible.
export function useResource<T>(path: string | null, pollMs?: number): Resource<T> {
  const [state, setState] = useState<{ path: string | null; data?: T; error: string; errorCode: string; loading: boolean }>({ path, error: "", errorCode: "", loading: path !== null })
  const [nonce, setNonce] = useState(0)
  const controller = useRef<AbortController | null>(null)
  const load = useCallback(
    (quiet: boolean) => {
      if (path === null) return
      controller.current?.abort()
      const abort = new AbortController()
      controller.current = abort
      if (!quiet) setState((current) => ({ ...current, path, loading: true, error: "", errorCode: "" }))
      api<T>(path, { signal: abort.signal })
        .then((data) => {
          if (!abort.signal.aborted) setState({ path, data, error: "", errorCode: "", loading: false })
        })
        .catch((reason: unknown) => {
          if (abort.signal.aborted) return
          setState((current) => ({
            ...current,
            path,
            loading: false,
            error: describeError(reason, "Could not load this information."),
            errorCode: reason instanceof ApiError ? (reason.code ?? "") : "",
          }))
        })
    },
    [path],
  )
  useEffect(() => {
    if (path === null) {
      setState({ path, error: "", errorCode: "", loading: false })
      return
    }
    setState((current) => (current.path === path ? current : { path, error: "", errorCode: "", loading: true }))
    load(false)
    return () => controller.current?.abort()
  }, [path, nonce, load])
  usePolling(() => load(true), pollMs ?? 0, !!pollMs && path !== null, false)
  const reload = useCallback(() => setNonce((value) => value + 1), [])
  const setData = useCallback((next: T) => setState((current) => ({ ...current, data: next, error: "", errorCode: "" })), [])
  const sameRequest = state.path === path
  return {
    data: sameRequest ? state.data : undefined,
    error: sameRequest ? state.error : "",
    errorCode: sameRequest ? state.errorCode : "",
    loading: sameRequest ? state.loading : path !== null,
    reload,
    setData,
  }
}

// useSearchParam reads a URL search parameter and follows navigate() and back/forward.
export function useSearchParam(name: string): string {
  const read = () => (typeof window === "undefined" ? "" : new URLSearchParams(window.location.search).get(name) ?? "")
  const [value, setValue] = useState(read)
  useEffect(() => {
    const update = () => setValue(new URLSearchParams(window.location.search).get(name) ?? "")
    window.addEventListener(NAVIGATE_EVENT, update)
    window.addEventListener("popstate", update)
    window.addEventListener("hashchange", update)
    return () => {
      window.removeEventListener(NAVIGATE_EVENT, update)
      window.removeEventListener("popstate", update)
      window.removeEventListener("hashchange", update)
    }
  }, [name])
  return value
}

// ---------------------------------------------------------------------------
// State components

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="lgf-state lgf-loading" role="status" aria-live="polite">
      <span className="lgf-spinner" aria-hidden="true" />
      {label}
    </div>
  )
}

export function ErrorNotice({ message, onRetry, children }: { message: string; onRetry?: () => void; children?: ReactNode }) {
  return (
    <div className="lgf-state lgf-error" role="alert">
      <p>{message}</p>
      <div className="lgf-actions">
        {onRetry && (
          <button type="button" className="lgf-button lgf-secondary" onClick={onRetry}>
            Try again
          </button>
        )}
        {children}
      </div>
    </div>
  )
}

export function Empty({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="lgf-state lgf-empty">
      <strong>{title}</strong>
      {children && <div className="lgf-empty-body">{children}</div>}
      {action && <div className="lgf-actions">{action}</div>}
    </div>
  )
}

// Unavailable shows an API "unavailable" reason with a button to the workspace that fixes it.
export function Unavailable({ reason, workspace, label }: { reason: string; workspace: WorkspaceID; label: string }) {
  return (
    <div className="lgf-state lgf-unavailable" role="status">
      <p>{reason || "This is not available yet."}</p>
      <div className="lgf-actions">
        <button type="button" className="lgf-button lgf-secondary" onClick={() => navigate(workspace)}>
          {label}
        </button>
      </div>
    </div>
  )
}

export type BadgeTone = "good" | "info" | "warn" | "bad" | "muted" | "critical" | "high" | "medium" | "low"

export function Badge({ tone, title, children }: { tone: BadgeTone; title?: string; children: ReactNode }) {
  return (
    <span className={`lgf-badge lgf-tone-${tone}`} title={title}>
      {children}
    </span>
  )
}

// Toggle is an accessible on/off switch button.
export function Toggle({ checked, onChange, label, description, disabled, busy }: { checked: boolean; onChange: (next: boolean) => void; label: string; description?: ReactNode; disabled?: boolean; busy?: boolean }) {
  const descriptionID = useId()
  return (
    <div className="lgf-toggle-row">
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-describedby={description ? descriptionID : undefined}
        className={`lgf-switch${checked ? " lgf-on" : ""}`}
        disabled={disabled || busy}
        onClick={() => onChange(!checked)}
      >
        <span className="lgf-switch-track" aria-hidden="true">
          <span className="lgf-switch-thumb" />
        </span>
        <span className="lgf-switch-label">{label}</span>
        <span className="lgf-switch-state">{busy ? "Saving…" : checked ? "On" : "Off"}</span>
      </button>
      {description && (
        <p id={descriptionID} className="lgf-hint">
          {description}
        </p>
      )}
    </div>
  )
}

export function WindowSelect({ value, onChange, id, disabled }: { value: TimeWindow; onChange: (next: TimeWindow) => void; id?: string; disabled?: boolean }) {
  return (
    <select id={id} className="lgf-select" value={value} disabled={disabled} onChange={(event) => onChange(event.target.value as TimeWindow)}>
      {TIME_WINDOWS.map((window) => (
        <option key={window.value} value={window.value}>
          {window.label}
        </option>
      ))}
    </select>
  )
}

// ---------------------------------------------------------------------------
// Device picker

export function deviceChoiceFromInventory(device: InventoryDevice): DeviceChoice {
  const addresses = (device.addresses ?? []).filter((address) => address.active).map((address) => address.address)
  const macs = (device.identities ?? []).filter((identity) => identity.kind === "MAC").map((identity) => identity.value)
  const name = device.friendly_name || device.hostnames?.[0]?.hostname || (device.vendor?.name ? `${device.vendor.name} device` : device.id)
  return { device_id: device.id, name, vendor: device.vendor?.name ?? "", addresses, hardware_addresses: macs, online: device.online }
}

export function deviceChoiceFromMatch(match: DeviceResolveResponse["matches"][number]): DeviceChoice {
  return {
    device_id: match.device_id,
    name: match.friendly_name || match.device_id,
    vendor: match.vendor,
    addresses: match.addresses,
    hardware_addresses: match.hardware_addresses,
    online: match.online,
  }
}

function matchesText(choice: DeviceChoice, text: string): boolean {
  const needle = text.trim().toLowerCase()
  if (!needle) return true
  const compactNeedle = needle.replace(/[^0-9a-f]/g, "")
  return (
    choice.name.toLowerCase().includes(needle) ||
    choice.vendor.toLowerCase().includes(needle) ||
    choice.device_id.toLowerCase() === needle ||
    choice.addresses.some((address) => address.toLowerCase().startsWith(needle)) ||
    (compactNeedle.length >= 4 && choice.hardware_addresses.some((mac) => mac.toLowerCase().replace(/[^0-9a-f]/g, "").includes(compactNeedle)))
  )
}

export function deviceSubtitle(choice: DeviceChoice): string {
  return [choice.vendor, choice.addresses[0], choice.hardware_addresses[0]].filter(Boolean).join(" · ")
}

// DevicePicker lets people choose a device by typing a name, IP or MAC.
// It filters the inventory locally and asks the resolver for anything else.
export function DevicePicker({ value, onChange, label = "Device", autoFocus, disabled }: { value: DeviceChoice | null; onChange: (next: DeviceChoice | null) => void; label?: string; autoFocus?: boolean; disabled?: boolean }) {
  const inventory = useResource<InventorySnapshot>("/api/v1/devices?sort=last_seen&direction=desc")
  const [text, setText] = useState("")
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(0)
  const [resolved, setResolved] = useState<DeviceChoice[]>([])
  const [resolveError, setResolveError] = useState("")
  const inputID = useId()
  const listID = useId()
  const choices = useMemo(() => (inventory.data?.devices ?? []).map(deviceChoiceFromInventory), [inventory.data])
  const local = useMemo(() => choices.filter((choice) => matchesText(choice, text)), [choices, text])
  const options = useMemo(() => {
    const merged = [...local]
    for (const choice of resolved) if (!merged.some((item) => item.device_id === choice.device_id)) merged.push(choice)
    return merged.slice(0, 12)
  }, [local, resolved])

  useEffect(() => {
    setResolved([])
    setResolveError("")
    const query = text.trim()
    if (query.length < 2 || local.length > 0) return
    const abort = new AbortController()
    const timer = window.setTimeout(() => {
      api<DeviceResolveResponse>(`/api/v1/devices/resolve?q=${encodeURIComponent(query)}`, { signal: abort.signal })
        .then((body) => setResolved((body.matches ?? []).map(deviceChoiceFromMatch)))
        .catch((reason: unknown) => {
          if (!abort.signal.aborted) setResolveError(describeError(reason, "No device matches."))
        })
    }, 300)
    return () => {
      window.clearTimeout(timer)
      abort.abort()
    }
  }, [text, local.length])

  useEffect(() => setActive(0), [text])

  const choose = (choice: DeviceChoice) => {
    onChange(choice)
    setText("")
    setOpen(false)
  }

  if (value) {
    return (
      <div className="lgf-field">
        <span className="lgf-label">{label}</span>
        <div className="lgf-device-chosen">
          <span className={`lgf-dot${value.online ? " lgf-online" : ""}`} aria-label={value.online ? "Online" : "Offline"} role="img" />
          <div>
            <strong>{value.name}</strong>
            <small>{deviceSubtitle(value) || value.device_id}</small>
          </div>
          {!disabled && (
            <button type="button" className="lgf-button lgf-secondary lgf-small" onClick={() => onChange(null)}>
              Change
            </button>
          )}
        </div>
      </div>
    )
  }

  const showList = open && options.length > 0
  return (
    <div className="lgf-field lgf-combobox">
      <label className="lgf-label" htmlFor={inputID}>
        {label}
      </label>
      <div className="lgf-combo-anchor">
      <input
        id={inputID}
        className="lgf-input"
        type="text"
        role="combobox"
        autoComplete="off"
        spellCheck={false}
        autoFocus={autoFocus}
        disabled={disabled}
        placeholder="Type a name, IP or MAC address"
        aria-expanded={showList}
        aria-controls={listID}
        aria-autocomplete="list"
        aria-activedescendant={showList && options[active] ? `${listID}-${active}` : undefined}
        value={text}
        onChange={(event) => {
          setText(event.target.value)
          setOpen(true)
        }}
        onFocus={() => setOpen(true)}
        onBlur={() => window.setTimeout(() => setOpen(false), 150)}
        onKeyDown={(event) => {
          if (event.key === "ArrowDown") {
            event.preventDefault()
            setOpen(true)
            setActive((index) => Math.min(index + 1, Math.max(options.length - 1, 0)))
          } else if (event.key === "ArrowUp") {
            event.preventDefault()
            setActive((index) => Math.max(index - 1, 0))
          } else if (event.key === "Enter") {
            if (showList && options[active]) {
              event.preventDefault()
              choose(options[active])
            }
          } else if (event.key === "Escape") {
            setOpen(false)
          }
        }}
      />
      {showList && (
        <ul id={listID} role="listbox" className="lgf-listbox" aria-label="Matching devices">
          {options.map((option, index) => (
            <li
              key={option.device_id}
              id={`${listID}-${index}`}
              role="option"
              aria-selected={index === active}
              className={index === active ? "lgf-active" : undefined}
              onMouseDown={(event) => {
                event.preventDefault()
                choose(option)
              }}
              onMouseEnter={() => setActive(index)}
            >
              <span className={`lgf-dot${option.online ? " lgf-online" : ""}`} aria-hidden="true" />
              <span>
                <strong>{option.name}</strong>
                <small>{deviceSubtitle(option) || option.device_id}</small>
              </span>
            </li>
          ))}
        </ul>
      )}
      </div>
      <p className="lgf-hint" aria-live="polite">
        {inventory.loading && !inventory.data
          ? "Loading devices…"
          : text.trim() && options.length === 0
            ? resolveError || "No device matches yet. Check the name, IP or MAC, or open Devices to see everything ShakerProxy has found."
            : inventory.error
              ? `Device list unavailable (${inventory.error}). You can still type an exact name, IP or MAC.`
              : choices.length === 0
                ? "No devices yet. Connect a device to ShakerProxy's Wi-Fi or lab port and it will appear here."
                : `${choices.length} device${choices.length === 1 ? "" : "s"} known. Start typing to filter.`}
      </p>
    </div>
  )
}

// CopyButton copies text to the clipboard and confirms briefly.
export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      type="button"
      className="lgf-button lgf-secondary lgf-small"
      onClick={() => {
        navigator.clipboard
          ?.writeText(text)
          .then(() => {
            setCopied(true)
            window.setTimeout(() => setCopied(false), 1500)
          })
          .catch(() => setCopied(false))
      }}
    >
      {copied ? "Copied" : label}
    </button>
  )
}
