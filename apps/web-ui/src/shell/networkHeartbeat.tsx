import { useEffect, useRef, useState } from "react"
import { api } from "../api"
import { isApplying, shouldSendHeartbeat } from "../lib/networkTransaction"
import { useAppState } from "./AppContext"
import { timeoutSignal, usePolling } from "./hooks"
import type { Status } from "../types"

// A committed network change is kept only if this browser can still reach
// ShakerProxy after the host applied it: the host waits for a heartbeat carrying
// the health token from the commit response, and rolls back without it.
//
// The watcher lives in the dashboard shell, not on the Network page, so the
// heartbeat is still sent when you switch to another workspace or the tab is
// hidden. The token is kept for this tab only (sessionStorage), so a reload
// during the apply can still send it.

const HEARTBEAT_KEY = "shakerproxy.network-heartbeat."
const HEARTBEAT_EVENT = "shakerproxy:network-heartbeat"
const REQUEST_TIMEOUT_MS = 5000

export type HeartbeatToken = { token: string; planHash: string }

export function storeHeartbeat(applyID: string, value: HeartbeatToken | null): void {
  try {
    if (value) window.sessionStorage.setItem(HEARTBEAT_KEY + applyID, JSON.stringify(value))
    else window.sessionStorage.removeItem(HEARTBEAT_KEY + applyID)
  } catch {
    // Storage unavailable: the heartbeat cannot survive a reload.
  }
  window.dispatchEvent(new CustomEvent(HEARTBEAT_EVENT, { detail: { applyID } }))
}

export function loadHeartbeat(applyID: string): HeartbeatToken | null {
  try {
    const raw = window.sessionStorage.getItem(HEARTBEAT_KEY + applyID)
    return raw ? (JSON.parse(raw) as HeartbeatToken) : null
  } catch {
    return null
  }
}

// NetworkHeartbeat watches an in-flight change that this tab committed and
// sends the heartbeat once the host reports AWAITING_HEALTH.
export function NetworkHeartbeat() {
  const { status, refreshStatus } = useAppState()
  const staged = status?.staged_network_plan
  const [watching, setWatching] = useState<string | null>(null)
  const sent = useRef(new Set<string>())

  // Start watching when status shows an applying change we hold a token for,
  // or right after a commit stores the token.
  useEffect(() => {
    const consider = (applyID: string | undefined, phase: string | undefined) => {
      if (applyID && phase && isApplying(phase) && loadHeartbeat(applyID)) setWatching(applyID)
    }
    consider(staged?.apply_id, staged?.status)
    const onStored = (event: Event) => {
      const applyID = (event as CustomEvent<{ applyID: string }>).detail?.applyID
      if (applyID && loadHeartbeat(applyID)) setWatching(applyID)
    }
    window.addEventListener(HEARTBEAT_EVENT, onStored)
    return () => window.removeEventListener(HEARTBEAT_EVENT, onStored)
  }, [staged?.apply_id, staged?.status])

  usePolling(
    async (signal) => {
      if (!watching) return
      try {
        const current = await api<Status>("/api/v1/system/status", {
          signal: timeoutSignal(signal, REQUEST_TIMEOUT_MS),
        })
        const plan = current.staged_network_plan
        if (!plan || plan.apply_id !== watching || !isApplying(plan.status)) {
          // Done, undone or waiting for confirmation: no heartbeat needed.
          setWatching(null)
          void refreshStatus()
          return
        }
        const token = loadHeartbeat(watching)
        if (token && shouldSendHeartbeat(plan.status, sent.current.has(watching))) {
          await api(`/api/v1/network/staged/${watching}/heartbeat`, {
            method: "POST",
            body: JSON.stringify({ plan_hash: token.planHash, token: token.token }),
            signal: timeoutSignal(signal, REQUEST_TIMEOUT_MS),
          })
          sent.current.add(watching)
        }
      } catch {
        // Try again on the next tick until the host's deadline; the Network
        // page shows the outcome.
      }
    },
    1000,
    [watching],
    { enabled: watching !== null, whileHidden: true },
  )

  // Closing the tab now would stop the heartbeat and undo the change.
  useEffect(() => {
    if (!watching) return
    const beforeUnload = (event: BeforeUnloadEvent) => {
      event.preventDefault()
    }
    window.addEventListener("beforeunload", beforeUnload)
    return () => window.removeEventListener("beforeunload", beforeUnload)
  }, [watching])

  return null
}
