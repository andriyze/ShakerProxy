import { createContext, useContext } from "react"
import type { Preflight, Status } from "../types"

// Appliance-wide state shared by every workspace. Status is polled by the
// shell every 15 seconds; call refreshStatus() right after any action that
// changes it (network apply, capture start/stop, policy apply).
export type AppState = {
  status: Status | null
  statusError: string
  refreshStatus: () => Promise<void>
  preflight: Preflight | null
  preflightError: string
  reloadPreflight: () => Promise<void>
}

const noop = async () => {}

export const AppContext = createContext<AppState>({
  status: null,
  statusError: "",
  refreshStatus: noop,
  preflight: null,
  preflightError: "",
  reloadPreflight: noop,
})

export function useAppState(): AppState {
  return useContext(AppContext)
}

export const ROUTED = "ROUTED_PASSTHROUGH"

export function isRouted(status: Status | null): boolean {
  return status?.operating_mode === ROUTED
}
