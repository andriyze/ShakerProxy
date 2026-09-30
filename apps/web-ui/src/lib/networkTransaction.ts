// Network change (staged plan) lifecycle helpers. Pure.
//
// Phases come from internal/networktransaction plus the staging states the
// gateway reports before a commit.

export const STAGED = "STAGED_NOT_APPLIED"
export const AWAITING_CONFIRMATION = "AWAITING_CONFIRMATION"
export const AWAITING_HEALTH = "AWAITING_HEALTH"

// Host is applying the change; the browser must keep polling (and send the
// management heartbeat once the host is waiting for it).
export const APPLYING_PHASES = ["ACCEPTED", "PREPARING", "WATCHDOG_ARMED", "APPLYING", AWAITING_HEALTH] as const

export const FAILED_PHASES = ["ROLLBACK_REQUIRED", "ROLLING_BACK", "ROLLED_BACK", "ROLLBACK_FAILED", "FAILED"] as const

export const FINAL_PHASES = ["CONFIRMED", "ROLLED_BACK", "ROLLBACK_FAILED", "FAILED", "DISCARDED", "EXPIRED"] as const

export function isApplying(phase: string): boolean {
  return (APPLYING_PHASES as readonly string[]).includes(phase)
}

export function isFailed(phase: string): boolean {
  return (FAILED_PHASES as readonly string[]).includes(phase)
}

export function isFinal(phase: string): boolean {
  return (FINAL_PHASES as readonly string[]).includes(phase)
}

// isTransactionActive: a staged or in-flight change the user still has to
// act on or wait for.
export function isTransactionActive(phase: string | undefined): boolean {
  if (!phase) return false
  return (
    phase === STAGED ||
    phase === AWAITING_CONFIRMATION ||
    isApplying(phase) ||
    phase === "ROLLING_BACK" ||
    phase === "ROLLBACK_REQUIRED"
  )
}

// shouldSendHeartbeat: the browser heartbeat proves this browser can still
// reach ShakerProxy *after* the host applied the change, so it is sent only when
// the host is waiting for health evidence — never right after commit.
export function shouldSendHeartbeat(phase: string, alreadySent: boolean): boolean {
  return phase === AWAITING_HEALTH && !alreadySent
}

// pollInterval: fast while the host works, slower while waiting for the
// person to confirm, none once the change is final.
export function pollInterval(phase: string): number {
  if (isApplying(phase) || phase === "ROLLING_BACK" || phase === "ROLLBACK_REQUIRED") return 1000
  if (phase === AWAITING_CONFIRMATION) return 2000
  if (phase === STAGED) return 10_000
  return 0
}

export function secondsLeft(deadline: string | undefined, now: number): number | null {
  if (!deadline) return null
  const at = Date.parse(deadline)
  if (!Number.isFinite(at)) return null
  return Math.max(0, Math.ceil((at - now) / 1000))
}

export function formatCountdown(seconds: number): string {
  const minutes = Math.floor(seconds / 60)
  const rest = seconds % 60
  return `${minutes}:${String(rest).padStart(2, "0")}`
}

// describePhase explains a phase in plain language.
export function describePhase(phase: string): string {
  switch (phase) {
    case STAGED:
      return "Saved and ready to apply. Nothing has changed on the network yet."
    case "ACCEPTED":
    case "PREPARING":
    case "WATCHDOG_ARMED":
      return "Getting ready. An automatic undo is armed before anything changes."
    case "APPLYING":
      return "Applying the new network settings…"
    case AWAITING_HEALTH:
      return "Checking that this browser, the internet connection and DNS still work…"
    case AWAITING_CONFIRMATION:
      return "The new network works. Confirm to keep it — otherwise ShakerProxy undoes the change automatically."
    case "CONFIRMED":
      return "Done. The lab network is live."
    case "ROLLBACK_REQUIRED":
    case "ROLLING_BACK":
      return "Something did not work, so ShakerProxy is undoing the change."
    case "ROLLED_BACK":
      return "The change was undone. The network is back to how it was."
    case "ROLLBACK_FAILED":
      return "The automatic undo did not finish. Check the appliance from its local console before trying again."
    case "FAILED":
      return "The change failed before it was applied. Nothing changed."
    default:
      return phase.replaceAll("_", " ").toLowerCase()
  }
}

// runningLab describes the confirmed lab network the appliance is running, or
// null when none is. A staged candidate never hides the running plan: the
// gateway then reports it separately as confirmed_network_plan.
export type RunningLab = { labInterface: string; planHash: string; bypass: boolean }

export function runningLab(status: {
  operating_mode?: string
  emergency_bypass?: boolean
  lab_interface?: string
  staged_network_plan?: { plan_hash: string; status: string }
  confirmed_network_plan?: { plan_hash: string }
} | null): RunningLab | null {
  if (!status) return null
  const routing = status.operating_mode === "ROUTED_PASSTHROUGH" || status.emergency_bypass === true
  if (!routing || !status.lab_interface) return null
  const plan =
    status.confirmed_network_plan ??
    (status.staged_network_plan?.status === "CONFIRMED" ? status.staged_network_plan : undefined)
  return { labInterface: status.lab_interface, planHash: plan?.plan_hash ?? "", bypass: status.emergency_bypass === true }
}

// The firewall check blocks every apply while ShakerProxy's own chains exist;
// with a lab running that is expected, and the fix is to turn the lab off.
export const CHAIN_CONFLICT = "SHAKERPROXY_CHAIN_CONFLICT"
