// Pure helpers for the "Inspect a device" wizard: interpreting TLS outcomes
// seen while verifying decryption or certificate validation.
// Keep this file free of runtime imports so node --test can load it directly.
import type { CATrust, RecentEvent, TLSInterceptionState } from "./types"

export type InspectGoal = "decrypt" | "validate"

export const GOALS: readonly { value: InspectGoal; title: string; detail: string; caTrust: CATrust }[] = [
  {
    value: "decrypt",
    title: "See its HTTPS traffic",
    detail: "Install ShakerProxy's certificate on the device so ShakerProxy can decrypt and show its HTTPS requests.",
    caTrust: "INSTALLED",
  },
  {
    value: "validate",
    title: "Check whether it validates certificates",
    detail: "Don't install anything. ShakerProxy presents its own untrusted certificate; a secure device must refuse it.",
    caTrust: "NOT_INSTALLED",
  },
]

export function goalInfo(goal: InspectGoal) {
  return GOALS.find((item) => item.value === goal) ?? GOALS[0]
}

// suggestPlatform picks the most likely onboarding instructions tab for a
// device from its vendor and name. Returns undefined when there is no hint.
export function suggestPlatform(vendor: string, name: string, available: readonly string[]): string | undefined {
  const text = `${vendor} ${name}`.toLowerCase()
  const rules: [RegExp, string[]][] = [
    [/\b(iphone|ipad|ios)\b/, ["ios"]],
    [/\b(mac|macbook|imac)\b/, ["macos"]],
    [/\bapple\b/, ["ios", "macos"]],
    [/\b(android tv|google tv|chromecast|shield|fire ?tv|firestick)\b/, ["android-tv", "android"]],
    [/\b(tv|bravia|webos|tizen|roku|vizio|hisense|tcl)\b/, ["smart-tv", "android-tv"]],
    [/\b(pixel|android|galaxy|oneplus|xiaomi|huawei|oppo|motorola)\b/, ["android"]],
    [/\b(samsung|lg|sony|philips|panasonic)\b/, ["smart-tv", "android"]],
    [/\b(windows|surface|dell|lenovo|hp)\b/, ["windows"]],
    [/\b(linux|raspberry|ubuntu|debian)\b/, ["linux"]],
  ]
  for (const [pattern, platforms] of rules) {
    if (!pattern.test(text)) continue
    const match = platforms.find((platform) => available.includes(platform))
    if (match) return match
  }
  return undefined
}

// verifyEventsPath returns the recent-events query for one device's TLS
// outcomes (newest first, bounded to 100).
export function verifyEventsPath(deviceID: string): string {
  const query = `device.id:${deviceID} AND (tls.state:INTERCEPTED OR tls.state:FAILED OR tls.state:BYPASSED)`
  return `/api/v1/events?limit=100&q=${encodeURIComponent(query)}`
}

export type TLSOutcome = {
  host: string
  state: TLSInterceptionState
  count: number
  last_seen: string
  pinning_suspected: boolean
  tone: "critical" | "good" | "warn" | "info"
  explanation: string
}

export function outcomeExplanation(goal: InspectGoal, state: TLSInterceptionState, pinningSuspected: boolean): { tone: TLSOutcome["tone"]; explanation: string } {
  if (state === "INTERCEPTED") {
    return goal === "validate"
      ? { tone: "critical", explanation: "Accepted ShakerProxy's untrusted certificate. Anyone on the same network could read this traffic." }
      : { tone: "good", explanation: "Decrypted. Its requests now appear in Traffic." }
  }
  if (state === "FAILED") {
    if (goal === "validate") return { tone: "good", explanation: "Refused the untrusted certificate, as a secure device should." }
    return pinningSuspected
      ? { tone: "warn", explanation: "Refused: this app most likely pins its own certificate, so it cannot be decrypted." }
      : { tone: "warn", explanation: "Refused: the certificate is not trusted yet (finish the install step), or the app pins its certificate." }
  }
  return { tone: "info", explanation: "Passed through without decryption (bypass rule or pinning fallback)." }
}

// summarizeOutcomes groups TLS events at or after `sinceMs` by host, keeping
// the newest state per host. Hosts are ordered by severity, then recency.
export function summarizeOutcomes(events: readonly RecentEvent[], goal: InspectGoal, sinceMs = 0): TLSOutcome[] {
  const byHost = new Map<string, TLSOutcome>()
  const ordered = [...events]
    .filter((event) => event.tls_interception_state && Date.parse(event.occurred_at) >= sinceMs)
    .sort((a, b) => Date.parse(a.occurred_at) - Date.parse(b.occurred_at))
  for (const event of ordered) {
    const state = event.tls_interception_state as TLSInterceptionState
    const host = event.tls_server_name || (event.destination_ip ? `${event.destination_ip}${event.destination_port ? `:${event.destination_port}` : ""}` : "unknown host")
    const previous = byHost.get(host)
    const pinning = !!event.tls_pinning_suspected || (previous?.pinning_suspected ?? false)
    const { tone, explanation } = outcomeExplanation(goal, state, pinning)
    byHost.set(host, { host, state, count: (previous?.count ?? 0) + 1, last_seen: event.occurred_at, pinning_suspected: pinning, tone, explanation })
  }
  const toneRank: Record<TLSOutcome["tone"], number> = { critical: 0, warn: 1, good: 2, info: 3 }
  return [...byHost.values()].sort((a, b) => toneRank[a.tone] - toneRank[b.tone] || Date.parse(b.last_seen) - Date.parse(a.last_seen))
}

export type Verdict = {
  status: "waiting" | "critical" | "pass" | "success" | "partial" | "refused"
  title: string
  detail: string
}

export function verdict(outcomes: readonly TLSOutcome[], goal: InspectGoal): Verdict {
  const intercepted = outcomes.filter((item) => item.state === "INTERCEPTED").length
  const failed = outcomes.filter((item) => item.state === "FAILED").length
  const hosts = (count: number) => `${count} host${count === 1 ? "" : "s"}`
  if (intercepted === 0 && failed === 0) {
    return {
      status: "waiting",
      title: "Waiting for HTTPS connections…",
      detail: "Use the device now: open its apps, sign in, or restart it so it connects to its servers. Results appear here within a few seconds.",
    }
  }
  if (goal === "validate") {
    if (intercepted > 0) {
      return {
        status: "critical",
        title: `Critical: the device accepted an untrusted certificate for ${hosts(intercepted)}`,
        detail: "ShakerProxy's certificate is not installed, yet the device let ShakerProxy decrypt these connections. An attacker on the same network could read or change this traffic. This is recorded as a critical finding in the device report.",
      }
    }
    return {
      status: "pass",
      title: `Good so far: the device refused the untrusted certificate for ${hosts(failed)}`,
      detail: "Keep using the device for a while; every app and background service should also refuse. Any decrypted connection would be a critical finding.",
    }
  }
  if (intercepted > 0 && failed === 0) return { status: "success", title: `Decrypting HTTPS for ${hosts(intercepted)}`, detail: "It works. Open Traffic to see the decrypted requests." }
  if (intercepted > 0) {
    return {
      status: "partial",
      title: `Decrypting ${hosts(intercepted)}; ${hosts(failed)} refused`,
      detail: "Some apps refuse ShakerProxy's certificate. That usually means certificate pinning (the app only trusts its own certificate) or that the app ignores user-installed certificates (common on Android 7+).",
    }
  }
  return {
    status: "refused",
    title: `The device refused ShakerProxy's certificate for ${hosts(failed)}`,
    detail: "The certificate is probably not trusted yet. Go back to the install step and make sure it is installed and fully trusted (on iPhone: Settings → General → About → Certificate Trust Settings). If only some apps refuse, they may pin their certificates.",
  }
}
