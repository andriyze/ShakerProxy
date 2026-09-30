// Workspace routing for the dashboard shell. The shell shows one workspace at
// a time, selected by the URL hash "#/<workspace>" (see features/registry.ts).
// Pure functions only, so they can be unit tested without a browser.
import type { WorkspaceID } from "../features/registry"

export type WorkspaceMeta = {
  id: WorkspaceID
  label: string
  // One short plain-language line shown under the label in the navigation.
  description: string
  // One sentence at the top of the workspace saying what you do there.
  intro: string
}

// Navigation order (contracts §12). "testlab" is not a top-level workspace;
// the Virtual Test Lab lives in System.
export const WORKSPACES: readonly WorkspaceMeta[] = [
  {
    id: "start",
    label: "Start",
    description: "Set up ShakerProxy step by step",
    intro: "Follow these steps to connect a device, watch what it does and test it.",
  },
  {
    id: "devices",
    label: "Devices",
    description: "What is connected to the lab",
    intro: "Every device ShakerProxy has seen on the lab network. Open one to see its details, report and traffic.",
  },
  {
    id: "traffic",
    label: "Traffic",
    description: "What your devices are doing",
    intro: "Live activity from your devices: lookups, connections, web requests and alerts. Click a row for details.",
  },
  {
    id: "protocols",
    label: "Protocols",
    description: "Which protocols devices use",
    intro: "Which protocols each device speaks, including unusual ones and traffic ShakerProxy cannot see inside.",
  },
  {
    id: "tests",
    label: "Tests",
    description: "Test runs, reports, comparisons",
    intro: "Name a test run for a device, get a security report for it, and compare two runs.",
  },
  {
    id: "captures",
    label: "Captures",
    description: "Record packets to a file",
    intro: "Record the lab network's packets to files you can download and open in Wireshark.",
  },
  {
    id: "policy",
    label: "DNS & HTTPS",
    description: "Decrypt HTTPS, control DNS",
    intro: "Choose which devices ShakerProxy decrypts, install its certificate on them, and control how devices use DNS.",
  },
  {
    id: "network",
    label: "Network",
    description: "Set up the lab network",
    intro:
      "Tell ShakerProxy which port goes to the internet and where your test devices connect. Changes roll back automatically if something breaks.",
  },
  {
    id: "cases",
    label: "Cases",
    description: "Keep evidence together",
    intro: "Group recordings and exports for an investigation and protect them from deletion.",
  },
  {
    id: "integrations",
    label: "Integrations",
    description: "API tokens and AI agents",
    intro: "Connect scripts, AI assistants and log collectors to ShakerProxy with limited, expiring access.",
  },
  {
    id: "system",
    label: "System",
    description: "Health and self-tests",
    intro: "Check that ShakerProxy itself is healthy, run self-tests, and see what this build supports.",
  },
]

export const DEFAULT_WORKSPACE: WorkspaceID = "start"

// Older links and the previous scroll-navigation anchors map onto the new
// workspaces so bookmarks keep working.
const ALIASES: Record<string, WorkspaceID> = {
  overview: "start",
  testlab: "system",
  dns: "policy",
  https: "policy",
  tls: "policy",
}

export function isWorkspaceID(value: string): value is WorkspaceID {
  return WORKSPACES.some((workspace) => workspace.id === value)
}

// parseWorkspaceHash maps a location hash such as "#/traffic" or
// "#/traffic?x" to a known workspace, falling back to Start.
export function parseWorkspaceHash(hash: string): WorkspaceID {
  const match = /^#\/?([a-z]+)/i.exec(hash)
  if (!match) return DEFAULT_WORKSPACE
  const name = match[1].toLowerCase()
  if (isWorkspaceID(name)) return name
  return ALIASES[name] ?? DEFAULT_WORKSPACE
}

export function workspaceMeta(id: WorkspaceID): WorkspaceMeta {
  return WORKSPACES.find((workspace) => workspace.id === id) ?? WORKSPACES[0]
}

// workspaceForShortcut maps Alt+<digit> to a workspace using KeyboardEvent.code
// ("Digit1"…"Digit9", "Digit0" for the tenth), which is layout-independent:
// on macOS Alt+1 produces event.key "¡", so event.key must not be used.
export function workspaceForShortcut(code: string): WorkspaceID | undefined {
  const match = /^Digit([0-9])$/.exec(code)
  if (!match) return undefined
  const digit = Number(match[1])
  const index = digit === 0 ? 9 : digit - 1
  return WORKSPACES[index]?.id
}

// URL search parameters owned by the shell's own workspaces (the Traffic
// query and the device list). Feature views handle their own parameters
// (for example inspect_device) through the shakerproxy:navigate event, so a
// change to those must not remount the workspace underneath them.
const SHELL_PARAM_PREFIXES = ["traffic_", "device_"]

// routeKey identifies a navigation target; the shell remounts the workspace
// when it changes so the workspace re-reads its URL state (traffic_q etc.).
export function routeKey(hash: string, search: string): string {
  const owned = [...new URLSearchParams(search).entries()]
    .filter(([name]) => SHELL_PARAM_PREFIXES.some((prefix) => name.startsWith(prefix)))
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([name, value]) => `${name}=${value}`)
    .join("&")
  return `${parseWorkspaceHash(hash)}|${owned}`
}
