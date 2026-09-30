// Feature registry: the only coupling point between the dashboard shell
// (main.tsx) and self-contained feature modules under src/features/.
//
// Feature modules export React components and register them here. The shell
// renders registered views inside its workspaces, network-plan extensions
// inside the plan builder, and device extensions inside the device detail
// drawer. Feature modules must use ../api for every request and must not
// touch DOM owned by the shell.
import type { ComponentType } from "react"

export type WorkspaceID =
  | "start"
  | "tests"
  | "traffic"
  | "devices"
  | "protocols"
  | "captures"
  | "cases"
  | "policy"
  | "network"
  | "integrations"
  | "testlab"
  | "system"

export type FeatureView = {
  id: string
  workspace: WorkspaceID
  title: string
  // Lower numbers render first within a workspace.
  order: number
  Component: ComponentType
}

// Plan extensions edit one top-level key of the network plan JSON
// (e.g. "wifi" or "ipv6"). onChange replaces that key's value.
export type PlanInterface = {
  name: string
  stable_id: string
  hardware_address?: string
  wireless?: boolean
  ap_supported?: boolean | null
  wireless_bands?: string[]
  addresses: string[]
  flags: string[]
}

export type PlanExtensionProps = {
  planKey: string
  value: unknown
  onChange: (next: unknown) => void
  // Role assignment for interfaces lives in the shell; extensions may request
  // a role for an interface (e.g. "WIFI_AP") through this callback.
  interfaces: PlanInterface[]
  roles: Record<string, string>
  onRoleChange: (stableID: string, role: string) => void
  disabled: boolean
  // The plan's topology (e.g. "TWO_NIC", "VLAN_TRUNK"), so an extension can
  // tell whether it applies.
  topology?: string
  // Issues from the latest server check (preview) of the whole plan.
  validation?: { errors: PlanIssue[]; warnings: PlanIssue[] }
}

export type PlanIssue = { code: string; path: string; message: string }

export type PlanExtension = {
  id: string
  planKey: string
  title: string
  order: number
  // Default value inserted into a new plan, or undefined to omit the key.
  defaultValue?: () => unknown
  Component: ComponentType<PlanExtensionProps>
}

export type DeviceExtensionProps = {
  deviceID: string
  deviceName?: string
}

export type DeviceExtension = {
  id: string
  title: string
  order: number
  Component: ComponentType<DeviceExtensionProps>
}

export const featureViews: FeatureView[] = []
export const planExtensions: PlanExtension[] = []
export const deviceExtensions: DeviceExtension[] = []

export function viewsFor(workspace: WorkspaceID): FeatureView[] {
  return featureViews.filter((view) => view.workspace === workspace).sort((a, b) => a.order - b.order)
}

export function sortedPlanExtensions(): PlanExtension[] {
  return [...planExtensions].sort((a, b) => a.order - b.order)
}

export function sortedDeviceExtensions(): DeviceExtension[] {
  return [...deviceExtensions].sort((a, b) => a.order - b.order)
}

// Navigation contract. The shell renders one workspace at a time selected by
// the URL hash "#/<workspace>". Workspace state that already lives in URL
// search parameters (for example traffic_q and traffic_source for the traffic
// query, or device list filters) is preserved. navigate() updates both and
// dispatches "shakerproxy:navigate" so the shell re-reads URL state.
export const NAVIGATE_EVENT = "shakerproxy:navigate"

export function workspaceHref(workspace: WorkspaceID, params: Record<string, string> = {}): string {
  const search = new URLSearchParams(window.location.search)
  for (const [key, value] of Object.entries(params)) {
    if (value === "") search.delete(key)
    else search.set(key, value)
  }
  const query = search.toString()
  return `${window.location.pathname}${query ? `?${query}` : ""}#/${workspace}`
}

export function navigate(workspace: WorkspaceID, params: Record<string, string> = {}): void {
  window.history.pushState(null, "", workspaceHref(workspace, params))
  window.dispatchEvent(new CustomEvent(NAVIGATE_EVENT, { detail: { workspace, params } }))
}

export function currentWorkspace(): WorkspaceID | undefined {
  const match = /^#\/([a-z]+)/.exec(window.location.hash)
  return match ? (match[1] as WorkspaceID) : undefined
}
