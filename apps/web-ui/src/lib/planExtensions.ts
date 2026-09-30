// Merging network-plan extension state (features/registry.ts PlanExtension)
// into the plan JSON the shell builds. Pure.

export type PlannedInterface = Record<string, unknown> & { stable_id: string; current_name?: string; role: string }

export type InterfaceIdentity = { name: string; stable_id: string; hardware_address?: string }

// Topologies whose lab side the shell builds from its own fields, so
// extensions (Wi-Fi AP, IPv6 strategy) do not apply to them.
export const TOPOLOGIES_WITHOUT_EXTENSIONS = new Set(["PASSIVE_SENSOR", "SINGLE_ARM"])

export function extensionsApply(topology: string): boolean {
  return !TOPOLOGIES_WITHOUT_EXTENSIONS.has(topology)
}

// mergePlanExtensions writes each extension's value under its planKey.
// Undefined values leave the shell's own value (or omit the key).
export function mergePlanExtensions(
  plan: Record<string, unknown>,
  values: Record<string, unknown>,
  planKeys: Iterable<string>,
): Record<string, unknown> {
  const next = { ...plan }
  for (const key of planKeys) {
    const value = values[key]
    if (value !== undefined) next[key] = value
  }
  return next
}

// applyExtensionRoles applies roles requested by extensions (for example
// "WIFI_AP" for a wireless interface). A requested role replaces the role
// the shell gave that interface; an empty role removes a previously
// requested extension role but never removes a shell-assigned interface.
export function applyExtensionRoles(
  planned: PlannedInterface[],
  roles: Record<string, string>,
  interfaces: InterfaceIdentity[],
): PlannedInterface[] {
  const next = planned.map((item) => ({ ...item }))
  for (const [stableID, role] of Object.entries(roles)) {
    if (!role) continue
    const existing = next.find((item) => item.stable_id === stableID && item.vlan_id === undefined)
    if (existing) {
      existing.role = role
      continue
    }
    const source = interfaces.find((item) => item.stable_id === stableID)
    if (!source) continue
    next.push({
      stable_id: source.stable_id,
      current_name: source.name,
      ...(source.hardware_address ? { permanent_mac: source.hardware_address } : {}),
      role,
    })
  }
  return next
}

// shellRoles describes the roles the shell's own selects assign, keyed by
// stable interface ID, so extensions can show them.
export function shellRoles(assignments: { stableID?: string; role: string }[]): Record<string, string> {
  const roles: Record<string, string> = {}
  for (const assignment of assignments) if (assignment.stableID) roles[assignment.stableID] = assignment.role
  return roles
}

export function interfaceLabel(item: {
  name: string
  driver?: string
  wireless?: boolean
  ap_supported?: boolean | null
}): string {
  const wifi = item.wireless
    ? item.ap_supported === true
      ? " · Wi-Fi (can host an access point)"
      : item.ap_supported === false
        ? " · Wi-Fi (no access point support)"
        : " · Wi-Fi"
    : ""
  return `${item.name}${wifi}${item.driver && !item.wireless ? ` · ${item.driver}` : ""}`
}
