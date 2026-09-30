// Maps network-plan validation issues from the server preview onto the
// fields of a plan extension editor.
// Keep this file free of runtime imports so node --test can load it directly.
import type { PlanValidationResult } from "./types"

export type ServerIssue = { field: string; code: string; message: string; severity: "error" | "warning" }

// serverPlanIssues returns the issues that belong to one plan key: a path of
// "<planKey>.<field>" maps to that field, "<planKey>" alone to "" (general).
// Issues on "interfaces[…]" or "interfaces" whose code starts with codePrefix
// map to the "interface" field; other codePrefix issues are general.
export function serverPlanIssues(validation: PlanValidationResult | undefined, planKey: string, codePrefix = ""): ServerIssue[] {
  if (!validation) return []
  const result: ServerIssue[] = []
  const collect = (issues: readonly { code: string; path: string; message: string }[] | undefined, severity: ServerIssue["severity"]) => {
    for (const issue of issues ?? []) {
      const path = issue.path ?? ""
      const ownsCode = codePrefix !== "" && (issue.code ?? "").startsWith(codePrefix)
      let field: string | undefined
      if (path === planKey) field = ""
      else if (path.startsWith(`${planKey}.`)) field = path.slice(planKey.length + 1).split(/[.[]/)[0]
      else if (ownsCode && /^interfaces(\[|$|\.)/.test(path)) field = "interface"
      else if (ownsCode) field = ""
      if (field !== undefined) result.push({ field, code: issue.code, message: issue.message, severity })
    }
  }
  collect(validation.errors, "error")
  collect(validation.warnings, "warning")
  return result
}
