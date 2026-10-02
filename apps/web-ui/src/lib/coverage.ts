import type { CoverageReport, CoverageResult } from "../types"

// Plain wording for the visibility coverage panel; no runtime imports so it
// loads on its own in tests.

export function coverageDelay(result: CoverageResult): string {
  if (result.status !== "PASS") return "—"
  const milliseconds = result.latency_ms ?? 0
  return milliseconds < 1000 ? "under 1 s" : `${(milliseconds / 1000).toFixed(1)} s`
}

export function coverageHeadline(run: CoverageReport | null): string {
  if (!run) return "Not run yet. Run it to prove which kinds of traffic ShakerProxy records on this appliance."
  if (run.state === "RUNNING") return `${run.phase || "Running"}…`
  if (run.state === "FAILED") return `The last check failed: ${run.error || "unknown error"}`
  const probed = run.pass_count + run.fail_count
  return `${run.pass_count} of ${probed} traffic types seen and identified${run.fail_count ? `; ${run.fail_count} missing or not identified` : ""}.`
}
