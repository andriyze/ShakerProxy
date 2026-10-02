import assert from "node:assert/strict"
import test from "node:test"
import { coverageDelay, coverageHeadline } from "../../apps/web-ui/src/lib/coverage.ts"
import { webUIFile } from "./web-ui-source.mjs"

const result = (status, latency) => ({ id: "x", name: "X", category: "c", status, summary: "", event_kinds: [], latency_ms: latency, attributed: false })

test("coverage results read as plain words", () => {
  assert.equal(coverageDelay(result("PASS", 2100)), "2.1 s")
  assert.equal(coverageDelay(result("PASS", 400)), "under 1 s")
  assert.equal(coverageDelay(result("FAIL", 2100)), "—")
  assert.match(coverageHeadline(null), /^Not run yet/)
  assert.equal(coverageHeadline({ state: "RUNNING", phase: "Sending one of each traffic type" }), "Sending one of each traffic type…")
  assert.equal(coverageHeadline({ state: "FAILED", error: "The virtual test lab could not be built" }), "The last check failed: The virtual test lab could not be built")
  assert.equal(
    coverageHeadline({ state: "COMPLETED", pass_count: 12, fail_count: 2 }),
    "12 of 14 traffic types seen and identified; 2 missing or not identified.",
  )
})

test("the System page runs the coverage check and lists every way around ShakerProxy", () => {
  assert.match(webUIFile("workspaces/system/SystemWorkspace.tsx"), /<VisibilityCoveragePanel \/>\s*<WiFiVisibilityPanel \/>\s*<TestLabPanel \/>/)
  const panel = webUIFile("workspaces/system/VisibilityCoveragePanel.tsx")
  assert.match(panel, /api<CoverageOverview>\("\/api\/v1\/coverage"\)/)
  assert.match(panel, /withPassword\("run the visibility coverage check"/)
  assert.match(panel, /"\/api\/v1\/coverage\/runs", \{ method: "POST"/)
  assert.match(panel, /Ways around ShakerProxy in this lab/)
  // Polls quickly only while a check runs.
  assert.match(panel, /usePolling\(\(\) => refresh\(\), running \? 3_000 : 30_000, \[running\]\)/)
})
