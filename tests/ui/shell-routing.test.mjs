import assert from "node:assert/strict"
import test from "node:test"
import {
  DEFAULT_WORKSPACE,
  WORKSPACES,
  parseWorkspaceHash,
  routeKey,
  workspaceForShortcut,
  workspaceMeta,
} from "../../apps/web-ui/src/lib/routing.ts"
import { webUIFile } from "./web-ui-source.mjs"

test("workspaces follow the contract order with plain labels", () => {
  assert.deepEqual(
    WORKSPACES.map((workspace) => workspace.id),
    ["start", "devices", "traffic", "protocols", "tests", "captures", "policy", "network", "cases", "integrations", "system"],
  )
  assert.equal(workspaceMeta("policy").label, "DNS & HTTPS")
  for (const workspace of WORKSPACES) {
    assert.ok(workspace.description.length > 0 && workspace.description.length <= 40, workspace.id)
    assert.ok(workspace.intro.length > 0, workspace.id)
  }
})

test("hash routing maps known, aliased and unknown hashes", () => {
  assert.equal(DEFAULT_WORKSPACE, "start")
  assert.equal(parseWorkspaceHash(""), "start")
  assert.equal(parseWorkspaceHash("#/"), "start")
  assert.equal(parseWorkspaceHash("#/traffic"), "traffic")
  assert.equal(parseWorkspaceHash("#/Traffic"), "traffic")
  assert.equal(parseWorkspaceHash("#/devices?x=1"), "devices")
  assert.equal(parseWorkspaceHash("#/testlab"), "system")
  assert.equal(parseWorkspaceHash("#/overview"), "start")
  assert.equal(parseWorkspaceHash("#/nope"), "start")
  assert.equal(parseWorkspaceHash("#traffic"), "traffic")
})

test("route keys change with the workspace or the shell's own URL state", () => {
  assert.equal(routeKey("#/traffic", "?traffic_q=a"), "traffic|traffic_q=a")
  assert.notEqual(routeKey("#/traffic", "?traffic_q=a"), routeKey("#/traffic", "?traffic_q=b"))
  assert.notEqual(routeKey("#/devices", "?device_view=online"), routeKey("#/devices", ""))
  assert.equal(routeKey("#/bogus", ""), "start|")
  // Feature-owned parameters (the inspect wizard's inspect_device) do not
  // remount the workspace; the feature reacts to shakerproxy:navigate itself.
  assert.equal(routeKey("#/start", "?inspect_device=tv"), routeKey("#/start", ""))
  assert.equal(
    routeKey("#/traffic", "?b=1&traffic_source=ZEEK&traffic_q=x"),
    routeKey("#/traffic", "?traffic_q=x&traffic_source=ZEEK"),
  )
})

test("Alt+digit shortcuts use KeyboardEvent.code, not the typed character", () => {
  assert.equal(workspaceForShortcut("Digit1"), "start")
  assert.equal(workspaceForShortcut("Digit3"), "traffic")
  assert.equal(workspaceForShortcut("Digit0"), "integrations")
  assert.equal(workspaceForShortcut("KeyA"), undefined)
  // macOS produces "¡" for Alt+1 in event.key.
  assert.equal(workspaceForShortcut("¡"), undefined)
  const dashboard = webUIFile("shell/Dashboard.tsx")
  assert.match(dashboard, /workspaceForShortcut\(event\.code\)/)
  assert.doesNotMatch(dashboard, /Number\(event\.key\)/)
})

test("the shell follows hash changes, back/forward and shakerproxy:navigate", () => {
  const dashboard = webUIFile("shell/Dashboard.tsx")
  assert.match(dashboard, /addEventListener\("hashchange", update\)/)
  assert.match(dashboard, /addEventListener\("popstate", update\)/)
  assert.match(dashboard, /addEventListener\(NAVIGATE_EVENT, update\)/)
  assert.match(dashboard, /<WorkspaceView key=\{route\.key\} id=\{route\.workspace\} \/>/)
  const nav = webUIFile("shell/SideNav.tsx")
  assert.match(nav, /aria-current=\{current === workspace\.id \? "page" : undefined\}/)
})
