import assert from "node:assert/strict"
import { readdir, readFile } from "node:fs/promises"
import { registerHooks } from "node:module"
import test from "node:test"

const dir = new URL("../../apps/web-ui/src/features/", import.meta.url)
const read = (name) => readFile(new URL(name, dir), "utf8")
const files = (await readdir(dir)).filter((name) => /\.(ts|tsx)$/.test(name))
const sources = Object.fromEntries(await Promise.all(files.map(async (name) => [name, await read(name)])))

const REGISTRATIONS = [
  ["ProtocolsView.tsx", /registerView\(\{ id: "protocols", workspace: "protocols",/],
  ["TestsView.tsx", /registerView\(\{ id: "test-runs", workspace: "tests",/],
  ["InspectWizard.tsx", /registerView\(\{ id: "inspect-wizard", workspace: "start",/],
  ["InspectWizard.tsx", /registerDeviceExtension\(\{ id: "inspect-device", title: "Inspect this device",/],
  ["DeviceReport.tsx", /registerDeviceExtension\(\{ id: "device-report",/],
  ["DeviceControls.tsx", /registerDeviceExtension\(\{ id: "device-controls",/],
  ["WifiPlanEditor.tsx", /registerPlanExtension\(\{ id: "wifi-ap", planKey: "wifi",/],
  ["Ipv6PlanEditor.tsx", /registerPlanExtension\(\{ id: "lab-ipv6", planKey: "ipv6",.*defaultValue: \(\) => \(\{ strategy: "DISABLED" \}\)/],
]

test("every feature registers itself and index.ts imports it", () => {
  const index = sources["index.ts"]
  for (const [file, pattern] of REGISTRATIONS) {
    assert.match(sources[file], pattern, file)
    assert.match(index, new RegExp(`import "\\./${file.replace(/\.tsx$/, "")}"`), `index.ts imports ${file}`)
  }
  assert.match(index, /export \* from "\.\/registry"/)
})

test("the registry import has no side effects beyond registration", () => {
  const code = sources["index.ts"].split("\n").filter((line) => line.trim() && !line.trim().startsWith("//"))
  for (const line of code) assert.match(line, /^(import "\.\/[A-Za-z0-9]+"|export \* from "\.\/registry")$/, line)
  // Feature modules only touch the registry at top level: no timers, listeners or requests on import.
  for (const [name, source] of Object.entries(sources)) {
    const topLevel = source.split("\n").filter((line) => /^[a-zA-Z]/.test(line) && !/^(import|export|const|let|type|function|registerView|registerPlanExtension|registerDeviceExtension|\/\/)/.test(line))
    assert.deepEqual(topLevel, [], `${name} has unexpected top-level statements`)
  }
})

test("requests go through the shared API client", () => {
  for (const [name, source] of Object.entries(sources)) {
    if (name === "registry.ts") continue
    assert.doesNotMatch(source, /\bfetch\(|XMLHttpRequest|new WebSocket|EventSource/, name)
    assert.doesNotMatch(source, /dangerouslySetInnerHTML|innerHTML\s*=/, `${name} must not inject HTML`)
    assert.doesNotMatch(source, /localStorage|sessionStorage/, `${name} must not keep its own session state`)
  }
  for (const name of ["ProtocolsView.tsx", "TestsView.tsx", "DeviceReport.tsx", "DeviceControls.tsx", "InspectWizard.tsx", "StartTestRun.tsx", "shared.tsx"]) {
    assert.match(sources[name], /from "\.\.\/api"|from "\.\/shared"/, name)
  }
  assert.match(sources["shared.tsx"], /import \{ api, (ApiError, )?describeError \} from "\.\.\/api"/)
})

test("contract endpoints are wired to the right screens", () => {
  const all = Object.values(sources).join("\n")
  for (const endpoint of ["/api/v1/protocols?", "/api/v1/protocols/catalog", "/protocols?window=", "/api/v1/test-sessions", "/stop", "/report?", "/compare?", "/ca-trust", "/controls", "/api/v1/interception-ca/onboarding", "/api/v1/devices/resolve?q=", "/api/v1/devices?", "/api/v1/events?limit=100&q="]) {
    assert.ok(all.includes(endpoint), endpoint)
  }
  assert.match(sources["TestsView.tsx"], /method: "PATCH"/)
  assert.match(sources["TestsView.tsx"], /method: "DELETE"/)
  assert.match(sources["DeviceReport.tsx"], /method: "PUT", body: JSON\.stringify\(\{ state \}\)/)
  assert.match(sources["InspectWizard.tsx"], /controlsUpdate\(current, \{ decrypt_https: true \}\)/)
  assert.match(sources["ProtocolsView.tsx"], /navigate\("traffic", \{ traffic_q: trafficQueryForProtocol\(protocol\.protocol\) \}\)/)
  assert.match(sources["DeviceReport.tsx"], /downloadBlob\(/)
  assert.match(sources["DeviceReport.tsx"], /window\.print\(\)/)
})

test("polling respects visibility and minimum intervals", () => {
  assert.match(sources["shared.tsx"], /document\.visibilityState === "visible"/)
  assert.match(sources["shared.tsx"], /visibilitychange/)
  for (const [name, source] of Object.entries(sources)) {
    for (const match of source.matchAll(/usePolling\([^,]+,\s*(\d[\d_]*)/g)) {
      const interval = Number(match[1].replace(/_/g, ""))
      if (name === "InspectWizard.tsx") assert.equal(interval, 3000, "wizard verify polls every 3 s")
      else assert.ok(interval >= 5000, `${name} polls every ${interval} ms`)
    }
    for (const match of source.matchAll(/useResource<[^>]+>\(.*,\s*(\d+)\)\s*$/gm)) assert.ok(Number(match[1]) >= 5000, `${name} resource polls every ${match[1]} ms`)
    if (name !== "shared.tsx") assert.doesNotMatch(source, /setInterval\(/, `${name} must poll through usePolling`)
  }
})

test("plan extensions render inside the shell's form without nesting forms", () => {
  for (const name of ["WifiPlanEditor.tsx", "Ipv6PlanEditor.tsx"]) {
    const code = sources[name].split("\n").filter((line) => !line.trim().startsWith("//")).join("\n")
    assert.doesNotMatch(code, /<form[\s>]/, name)
    assert.doesNotMatch(code, /<button(?![^>]*type="button")/, `${name} buttons must be type="button"`)
    assert.match(sources[name], /<fieldset className="lgf-plan-ext/, name)
  }
  assert.match(sources["WifiPlanEditor.tsx"], /onRoleChange\(stableID, AP_ROLE\)/)
  assert.match(sources["WifiPlanEditor.tsx"], /const AP_ROLE = "WIFI_AP"/)
})

test("every control is labelled", () => {
  for (const [name, source] of Object.entries(sources)) {
    if (!name.endsWith(".tsx")) continue
    const inputs = source.match(/<(input|select|textarea)\b[^>]*>/g) ?? []
    for (const tag of inputs) {
      const labelled = /\bid=|aria-label=|aria-labelledby=/.test(tag) || /type="(checkbox|radio)"/.test(tag)
      assert.ok(labelled, `${name}: ${tag.slice(0, 80)}`)
    }
  }
})

// Resolve extension-less relative imports (as Vite does) so register.ts can load.
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (/^\.\.?\//.test(specifier) && !/\.[cm]?[jt]sx?$/.test(specifier) && context.parentURL?.includes("/apps/web-ui/src/")) {
      return nextResolve(`${specifier}.ts`, context)
    }
    return nextResolve(specifier, context)
  },
})

test("registration is idempotent and ordered", async () => {
  const registry = await import("../../apps/web-ui/src/features/registry.ts")
  const { registerView, registerPlanExtension, registerDeviceExtension } = await import("../../apps/web-ui/src/features/register.ts")
  const Component = () => null
  registerView({ id: "b", workspace: "tests", title: "B", order: 20, Component })
  registerView({ id: "a", workspace: "tests", title: "A", order: 10, Component })
  registerView({ id: "a", workspace: "tests", title: "A2", order: 10, Component })
  assert.deepEqual(registry.viewsFor("tests").map((view) => view.title), ["A2", "B"])
  registerPlanExtension({ id: "wifi-ap", planKey: "wifi", title: "Wi-Fi", order: 10, Component })
  registerPlanExtension({ id: "wifi-ap", planKey: "wifi", title: "Wi-Fi", order: 10, Component })
  assert.equal(registry.planExtensions.length, 1)
  registerDeviceExtension({ id: "x", title: "X", order: 1, Component })
  registerDeviceExtension({ id: "x", title: "X", order: 1, Component })
  assert.equal(registry.deviceExtensions.length, 1)
})
