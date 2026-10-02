import assert from "node:assert/strict"
import test from "node:test"
import { webUIFile, webUIFiles } from "./web-ui-source.mjs"

test("every workspace renders its registered feature views inside an error boundary", () => {
  const common = webUIFile("shell/common.tsx")
  assert.match(common, /const views = viewsFor\(workspace\)/)
  assert.match(common, /<FeatureBoundary title=\{view\.title\}> <view\.Component \/>/)
  const workspaces = webUIFile("workspaces/index.tsx")
  for (const id of ["protocols", "tests"]) assert.match(workspaces, new RegExp(`id="${id}"`))
  const expected = {
    "workspaces/start/StartWorkspace.tsx": "start",
    "workspaces/devices/DevicesWorkspace.tsx": "devices",
    "workspaces/traffic/TrafficWorkspace.tsx": "traffic",
    "workspaces/captures/CapturesWorkspace.tsx": "captures",
    "workspaces/policy/PolicyWorkspace.tsx": "policy",
    "workspaces/network/NetworkWorkspace.tsx": "network",
    "workspaces/cases/CasesWorkspace.tsx": "cases",
    "workspaces/integrations/IntegrationsWorkspace.tsx": "integrations",
    "workspaces/system/SystemWorkspace.tsx": "system",
  }
  for (const [path, id] of Object.entries(expected)) {
    assert.match(webUIFile(path), new RegExp(`<FeatureViews workspace="${id}" />`), path)
  }
  assert.match(webUIFile("workspaces/system/SystemWorkspace.tsx"), /<FeatureViews workspace="testlab" \/>/)
})

test("the Start checklist renders above the start feature views", () => {
  const start = webUIFile("workspaces/start/StartWorkspace.tsx")
  assert.ok(start.indexOf('className="checklist"') < start.indexOf('<FeatureViews workspace="start" />'))
  assert.match(start, /navigate\(item\.action\.workspace\)/)
})

test("the device drawer renders device extensions and a View traffic action", () => {
  const drawer = webUIFile("workspaces/devices/DeviceDetailDrawer.tsx")
  assert.match(drawer, /const extensions = sortedDeviceExtensions\(\)/)
  assert.match(drawer, /<extension\.Component deviceID=\{device\.id\}/)
  assert.match(drawer, /View traffic/)
  const inventory = webUIFile("workspaces/devices/DeviceInventory.tsx")
  assert.match(inventory, /navigate\("traffic", \{ traffic_q: deviceQuery\(deviceID, "", formerIDs\), traffic_source: "" \}\)/)
})

test("the shell uses the features index (type-only imports aside)", () => {
  assert.match(webUIFile("main.tsx"), /import "\.\/features"/)
  for (const path of webUIFiles()) {
    const source = webUIFile(path)
    for (const match of source.matchAll(/import (?!type\b)[^"]*? from "([^"]*features[^"]*)"/g)) {
      assert.match(match[1], /\/features$/, `${path} imports ${match[1]} instead of the features index`)
    }
  }
})
