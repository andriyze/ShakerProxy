import assert from "node:assert/strict"
import test from "node:test"
import { buildChecklist, checklistProgress, nextStep } from "../../apps/web-ui/src/lib/checklist.ts"

const fresh = {
  operatingMode: "SAFE_SETUP",
  networkChangePending: false,
  onlineDevices: 0,
  caAvailable: false,
  caReason: "Apply a routed network plan first",
  recentEvents: 0,
  testRuns: 0,
}

test("a fresh appliance starts at the network step", () => {
  const items = buildChecklist(fresh)
  assert.deepEqual(
    items.map((item) => item.id),
    ["network", "device", "https", "traffic", "test"],
  )
  assert.ok(items.every((item) => item.state === "todo"))
  assert.equal(nextStep(items)?.id, "network")
  assert.equal(items[0].action.workspace, "network")
  assert.equal(items[2].detail, "Apply a routed network plan first")
  assert.deepEqual(checklistProgress(items), { done: 0, total: 5 })
})

test("each item is computed from real state and links to where you do it", () => {
  const items = buildChecklist({
    operatingMode: "ROUTED_PASSTHROUGH",
    networkChangePending: false,
    onlineDevices: 2,
    caAvailable: true,
    recentEvents: 5,
    testRuns: 0,
  })
  assert.deepEqual(
    items.map((item) => item.state),
    ["done", "done", "done", "done", "todo"],
  )
  assert.equal(nextStep(items)?.id, "test")
  assert.equal(nextStep(items)?.action.workspace, "tests")
  assert.match(items[1].detail, /2 devices online/)
  assert.deepEqual(
    items.map((item) => item.action.workspace),
    ["network", "devices", "policy", "traffic", "tests"],
  )
})

test("unknown inputs are shown as unknown, never as done", () => {
  const items = buildChecklist({
    operatingMode: null,
    networkChangePending: false,
    onlineDevices: null,
    caAvailable: null,
    recentEvents: null,
    testRuns: null,
  })
  assert.ok(items.every((item) => item.state === "unknown"))
  assert.equal(nextStep(items), undefined)
  assert.match(items[4].detail, /not available on this appliance/)
})

test("a pending network change is called out", () => {
  const [network] = buildChecklist({ ...fresh, networkChangePending: true })
  assert.equal(network.state, "todo")
  assert.match(network.detail, /waiting for you/)
})
