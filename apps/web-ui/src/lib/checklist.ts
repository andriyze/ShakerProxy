// First-run checklist for the Start workspace, computed from real appliance
// state. Pure so the rules can be unit tested.
import type { WorkspaceID } from "../features/registry"

// Each input is null when ShakerProxy could not find out (endpoint unavailable or
// still loading); the item then shows as "unknown" rather than done or failed.
export type ChecklistInputs = {
  operatingMode: string | null
  networkChangePending: boolean
  onlineDevices: number | null
  caAvailable: boolean | null
  caReason?: string
  recentEvents: number | null
  testRuns: number | null
}

export type ChecklistState = "done" | "todo" | "unknown"

export type ChecklistItem = {
  id: "network" | "device" | "https" | "traffic" | "test"
  title: string
  state: ChecklistState
  detail: string
  action: { label: string; workspace: WorkspaceID }
}

export const ROUTED_MODE = "ROUTED_PASSTHROUGH"

function state(value: boolean | null): ChecklistState {
  if (value === null) return "unknown"
  return value ? "done" : "todo"
}

function plural(count: number, word: string): string {
  return `${count} ${word}${count === 1 ? "" : "s"}`
}

export function buildChecklist(inputs: ChecklistInputs): ChecklistItem[] {
  const networkDone = inputs.operatingMode === null ? null : inputs.operatingMode === ROUTED_MODE
  const devicesDone = inputs.onlineDevices === null ? null : inputs.onlineDevices > 0
  const trafficDone = inputs.recentEvents === null ? null : inputs.recentEvents > 0
  const testsDone = inputs.testRuns === null ? null : inputs.testRuns > 0

  return [
    {
      id: "network",
      title: "Set up the lab network",
      state: state(networkDone),
      detail: networkDone
        ? "The lab network is live. Devices on it reach the internet through ShakerProxy."
        : inputs.networkChangePending
          ? "A network change is waiting for you. Open Network to finish or discard it."
          : "Pick the port that goes to the internet and the port (or Wi-Fi) your test devices use, then apply.",
      action: { label: networkDone ? "Review network" : "Set up network", workspace: "network" },
    },
    {
      id: "device",
      title: "Connect a device",
      state: state(devicesDone),
      detail: devicesDone
        ? `${plural(inputs.onlineDevices ?? 0, "device")} online right now.`
        : devicesDone === null
          ? "ShakerProxy could not check for devices yet."
          : "Plug the device into the lab port or join the lab Wi-Fi. It appears here within a minute.",
      action: { label: devicesDone ? "See devices" : "Find my device", workspace: "devices" },
    },
    {
      id: "https",
      title: "Get ready to decrypt HTTPS",
      state: state(inputs.caAvailable),
      detail: inputs.caAvailable
        ? "The ShakerProxy certificate is ready. Install it on a device to see inside its HTTPS traffic."
        : inputs.caAvailable === null
          ? "ShakerProxy could not check the HTTPS certificate yet."
          : inputs.caReason || "Set up the lab network first, then install the ShakerProxy certificate on your device.",
      action: { label: "Set up HTTPS decryption", workspace: "policy" },
    },
    {
      id: "traffic",
      title: "See traffic",
      state: state(trafficDone),
      detail: trafficDone
        ? "Traffic was seen in the last hour."
        : trafficDone === null
          ? "ShakerProxy could not check for traffic yet."
          : "Use the device normally — open its app, play a video. Activity shows up in Traffic.",
      action: { label: "Watch traffic", workspace: "traffic" },
    },
    {
      id: "test",
      title: "Run your first test",
      state: state(testsDone),
      detail: testsDone
        ? `${plural(inputs.testRuns ?? 0, "test run")} recorded.`
        : testsDone === null
          ? "Test runs are not available on this appliance yet."
          : "Start a named test run for a device so you can report on it and compare runs later.",
      action: { label: testsDone ? "See tests" : "Start a test", workspace: "tests" },
    },
  ]
}

// nextStep returns the first item that still needs doing, or undefined when
// everything known is done.
export function nextStep(items: ChecklistItem[]): ChecklistItem | undefined {
  return items.find((item) => item.state === "todo")
}

export function checklistProgress(items: ChecklistItem[]): { done: number; total: number } {
  return { done: items.filter((item) => item.state === "done").length, total: items.length }
}
