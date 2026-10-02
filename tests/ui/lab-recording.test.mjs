import assert from "node:assert/strict"
import test from "node:test"
import { labRecordingNotice } from "../../apps/web-ui/src/lib/labRecording.ts"
import { webUIFile } from "./web-ui-source.mjs"

const CAPTURE = `capture-${"0a".repeat(16)}`
const base = { operating_mode: "ROUTED_PASSTHROUGH", capture_available: true }

test("the lab recording banner says what is recorded and offers the switch", () => {
  assert.equal(labRecordingNotice(null), null)
  assert.deepEqual(labRecordingNotice({ ...base, active_capture_id: CAPTURE, lab_recording: { enabled: true, recording: true, session_id: CAPTURE, checked_at: "" } }), {
    tone: "recording",
    text: "Recording lab traffic.",
    action: "off",
    captureID: CAPTURE,
  })
  const manual = labRecordingNotice({ ...base, lab_recording: { enabled: true, recording: true, manual: true, session_id: CAPTURE, checked_at: "" } })
  assert.equal(manual.tone, "recording")
  assert.equal(manual.action, undefined)
  assert.match(manual.text, /resumes when it ends/)
  const off = labRecordingNotice({ ...base, lab_recording: { enabled: false, recording: false, checked_at: "" } })
  assert.equal(off.tone, "warning")
  assert.equal(off.action, "on")
  assert.match(off.text, /off/)
  const noLab = labRecordingNotice({ ...base, lab_recording: { enabled: true, recording: false, reason: "No lab network plan is confirmed yet. Recording starts when one is.", checked_at: "" } })
  assert.equal(noLab.text, "No lab network plan is confirmed yet. Recording starts when one is.")
  assert.equal(noLab.action, undefined)
})

test("an older gateway without automatic recording still gets the capture hint", () => {
  assert.match(labRecordingNotice({ ...base }).text, /Start a capture/)
  assert.equal(labRecordingNotice({ ...base, active_capture_id: CAPTURE }).tone, "recording")
})

test("Traffic and Devices show the lab recording banner, which toggles through the API", () => {
  assert.match(webUIFile("workspaces/traffic/TrafficWorkspace.tsx"), /<LabRecordingBanner \/>/)
  assert.match(webUIFile("workspaces/devices/DevicesWorkspace.tsx"), /<LabRecordingBanner \/>/)
  const banner = webUIFile("shell/LabRecordingBanner.tsx")
  assert.match(banner, /"\/api\/v1\/captures\/lab-recording", \{ method: "PUT"/)
  assert.match(banner, /await refreshStatus\(\)/)
})
