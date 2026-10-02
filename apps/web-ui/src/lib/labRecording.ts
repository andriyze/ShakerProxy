import type { Status } from "../types"

export type LabRecordingNotice = {
  tone: "recording" | "warning"
  text: string
  // The switch to offer: turn automatic recording off, or back on.
  action?: "on" | "off"
  captureID?: string
}

// labRecordingNotice says, in one line, whether lab traffic is being
// recorded (and so analyzed) and what to do when it is not.
export function labRecordingNotice(status: Status | null): LabRecordingNotice | null {
  if (!status) return null
  const recording = status.lab_recording
  if (!recording) {
    // A gateway without automatic recording: only a manual capture records.
    if (status.active_capture_id) return { tone: "recording", text: "Recording lab traffic.", captureID: status.active_capture_id }
    return {
      tone: "warning",
      text: "Nothing is being recorded right now, so devices' connections and DNS lookups are not analyzed. Start a capture to see them here.",
    }
  }
  if (recording.recording && recording.manual) {
    return {
      tone: "recording",
      text: "Recording lab traffic with a manual capture. Automatic recording resumes when it ends.",
      captureID: recording.session_id,
    }
  }
  if (recording.recording) {
    return { tone: "recording", text: "Recording lab traffic.", action: "off", captureID: recording.session_id }
  }
  if (!recording.enabled) {
    return {
      tone: "warning",
      text: "Automatic lab recording is off, so devices' connections and DNS lookups are not analyzed.",
      action: "on",
    }
  }
  return { tone: "warning", text: recording.reason || "Lab traffic is not being recorded right now." }
}
