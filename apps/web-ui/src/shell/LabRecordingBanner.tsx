import React, { useState } from "react"
import { api, describeError } from "../api"
import { labRecordingNotice } from "../lib/labRecording"
import type { LabRecordingStatus } from "../types"
import { useAppState } from "./AppContext"

// LabRecordingBanner says whether lab traffic is being recorded, and so
// analyzed, with a switch for automatic recording.
export function LabRecordingBanner() {
  const { status, refreshStatus } = useAppState()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const notice = labRecordingNotice(status)
  if (!notice) return null

  async function setRecording(enabled: boolean) {
    setBusy(true)
    setError("")
    try {
      await api<LabRecordingStatus>("/api/v1/captures/lab-recording", { method: "PUT", body: JSON.stringify({ enabled }) })
      await refreshStatus()
    } catch (reason) {
      setError(describeError(reason, "The recording setting could not be changed"))
    } finally {
      setBusy(false)
    }
  }

  return (
    <p className={`lab-recording ${notice.tone}`} role="status">
      {notice.tone === "recording" && <span className="lab-recording-dot" aria-hidden="true" />}
      {notice.text}{" "}
      {notice.captureID && notice.tone === "recording" && <a href="#/captures">View capture</a>}
      {!status?.lab_recording && notice.tone === "warning" && <a href="#/captures">Start a capture</a>}
      {notice.action && (
        <button type="button" className="quiet lab-recording-switch" disabled={busy} onClick={() => void setRecording(notice.action === "on")}>
          {notice.action === "on" ? "Turn on" : "Turn off"}
        </button>
      )}
      {error && <span className="lab-recording-error">{error}</span>}
    </p>
  )
}
