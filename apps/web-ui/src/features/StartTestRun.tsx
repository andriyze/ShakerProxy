// "Start test run" form (§5), shared by the Tests workspace and the wizard.
import { useId, useState, type FormEvent } from "react"
import { api, describeError } from "../api"
import { defaultRunName } from "./tests-model"
import { DevicePicker } from "./shared"
import type { DeviceChoice, StartTestSessionRequest, TestSession } from "./types"

export function StartTestRunForm({ fixedDevice, onStarted, submitLabel = "Start test run" }: { fixedDevice?: DeviceChoice; onStarted: (session: TestSession) => void; submitLabel?: string }) {
  const [picked, setPicked] = useState<DeviceChoice | null>(null)
  const [name, setName] = useState("")
  const [capture, setCapture] = useState(false)
  const [fullCapture, setFullCapture] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const nameID = useId()
  const captureHintID = useId()
  const device = fixedDevice ?? picked

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!device) {
      setError("Choose the device you are testing first.")
      return
    }
    setBusy(true)
    setError("")
    const body: StartTestSessionRequest = { device: device.device_id, capture }
    if (capture && fullCapture) body.full_capture = true
    if (name.trim()) body.name = name.trim()
    try {
      const session = await api<TestSession>("/api/v1/test-sessions", { method: "POST", body: JSON.stringify(body) })
      setName("")
      setCapture(false)
      setFullCapture(false)
      if (!fixedDevice) setPicked(null)
      onStarted(session)
    } catch (reason) {
      setError(describeError(reason, "Could not start the test run."))
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="lgf-form" onSubmit={submit} noValidate>
      {!fixedDevice && <DevicePicker value={picked} onChange={setPicked} />}
      <div className="lgf-field">
        <label className="lgf-label" htmlFor={nameID}>
          Name <span className="lgf-optional">(optional)</span>
        </label>
        <input id={nameID} className="lgf-input" type="text" maxLength={128} value={name} placeholder={device ? defaultRunName(device.name) : "Firmware 2.1 first boot"} onChange={(event) => setName(event.target.value)} />
        <p className="lgf-hint">Name it after what you are testing, e.g. the firmware or app version, so comparisons are easy to read.</p>
      </div>
      <label className="lgf-checkbox">
        <input type="checkbox" checked={capture} aria-describedby={captureHintID} onChange={(event) => setCapture(event.target.checked)} />
        Also record packets
      </label>
      <p id={captureHintID} className="lgf-hint lgf-tight">
        Saves a packet capture (PCAP) of the run for Wireshark, when capture is available on this ShakerProxy. Only one run per device can be active; starting a new one stops the previous run.
      </p>
      {capture && (
        <label className="lgf-checkbox">
          <input type="checkbox" checked={fullCapture} onChange={(event) => setFullCapture(event.target.checked)} />
          Record whole packets, so TLS server names and certificates are analyzed (larger files; includes unencrypted content)
        </label>
      )}
      {error && (
        <p className="lgf-inline-error" role="alert">
          {error}
        </p>
      )}
      <div className="lgf-actions">
        <button type="submit" className="lgf-button" disabled={busy || !device}>
          {busy ? "Starting…" : submitLabel}
        </button>
      </div>
    </form>
  )
}
