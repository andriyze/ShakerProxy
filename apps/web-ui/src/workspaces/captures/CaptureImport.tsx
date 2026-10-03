import React, { FormEvent, useRef, useState } from "react"
import { authFetch, responseError } from "../../shell/authFetch"
import { describeError } from "../../api"
import { formatBytes } from "../../lib/format"
import { ErrorBox } from "../../shell/common"

type ImportResult = {
  session_id: string
  packets: number
  size_bytes: number
  first_packet?: string
  last_packet?: string
  view_path: string
}

// CaptureImport uploads a .pcapng captured elsewhere (for example the UniFi
// gateway's own packet capture) and shows it being analyzed like a recording.
export function CaptureImport({ canImport, blockedReason, onImported }: { canImport: boolean; blockedReason: string; onImported: () => void }) {
  const fileInput = useRef<HTMLInputElement>(null)
  const [name, setName] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const [result, setResult] = useState<ImportResult | null>(null)

  async function submit(event: FormEvent) {
    event.preventDefault()
    const file = fileInput.current?.files?.[0]
    if (!file) {
      setError("Choose a .pcapng file to import.")
      return
    }
    const form = new FormData()
    form.append("file", file)
    if (name.trim()) form.append("name", name.trim())
    setBusy(true)
    setError("")
    setResult(null)
    try {
      const response = await authFetch("/api/v1/captures/import", { method: "POST", body: form })
      if (!response.ok) throw await responseError(response)
      setResult((await response.json()) as ImportResult)
      setName("")
      if (fileInput.current) fileInput.current.value = ""
      onImported()
    } catch (reason) {
      setError(describeError(reason, "The capture could not be imported"))
    } finally {
      setBusy(false)
    }
  }

  return (
    <details className="capture-import">
      <summary>Import a capture</summary>
      <p className="capture-import-help">
        Analyze a .pcapng taken elsewhere — the UniFi gateway's own packet capture, or tcpdump on another box — like a recording. It appears in Traffic under its own time window.
      </p>
      {canImport ? (
        <form className="capture-import-form" onSubmit={submit}>
          <label>
            <span>Capture file (.pcapng)</span>
            <input ref={fileInput} type="file" accept=".pcapng,application/octet-stream" disabled={busy} />
          </label>
          <label>
            <span>Name (optional)</span>
            <input type="text" value={name} maxLength={96} placeholder="UniFi gateway capture" onChange={(event) => setName(event.target.value)} disabled={busy} />
          </label>
          <button disabled={busy}>{busy ? "Importing…" : "Import and analyze"}</button>
        </form>
      ) : (
        <p className="capture-gate">{blockedReason}</p>
      )}
      <ErrorBox message={error} />
      {result && (
        <p className="capture-import-result">
          Imported {result.packets.toLocaleString()} packets ({formatBytes(result.size_bytes)}). Analyzing now.{" "}
          <a href={result.view_path}>View its traffic</a>.
        </p>
      )}
    </details>
  )
}
