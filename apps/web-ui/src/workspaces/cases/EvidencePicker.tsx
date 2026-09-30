import React, { useEffect, useState } from "react"
import { api } from "../../api"
import type { CaptureExportRecord, CaptureView } from "../../types"

type Option = { id: string; label: string; detail: string }

const MAX_CAPTURES_FOR_EXPORTS = 20

// EvidencePicker lets you choose a recording or a completed export from a
// list instead of pasting identifiers. It renders the kind, artifact_id and
// label fields of the "Add to case" form.
export function EvidencePicker() {
  const [kind, setKind] = useState<"CAPTURE" | "CAPTURE_EXPORT">("CAPTURE")
  const [captures, setCaptures] = useState<Option[] | null>(null)
  const [exports, setExports] = useState<Option[] | null>(null)
  const [artifactID, setArtifactID] = useState("")
  const [label, setLabel] = useState("")
  const [labelEdited, setLabelEdited] = useState(false)

  useEffect(() => {
    let active = true
    api<{ captures: CaptureView[] }>("/api/v1/captures")
      .then(async (result) => {
        const views = Array.isArray(result.captures) ? result.captures : []
        if (!active) return
        setCaptures(
          views.map((view) => ({
            id: view.session.id,
            label: view.session.request.name,
            detail: `${view.active ? "recording now" : view.state.toLowerCase()} · started ${new Date(view.session.started_at).toLocaleString()}`,
          })),
        )
        const finalized = views.filter((view) => view.manifest).slice(0, MAX_CAPTURES_FOR_EXPORTS)
        const pages = await Promise.all(
          finalized.map((view) =>
            api<{ exports: CaptureExportRecord[] }>(`/api/v1/captures/${view.session.id}/exports`)
              .then((page) => (Array.isArray(page.exports) ? page.exports : []))
              .catch(() => [] as CaptureExportRecord[]),
          ),
        )
        if (!active) return
        setExports(
          pages
            .flat()
            .filter((record) => record.complete)
            .map((record) => ({
              id: record.id,
              label: record.file_name,
              detail: `exported by ${record.username} · ${new Date(record.exported_at).toLocaleString()}`,
            })),
        )
      })
      .catch(() => {
        if (!active) return
        setCaptures([])
        setExports([])
      })
    return () => {
      active = false
    }
  }, [])

  const options = kind === "CAPTURE" ? captures : exports
  function choose(id: string) {
    setArtifactID(id)
    const option = options?.find((item) => item.id === id)
    if (option && !labelEdited) setLabel(option.label)
  }

  return (
    <>
      <label>
        What to add
        <select
          name="kind"
          value={kind}
          onChange={(event) => {
            setKind(event.target.value === "CAPTURE_EXPORT" ? "CAPTURE_EXPORT" : "CAPTURE")
            setArtifactID("")
            if (!labelEdited) setLabel("")
          }}
        >
          <option value="CAPTURE">A recording (capture)</option>
          <option value="CAPTURE_EXPORT">A downloaded capture file (export)</option>
        </select>
      </label>
      {options && options.length > 0 ? (
        <label>
          {kind === "CAPTURE" ? "Recording" : "Export"}
          <select name="artifact_id" value={artifactID} onChange={(event) => choose(event.target.value)} required>
            <option value="" disabled>
              {options === null ? "Loading…" : "Choose one"}
            </option>
            {options.map((option) => (
              <option key={option.id} value={option.id}>
                {option.label} — {option.detail}
              </option>
            ))}
          </select>
        </label>
      ) : (
        <label>
          {kind === "CAPTURE" ? "Recording ID" : "Export ID"}
          <span className="hint">
            {options === null
              ? "Loading your recordings…"
              : kind === "CAPTURE"
                ? "No recordings found. Paste a capture ID (capture-…) if you have one."
                : "No completed exports found. Export a file from Captures first, or paste an export ID."}
          </span>
          <input
            name="artifact_id"
            value={artifactID}
            onChange={(event) => setArtifactID(event.target.value)}
            required
            placeholder={kind === "CAPTURE" ? "capture-…" : "export-…"}
          />
        </label>
      )}
      <label>
        Label
        <input
          name="label"
          maxLength={256}
          required
          value={label}
          onChange={(event) => {
            setLabel(event.target.value)
            setLabelEdited(true)
          }}
        />
      </label>
    </>
  )
}
