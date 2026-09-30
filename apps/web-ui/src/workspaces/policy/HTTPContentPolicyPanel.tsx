import React, { FormEvent, useState } from "react"
import { withPassword } from "../../shell/passwordPrompt"
import { api, describeError } from "../../api"
import { useResource } from "../../shell/hooks"
import type { HTTPContentPolicyView } from "../../types"

function validatePolicyView(value: HTTPContentPolicyView): HTTPContentPolicyView {
  if (
    value?.schema !== 1 ||
    value.policy?.schema !== 1 ||
    !Number.isSafeInteger(value.policy.revision) ||
    value.policy.revision < 1 ||
    typeof value.policy.capture_http_content !== "boolean" ||
    value.tls_interception_independent !== true ||
    value.applies_without_restart !== true ||
    value.storage_boundary !== "local_sensor_only" ||
    !Number.isSafeInteger(value.maximum_body_preview_bytes) ||
    value.maximum_body_preview_bytes < 0 ||
    value.maximum_body_preview_bytes > 1024 * 1024
  ) {
    throw new Error("The content setting returned by ShakerProxy is invalid.")
  }
  return value
}

function formatPolicyBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  return `${Math.round(bytes / 1024)} KiB`
}

// Whether decrypted HTTP headers and body previews are stored. Independent
// of which devices are decrypted (the traffic policy above).
export function HTTPContentPolicyPanel() {
  const loaded = useResource(async (signal) =>
    validatePolicyView(await api<HTTPContentPolicyView>("/api/v1/http-content-policy", { signal })),
  )
  const [override, setOverride] = useState<HTTPContentPolicyView | null>(null)
  const [capture, setCapture] = useState<boolean | null>(null)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<{ text: string; error: boolean } | null>(null)
  const view = override ?? loaded.data
  const checked = capture ?? view?.policy.capture_http_content ?? false

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!view || busy) return
    const form = event.currentTarget
    const data = new FormData(form)
    const expectedRevision = view.policy.revision
    const administratorPassword = String(data.get("password") ?? "")
    const enabling = checked && !view.policy.capture_http_content
    setBusy(true)
    setMessage({ text: "Saving…", error: false })
    try {
      const next = validatePolicyView(
        await withPassword(
          enabling ? "keep decrypted content" : "change this setting",
          (password) =>
            api<HTTPContentPolicyView>("/api/v1/http-content-policy", {
              method: "PUT",
              body: JSON.stringify({
                expected_revision: expectedRevision,
                capture_http_content: checked,
                ...(password ? { password } : {}),
              }),
            }),
          administratorPassword,
        ),
      )
      setOverride(next)
      setCapture(null)
      form.reset()
      setMessage({
        text: next.policy.capture_http_content
          ? "From now on, decrypted web requests keep their headers and a preview of their content."
          : "From now on, decrypted web requests keep only their summary (no headers or content). Decryption itself is unchanged.",
        error: false,
      })
    } catch (reason) {
      setMessage({ text: describeError(reason, "The setting could not be saved"), error: true })
    } finally {
      setBusy(false)
    }
  }

  const on = view?.policy.capture_http_content
  return (
    <section className="http-content-policy" aria-labelledby="http-content-title">
      <header className="http-content-policy-header">
        <div>
          <p className="eyebrow">Step 3 · Privacy</p>
          <h2 id="http-content-title">Keep the content of decrypted web requests?</h2>
        </div>
        <span className={`http-content-policy-state ${on ? "enabled" : "disabled"}`}>
          {view ? (on ? "CONTENT KEPT" : "SUMMARY ONLY") : loaded.error ? "UNAVAILABLE" : "LOADING"}
        </span>
      </header>
      <p className="http-content-policy-explanation">
        {on
          ? `Decrypted web requests and responses keep their headers and up to ${formatPolicyBytes(view?.maximum_body_preview_bytes ?? 0)} of content each. Password-like headers stay hidden until you reveal them.`
          : "Decrypted web requests keep only method, host, path, status, sizes and timing — no headers or content."}
      </p>
      <div className="http-content-policy-boundary">
        <strong>STORED ON THIS APPLIANCE ONLY</strong>
        <span>
          Changing this takes effect immediately for new requests. It does not delete content already stored and does
          not change the TLS interception or pinning-bypass policy.
        </span>
      </div>
      {loaded.error && !view && (
        <p className="http-content-policy-message error" role="alert">
          {loaded.error}
        </p>
      )}
      {view && (
        <form className="http-content-policy-form" onSubmit={submit}>
          <label className="http-content-policy-switch">
            <input
              type="checkbox"
              checked={checked}
              onChange={(event) => setCapture(event.target.checked)}
              disabled={busy}
            />
            <span>
              <strong>Keep headers and a preview of the content</strong>
              <small>Off keeps method, host, path, status, sizes, TLS, DNS, device and timing information.</small>
            </span>
          </label>
          {checked && !view.policy.capture_http_content && (
            <label className="http-content-policy-password">
              <span>Administrator password (always needed to start keeping content)</span>
              <input type="password" name="password" autoComplete="current-password" required disabled={busy} />
            </label>
          )}
          <button disabled={busy}>{busy ? "Saving…" : "Save"}</button>
        </form>
      )}
      {view && (
        <small className="http-content-policy-provenance">
          Revision {view.policy.revision}
          {view.policy.updated_by ? ` · changed by ${view.policy.updated_by}` : " · default setting"}
          {view.policy.updated_at ? ` · ${new Date(view.policy.updated_at).toLocaleString()}` : ""}
        </small>
      )}
      {message && (
        <p
          className={`http-content-policy-message ${message.error ? "error" : "status"}`}
          role={message.error ? "alert" : "status"}
        >
          {message.text}
        </p>
      )}
    </section>
  )
}
