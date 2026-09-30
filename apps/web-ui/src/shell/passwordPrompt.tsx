import React, { FormEvent, useEffect, useRef, useState } from "react"
import { registerPasswordPrompter, type PasswordRequest } from "../lib/passwordConfirm"

// The shared "Confirm it's you" dialog behind withPassword(). Components
// import withPassword from here; the retry logic lives in lib/passwordConfirm.
export { PasswordCancelled, passwordNeeded, withPassword } from "../lib/passwordConfirm"

type Pending = PasswordRequest & { resolve: (value: string | null) => void }

// PasswordPromptHost renders the dialog. Mount it once inside the signed-in
// dashboard; without it withPassword() just reports the server's error.
export function PasswordPromptHost() {
  const [request, setRequest] = useState<Pending | null>(null)
  const pending = useRef<Pending | null>(null)
  const input = useRef<HTMLInputElement>(null)

  useEffect(() => {
    const unregister = registerPasswordPrompter(
      (next) =>
        new Promise<string | null>((resolve) => {
          // Only one dialog at a time: an older request is cancelled.
          pending.current?.resolve(null)
          const entry = { ...next, resolve }
          pending.current = entry
          setRequest(entry)
        }),
    )
    return () => {
      unregister()
      pending.current?.resolve(null)
      pending.current = null
    }
  }, [])

  function settle(value: string | null) {
    pending.current?.resolve(value)
    pending.current = null
    setRequest(null)
  }

  useEffect(() => {
    if (!request) return
    input.current?.focus()
    const keydown = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return
      event.stopPropagation()
      settle(null)
    }
    document.addEventListener("keydown", keydown, true)
    return () => document.removeEventListener("keydown", keydown, true)
  }, [request])

  if (!request) return null
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const value = input.current?.value ?? ""
    if (!value) return
    settle(value)
  }
  function cancel() {
    settle(null)
  }
  return (
    <div
      className="password-prompt-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) cancel()
      }}
    >
      <form
        className="password-prompt"
        role="dialog"
        aria-modal="true"
        aria-labelledby="password-prompt-title"
        onSubmit={submit}
      >
        <h2 id="password-prompt-title">Confirm it's you</h2>
        <p>
          Enter your administrator password to {request.action}. ShakerProxy then remembers it for 10 minutes in this
          session.
        </p>
        <label>
          Administrator password
          <input ref={input} type="password" autoComplete="current-password" required />
        </label>
        {request.error && (
          <p className="error" role="alert">
            {request.error}
          </p>
        )}
        <div className="password-prompt-actions">
          <button type="button" className="quiet" onClick={cancel}>
            Cancel
          </button>
          <button type="submit">Confirm</button>
        </div>
      </form>
    </div>
  )
}
