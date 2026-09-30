import React, { FormEvent, useState } from "react"
import { ErrorBox, Notice, Shell } from "./common"
import { api, describeError } from "../api"
import { isUnavailableEndpoint } from "../lib/errors"
import { rememberSessionExpiry } from "./sessionExpiry"
import type { LoginResult, RecoverResult } from "../types"

export function Setup({ onComplete }: { onComplete: (token: string, codes: string[]) => void }) {
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setError("")
    const data = new FormData(event.currentTarget)
    try {
      const result = await api<LoginResult & { recovery_codes: string[] }>("/api/v1/setup/complete", {
        method: "POST",
        body: JSON.stringify({
          setup_token: data.get("token"),
          username: "admin",
          password: data.get("password"),
          authorization_acknowledged: data.get("ack") === "on",
        }),
      })
      rememberSessionExpiry(result)
      onComplete(result.session_token, Array.isArray(result.recovery_codes) ? result.recovery_codes : [])
    } catch (reason) {
      setError(describeError(reason, "Setup failed. Check the setup token and try again."))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Shell>
      <p className="eyebrow">Welcome to ShakerProxy</p>
      <h1>Create your admin account.</h1>
      <p className="lede">
        This takes a minute. Nothing on your network changes yet — you choose when to turn on routing, decryption and
        recording later.
      </p>
      <form onSubmit={submit}>
        <label>
          Setup token
          <span className="hint" id="setup-token-hint">
            A one-time code printed by the installer (or by <code>make dev</code> when developing). On an installed
            appliance you can show it again with <code>sudo cat /etc/shakerproxy/setup-token</code>; after{" "}
            <code>sudo shakerproxy admin reset</code> it is in <code>/var/lib/shakerproxy/control-api/setup-token</code>.
          </span>
          <input
            name="token"
            type="password"
            autoComplete="one-time-code"
            aria-describedby="setup-token-hint"
            required
          />
        </label>
        <label>
          Admin password
          <span className="hint" id="setup-password-hint">
            At least 14 characters, with upper- and lower-case letters, a number and a symbol.
          </span>
          <input
            name="password"
            type="password"
            autoComplete="new-password"
            minLength={14}
            aria-describedby="setup-password-hint"
            required
          />
        </label>
        <label className="check">
          <input name="ack" type="checkbox" required />
          <span>
            I will only inspect devices and networks I own or am allowed to test. I understand recordings can contain
            passwords and private messages.
          </span>
        </label>
        {error && <ErrorBox message={error} />}
        <button disabled={busy}>{busy ? "Creating account…" : "Create admin account"}</button>
      </form>
    </Shell>
  )
}

export function Login({ onLogin, notice }: { onLogin: (token: string) => void; notice: string }) {
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)
  const [recovering, setRecovering] = useState(false)
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setError("")
    const data = new FormData(event.currentTarget)
    try {
      const result = await api<LoginResult>("/api/v1/auth/login", {
        method: "POST",
        body: JSON.stringify({ username: data.get("username"), password: data.get("password") }),
      })
      rememberSessionExpiry(result)
      onLogin(result.session_token)
    } catch (reason) {
      setError(describeError(reason, "Sign-in failed. Check your username and password."))
    } finally {
      setBusy(false)
    }
  }
  if (recovering) return <Recover onLogin={onLogin} onCancel={() => setRecovering(false)} />
  return (
    <Shell>
      <p className="eyebrow">ShakerProxy</p>
      <h1>Sign in.</h1>
      {notice && <Notice tone="warn">{notice}</Notice>}
      <form onSubmit={submit}>
        <label>
          Username
          <input name="username" defaultValue="admin" autoComplete="username" required />
        </label>
        <label>
          Password
          <input name="password" type="password" autoComplete="current-password" required autoFocus />
        </label>
        {error && <ErrorBox message={error} />}
        <button disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
      </form>
      <p className="auth-alt">
        <button type="button" className="link-button" onClick={() => setRecovering(true)}>
          Forgot password? Use a recovery code
        </button>
      </p>
    </Shell>
  )
}

function Recover({ onLogin, onCancel }: { onLogin: (token: string) => void; onCancel: () => void }) {
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)
  const [done, setDone] = useState<{ token: string; remaining?: number } | null>(null)
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setError("")
    const data = new FormData(event.currentTarget)
    if (data.get("new_password") !== data.get("confirm_password")) {
      setError("The two new passwords do not match.")
      setBusy(false)
      return
    }
    try {
      const result = await api<RecoverResult>("/api/v1/auth/recover", {
        method: "POST",
        body: JSON.stringify({
          username: data.get("username"),
          recovery_code: String(data.get("recovery_code") ?? "").trim(),
          new_password: data.get("new_password"),
        }),
      })
      rememberSessionExpiry(result)
      setDone({ token: result.session_token, remaining: result.remaining_recovery_codes })
    } catch (reason) {
      setError(
        isUnavailableEndpoint(reason)
          ? "This appliance does not support recovery codes yet. Ask whoever installed it to reset the admin account."
          : describeError(reason, "Recovery failed. Check the recovery code and try again."),
      )
    } finally {
      setBusy(false)
    }
  }
  if (done) {
    return (
      <Shell>
        <p className="eyebrow">Password changed</p>
        <h1>You're back in.</h1>
        <p className="lede">
          Each recovery code works once.
          {done.remaining !== undefined &&
            ` You have ${done.remaining} recovery code${done.remaining === 1 ? "" : "s"} left.`}
          {done.remaining !== undefined && done.remaining < 3 && " Generate new ones soon."}
        </p>
        <button type="button" onClick={() => onLogin(done.token)}>
          Continue to ShakerProxy
        </button>
      </Shell>
    )
  }
  return (
    <Shell>
      <p className="eyebrow">Account recovery</p>
      <h1>Reset your password.</h1>
      <p className="lede">Use one of the recovery codes you saved when you created the admin account.</p>
      <form onSubmit={submit}>
        <label>
          Username
          <input name="username" defaultValue="admin" autoComplete="username" required />
        </label>
        <label>
          Recovery code
          <input name="recovery_code" autoComplete="one-time-code" spellCheck={false} required />
        </label>
        <label>
          New password
          <span className="hint">
            At least 14 characters, with upper- and lower-case letters, a number and a symbol.
          </span>
          <input name="new_password" type="password" autoComplete="new-password" minLength={14} required />
        </label>
        <label>
          Repeat new password
          <input name="confirm_password" type="password" autoComplete="new-password" minLength={14} required />
        </label>
        {error && <ErrorBox message={error} />}
        <button disabled={busy}>{busy ? "Resetting…" : "Reset password and sign in"}</button>
      </form>
      <p className="auth-alt">
        <button type="button" className="link-button" onClick={onCancel}>
          Back to sign in
        </button>
      </p>
    </Shell>
  )
}
