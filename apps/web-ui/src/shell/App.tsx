import React, { useCallback, useEffect, useState } from "react"
import { ErrorBox, Shell } from "./common"
import { Login, Setup } from "./Auth"
import { Dashboard } from "./Dashboard"
import {
  api,
  authorizationHeaders,
  clearSession,
  describeError,
  hasSession,
  onSessionChange,
  setSessionToken,
} from "../api"
import { loginNotice } from "../lib/errors"
import { forgetSessionExpiry } from "./sessionExpiry"
import type { Phase } from "../types"

// signOut revokes the server session (ignoring older appliances that do not
// have the endpoint yet) and then forgets the token locally.
async function signOut(): Promise<void> {
  try {
    await fetch("/api/v1/auth/logout", {
      method: "POST",
      headers: authorizationHeaders({ "Content-Type": "application/json", Accept: "application/json" }),
      body: "{}",
      cache: "no-store",
      credentials: "same-origin",
    })
  } catch {
    // Offline or not deployed: the local session is still cleared below.
  }
  clearSession("signed-out")
}

export function App() {
  // A stored session (sessionStorage, same tab) skips the login screen on
  // reload. If it has expired, the first API call returns 401 and the session
  // listener below brings the login screen back with an explanation.
  const [phase, setPhase] = useState<Phase>(() => (hasSession() ? "dashboard" : "loading"))
  const [notice, setNotice] = useState("")
  const [error, setError] = useState("")
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([])

  useEffect(
    () =>
      onSessionChange((token, reason) => {
        if (token) return
        setRecoveryCodes([])
        forgetSessionExpiry()
        setNotice(loginNotice(reason))
        setPhase("login")
      }),
    [],
  )

  const checkSetup = useCallback(async () => {
    setError("")
    try {
      const { configured } = await api<{ configured: boolean }>("/api/v1/setup/status")
      setPhase(configured ? "login" : "setup")
    } catch (reason) {
      setError(describeError(reason, "ShakerProxy is not answering."))
    }
  }, [])

  useEffect(() => {
    if (phase === "loading") void checkSetup()
  }, [phase, checkSetup])

  if (phase === "loading") {
    return (
      <Shell>
        <p className="eyebrow">ShakerProxy</p>
        <h1>Connecting…</h1>
        {error && (
          <ErrorBox
            message={`${error} Check that the appliance is running, then try again.`}
            onRetry={() => void checkSetup()}
          />
        )}
      </Shell>
    )
  }
  if (phase === "setup") {
    return (
      <Setup
        onComplete={(token, codes) => {
          setSessionToken(token)
          setRecoveryCodes(codes)
          setNotice("")
          setPhase("dashboard")
        }}
      />
    )
  }
  if (phase === "login") {
    return (
      <Login
        notice={notice}
        onLogin={(token) => {
          setSessionToken(token)
          setNotice("")
          setPhase("dashboard")
        }}
      />
    )
  }
  return (
    <Dashboard recoveryCodes={recoveryCodes} onDismissRecoveryCodes={() => setRecoveryCodes([])} onSignOut={signOut} />
  )
}
