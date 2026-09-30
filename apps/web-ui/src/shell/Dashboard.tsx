import React, { useEffect, useMemo, useRef, useState } from "react"
import { AppContext, isRouted, type AppState } from "./AppContext"
import { ErrorBox } from "./common"
import { useNow, useResource } from "./hooks"
import { expiryWarning, sessionAbsoluteExpiry } from "./sessionExpiry"
import { SideNav } from "./SideNav"
import { PasswordPromptHost } from "./passwordPrompt"
import { NetworkHeartbeat } from "./networkHeartbeat"
import { api } from "../api"
import { NAVIGATE_EVENT } from "../features"
import { normalizePreflight } from "../lib/normalize"
import { parseWorkspaceHash, routeKey, workspaceForShortcut, workspaceMeta } from "../lib/routing"
import { isTransactionActive } from "../lib/networkTransaction"
import { WorkspaceView } from "../workspaces"
import type { Preflight, Status } from "../types"

export const STATUS_POLL_MS = 15_000

function readRoute() {
  return {
    workspace: parseWorkspaceHash(window.location.hash),
    key: routeKey(window.location.hash, window.location.search),
  }
}

// useRoute follows "#/<workspace>" through link clicks, back/forward and the
// registry's navigate() ("shakerproxy:navigate"), and remounts the workspace when
// the target changes so it re-reads its URL search parameters.
function useRoute() {
  const [route, setRoute] = useState(readRoute)
  useEffect(() => {
    const update = () =>
      setRoute((current) => {
        const next = readRoute()
        return next.key === current.key ? current : next
      })
    window.addEventListener("hashchange", update)
    window.addEventListener("popstate", update)
    window.addEventListener(NAVIGATE_EVENT, update)
    return () => {
      window.removeEventListener("hashchange", update)
      window.removeEventListener("popstate", update)
      window.removeEventListener(NAVIGATE_EVENT, update)
    }
  }, [])
  useEffect(() => {
    // Canonicalize unknown or empty hashes without adding a history entry.
    const canonical = `#/${route.workspace}`
    if (window.location.hash !== canonical && !window.location.hash.startsWith(`${canonical}?`)) {
      window.history.replaceState(
        window.history.state,
        "",
        `${window.location.pathname}${window.location.search}${canonical}`,
      )
    }
  }, [route.workspace])
  return route
}

function isEditable(target: EventTarget | null): boolean {
  const element = target as HTMLElement | null
  return (
    element instanceof HTMLInputElement ||
    element instanceof HTMLTextAreaElement ||
    element instanceof HTMLSelectElement ||
    Boolean(element?.isContentEditable)
  )
}

function useWorkspaceShortcuts() {
  useEffect(() => {
    const keydown = (event: KeyboardEvent) => {
      if (!event.altKey || event.metaKey || event.ctrlKey || event.shiftKey || isEditable(event.target)) return
      const workspace = workspaceForShortcut(event.code)
      if (!workspace) return
      event.preventDefault()
      window.location.hash = `#/${workspace}`
    }
    document.addEventListener("keydown", keydown)
    return () => document.removeEventListener("keydown", keydown)
  }, [])
}

function ModeIndicator({ status, error }: { status: Status | null; error: string }) {
  let label = "Connecting…"
  let tone = "muted"
  let href = "#/system"
  if (error && !status) {
    label = "Status unavailable"
    tone = "warn"
  } else if (status?.emergency_bypass) {
    label = "Emergency bypass on"
    tone = "warn"
  } else if (status?.staged_network_plan && isTransactionActive(status.staged_network_plan.status)) {
    label = "Network change in progress"
    tone = "warn"
    href = "#/network"
  } else if (status?.active_capture_id) {
    label = "Recording packets"
    tone = "rec"
    href = "#/captures"
  } else if (isRouted(status)) {
    label = "Lab network live"
    tone = "good"
    href = "#/network"
  } else if (status) {
    label = "Lab network not set up"
    tone = "muted"
    href = "#/network"
  }
  return (
    <a className={`mode-indicator ${tone}`} href={href} aria-live="polite">
      <span className="mode-dot" aria-hidden="true" />
      {label}
    </a>
  )
}

function RecoveryCodes({ codes, onDismiss }: { codes: string[]; onDismiss: () => void }) {
  const [copied, setCopied] = useState(false)
  return (
    <section className="recovery" aria-labelledby="recovery-title">
      <h2 id="recovery-title">Save your recovery codes now</h2>
      <p>
        If you forget your password, one of these codes lets you set a new one. Each works once. ShakerProxy stores only a
        fingerprint of them and cannot show them again.
      </p>
      <div className="codes">
        {codes.map((code) => (
          <code key={code}>{code}</code>
        ))}
      </div>
      <div className="recovery-actions">
        <button
          type="button"
          className="quiet"
          onClick={() => {
            void navigator.clipboard
              ?.writeText(codes.join("\n"))
              .then(() => setCopied(true))
              .catch(() => setCopied(false))
          }}
        >
          {copied ? "Copied" : "Copy codes"}
        </button>
        <button type="button" onClick={onDismiss}>
          I have saved them
        </button>
      </div>
    </section>
  )
}

export function Dashboard({
  recoveryCodes,
  onDismissRecoveryCodes,
  onSignOut,
}: {
  recoveryCodes: string[]
  onDismissRecoveryCodes: () => void
  onSignOut: () => Promise<void>
}) {
  const route = useRoute()
  useWorkspaceShortcuts()
  const status = useResource((signal) => api<Status>("/api/v1/system/status", { signal }), [], {
    intervalMs: STATUS_POLL_MS,
  })
  const preflight = useResource(
    async (signal) => normalizePreflight(await api<Preflight>("/api/v1/preflight", { signal })),
    [],
    { intervalMs: 5 * 60_000 },
  )
  const appState = useMemo<AppState>(
    () => ({
      status: status.data,
      statusError: status.error,
      refreshStatus: status.reload,
      preflight: preflight.data,
      preflightError: preflight.error,
      reloadPreflight: preflight.reload,
    }),
    [status.data, status.error, status.reload, preflight.data, preflight.error, preflight.reload],
  )
  const meta = workspaceMeta(route.workspace)
  const main = useRef<HTMLElement>(null)
  const firstRoute = useRef(true)
  const [signingOut, setSigningOut] = useState(false)
  const now = useNow(15_000)
  const expiry = expiryWarning(sessionAbsoluteExpiry(), now)

  const reloadStatus = status.reload
  useEffect(() => {
    document.title = `${meta.label} · ShakerProxy`
    if (firstRoute.current) {
      firstRoute.current = false
      return
    }
    // Opening a workspace re-checks appliance status so its gates (routed,
    // capture available, emergency bypass) are current.
    void reloadStatus()
    window.scrollTo({ top: 0 })
    main.current?.focus({ preventScroll: true })
  }, [route.key, meta.label, reloadStatus])

  return (
    <AppContext.Provider value={appState}>
      <div className="app">
        <a
          className="skip-link"
          href="#workspace-main"
          onClick={(event) => {
            event.preventDefault()
            main.current?.focus()
          }}
        >
          Skip to content
        </a>
        <header className="topbar">
          <a className="brand" href="#/start" aria-label="ShakerProxy — Start">
            <span className="mark">S</span>
            <span>SHAKERPROXY</span>
          </a>
          <ModeIndicator status={status.data} error={status.error} />
          <button
            type="button"
            className="quiet"
            disabled={signingOut}
            onClick={() => {
              setSigningOut(true)
              void onSignOut().finally(() => setSigningOut(false))
            }}
          >
            {signingOut ? "Signing out…" : "Sign out"}
          </button>
        </header>
        <div className="app-body">
          <SideNav current={route.workspace} status={status.data} />
          <main className="workspace" id="workspace-main" ref={main} tabIndex={-1} aria-labelledby="workspace-title">
            {recoveryCodes.length > 0 && <RecoveryCodes codes={recoveryCodes} onDismiss={onDismissRecoveryCodes} />}
            {expiry && (
              <div className="notice notice-warn session-warning" role="alert">
                {expiry}{" "}
                <button type="button" className="quiet" onClick={() => void onSignOut()}>
                  Sign in again
                </button>
              </div>
            )}
            {status.error && (
              <ErrorBox
                message={`ShakerProxy status could not be refreshed: ${status.error}`}
                onRetry={() => void status.reload()}
              />
            )}
            <header className="workspace-head">
              <h1 id="workspace-title">{meta.label}</h1>
              <p>{meta.intro}</p>
            </header>
            <WorkspaceView key={route.key} id={route.workspace} />
          </main>
        </div>
        <PasswordPromptHost />
        <NetworkHeartbeat />
      </div>
    </AppContext.Provider>
  )
}
