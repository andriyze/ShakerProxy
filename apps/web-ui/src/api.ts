// Shared authenticated API client and dashboard session store.
//
// Every UI module, React or not, must use this module instead of keeping its
// own copy of the bearer token or wrapping window.fetch. The token is kept in
// sessionStorage so a page reload keeps the operator signed in within the same
// tab, while closing the tab still ends the browser session.

const STORAGE_KEY = "shakerproxy.session.v1"

export type SessionEndReason = "signed-out" | "expired"
export type SessionListener = (token: string, reason?: SessionEndReason) => void

export class ApiError extends Error {
  readonly status: number
  readonly code?: string

  constructor(message: string, status: number, code?: string) {
    super(message)
    this.name = "ApiError"
    this.status = status
    this.code = code
  }
}

let token = readStoredToken()
const listeners = new Set<SessionListener>()

function readStoredToken(): string {
  try {
    return window.sessionStorage.getItem(STORAGE_KEY) ?? ""
  } catch {
    return ""
  }
}

function storeToken(value: string): void {
  try {
    if (value) window.sessionStorage.setItem(STORAGE_KEY, value)
    else window.sessionStorage.removeItem(STORAGE_KEY)
  } catch {
    // Storage can be unavailable (private mode, blocked site data); the
    // in-memory token still works for this page.
  }
}

function notify(reason?: SessionEndReason): void {
  for (const listener of listeners) {
    try {
      listener(token, reason)
    } catch {
      // One listener must not break the others.
    }
  }
}

export function getSessionToken(): string {
  return token
}

export function hasSession(): boolean {
  return token !== ""
}

export function setSessionToken(next: string): void {
  token = next.trim()
  storeToken(token)
  notify()
}

export function clearSession(reason: SessionEndReason = "signed-out"): void {
  if (!token) return
  token = ""
  storeToken("")
  notify(reason)
}

// onSessionChange registers a listener and returns an unsubscribe function.
// The listener receives "" and a reason when the session ends.
export function onSessionChange(listener: SessionListener): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

export function authorizationHeaders(init?: HeadersInit): Headers {
  const headers = new Headers(init)
  if (token) headers.set("Authorization", `Bearer ${token}`)
  return headers
}

// errorMessage extracts a human-readable message from any ShakerProxy error body:
// {"error":{"code","message"}}, {"error":"code"}, or {"message":"..."}.
export function errorMessage(body: unknown, status: number): { message: string; code?: string } {
  if (body && typeof body === "object") {
    const record = body as Record<string, unknown>
    const error = record.error
    if (error && typeof error === "object") {
      const detail = error as Record<string, unknown>
      const code = typeof detail.code === "string" ? detail.code : undefined
      if (code === "reauthentication_failed") {
        return { message: "The administrator password is not correct. Nothing was changed.", code }
      }
      if (code === "reauthentication_required" || code === "password_required") {
        return { message: "This change needs your administrator password. Nothing was changed.", code }
      }
      const message = typeof detail.message === "string" && detail.message ? detail.message : undefined
      if (message) return { message, code }
      if (code) return { message: humanizeCode(code), code }
    }
    if (typeof error === "string" && error) return { message: humanizeCode(error), code: error }
    if (typeof record.message === "string" && record.message) return { message: record.message }
  }
  if (status === 401) return { message: "Your session has expired. Sign in again." }
  if (status === 403) return { message: "This action is not permitted for the current session." }
  if (status === 404) return { message: "The requested item no longer exists." }
  if (status >= 500) return { message: `The appliance could not complete the request (${status}). Try again shortly.` }
  return { message: `Request failed (${status})` }
}

function humanizeCode(code: string): string {
  const words = code.replace(/[_-]+/g, " ").trim().toLowerCase()
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : code
}

// 401 codes that do not mean the session is gone: the appliance asking for
// the administrator password ("reauthentication_required",
// "password_required"), a wrong password typed to confirm a sensitive action
// ("reauthentication_failed"), or a failed sign-in.
const SESSION_KEEPING_401_CODES = new Set([
  "reauthentication_required",
  "password_required",
  "reauthentication_failed",
  "invalid_credentials",
])

// endSessionIfUnauthorized clears the session for a 401 that means the
// session itself is no longer valid (expired, revoked, missing).
export function endSessionIfUnauthorized(status: number, code?: string): void {
  if (status !== 401 || !token) return
  if (code && SESSION_KEEPING_401_CODES.has(code)) return
  clearSession("expired")
}

async function request(path: string, init: RequestInit): Promise<Response> {
  const headers = authorizationHeaders(init.headers)
  if (init.body && typeof init.body === "string" && !headers.has("Content-Type")) headers.set("Content-Type", "application/json")
  if (!headers.has("Accept")) headers.set("Accept", "application/json")
  return fetch(path, { cache: "no-store", credentials: "same-origin", ...init, headers })
}

// api performs an authenticated JSON request and returns the decoded body.
export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await request(path, init)
  const text = await response.text()
  let body: unknown = {}
  if (text) {
    try {
      body = JSON.parse(text)
    } catch {
      body = {}
    }
  }
  if (!response.ok) {
    const { message, code } = errorMessage(body, response.status)
    endSessionIfUnauthorized(response.status, code)
    throw new ApiError(message, response.status, code)
  }
  return body as T
}

// apiBlob performs an authenticated request for a binary download.
export async function apiBlob(path: string, init: RequestInit = {}): Promise<Blob> {
  const headers = new Headers(init.headers)
  if (!headers.has("Accept")) headers.set("Accept", "*/*")
  const response = await request(path, { ...init, headers })
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    const { message, code } = errorMessage(body, response.status)
    endSessionIfUnauthorized(response.status, code)
    throw new ApiError(message, response.status, code)
  }
  return response.blob()
}

export function downloadBlob(blob: Blob, fileName: string): void {
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement("a")
  anchor.href = url
  anchor.download = fileName
  anchor.rel = "noopener"
  document.body.append(anchor)
  anchor.click()
  anchor.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export function describeError(reason: unknown, fallback = "Something went wrong"): string {
  if (reason instanceof Error && reason.message) return reason.message
  return fallback
}
