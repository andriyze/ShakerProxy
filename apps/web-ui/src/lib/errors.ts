// User-facing error wording shared by the shell. Pure so it can be tested.

export const SESSION_EXPIRED_MESSAGE = "Your session expired — sign in again"

export type SessionEndReasonLike = "signed-out" | "expired" | undefined

// loginNotice is the message the login screen shows after a session ends.
export function loginNotice(reason: SessionEndReasonLike): string {
  return reason === "expired" ? SESSION_EXPIRED_MESSAGE : ""
}

type ErrorLike = { name?: unknown; message?: unknown; status?: unknown }

function asErrorLike(reason: unknown): ErrorLike {
  return reason && typeof reason === "object" ? (reason as ErrorLike) : {}
}

// errorStatus returns the HTTP status carried by an ApiError, or 0.
export function errorStatus(reason: unknown): number {
  const status = asErrorLike(reason).status
  return typeof status === "number" ? status : 0
}

// isUnavailableEndpoint is true when the appliance does not implement an
// endpoint yet (older build), so the UI can hide the feature instead of
// showing an error.
export function isUnavailableEndpoint(reason: unknown): boolean {
  const status = errorStatus(reason)
  return status === 404 || status === 405 || status === 501
}

export function isAbort(reason: unknown): boolean {
  return asErrorLike(reason).name === "AbortError"
}

// friendlyError turns any thrown value into one sentence a person can act on.
export function friendlyError(reason: unknown, fallback = "Something went wrong. Try again."): string {
  const error = asErrorLike(reason)
  const message = typeof error.message === "string" ? error.message.trim() : ""
  if (error.name === "TypeError" && /fetch|network|load failed/i.test(message)) {
    return "ShakerProxy is not reachable. Check that the appliance is running and this computer can reach it, then try again."
  }
  if (errorStatus(reason) === 401) return SESSION_EXPIRED_MESSAGE
  if (message && message !== "[object Object]") return message
  return fallback
}
