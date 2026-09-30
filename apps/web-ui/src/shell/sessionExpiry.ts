// Absolute session lifetime. Sessions slide with use (1 hour idle), but end
// 12 hours after sign-in regardless; sign-in, setup and recovery responses
// report that limit as absolute_expires_at. It is kept next to the session
// (same tab) so the dashboard can warn shortly before it.

const KEY = "shakerproxy.session-absolute-expiry.v1"

export const EXPIRY_WARNING_MS = 2 * 60 * 1000

export function rememberSessionExpiry(response: { absolute_expires_at?: string } | null | undefined): void {
  const at = response?.absolute_expires_at ? Date.parse(response.absolute_expires_at) : Number.NaN
  try {
    if (Number.isFinite(at)) window.sessionStorage.setItem(KEY, String(at))
    else window.sessionStorage.removeItem(KEY)
  } catch {
    // Storage unavailable: no warning, the session still works.
  }
}

export function forgetSessionExpiry(): void {
  try {
    window.sessionStorage.removeItem(KEY)
  } catch {
    // Nothing stored.
  }
}

export function sessionAbsoluteExpiry(): number | null {
  try {
    const value = Number(window.sessionStorage.getItem(KEY))
    return Number.isFinite(value) && value > 0 ? value : null
  } catch {
    return null
  }
}

// expiryWarning returns the warning to show at `now`, or "" when none is due.
export function expiryWarning(expiresAt: number | null, now: number): string {
  if (!expiresAt || now < expiresAt - EXPIRY_WARNING_MS) return ""
  const time = new Date(expiresAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
  return now >= expiresAt
    ? "Your session has reached its 12-hour limit. Sign in again to continue."
    : `Your session ends at ${time} (12-hour limit). Finish what you are doing and sign in again.`
}
