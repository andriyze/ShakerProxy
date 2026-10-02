// After an upgrade, a page loaded from the previous version asks for page
// code that no longer exists. Browsers word the failure differently.
const STALE_BUILD = /dynamically imported module|importing a module script failed|unable to preload css|loading (css )?chunk [^ ]+ failed/i

const RELOADED_AT = "shakerproxy.reloadedForNewVersion"

export function isStaleBuildError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error ?? "")
  return STALE_BUILD.test(message)
}

// reloadForNewVersion reloads the page once to pick up the new version and
// reports whether it did. A second failure within a minute is a real error,
// not an upgrade, so it is shown instead of reloading in a loop.
export function reloadForNewVersion(now: number = Date.now(), reload: () => void = () => window.location.reload()): boolean {
  try {
    const last = Number(window.sessionStorage.getItem(RELOADED_AT) ?? 0)
    if (now - last < 60_000) return false
    window.sessionStorage.setItem(RELOADED_AT, String(now))
  } catch {
    // Without session storage there is no loop guard; show the error instead.
    return false
  }
  reload()
  return true
}
