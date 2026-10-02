import assert from "node:assert/strict"
import test from "node:test"
import { isStaleBuildError, reloadForNewVersion } from "../../apps/web-ui/src/lib/staleBuild.ts"

test("page code from before an upgrade is recognised in every browser's wording", () => {
  // Firefox (the tester's screenshot), Chrome, Safari, and Vite's stylesheet preload.
  assert.equal(isStaleBuildError(new TypeError("error loading dynamically imported module: https://127.0.0.1:8443/assets/CapturesWorkspace-DD9f9JVh.js")), true)
  assert.equal(isStaleBuildError(new TypeError("Failed to fetch dynamically imported module: https://x/assets/a.js")), true)
  assert.equal(isStaleBuildError(new TypeError("Importing a module script failed.")), true)
  assert.equal(isStaleBuildError(new Error("Unable to preload CSS for /assets/a.css")), true)
  assert.equal(isStaleBuildError(new TypeError("Cannot read properties of null (reading 'length')")), false)
})

test("the page reloads once for a new version, never in a loop", () => {
  const store = new Map()
  globalThis.window = { sessionStorage: { getItem: (key) => store.get(key) ?? null, setItem: (key, value) => store.set(key, value) } }
  try {
    let reloads = 0
    const reload = () => reloads++
    assert.equal(reloadForNewVersion(1_000_000, reload), true)
    assert.equal(reloadForNewVersion(1_030_000, reload), false, "a second failure within a minute is shown, not reloaded")
    assert.equal(reloadForNewVersion(1_070_000, reload), true)
    assert.equal(reloads, 2)
  } finally {
    delete globalThis.window
  }
})

test("a missing build file is a 404, not the app page", async () => {
  const { readFile } = await import("node:fs/promises")
  const conf = await readFile(new URL("../../apps/web-ui/nginx.conf", import.meta.url), "utf8")
  assert.match(conf, /location \/assets\/ \{[^}]*try_files \$uri =404;/)
  assert.match(conf, /location \/ \{[^}]*Cache-Control "no-cache"/)
  // Each location repeats the security headers, which add_header would otherwise drop.
  assert.equal(conf.match(/Content-Security-Policy/g).length, 3)
})
