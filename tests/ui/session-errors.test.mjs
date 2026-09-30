import assert from "node:assert/strict"
import test from "node:test"
import {
  ApiError,
  api,
  clearSession,
  endSessionIfUnauthorized,
  errorMessage,
  getSessionToken,
  onSessionChange,
  setSessionToken,
} from "../../apps/web-ui/src/api.ts"
import {
  SESSION_EXPIRED_MESSAGE,
  errorStatus,
  friendlyError,
  isUnavailableEndpoint,
  loginNotice,
} from "../../apps/web-ui/src/lib/errors.ts"
import { webUIFile } from "./web-ui-source.mjs"

test("login notice explains an expired session only", () => {
  assert.equal(SESSION_EXPIRED_MESSAGE, "Your session expired — sign in again")
  assert.equal(loginNotice("expired"), SESSION_EXPIRED_MESSAGE)
  assert.equal(loginNotice("signed-out"), "")
  assert.equal(loginNotice(undefined), "")
})

test("error mapping gives one actionable sentence", () => {
  assert.equal(errorMessage({ error: { code: "x", message: "Pick a device first." } }, 400).message, "Pick a device first.")
  assert.equal(errorMessage({ error: "revision_conflict" }, 409).message, "Revision conflict")
  assert.equal(errorMessage({ message: "plain" }, 400).message, "plain")
  // Object-shaped errors never surface as "[object Object]".
  assert.doesNotMatch(errorMessage({ error: { code: "bad_thing" } }, 400).message, /object Object/)
  assert.match(errorMessage({ error: { code: "reauthentication_failed", message: "administrator re-authentication failed" } }, 401).message, /password is not correct/)
  assert.equal(friendlyError(new TypeError("Failed to fetch")).startsWith("ShakerProxy is not reachable"), true)
  assert.equal(friendlyError(new ApiError("gone", 401)), SESSION_EXPIRED_MESSAGE)
  assert.equal(friendlyError({ message: "[object Object]" }, "fallback"), "fallback")
  assert.equal(errorStatus(new ApiError("x", 404)), 404)
  assert.equal(isUnavailableEndpoint(new ApiError("x", 404)), true)
  assert.equal(isUnavailableEndpoint(new ApiError("x", 405)), true)
  assert.equal(isUnavailableEndpoint(new ApiError("x", 500)), false)
})

test("a wrong confirmation password keeps the session; an invalid session ends it", () => {
  const reasons = []
  const stop = onSessionChange((token, reason) => {
    if (!token) reasons.push(reason)
  })
  setSessionToken("token-one")
  endSessionIfUnauthorized(401, "reauthentication_failed")
  endSessionIfUnauthorized(401, "invalid_credentials")
  endSessionIfUnauthorized(403, "forbidden")
  assert.equal(getSessionToken(), "token-one")
  endSessionIfUnauthorized(401, "invalid_session")
  assert.equal(getSessionToken(), "")
  assert.deepEqual(reasons, ["expired"])
  stop()
})

test("api() ends the session on 401 and reports a readable error", async () => {
  const originalFetch = globalThis.fetch
  const reasons = []
  const stop = onSessionChange((token, reason) => {
    if (!token) reasons.push(reason)
  })
  try {
    setSessionToken("token-two")
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ error: { code: "invalid_session", message: "session is invalid or expired" } }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      })
    await assert.rejects(api("/api/v1/system/status"), (error) => error instanceof ApiError && error.status === 401)
    assert.equal(getSessionToken(), "")
    assert.deepEqual(reasons, ["expired"])

    setSessionToken("token-three")
    let sentAuthorization = ""
    globalThis.fetch = async (_path, init) => {
      sentAuthorization = new Headers(init.headers).get("Authorization")
      return new Response(JSON.stringify({ ok: true }), { status: 200 })
    }
    assert.deepEqual(await api("/api/v1/system/status"), { ok: true })
    assert.equal(sentAuthorization, "Bearer token-three")
  } finally {
    globalThis.fetch = originalFetch
    stop()
    clearSession()
  }
})

test("sign-out revokes the server session before clearing it locally", () => {
  const app = webUIFile("shell/App.tsx")
  assert.match(app, /fetch\("\/api\/v1\/auth\/logout", \{ method: "POST"/)
  assert.match(app, /clearSession\("signed-out"\)/)
  assert.match(app, /onSessionChange\(\(token, reason\) =>/)
  assert.match(app, /setNotice\(loginNotice\(reason\)\)/)
  const auth = webUIFile("shell/Auth.tsx")
  assert.match(auth, /Forgot password\? Use a recovery code/)
  assert.match(auth, /\/api\/v1\/auth\/recover/)
  assert.match(auth, /recovery_code/)
  assert.match(auth, /new_password/)
  assert.doesNotMatch(auth, /Step 1 of 9/)
  assert.match(auth, /make dev/)
})
