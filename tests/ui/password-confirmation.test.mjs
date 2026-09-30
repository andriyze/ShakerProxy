import assert from "node:assert/strict"
import test from "node:test"
import { ApiError, endSessionIfUnauthorized, getSessionToken, setSessionToken, clearSession, errorMessage } from "../../apps/web-ui/src/api.ts"
import {
  PASSWORD_CANCELLED,
  PasswordCancelled,
  passwordNeeded,
  registerPasswordPrompter,
  withPassword,
} from "../../apps/web-ui/src/lib/passwordConfirm.ts"
import { webUIFile, webUIFiles } from "./web-ui-source.mjs"

const needed = new ApiError("confirm", 401, "reauthentication_required")
const always = new ApiError("always", 401, "password_required")
const wrong = new ApiError("wrong", 401, "reauthentication_failed")

test("password requests are recognised and never end the session", () => {
  assert.equal(passwordNeeded(needed), true)
  assert.equal(passwordNeeded(always), true)
  assert.equal(passwordNeeded(wrong), false)
  assert.equal(passwordNeeded(new ApiError("gone", 401, "invalid_session")), false)
  setSessionToken("still-valid")
  endSessionIfUnauthorized(401, "reauthentication_required")
  endSessionIfUnauthorized(401, "password_required")
  assert.equal(getSessionToken(), "still-valid")
  clearSession()
  assert.match(errorMessage({ error: { code: "password_required", message: "include password" } }, 401).message, /needs your administrator password/)
})

test("withPassword tries without a password, then asks once and retries", async () => {
  const prompts = []
  const stop = registerPasswordPrompter(async (request) => {
    prompts.push(request)
    return "secret"
  })
  try {
    const sent = []
    const result = await withPassword("rename this device", async (password) => {
      sent.push(password)
      if (!password) throw needed
      return "saved"
    })
    assert.equal(result, "saved")
    assert.deepEqual(sent, [undefined, "secret"])
    assert.deepEqual(prompts, [{ action: "rename this device", error: "" }])
  } finally {
    stop()
  }
})

test("a wrong password re-prompts with an explanation; cancelling stops", async () => {
  const prompts = []
  const answers = ["bad", null]
  const stop = registerPasswordPrompter(async (request) => {
    prompts.push(request.error)
    return answers.shift()
  })
  try {
    await assert.rejects(
      withPassword("delete this case", async (password) => {
        if (!password) throw always
        throw wrong
      }),
      (error) => error instanceof PasswordCancelled && error.message === PASSWORD_CANCELLED,
    )
    assert.deepEqual(prompts, ["", "That password is not correct. Try again."])
  } finally {
    stop()
  }
})

test("a password typed in the form is used first; other errors pass through", async () => {
  const sent = []
  const stop = registerPasswordPrompter(async () => {
    throw new Error("must not prompt")
  })
  try {
    assert.equal(
      await withPassword("apply", async (password) => {
        sent.push(password)
        return "ok"
      }, "typed"),
      "ok",
    )
    assert.deepEqual(sent, ["typed"])
    await assert.rejects(withPassword("x", async () => { throw new ApiError("conflict", 409, "revision_conflict") }), /conflict/)
  } finally {
    stop()
  }
})

test("password fields remain only where the password is always required", () => {
  const fields = new Map()
  for (const path of webUIFiles()) {
    if (path.startsWith("features/")) continue
    const count = (webUIFile(path).match(/type="password"/g) ?? []).length
    if (count) fields.set(path, count)
  }
  assert.deepEqual(Object.fromEntries(fields), {
    "shell/Auth.tsx": 5, // setup token + password, sign-in, recovery (new + repeat)
    "shell/passwordPrompt.tsx": 1, // the on-demand dialog
    "workspaces/captures/CaptureDeletion.tsx": 3, // delete, retry, supersede
    "workspaces/captures/CaptureRetention.tsx": 2, // policy apply, manual run
    "workspaces/devices/DeviceTrafficDeletion.tsx": 5, // four deletion choices, retry
    "workspaces/integrations/AutomationIntegrations.tsx": 1, // token creation
    "workspaces/network/NetworkChange.tsx": 2, // commit, confirm
    "workspaces/policy/HTTPContentPolicyPanel.tsx": 1, // turning content retention on
    "workspaces/policy/TrafficPolicyPanel.tsx": 1, // decrypting every device
    "workspaces/integrations/McpSetup.tsx": 1, // investigator token creation
  })
})
