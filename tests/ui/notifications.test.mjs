import assert from "node:assert/strict"
import test from "node:test"
import { webUIFile } from "./web-ui-source.mjs"

const source = webUIFile("workspaces/integrations/Notifications.tsx")

test("notifications UI is opt-in, step-up and secret-safe", () => {
  // Off until a rule is added, in plain wording.
  assert.match(source, /Off until you add a rule/)
  // Every config change goes through the administrator step-up with the
  // optimistic revision, like the other integrations.
  assert.match(source, /withPassword\(/)
  assert.match(source, /expected_revision:\s*view!\.revision/)
  // It never persists anything to the browser.
  assert.doesNotMatch(source, /localStorage|sessionStorage/)
  // A notification never shows a secret value; the wording says so.
  assert.match(source, /never shows a\s*\n?\s*secret value|never shows a secret value/)
})

test("notifications UI offers the triggers, channels and a test", () => {
  for (const trigger of ["NEW_DEVICE", "BYPASSING_DEVICE", "CLEARTEXT_EXPOSURE", "FLAGGED_DOMAIN", "SECURITY_ALERT"]) {
    assert.ok(source.includes(trigger), `missing trigger ${trigger}`)
  }
  // Webhook and Slack channels, a per-channel test, and mark-all-read.
  assert.match(source, /notifications\/test/)
  assert.match(source, /\/api\/v1\/notifications\/read/)
  assert.match(source, /Slack \/ Mattermost \/ Discord/)
  assert.match(source, /hooks\.slack\.com/)
})

test("notifications is mounted in the Integrations workspace", () => {
  const workspace = webUIFile("workspaces/integrations/IntegrationsWorkspace.tsx")
  assert.match(workspace, /<Notifications \/>/)
})
