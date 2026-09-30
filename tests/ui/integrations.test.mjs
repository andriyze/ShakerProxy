import assert from "node:assert/strict";
import test from "node:test";
import {webUIFile} from "./web-ui-source.mjs";

const source=webUIFile("workspaces/integrations/AutomationIntegrations.tsx");

test("automation UI preserves display-once and disabled-forwarder boundaries",()=>{
  assert.match(source,/cleartext is shown once and is not stored by ShakerProxy/);
  assert.match(source,/Forwarder created disabled/);
  assert.match(source,/never event bodies, packet bytes, TLS key logs, CA material, or administrator credentials/);
  assert.match(source,/autoComplete="current-password"/);
  assert.doesNotMatch(source,/localStorage|sessionStorage/);
});

test("token and forwarder mutations submit exact safety fields",()=>{
  assert.match(source,/expires_in_seconds:\s*Number\(data\.get\("expires_hours"\)\)\s*\*\s*3600/);
  assert.match(source,/expected_revision:\s*item\.integration\.revision/);
  assert.match(source,/enabled:\s*!item\.integration\.enabled/);
  assert.match(source,/password:\s*data\.get\("password"\)/);
});
