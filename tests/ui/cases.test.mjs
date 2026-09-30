import assert from "node:assert/strict";
import test from "node:test";
import {webUIFile} from "./web-ui-source.mjs";

const source=webUIFile("workspaces/cases/CaseWorkspace.tsx");

test("case workspace never collapses a partial hold into protected",()=>{
  assert.match(source,/PARTIAL HOLD: one or more capture references are not protected/);
  assert.match(source,/Protection is incomplete[.] Failed capture references remain deletable/);
  assert.match(source,/result[.]failure\s*\?\s*`NOT PROTECTED/);
});

test("case hold and status changes confirm the password on demand and stay idempotent",()=>{
  // One key per logical change, reused if the password prompt retries it.
  assert.match(source,/const key = idempotencyKey\(active\s*\?\s*"case-hold"\s*:\s*"case-release"\)/);
  assert.match(source,/"Idempotency-Key":\s*key/);
  assert.match(source,/withPassword\(active \? "protect these recordings" : "release the hold"/);
  assert.match(source,/withPassword\(status === "CLOSED" \? "close this case" : "reopen this case"/);
  // Recent confirmation is enough for case changes, so there is no password field.
  assert.doesNotMatch(source,/name="password"/);
  assert.match(source,/start-time retention locks may still apply/);
});

test("evidence can be removed and cases deleted without touching the artifacts",()=>{
  assert.match(source,/\/api\/v1\/cases\/\$\{caseRecord\.id\}\/evidence\/\$\{encodeURIComponent\(evidenceID\)\}/);
  assert.match(source,/Its recordings and exports are kept/);
});
