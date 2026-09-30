import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import test from "node:test";
import {webUIFile, webUIFiles} from "./web-ui-source.mjs";

const index=readFileSync(new URL("../../apps/web-ui/index.html",import.meta.url),"utf8");
const main=webUIFile("main.tsx");
const mcp=webUIFile("workspaces/integrations/McpSetup.tsx");
const policy=webUIFile("workspaces/policy/HTTPContentPolicyPanel.tsx");

test("the dashboard is one React entry point with no injected modules",()=>{
  const scripts=[...index.matchAll(/<script[^>]*src="([^"]+)"/g)].map((match)=>match[1]);
  assert.deepEqual(scripts,["/src/main.tsx"]);
  assert.doesNotMatch(index,/<link[^>]+stylesheet/);
  assert.match(main,/import "\.\/features"/);
  assert.match(main,/styles\/mcp-setup\.css/);
  assert.match(main,/styles\/http-content-policy\.css/);
});

test("no shell module patches window.fetch, sniffs the bearer token or observes the DOM",()=>{
  for(const path of webUIFiles()){
    if(path==="api.ts")continue;
    const source=webUIFile(path);
    assert.doesNotMatch(source,/window\.fetch\s*=/,path);
    assert.doesNotMatch(source,/MutationObserver/,path);
    assert.doesNotMatch(source,/headers\.get\("Authorization"\)/,path);
    assert.doesNotMatch(source,/Bearer \$\{/,path);
  }
});

test("MCP wizard creates only short-lived investigator credentials",()=>{
  assert.match(mcp,/REQUIRED_MCP_SCOPES = \["system:read", "devices:read", "traffic:read"\]/);
  assert.match(mcp,/\/api\/v1\/auth\/tokens/);
  assert.match(mcp,/expires_in_seconds: 86400/);
  assert.match(mcp,/sensitive_scope_acknowledged: false/);
  assert.match(mcp,/X-ShakerProxy-Secret-Handling/);
  assert.match(mcp,/display-once/);
  assert.match(mcp,/10 \* 60 \* 1000/);
  assert.match(mcp,/READ-ONLY · MCP/);
  assert.match(mcp,/shakerproxy-mcp setup/);
  assert.match(mcp,/shakerproxy-mcp doctor/);
  assert.match(mcp,/BatchMode=yes/);
  assert.match(mcp,/The token stays on the ShakerProxy sensor in remote mode/);
  assert.match(mcp,/Do not run shakerproxy-mcp as root/);
  assert.match(mcp,/The token never appears in MCP client JSON/);
  assert.match(mcp,/authFetch\("\/api\/v1\/auth\/tokens"/);
  assert.doesNotMatch(mcp,/lgt_[A-Za-z0-9_-]{20,}/);
  assert.doesNotMatch(mcp,/localStorage|sessionStorage/);
  assert.doesNotMatch(mcp,/captures:write|cases:write|traffic:plaintext/);
});

test("content retention remains revisioned and independent from interception",()=>{
  assert.match(policy,/tls_interception_independent !== true/);
  assert.match(policy,/applies_without_restart !== true/);
  assert.match(policy,/const expectedRevision = view\.policy\.revision/);
  assert.match(policy,/expected_revision: expectedRevision/);
  assert.match(policy,/const administratorPassword = /);
  // Turning retention on always needs the password (typed in the form); turning it off only a recent confirmation.
  assert.match(policy,/withPassword\([\s\S]*?administratorPassword,\s*\)/);
  assert.match(policy,/\.\.\.\(password \? \{ password \} : \{\}\)/);
  assert.match(policy,/checked && !view\.policy\.capture_http_content &&/);
  assert.match(policy,/does not change the TLS interception or pinning-bypass policy/);
});
