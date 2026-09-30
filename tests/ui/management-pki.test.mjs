import test from "node:test";
import assert from "node:assert/strict";
import {webUISource} from "./web-ui-source.mjs";

const source = webUISource();

test("management certificate is explicitly separated from interception trust", () => {
  assert.match(source, /not the interception CA/);
  assert.match(source, /must never be enrolled for traffic decryption/);
  assert.match(source, /shakerproxy-management-ca[.]pem/);
  assert.match(source, /download does not mean trusted/);
});

test("development does not pretend to have production management trust", () => {
  assert.match(source, /Development HTTP/);
  assert.match(source, /no local trust was created/);
});

test("interception trust and TLS controls are explicit and bounded", () => {
  assert.match(source, /api<InterceptionCAResponse>\("\/api\/v1\/interception-ca"/);
  assert.match(source, /interception-ca\/download[?]format=/);
  assert.match(source, /private key export disabled/);
  assert.match(source, /Decrypt eligible TCP TLS traffic/);
  assert.match(source, /TLS host exclusions/);
  assert.match(source, /TLS destination exclusions/);
  assert.match(source, /android-tv/);
  assert.match(source, /Desktop clients never receive automatic bypasses/);
  assert.match(source, /Preview traffic policy/);
});
