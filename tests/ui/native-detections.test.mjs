import assert from "node:assert/strict";
import test from "node:test";
import {webUIFile, webUISource} from "./web-ui-source.mjs";

const source=webUISource();
const types=webUIFile("types.ts");

test("native detection transitions expose bounded fields",()=>{
  assert.match(types,/detection_type\?:\s*string/);
  assert.match(source,/Native detection/);
  assert.match(source,/detection_severity/);
  assert.match(source,/detection_state/);
  assert.match(source,/detection_summary/);
});

test("resource pressure visibly preserves control and reduces refresh",()=>{
  assert.match(source,/Resource mode ·/);
  assert.match(source,/new captures[\s\S]{0,120}blocked/);
  assert.match(source,/routing and management preserved/);
  assert.match(source,/delay\s*=\s*60000/);
});
