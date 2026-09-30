import assert from "node:assert/strict";
import test from "node:test";
import {webUISource} from "./web-ui-source.mjs";

const source=webUISource();

test("recovery UI distinguishes verified target and not offered",()=>{
  assert.match(source,/RTO and RPO contracts/);
  assert.match(source,/objective.status\s*===\s*"verified"/);
  assert.match(source,/objective.status\s*===\s*"target"/);
  assert.match(source,/RTO not offered/);
  assert.match(source,/Data-loss contract and limits/);
});
