import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import test from "node:test";
import {webUISource} from "./web-ui-source.mjs";

const root = new URL("../../", import.meta.url);
const readJSON = async (path) => JSON.parse(await readFile(new URL(path, root), "utf8"));

test("every environment explicitly certifies every registered feature", async () => {
  const [registry, glossary, matrix] = await Promise.all([
    readJSON("schemas/feature-flags.yaml"),
    readJSON("schemas/glossary.yaml"),
    readJSON("schemas/support-matrix.yaml"),
  ]);
  assert.equal(registry.revision, glossary.revision);
  assert.equal(registry.revision, matrix.revision);
  const featureIDs = registry.features.map((feature) => feature.id).sort();
  const termIDs = new Set(glossary.terms.map((term) => term.id));
  for (const status of registry.status_vocabulary) assert.ok(termIDs.has(status));
  for (const environment of matrix.environments) {
    assert.deepEqual(environment.capabilities.map((entry) => entry.feature_id).sort(), featureIDs);
  }
});

test("the dashboard consumes capability badges from the authenticated API", () => {
  const source = webUISource();
  assert.match(source, /api<CapabilityBundle>\("\/api\/v1\/capabilities"/);
  assert.match(source, /feature\.badge/);
  assert.match(source, /feature\.promotion_gate/);
  assert.doesNotMatch(source, /TLS interception<\/strong><span>UNAVAILABLE/);
});
