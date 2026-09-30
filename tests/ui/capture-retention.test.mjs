import assert from "node:assert/strict";
import test from "node:test";
import {coordinatedRetentionRunRequest} from "../../apps/web-ui/src/lib/captureRetention.ts";

test("manual retention submits the complete persisted cross-backend preview", () => {
  const preview = {
    preview_sha256: "a".repeat(64),
    host_retention: {preview_sha256: "b".repeat(64)},
    selected: [{
      host_artifacts: {preview_sha256: "c".repeat(64)},
      normalized_events: {preview_sha256: "d".repeat(64)},
      zeek_checkpoint: {preview_sha256: "e".repeat(64)},
      suricata_checkpoint: {preview_sha256: "f".repeat(64)},
    }],
  };
  const request = coordinatedRetentionRunRequest(preview, "administrator-secret", 7);
  assert.strictEqual(request.preview, preview);
  assert.equal(request.password, "administrator-secret");
  assert.equal(request.policy_revision, 7);
  assert.equal("preview_sha256" in request, false);
});
