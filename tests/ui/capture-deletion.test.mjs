import assert from "node:assert/strict";
import test from "node:test";
import {
  captureArtifactsWereDeleted,
  captureDeletionCanCancel,
  captureDeletionCanRetry,
  coordinatedDeletionRequest,
  deletionBackendLabel,
} from "../../apps/web-ui/src/lib/captureDeletion.ts";

test("combined deletion request round-trips the immutable preview", () => {
  const preview = {
    preview_sha256: "a".repeat(64),
    host_artifacts: {preview_sha256: "b".repeat(64)},
    normalized_events: {preview_sha256: "c".repeat(64)},
    zeek_checkpoint: {preview_sha256: "d".repeat(64)},
    suricata_checkpoint: {preview_sha256: "e".repeat(64)},
  };
  const request = coordinatedDeletionRequest(preview, "administrator-secret", "capture-0123456789abcdef0123456789abcdef");
  assert.strictEqual(request.preview, preview);
  assert.equal(request.password, "administrator-secret");
  assert.equal(request.confirmation, "capture-0123456789abcdef0123456789abcdef");
});

test("capture card removal depends on the host backend acknowledgement", () => {
  assert.equal(captureArtifactsWereDeleted({backends: [
    {backend: "normalized_events", state: "COMPLETED"},
    {backend: "host_capture_artifacts", state: "FAILED"},
  ]}), false);
  assert.equal(captureArtifactsWereDeleted({backends: [
    {backend: "normalized_events", state: "COMPLETED"},
    {backend: "host_capture_artifacts", state: "COMPLETED"},
  ]}), true);
});

test("backend labels identify all authoritative deletion surfaces", () => {
  assert.match(deletionBackendLabel("normalized_events"), /Normalized events/);
  assert.match(deletionBackendLabel("zeek_checkpoint"), /Zeek/);
  assert.match(deletionBackendLabel("suricata_checkpoint"), /Suricata/);
  assert.match(deletionBackendLabel("host_capture_artifacts"), /PCAP/);
});

test("only terminal incomplete deletion jobs expose retry", () => {
  assert.equal(captureDeletionCanRetry("FAILED"), true);
  assert.equal(captureDeletionCanRetry("PARTIAL"), true);
  assert.equal(captureDeletionCanRetry("PENDING"), false);
  assert.equal(captureDeletionCanRetry("RUNNING"), false);
  assert.equal(captureDeletionCanRetry("COMPLETED"), false);
});

test("cancellation is shown only before every backend barrier", () => {
  const untouched = [
    {backend: "normalized_events", state: "NOT_STARTED"},
    {backend: "host_capture_artifacts", state: "NOT_STARTED"},
  ];
  assert.equal(captureDeletionCanCancel({state: "PENDING", backends: untouched}), true);
  assert.equal(captureDeletionCanCancel({state: "RUNNING", backends: untouched}), false);
  assert.equal(captureDeletionCanCancel({state: "PENDING", backends: [{backend: "normalized_events", state: "RUNNING"}]}), false);
  assert.equal(captureDeletionCanCancel({state: "PENDING", backends: []}), false);
});
