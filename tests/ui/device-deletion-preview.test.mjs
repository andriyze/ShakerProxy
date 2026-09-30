import assert from "node:assert/strict";
import test from "node:test";
import {
  deviceTrafficChoiceCanExecute,
  deviceTrafficChoicePresentation,
  deviceTrafficPreviewState,
} from "../../apps/web-ui/src/lib/deviceDeletion.ts";

test("all shared-PCAP choices state their packet boundary", () => {
  const choices = [
    "DELETE_METADATA_ONLY",
    "DELETE_DERIVED_CONTENT_ONLY",
    "DELETE_WHOLE_CAPTURE_FILES",
    "SANITIZE_AND_REWRITE_PCAP",
  ];
  for (const choice of choices) {
    const presentation = deviceTrafficChoicePresentation(choice);
    assert.ok(presentation.title);
    assert.ok(presentation.effect);
    assert.match(presentation.packetBoundary, /packet|PCAP|re-index/i);
  }
  assert.match(deviceTrafficChoicePresentation("DELETE_METADATA_ONLY").packetBoundary, /remain/i);
  assert.match(deviceTrafficChoicePresentation("DELETE_DERIVED_CONTENT_ONLY").effect, /normalized events.*analyzer checkpoints/i);
  assert.match(deviceTrafficChoicePresentation("DELETE_WHOLE_CAPTURE_FILES").packetBoundary, /collateral/i);
  assert.match(deviceTrafficChoicePresentation("DELETE_WHOLE_CAPTURE_FILES").effect, /metadata/i);
});

test("the UI never upgrades eligibility into execution availability", () => {
  assert.equal(deviceTrafficChoiceCanExecute({eligible: true, execution_available: false}), false);
  assert.equal(deviceTrafficChoiceCanExecute({eligible: false, execution_available: true}), false);
  assert.equal(deviceTrafficChoiceCanExecute({eligible: true, execution_available: true}), true);
});

test("every executable deletion choice still requires both server eligibility gates", () => {
  assert.equal(deviceTrafficChoiceCanExecute({eligible: true, execution_available: true}), true);
  assert.equal(deviceTrafficChoiceCanExecute({eligible: true, execution_available: false}), false);
});

test("exact status requires both the joined impact and an empty blocker set", () => {
  assert.equal(deviceTrafficPreviewState({exact_impact: true, pcap: {blockers: []}}), "EXACT");
  assert.equal(deviceTrafficPreviewState({exact_impact: false, pcap: {blockers: []}}), "BLOCKED");
  assert.equal(deviceTrafficPreviewState({exact_impact: true, pcap: {blockers: [{}]}}), "BLOCKED");
});
