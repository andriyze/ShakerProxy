import assert from "node:assert/strict";
import test from "node:test";
import {applySelectedDeviceToURL, selectedDeviceFromURL} from "../../apps/web-ui/src/lib/deviceDetailURL.ts";

const deviceID = `device-${"a".repeat(32)}`;

test("selected device deep links round trip without changing other query state", () => {
  const url = applySelectedDeviceToURL(new URL("https://shakerproxy.test/?device_view=online&event_query=dns"), deviceID);
  assert.equal(selectedDeviceFromURL(url.searchParams), deviceID);
  assert.equal(url.searchParams.get("device_view"), "online");
  assert.equal(url.searchParams.get("event_query"), "dns");
});

test("invalid device identifiers never enter shared URL state", () => {
  const source = new URL("https://shakerproxy.test/?device_id=../../secret&device_tag=camera");
  assert.equal(selectedDeviceFromURL(source.searchParams), "");
  const cleared = applySelectedDeviceToURL(source, "not-a-device");
  assert.equal(cleared.searchParams.get("device_id"), null);
  assert.equal(cleared.searchParams.get("device_tag"), "camera");
});
