import assert from "node:assert/strict";
import test from "node:test";
import {
  applyDeviceListFiltersToURL,
  defaultDeviceListFilters,
  deviceListAPIPath,
  parseDeviceListFilters,
} from "../../apps/web-ui/src/lib/deviceFilters.ts";

test("device filters omit defaults and encode bounded API parameters", () => {
  assert.equal(deviceListAPIPath(defaultDeviceListFilters), "/api/v1/devices");
  const filters = {...defaultDeviceListFilters, view: "online", q: "camera & tv", tag: "test bench", ip_family: "ipv6", min_confidence: "75", warnings: "present"};
  assert.equal(deviceListAPIPath(filters), "/api/v1/devices?view=online&q=camera+%26+tv&tag=test+bench&ip_family=ipv6&min_confidence=75&warnings=present");
});

test("device URL state round trips without disturbing unrelated state", () => {
  const filters = {...defaultDeviceListFilters, view: "recent", vlan_id: "20", sort: "name", direction: "asc"};
  const url = applyDeviceListFiltersToURL(new URL("https://shakerproxy.test/?event_query=dns&device_q=old"), filters);
  assert.equal(url.searchParams.get("event_query"), "dns");
  assert.equal(url.searchParams.get("device_q"), null);
  assert.deepEqual(parseDeviceListFilters(url.searchParams), filters);
});

test("unknown URL enum values fall back to safe defaults", () => {
  const parsed = parseDeviceListFilters(new URLSearchParams("device_view=deleted&device_sort=random&device_direction=sideways&device_ip_family=ipx&device_warnings=maybe&device_q=router"));
  assert.equal(parsed.view, "all");
  assert.equal(parsed.sort, "last_seen");
  assert.equal(parsed.direction, "desc");
  assert.equal(parsed.ip_family, "");
  assert.equal(parsed.warnings, "");
  assert.equal(parsed.q, "router");
});
