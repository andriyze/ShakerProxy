import assert from "node:assert/strict";
import test from "node:test";
import {webUIFile, webUISource} from "./web-ui-source.mjs";

const source=webUISource();
const types=webUIFile("types.ts");

test("DNS event metadata does not overstate client outcome",()=>{
  assert.match(types,/dns_query\?:\s*string/);
  assert.match(source,/DNS observation/);
  assert.match(source,/Observe only · no resolver policy or client outcome is inferred/);
});

test("installed hosts expose previewed and reauthenticated DNS forwarding controls",()=>{
  assert.match(source,/api<TrafficPolicyDocument>\("\/api\/v1\/traffic-policy"\)/);
  assert.match(source,/api<TrafficPolicyPreview>\("\/api\/v1\/traffic-policy\/preview"/);
  assert.match(source,/api<TrafficPolicyDocument>\("\/api\/v1\/traffic-policy\/rollback"/);
  assert.match(source,/expected_revision:\s*document[.]policy[.]revision/);
  assert.match(source,/Administrator password/);
  assert.match(source,/set both its default gateway and DNS server to the ShakerProxy client-side IP/);
  assert.match(source,/redirects UDP and TCP port 53/);
  assert.match(source,/Confirm a routed or single-arm network plan before enabling DNS enforcement/);
});

test("port ownership is read-only and connectivity probing is explicit",()=>{
  assert.match(source,/api<ServicePortPlan>\("\/api\/v1\/system\/ports"\)/);
  assert.match(source,/Run explicit connectivity probe/);
  assert.match(source,/api<ConnectivityReport>\("\/api\/v1\/system\/connectivity-probe",\s*\{\s*method:\s*"POST",\s*body:\s*"\{\}"\s*\}\)/);
  assert.match(source,/These results do not enable DNS or rewrite the host/);
});
