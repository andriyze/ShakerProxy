import assert from "node:assert/strict";
import test from "node:test";
import {tlsDeviceTrustObservations,tlsOutcomeExplanation} from "../../apps/web-ui/src/lib/tlsTrust.ts";

const device="device-0123456789abcdef0123456789abcdef";

test("a successful intercepted connection verifies only the observed client path",()=>{
  const observations=tlsDeviceTrustObservations([{occurred_at:"2026-09-03T12:00:00Z",device_id:device,tls_server_name:"api.example.test",tls_interception_state:"INTERCEPTED"}]);
  assert.equal(observations[0].status,"VERIFIED PATH");
  assert.match(observations[0].detail,/Individual pinned apps/);
});

test("probable pinning takes precedence over a prior successful trust path",()=>{
  const observations=tlsDeviceTrustObservations([
    {occurred_at:"2026-09-03T12:01:00Z",device_id:device,tls_server_name:"pinned.example.test",tls_interception_state:"FAILED",tls_pinning_suspected:true,tls_client_recent_success:true,tls_bypass_activated:true},
    {occurred_at:"2026-09-03T12:00:00Z",device_id:device,tls_server_name:"api.example.test",tls_interception_state:"INTERCEPTED"},
  ]);
  assert.equal(observations[0].status,"PINNING SUSPECTED");
  assert.match(observations[0].detail,/CA path works/);
});

test("ambiguous CA rejection is explained without claiming pinning",()=>{
  const explanation=tlsOutcomeExplanation({occurred_at:"2026-09-03T12:00:00Z",tls_interception_state:"FAILED",tls_failure_reason:"ca_not_trusted_or_pinning"});
  assert.match(explanation,/CA not trusted|Install and enable the CA/);
  assert.doesNotMatch(explanation,/probable app pinning/);
});
