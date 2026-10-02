import assert from "node:assert/strict";
import test from "node:test";
import {webUISource} from "./web-ui-source.mjs";

const source=webUISource();

test("topology editor exposes supported shapes, including the inline bridge",()=>{
  for(const topology of ["TWO_NIC","SINGLE_ARM","THREE_INTERFACE","VLAN_TRUNK","EXISTING_ROUTED_VLAN","PASSIVE_SENSOR","ADVANCED_CUSTOM","TRANSPARENT_BRIDGE"])assert.match(source,new RegExp(`value="${topology}"`));
  assert.match(source,/aria-label="Inline bridge topology"/);
  assert.match(source,/aria-label="Proposed routed topology"/);
  assert.match(source,/aria-label="Passive sensor topology"/);
  assert.match(source,/aria-label="Single-arm manual gateway topology"/);
  assert.match(source,/keep DHCP off/);
});

test("working WAN is preserved by default and risky ownership is explicit",()=>{
  assert.match(source,/useState<WANIPv4Mode>\("KEEP_EXISTING"\)/);
  assert.match(source,/useState<WANIPv6Mode>\("KEEP_EXISTING"\)/);
  assert.match(source,/Keep existing is the default and emits no WAN Netplan stanza/);
  assert.match(source,/allow_working_wan_change/);
  assert.match(source,/allow_cloud_init_override/);
  assert.match(source,/PPPoE is outside the v1 managed path/);
});

test("WAN and lab inputs cover static addresses VLAN MTU DNS and double NAT",()=>{
  for(const name of ["wan_ipv4_address","wan_ipv4_gateway","wan_ipv6_address","wan_ipv6_gateway","wan_vlan","lab_vlan","wan_mtu","lab_mtu","wan_dns_mode","upstream_nat"])assert.match(source,new RegExp(`name="${name}"`));
  assert.match(source,/Clamp TCP MSS on the lab side · not active in this release/);
  assert.match(source,/Prefix delegation · not active/);
});
