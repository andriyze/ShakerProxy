# Native detection transitions

ShakerProxy includes an experimental, bounded native detector for appliance and
local-network integrity signals that should not depend on a third-party ruleset.
It emits durable transition events for:

- unapproved DHCP servers (`ROGUE_DHCP`);
- unapproved IPv6 router advertisements (`ROGUE_RA`);
- a link-layer identity claiming a configured gateway address
  (`GATEWAY_SPOOF_SUSPECTED`);
- clock synchronization loss or absolute offset above five seconds;
- capture failure, packet drop, or analyzer-feed eviction; and
- CPU, memory, or managed-storage pressure.

An active condition produces one `OPEN` event. Repeated observations with the
same severity and summary are suppressed. A later healthy/authorized observation
produces one `RESOLVED` event. Open state and monotonic revision survive an
`ingestd` restart. The normalized event store exposes only bounded type,
severity, state, summary, and scope fields; raw detector payloads do not cross
the event-query boundary.

## Authorization baselines

Network-integrity detection is fail-closed with respect to configuration but
does not guess what is trusted. Analyzer DHCP/RA/ARP records activate these
detectors only when the corresponding baseline is non-empty:

```text
SHAKERPROXY_AUTHORIZED_DHCP_SERVERS=10.20.0.1,aa:bb:cc:dd:ee:ff
SHAKERPROXY_AUTHORIZED_ROUTER_ADVERTISEMENTS=fe80::1,aa:bb:cc:dd:ee:ff
SHAKERPROXY_GATEWAY_BINDINGS=10.20.0.1=aa:bb:cc:dd:ee:ff
```

Values are comma-separated and case-normalized. Gateway bindings use
`address=link-layer-identity`. Malformed values are ignored rather than widened.
The current parser integration is deliberately schema-specific and experimental;
release promotion requires pinned Zeek/Suricata fixture and packet-path tests for
every supported analyzer version. Empty baselines mean no rogue-network claim,
not that the network is healthy.

Authenticated host observations use the outer normalized-event timestamp; a
nested payload cannot backdate a detection transition. Detection failures are
logged and never reject the already-durable source observation. Native findings
are evidence, not an instruction to spoof, block, or modify the packet path.
