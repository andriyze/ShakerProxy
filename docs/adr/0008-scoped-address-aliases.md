# ADR 0008: Keep address aliases scoped and separate from device identity

Status: accepted for the Phase 3 inventory slice

## Context

An operator sometimes knows that an address belonged to a fixture even when
ShakerProxy has no stable MAC, DHCP client ID, or other device identity. Treating
the address as a device ID would incorrectly transfer history after DHCP reuse
or across IPv6 privacy-address changes. An unscoped label would also leak
between interfaces or VLANs.

## Decision

Store manual address aliases as independent, revisioned records. Require a
canonical IPv4/IPv6 prefix, interface, validity start, priority, confidence,
reason, and actor evidence; allow an optional VLAN and exclusive validity end.
Creation and replacement share the inventory's bounded, atomic SHA-256-chained
audit ledger and idempotency namespace.

Resolve a lookup only for an exact address/interface/VLAN/time tuple. Order
candidates by longest prefix, VLAN specificity, operator priority, and
confidence. Differently named candidates tied at that rank return an explicit
conflict and no winner. Later timestamps and IDs provide deterministic ordering
only after semantic ambiguity has been ruled out.

Do not attach an address alias to a `Device.id`, mutate observed lease evidence,
or apply it automatically to events that lack trustworthy interface/VLAN
scope. Surface overlaps with manual aliases or device observations as warnings.
Confirmed-plan DHCPv4 intervals carry interface, optional VLAN, and plan-hash
provenance; legacy or gateway-unavailable intervals retain unknown scope and
therefore produce conservative overlap warnings.

## Consequences

Manual labels cannot silently rewrite historical device attribution and can
represent both IPv4 and IPv6 before full IPv6 device discovery ships. Operators
must supply more scope than a bare `IP -> name` map, and current normalized
events cannot consume the alias until their network-interface evidence is
available. Existing lease history remains additive and is not rewritten when
confirmed scope first becomes available.
