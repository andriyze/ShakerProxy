# ADR 0007: version device names and project them at the control boundary

## Context

A ShakerProxy device has an immutable generated ID, but operators need a mutable
friendly name everywhere they inspect traffic. Showing only the latest name on
historical evidence is misleading, while allowing analyzers or ingest workers
to author administrator labels would cross a trust boundary.

## Decision

The inventory stores an optimistic-concurrency alias revision and a bounded
chain of changes containing actor, timestamp, previous value, new value, and
reason. Duplicate names remain legal and receive a derived conflict marker.

The authenticated control API reads this history through a short-lived cache
and enriches recent and SSE event projections after the internal ingest response
has passed validation. Analyzer workers and ingestd continue to handle immutable
device IDs only. Each event distinguishes the current name from the name in
effect at capture time and explicitly reports when historical certainty is not
available. Inventory failure degrades labels without hiding immutable evidence.

Rename requests require reauthentication, an idempotency key, a reason, and the
expected alias revision. The inventory write and hash-chained audit append are
atomic.

## Consequences

Old inventory files remain readable. A legacy friendly name with no revision
timestamp is usable as the current label but cannot be asserted as the name at
capture time. History is capped at 256 changes; evidence older than a truncated
boundary is likewise marked unknown. Address aliases, typed alias filters, and
name projection on DNS, notifications, and other future surfaces remain separate
Phase 3 work.
