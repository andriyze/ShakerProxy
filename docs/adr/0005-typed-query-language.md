# ADR 0005: one typed query AST for high-volume metadata

Status: traffic-query slice, bounded current/historical device-alias search,
anchored relative/absolute time expressions, parser-derived field/operator
autocomplete metadata, bounded inventory-backed alias/tag completion, event
facets, revisioned PostgreSQL saved views, and frozen event-query snapshots
implemented; policy/resolver cross-domain fields pending

ShakerProxy will use one versioned, typed filter language and AST across bounded
API queries, URL state, saved views, exports, and frozen bulk-action snapshots.
The ordinary UI will never send SQL, OpenSearch DSL, arbitrary regular
expressions, or engine-native filters.

The first implemented slice covers normalized analyzer-event metadata. It
supports explicit and adjacent `AND`, `OR`, `NOT`, parentheses, quoted values,
equality/inequality and ordered comparisons, canonical IP addresses and CIDRs,
bounded hostname-style wildcards, and binary byte units. Its allowlisted fields
are `source`, `kind`, `device.id`, `device.name`, `capture.id`, `src.ip`,
`dst.ip`, `src.port`, `dst.port`, `protocol`, `service`, `bytes`, `confidence`,
and `time`. The shorter `name` and `device` inputs canonicalize to
`device.name`.

The parser enforces UTF-8, byte, token, nesting, field, type, range, and pattern
limits. It returns a deterministic canonical expression. PostgreSQL compilation
maps typed fields to fixed columns and binds every value as a query argument;
the compiler independently rejects a forged or unknown AST. The API echoes the
canonical query and the internal client verifies that it matches the request.
The browser stores only the non-sensitive expression in shareable URL state and
keeps invalid input visible with the server's bounded validation error.

`device.name` is an exact, case-insensitive match over the current name and
retained alias revisions; `device.name:*` matches devices with any retained
name. The control API resolves at most 32 distinct operands and 256 total
device-ID associations from one cached inventory snapshot. It freezes that
snapshot for a recent request or for the lifetime of one live connection. A
broader result fails with `422` and is never truncated. Only sorted immutable
device IDs cross the authenticated query-only boundary to ingestd, where they
are bound as a PostgreSQL array inside the original boolean AST. The public
canonical query remains name-based. Missing, malformed, extra, duplicate, or
unresolved private mappings are rejected. Names pruned by the bounded alias
history cannot be searched and are not represented as if known.

`time:last_<number><s|m|h|d>` defines a relative window of at most 30 days.
The first recent page freezes the database clock as `query_anchor` and applies
the closed observation-time interval `[anchor-duration, anchor]`. Stable recent
page cursors carry that anchor. Its live continuation retains the same lower
bound while accepting newly committed matching events, and every live resume
cursor carries the anchor across disconnects. Absolute `time` comparisons
accept RFC3339 timestamps and canonicalize them to UTC. Legacy cursors without
an anchor remain valid for queries without relative time. The private anchor
transport is rejected on the public API, and PostgreSQL receives only bound
timestamps.

The authenticated query-metadata endpoint publishes the same bounded field
allowlist used by existence checks, plus each field's value type, accepted
operators, fixed enum values, aliases, wildcard capability, and parseable
examples. The response is versioned, no-store, parameter-free, and contains no
event rows, inventory names, payloads, or backend column names. The traffic
input consumes these suggestions through the browser's accessible native
completion control. Dynamic alias/tag completion is implemented through a
separate bounded endpoint; policy and resolver-provider completion remain
follow-on work until those authoritative engines exist.

The first recent page also computes `source`, `kind`, `protocol`, and `service`
facets inside the same PostgreSQL transaction, with the same canonical filter
and relative-time anchor as the rows. Populations of up to 10,000 matches are
reported as exact. Larger populations return counts over the newest 10,000
matching rows with `exact:false`, `count_relation:gte`, and
`basis:newest_sample`; the UI labels that basis and never presents it as a full
count. Each field returns at most 12 values plus an `other_count`. Older cursor
pages omit facets rather than repeatedly paying the aggregation cost. The
query-only client independently validates field order, values, bounds, sort
order, totals, and exact/sample claims before the control API exposes them.

Traffic saved views persist the same canonical query rather than an unchecked UI
string. A saved configuration also carries an allowlisted page, explicit
query/rolling/absolute time behavior, up to three deterministic sort terms,
ordered and pinned safe columns, density, and a bounded chart configuration.
Personal views are visible only to their owner; shared views are readable by
other authenticated actors, but only the owner may update or delete them.
Optimistic revisions append immutable PostgreSQL snapshots, retaining the newest
100 versions and at most 100 owned views. Duplicate and import always create a
new owned ID. Exports omit owner, editor, revision, and timestamps.

The control API still receives no PostgreSQL credential. It calls a narrow
internal saved-view repository using a third bearer credential that is distinct
from both event ingestion and event query tokens. The internal client validates
the complete response shape, ownership, bounds, revision ordering, and canonical
configuration before exposing it publicly.

Frozen traffic selections are server-issued, actor-bound query snapshots rather
than client-side ID lists. Creation freezes the canonical public expression,
rewritten friendly-name/tag-to-device-ID associations, a database-clock relative
time anchor, the fixed `(occurred_at DESC, record_id DESC)` ordering, and the
largest database-assigned monotonic ingestion sequence in one locked
transaction. The accompanying received-time/record tuple is evidence, not the
authority, so clock skew cannot admit later rows. The stored SHA-256 binds that
hidden query state, the actor, count,
watermark, policy version, creation time, and expiry. Later matching ingestion is
therefore outside the selected population. Counts are exact through 100,000;
larger sets are explicitly reported as a bounded `gte` lower limit. Snapshots
expire after 1–60 minutes, default to 15, and are capped at 20 active references
per actor. Only the creating actor can retrieve one. The query-only credential
may create or read this metadata but still cannot ingest events or mutate saved
views.

Authenticated dynamic completion now covers the authoritative inventory domains:
current and retained historical device aliases plus current normalized device
tags. Prefixes, result counts, response size, and debounce timing are bounded.
The resolver reads one cached inventory revision for combined alias/tag filters,
then transports only sorted immutable device IDs to storage and into frozen query
snapshots. Historical completion is explicitly marked, while tag completion is
current-state only. Policy names and resolver/provider identities remain omitted
until their authoritative engines exist; they will extend this contract rather
than returning synthetic values.

This slice deliberately omits payload/content search and regular expressions.
