# PostgreSQL device/time deletion verification

The schema-7 replay barrier, schema-8 deletion transaction, and schema-9 combined
coordinator binding are tested against
a real disposable PostgreSQL instance, not an emulated SQL backend. Set
`SHAKERPROXY_POSTGRES_TEST_URL` and run:

```bash
go test ./internal/ingest -run Postgres -count=1 -v
```

`TestPostgresEventSelectionTombstoneBlocksInFlightReplay` stages a valid batch
before installing the selection tombstone, then attempts the database write. It
proves:

- the additive migration creates the bounded selection table and indexes;
- the complete canonical selection and query snapshot evidence round-trip;
- an already-read matching batch is rejected with the typed tombstone error;
- neither `normalized_events` nor `normalized_event_identities` receives a row;
- exact replay returns the immutable original tombstone;
- reusing the operation ID with a different actor/evidence conflicts; and
- an unrelated device/address batch still commits.

The broader PostgreSQL suite must pass in the same run to prove the migration
preserves capture-wide tombstones, preview-bound capture deletion, partitioned
ingestion, global identity deduplication, and query behavior.

`TestPostgresEventSelectionDeletionIsSnapshotBoundAndVerified` additionally
proves that an exact query snapshot produces an independently hashed database
footprint, mutation is refused before preparation, a different preview cannot
reuse the prepared operation, and the serializable delete removes exactly the
target events and their exclusive identities while preserving unrelated data.
It checks the durable receipt and exact replay after the query snapshot has been
removed.

`TestPostgresEventSelectionPreviewRejectsRowsAfterSnapshotWatermark` inserts a
matching row after the frozen watermark and proves that preview creation fails
stale instead of silently omitting the row. These database-focused tests do not
by themselves prove public execution; the control-plane jobs and cross-backend
device/time workflow are covered separately and documented in
`device-traffic-deletion-preview.md`.

The non-database coordinator and transport tests run in the ordinary Go suite.
`TestEventSelectionDeletionServiceBindsSpoolAndDatabaseAndReplays` proves the
database barrier is prepared before the exact pending population is purged and
that retries reuse both barriers and the original receipt.
`TestEventSelectionDeletionServiceRejectsChangedCombinedPreview` proves the
durable tombstone's combined digest rejects a substituted spool preview. The
ingestd route and deletion-client tests cover the distinct credential, strict
request/response schemas, no-store behavior, redirect refusal, and typed error
mapping.
