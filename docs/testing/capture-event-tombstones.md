# Capture event tombstone evidence

These tests isolate replay prevention for normalized events. The primitive does
not itself delete existing PostgreSQL rows or coordinate host capture deletion;
the public coordinator composes it with database, analyzer, and host deletion as
documented in `capture-deletion.md`.

`internal/ingest/spool_test.go` proves that the spool persists a capture-bound
tombstone before purging matching pending records, rejects future intake,
removes a delayed record discovered after restart, preserves the first
operation evidence on replay, admits an unrelated capture, and fails closed on
a corrupt tombstone. `apps/ingestd/internal/server/server_test.go` proves that
late authenticated intake receives a bounded HTTP 410 response without exposing
the capture identifier.

`internal/ingest/postgres_test.go` covers schema version 5 and, when
`SHAKERPROXY_POSTGRES_TEST_URL` is configured, stages a valid analyzer batch before
creating its tombstone. The real PostgreSQL integration asserts that the later
write returns `ErrCaptureTombstoned` and creates neither an event row nor a
global identity row. A replay with different request metadata resolves to the
first immutable tombstone. The existing full sink integration runs against the
same migrated schema to protect partitioning, idempotency, queries, facets, and
snapshots.
