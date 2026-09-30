# Capture event deletion preview evidence

These tests isolate the immutable read-only contract for the normalized-event
backend. The preview primitive does not install barriers, delete rows, expose a
public route, or claim that space has been physically reclaimed; the public
coordinator consumes it as documented in `capture-deletion.md`.

`internal/ingest/event_deletion_test.go` creates two pending records for one
capture and an unrelated third record. The planner must return exactly two files
and the sum of their filesystem lengths, preserve a typed PostgreSQL footprint,
separate immediate spool estimates from deferred logical database bytes, bind a
ten-minute expiry, and reject digest tampering. Negative cases reject impossible
row/byte/sequence combinations and inconsistent pending-file evidence.

`internal/ingest/postgres_test.go` exercises the query against real PostgreSQL
when `SHAKERPROXY_POSTGRES_TEST_URL` is configured. After three capture-bound events
are drained, it verifies three event rows, three exclusively removable identity
rows, positive logical byte counts, a positive ingest watermark, and no
tombstone. The query takes the same per-capture transaction lock as ingestion
and reads all row categories from one repeatable snapshot. The test deliberately
does not equate `pg_column_size` totals with immediately available disk space.
