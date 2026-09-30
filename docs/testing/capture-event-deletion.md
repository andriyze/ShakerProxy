# Capture event deletion evidence

These tests isolate the normalized PostgreSQL deletion and spool/PostgreSQL
coordination primitives. They do not by themselves prove the complete public
deletion lifecycle; the control-plane and cross-backend evidence is documented
in `capture-deletion.md` and `capture-event-deletion-api.md`.

`internal/ingest/postgres_test.go` runs the destructive cases when
`SHAKERPROXY_POSTGRES_TEST_URL` is configured. The integration drains one real event,
creates the exact combined preview, and proves deletion is rejected before a
database tombstone exists. After both current replay barriers are installed, one
serializable call removes the event and its now-unreferenced global identity,
verifies both are absent, and commits exactly one receipt with the preview's
logical byte evidence. Repeating the same preview returns the original
completion time with `replayed=true`; a different valid preview conflicts.

The same integration changes a second capture's database population after
preview. Deletion returns `ErrCaptureEventDeletionPreviewStale`, retains both
events, and writes no partial receipt. A separately expired preview is rejected.
Schema assertions cover the versioned receipt table, and unit validation rejects
receipts that do not claim an authoritative absence check. Physical database
space reclamation is deliberately not asserted because row deletion leaves MVCC
and index maintenance to PostgreSQL.

The same test now calls `CaptureEventDeletionService` for the successful path.
It proves database preparation compares the reviewed row footprint before
writing its barrier, spool preparation compares the reviewed pending footprint
while holding the spool mutex, and response-loss replay returns the original
receipt after both stores are empty. A dedicated race-shaped case previews one
pending record, adds a second, and executes: the coordinator returns stale,
retains both files, does not create the spool tombstone, and leaves the earlier
database barrier visible so no delayed batch can cross into PostgreSQL. The
public control-plane retry preserves that safe partial result and reuses the
same reviewed preview; because the pending population changed, it remains stale
instead of widening scope. The public capture workflow can supersede stale
evidence with a fresh preview for unfinished backends while retaining completed,
immutable backend acknowledgements; see `capture-deletion.md`.
