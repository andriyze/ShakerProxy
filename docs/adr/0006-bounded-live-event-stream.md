# ADR 0006: bounded resumable live event delivery

Status: closed-rotation/finalized-analysis stream implemented; browser soak
evidence pending

ShakerProxy delivers new normalized analyzer metadata through authenticated
server-sent events. Native `EventSource` is not used because it cannot attach
the administrator bearer credential; the browser uses `fetch` and parses only
bounded `events` frames. The session credential remains memory-only and never
enters a URL, `localStorage`, `sessionStorage`, or IndexedDB.

The initial recent-event query returns a live cursor captured before the page
read. PostgreSQL assigns `received_at` with its own clock during insertion. The
initial page transaction briefly takes a table `SHARE` lock, reads the database
clock, and reads the bounded page while the lock remains held. Consequently a
concurrent insert either commits and is visible before the boundary or receives
a later timestamp after the boundary; an uncommitted older timestamp cannot
fall through the gap. The cursor is an opaque, versioned encoding of
`(received_at, record_id)` and, for a relative time filter, its frozen query
anchor. Live queries resume strictly after the received-time tuple in ascending
order. This ordering captures late-arriving analyzer records even
when their observation time is older than the visible page. The browser
deduplicates by immutable record ID, sorts the visible projection by observation
time, and retains at most 100 rows. Changing the typed query or fixed source
filter obtains a new page and cursor.

A relative recent query closes its initial observation-time window at the
database-time anchor. The live continuation keeps the anchored lower bound but
does not keep the initial upper bound, so newly observed matching events can
arrive. Reconnects reuse the cursor's anchor rather than silently sliding the
window. Non-relative queries and legacy cursors retain their prior behavior.

The public stream and internal batch endpoint reuse the same typed filter AST.
Internal reads are capped at 100 records and three seconds. The control API
allows at most 16 concurrent streams, polls at a fixed interval, sends bounded
heartbeats, disables proxy buffering and caching, and applies a five-second
write deadline. It holds no per-client event queue: a slow or failed consumer
is disconnected and resumes from its last delivered cursor.

The browser aborts its stream while hidden, reconnects from its in-memory
cursor when visible, and uses exponential backoff capped at ten seconds after
transient failure. Cursors are not persisted across sign-in or page reload;
the authoritative recent query safely establishes a new boundary. Raw analyzer
payloads are excluded from the projection at every hop.
