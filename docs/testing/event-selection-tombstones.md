# Device/time event replay tombstone verification

These tests isolate the spool half of preview-bound metadata deletion. The
component does not itself expose a deletion button or remove PostgreSQL rows;
the current device/time workflows compose it with database selection deletion
and, depending on the reviewed choice, analyzer and PCAP backends. See
`device-traffic-deletion-preview.md` and
`event-selection-postgres-tombstones.md`.

Run:

```bash
go test -race ./internal/ingest ./apps/ingestd/internal/server
```

The suite proves:

- adjacent address-evidence windows merge into one canonical half-open interval;
- explicit device identity matches first and a different explicit identity is
  never overridden by an address;
- unattributed Zeek/Suricata events use bounded source/destination address
  fallback only inside the evidence interval;
- the reviewed pending count and file bytes must match under the spool lock
  before any tombstone is written;
- successful installation atomically persists the tombstone, removes only the
  matching pending files, and leaves unrelated records available;
- future matching intake receives a non-sensitive HTTP 410 response;
- a matching record already in flight is purged by `PendingBatch` after restart;
- exact replay returns the original immutable evidence; and
- corrupt durable state after restart fails ingestion closed rather than being
  ignored or mislabeled as an ordinary deletion match.

The persistent population is capped at 1,024 tombstones and each selection at
256 canonical addresses. The cache avoids filesystem scans, repeated payload
projection, and per-event sorting while all mutation remains serialized by the
spool lock.
