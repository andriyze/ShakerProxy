# Capture event deletion internal API evidence

The internal lifecycle API is not itself a public deletion job. It exposes the
local spool/PostgreSQL coordinator to the control plane without exposing ingest
or database credentials; the public job persists and validates this outcome as
its `normalized_events` backend before invoking host artifact deletion.

`apps/ingestd/internal/server/event_deletions_test.go` proves missing, ingest,
and query tokens cannot call the routes; only the distinct deletion token can.
The preview route rejects bodies, validates the capture path, and returns
`Cache-Control: no-store`. Execute requires bounded `application/json`, rejects
unknown fields and path/preview mismatches, validates the backend outcome, and
maps expired, stale, and conflicting evidence to distinct bounded errors. Server
construction rejects a deletion token shared with another configured role.

`internal/ingest/deletion_client_test.go` verifies the client sends the scoped
token only to the exact internal paths, emits no body/content type for preview,
sends strict JSON for execution, validates returned preview/outcome evidence,
maps lifecycle errors back to sentinels, rejects malformed JSON and unsafe
origins, and refuses a redirect even when a caller supplies an HTTP client that
would otherwise follow it. Compose policy checks require the fourth token to be
read-only in exactly `control-api` and `ingestd`; development setup generates it
independently.
