# Cases and evidence holds

ShakerProxy's experimental case workspace groups verified evidence references for a
bounded investigation. It is a custody index, not a second copy of the evidence.
The current slice accepts finalized or active capture IDs, completed capture
export ledger IDs, and event query snapshot IDs. A generated case ID has the form `case-<32 lowercase hex>`.

## Durable case ledger

The control API stores at most 1,024 cases in a rootless service-private JSON
ledger. Each case contains an optimistic revision, `OPEN` or `CLOSED` status,
at most 1,024 evidence references, the latest hold outcome, and at most 2,048
timeline entries. Writes use a mode-0600 temporary file, `fsync`, atomic rename,
and directory `fsync`. Every timeline entry includes the previous entry's
SHA-256 and its own SHA-256. This detects accidental or casual edits; it is not
a signature and cannot defend against a compromised root account.

Creating, renaming or editing the (multi-line) description, attaching or
removing evidence, applying/releasing a hold, and changing status all append a
timeline event. `expected_revision` is optional; when sent, a stale revision is
rejected with `409 case_revision_changed`. Closing a case does not silently
release its hold, and closed cases must be reopened before their evidence
changes. Deleting a case removes its record and timeline but never the evidence
artifacts.

Holds constrain membership rather than freeze it: exports and query snapshots
can be attached while a hold is applied; a capture attached under an applied
hold is recorded as *not yet protected* (the hold becomes `PARTIAL`) until the
hold is applied again; a capture the hold protects cannot be removed, and a
case whose hold still protects any capture cannot be deleted, until the hold is
released.

A `QUERY_SNAPSHOT` reference pins the snapshot's canonical query, match count,
creation time, digest and dataset watermark in the case. Snapshots themselves
expire within an hour; re-running the pinned query over records at or below the
watermark reproduces the evidence, except for records later removed by
retention or deletion jobs.

## Host-enforced capture holds

A case hold is a post-capture retention override. Applying or releasing it
requires the administrator password (or a confirmation by the same session in
the last ten minutes) and accepts a printable 16–128-byte `Idempotency-Key`
(generated when omitted). The API derives a stable, bounded per-capture operation ID,
then asks `shakerproxy-gatewayd` to persist `hold.json` inside each referenced capture
directory. The sidecar contains its own optimistic revision, actor, reason,
idempotency evidence, and bounded history.

The host calculates one effective lock:

```text
capture start-time retention_lock OR active evidence hold
```

That effective lock is checked while producing deletion previews, immediately
again during deletion, in selective PCAP impact previews, and during automatic
retention selection. Adding a hold after finalization therefore protects an
existing capture without editing its immutable start-time provenance. Releasing
the case hold does not remove a start-time retention lock.

`ACTIVE` means every capture reference is protected. `INACTIVE` means every
capture reference reached the released state. `PARTIAL` means at least one host
could not confirm the desired state; the UI names those references as **not
protected** and leaves apply/release available for retry. The API never converts
a partial result into success. A hold cannot be created for a case with no
capture references, and only the owning case may release an active host hold.

## API and UI

Authenticated endpoints are documented in `schemas/api/openapi.yaml`:

- `GET|POST /api/v1/cases`
- `GET|PATCH|DELETE /api/v1/cases/{caseID}`
- `POST /api/v1/cases/{caseID}/evidence`
- `DELETE /api/v1/cases/{caseID}/evidence/{evidenceID}`
- `POST /api/v1/cases/{caseID}/hold`
- `PUT /api/v1/cases/{caseID}/status`

All responses use `Cache-Control: no-store` through the case handlers and the
global API security boundary. The dashboard provides creation, selection,
verified attachment, reauthenticated hold/release, status changes, per-capture
results, and the hash-chained timeline. A capture card with an active hold hides
its deletion control and identifies the owning case; the host remains the
authority even if the browser is stale.

## Explicit limits

This is not yet a complete legal-discovery system. The current host-enforced
hold protects ShakerProxy's capture directory and its coordinated retention/deletion
entry points only. A referenced export is an audit pointer; ShakerProxy cannot stop
deletion of a copy already delivered outside the appliance. A pinned query
snapshot does not retain the matching event rows. Devices, flows, DNS/TLS
observations, policies, notes, tags, owners, encrypted case bundles, managed
backup/index holds, archive status, signed timeline checkpoints, and role-based
case access remain promotion work.

Power-loss and clean-VM recovery evidence is also still required. Accordingly,
the feature is `experimental`, and every platform stays `not-certified` in the
support matrix despite the passing deterministic implementation tests.
