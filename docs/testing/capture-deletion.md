# Coordinated capture deletion evidence

The current public deletion test slice covers finalized named-capture host
artifacts, capture-bound normalized events and replay spool records, and both
analyzer checkpoints. It is not whole-system traffic deletion.

Run:

```bash
make verify
```

Host tests create a finalized manifest-bound PCAP, obtain an expiry-bound
preview, execute a deletion through the manager, verify capture and quarantine
paths are absent, reopen the durable job, replay the same idempotency key, and
prove the receipt prevents session-ID recreation. Separate cases reject
retention lock, expired/stale previews, unexpected files and symlinks, and
inexact confirmation. A cancellation case proves a failed host job reports the
exact remaining files and bytes without removing the capture.

Control API tests join that host preview with cryptographically validated
normalized-event, Zeek-checkpoint, and Suricata-checkpoint previews, bind the
overlap and export-record count into one digest, and persist a mode-`0600`,
bounded, strict ledger. They cover restart
idempotency, conflicting keys, expiry, tampering, trailing data, symlinks, false
completion, and mutation of a completed backend acknowledgement. The endpoint
tests prove password reauthentication and actor binding, normalized-event-first
execution, exact event and analyzer acknowledgement matching, completed replay
without another backend call, authenticated list/detail/retry routes, and three
authoritative states:

- all four acknowledgements produce `COMPLETED`;
- injected normalized-event failure produces `FAILED` and leaves the host
  backend `NOT_STARTED`;
- an injected analyzer failure leaves the host backend `NOT_STARTED` and
  produces durable `PARTIAL` with earlier acknowledgements intact;
- analyzer completion followed by injected host failure also produces durable
  `PARTIAL`.

Retry tests prove a `PARTIAL` job can complete a pending backend without calling
any completed backend again, and a `FAILED` event barrier can
restart before host deletion. They also cover wrong-password and missing-key
rejection, globally unique initial/retry idempotency keys, one unfinished retry
per operation, restart durability, immutable completed retry evidence, pending
operation resumption, and the crash window between terminal backend persistence
and retry-receipt persistence. The race-enabled control API suite exercises the
same coordinator and ledger paths.

Supersession coverage creates mixed terminal evidence, obtains a newer combined
preview, and proves only failed/unfinished backends return to `NOT_STARTED`.
The completed analyzer acknowledgement continues to validate against its older
immutable preview after restart; the replacement digest and globally unique
supersession key replay idempotently. The API and UI expose this separately from
ordinary retry because retry never refreshes reviewed evidence.

`tests/ui/capture-deletion.test.mjs` proves the full immutable preview is sent
back on confirmation and that a capture card is removed only after the host
backend reports `COMPLETED`. The rendered UI presents the combined PCAP/event/
spool/reclaim/export boundary and each backend state. `FAILED` and `PARTIAL`
cards expose a password-gated retry action while `PENDING`, `RUNNING`, and
`COMPLETED` cards do not. Terminal incomplete cards also expose a separately
password-gated fresh-preview supersession action. A `PENDING` card exposes cancellation only while every
backend is `NOT_STARTED`; API tests prove the durable cancellation replays and
is rejected after the normalized-event backend enters `RUNNING`. A 390-pixel
browser check verifies the retry form
stacks without horizontal overflow.

Engine/search indexes, export audit, external copies, backups, and exact
cross-device PCAP membership remain outside this operation.
