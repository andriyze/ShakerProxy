# Capture retention run evidence

Run:

```bash
go test ./internal/capture ./internal/gatewayprotocol \
  ./host/gatewayd/internal/daemon ./apps/control-api/internal/server
```

The host tests create a reviewed revisioned policy, start a manual run against
its exact preview, verify the selected session is absent, reload the durable run
and deletion job, and replay the same request idempotently. Negative cases
reject policy-revision and population drift. A synthetic persisted `PENDING`
record proves startup resumption completes the same stable per-capture deletion
request rather than selecting a new population.

API tests prove fresh password verification, server-bound actor identity,
password exclusion from the privileged RPC request, authenticated run history,
`no-store`, and a bounded response envelope. They also prove the public preview
freezes each selected host deletion boundary together with normalized-event,
exclusive-identity, pending-spool, Zeek-checkpoint, Suricata-checkpoint,
deferred-reclaim, and export evidence in a private durable ledger. Manual
execution must submit that complete preview and
uses it without issuing a second preview RPC; restart lookup uses the host digest
already embedded in the durable run. The UI shows complete, partial, failed,
remaining-byte, immediate-reclaim, and maintenance-reclaim evidence.

Scheduler tests additionally prove the first run waits a full cadence, exactly
one durable automatic run is created for a due slot, repeated checks do not
duplicate it, a disabled revision stops execution, and pre-run population drift
persists only generic failure evidence. Automatic execution obtains and persists
an exact combined preview before event-first deletion. Automatic and manual
triggers remain distinct in run history.
