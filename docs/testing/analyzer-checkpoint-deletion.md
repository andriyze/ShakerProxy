# Analyzer checkpoint deletion evidence

Run the focused service, broker, and race checks with the pinned Go toolchain:

```bash
docker run --rm -v "$PWD:/src" -w /src \
  golang:1.25.1-bookworm@sha256:c423747fbd96fd8f0b1102d947f51f9b266060217478e5f9bf86f145969562ee \
  go test -race ./internal/analyzer ./apps/analyzer-worker/cmd/analyzer-worker
```

The fixtures prove that preview evidence contains the exact checkpoint byte
count, SHA-256, engine, manifest, and delivered-event counters; changed evidence
is rejected; intent is durable before unlink; a missing checkpoint after a
simulated crash resumes safely; receipts are mode `0600`; completed requests
replay without mutation; and the durable barrier prevents the analyzer from
reprocessing a PCAP whose checkpoint was deleted.

The HTTP fixture also proves bearer authentication, no-store responses, strict
JSON decoding, session-bound paths, and typed stale/expired/conflict behavior.
Compose validation proves that port 8082 is exposed only between services on the
internal `control` network and is never published on the host.

The control API suite additionally proves the public schema-2 preview binds
both engine previews, executes normalized events before Zeek, Suricata, and host
artifacts, and rejects an acknowledgement whose engine, capture, operation,
actor, digest, presence, or exact deleted byte count differs. Either analyzer
failure leaves host deletion `NOT_STARTED`; completed acknowledgements survive
retry and restart. Persisted schema-1 two-backend jobs and retention previews
remain readable and replayable, while new public requests cannot downgrade.
