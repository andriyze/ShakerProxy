# Capture retention preview evidence

The retention preview freezes the exact four-backend population consumed by
revisioned policy and manual or scheduled runs.

Run:

```bash
go test ./internal/capture ./internal/gatewayprotocol \
  ./host/gatewayd/internal/daemon ./apps/control-api/internal/server
```

The selector tests create finalized captures with distinct ages and sizes,
including a retention-locked capture. They prove deterministic oldest-first
selection, age-before-byte ordering, complete reasons, stable preview digests,
lock preservation, and explicit reporting when a byte target cannot be met.
API tests prove strict bounded input, unknown-field rejection, authentication,
`no-store`, and an exact typed gateway request.

The combined preview binds each finalized named capture's PCAP/session metadata,
normalized events, pending spool, and exact Zeek and Suricata checkpoints. It
does not mutate policy, run deletion, infer device membership inside shared
PCAP, or claim removal of indexes, export audit, backups, or external copies.
