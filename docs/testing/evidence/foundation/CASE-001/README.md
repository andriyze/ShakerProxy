# CASE-001: cases and evidence-hold implementation evidence

Recorded: 2026-09-02 UTC

Scope: deterministic case-ledger, privileged capture-hold, API, and UI evidence.
No legal-discovery or platform certification is claimed.

The evidence run covers:

- bounded mode-0600 atomic case storage with optimistic revisions;
- SHA-256-chained case timeline validation and durable reload;
- verified capture membership and immutable membership while held;
- revisioned, idempotent post-finalization host hold sidecars;
- wrong-case release rejection and bounded hold history;
- manual capture-deletion and automatic-retention blocking;
- fresh-password case hold/release API orchestration;
- stable case-operation replay and derived per-capture operation identities; and
- explicit `PARTIAL` UI language that never calls an unprotected capture held.

Commands:

```text
go test ./internal/casework ./internal/capture ./internal/gatewayprotocol \
  ./host/gatewayd/internal/daemon ./apps/control-api/internal/server
npm --prefix apps/web-ui test
npm --prefix apps/web-ui run typecheck
make registry-check
make package-smoke PACKAGE_VERSION=0.1.0-dev.6
```

Not exercised here: systemd power-loss recovery, a clean-VM runtime, device/flow/
note membership, encrypted case-bundle export, signatures, role-specific case
access, or hold propagation to exports, backups, normalized data, analyzer state,
and optional indexes. External copies are outside appliance control. These are
promotion gates, so all support-matrix entries remain `not-certified`.
