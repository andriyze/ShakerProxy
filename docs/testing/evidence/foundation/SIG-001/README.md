# SIG-001: signed content lifecycle evidence

Recorded: 2026-09-02 UTC

Portable tests generate an ephemeral RSA-3072 key, sign valid Suricata bundles,
and prove signature/hash validation, exact artifact inventory, preview diff,
optimistic updates, pin blocking, unpin, verified offline rollback, state/audit
integrity, artifact tamper rejection, and automatic last-known-good restoration
after a simulated consumer load failure.

```text
go test ./internal/signedcontent ./host/cli/cmd/shakerproxy
make registry-check
make package-smoke PACKAGE_VERSION=0.1.0-dev.8
```

No private test key is stored. This is implementation evidence, not a clean-VM
claim. Production consumer reload, real Suricata/Zeek health, resolver matching,
power-loss recovery, and signed online source delivery are not certified.
