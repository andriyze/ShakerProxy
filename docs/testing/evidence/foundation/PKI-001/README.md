# PKI-001: management authority separation evidence

Recorded: 2026-09-02 UTC

Scope: deterministic implementation, API, CLI, packaging, and Compose policy
evidence. No browser-trust or platform certification is claimed.

The evidence run covers:

- purpose-constrained ECDSA P-256 management root and server-only leaf;
- root-only CA custody and a leaf-readable `shakerproxy-edge` group boundary;
- atomic, versioned leaf activation and idempotent provisioning;
- strict rejection of corrupt, incomplete, mismatched, or reused authority
  material;
- a separate root-only, keyless interception namespace;
- authenticated, no-store public certificate/status endpoints;
- non-overwriting CLI export with certificate/metadata verification;
- explicit production Caddy HTTPS termination; and
- Compose policy proving that the edge receives only the management leaf.

Commands:

```text
go test ./internal/managementpki ./host/pki/cmd/shakerproxy-pki \
  ./host/cli/cmd/shakerproxy ./apps/control-api/internal/server
./tests/security/runtime-provisioning.sh
./tests/security/compose-policy.sh
make compose-check
make package-smoke PACKAGE_VERSION=0.1.0-dev.5
```

The package smoke executes the amd64 provisioner and CLI export inside pinned
Ubuntu 24.04, but does not install the package through systemd. Not exercised
here: browser/OS enrollment, a running production edge, leaf
rotation without request loss, encrypted backup/restore, power loss during
rotation, or the Ubuntu 24.04/26.04 clean-install matrix. Those remain
promotion gates.
