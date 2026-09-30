# Capture retention policy evidence

Run:

```bash
go test ./internal/capture ./internal/gatewayprotocol \
  ./host/gatewayd/internal/daemon ./apps/control-api/internal/server
```

The host tests prove the revision-zero safe default, exact preview-bound apply,
atomic reload, idempotent replay, conflicting-key rejection, optimistic
revision conflict, expired and drifted preview rejection, and exactly one
winner under concurrent updates. Enablement is covered with the scheduled
executor tests in `capture-retention-runs.md`.

The API tests prove authenticated `no-store` reads, fresh password verification,
server-bound actor identity, typed gateway requests, and absence of the password
from privileged RPC payloads. Timer and deletion-run evidence is documented
separately in `capture-retention-runs.md`.
