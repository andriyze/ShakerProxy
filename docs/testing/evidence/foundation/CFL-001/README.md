# CFL-001: appliance configuration lock evidence

Recorded: 2026-09-02 UTC

Scope: implementation and contention evidence; no platform runtime
certification is claimed.

The evidence run covers:

- exclusive contention between independently opened file descriptors and test
  processes;
- bounded wait and typed busy errors containing the current category and
  operation ID;
- strict, bounded, no-follow metadata with active versus stale-crash status;
- stale metadata replacement after kernel ownership is absent;
- rejection of symbolic-link lock paths and invalid operation identities;
- gateway mutation refusal while an installer-category owner holds the same
  lock, while read-only status remains available;
- the asynchronous network apply and independent watchdog using the shared
  category contract; and
- installer, repair, application rollback, update, and uninstall scripts using
  the same path plus durable unresolved-network-phase checks.

Commands:

```text
go test ./internal/configlock ./internal/gatewayprotocol \
  ./internal/networktransaction ./host/gatewayd/internal/daemon \
  ./host/watchdog/cmd/shakerproxy-network-watchdog
bash -n packaging/install.sh packaging/uninstall/uninstall.sh
./tests/security/systemd-policy.sh
```

Not exercised here: concurrent processes in a clean systemd VM, forced daemon
death while holding the lock, watchdog contention at its real confirmation
deadline, DNS enforcement, restore, or signed-ruleset activation. Those remain
promotion gates.
