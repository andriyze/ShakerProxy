# DET-001 native detection and pressure evidence

Scope: deterministic unit/integration evidence plus one Ubuntu 26.04
shared-VPS safe-runtime exercise.

- `internal/detection/detection_test.go` covers every built-in family, explicit
  network authorization baselines, open-event suppression, durable restart, and
  resolution.
- `internal/resourcepressure/pressure_test.go` covers normal, degraded,
  critical, and unknown evidence semantics.
- `apps/ingestd/internal/server/server_test.go` proves one accepted authenticated
  observation produces one durable derived transition and replay produces none.
- `internal/ingest/detection_projection_test.go` proves only the allowlisted,
  bounded detection schema reaches recent/live event readers.
- `host/gatewayd/internal/daemon/diagnostics_test.go` binds resource pressure into
  the stable read-only diagnostic report.
- `../UBU2604-001/README.md` records a real ingestd restart with one projected
  `CLOCK_DRIFT` OPEN transition, exact-replay and post-restart suppression, and
  one RESOLVED transition through the authenticated public query boundary.

This is not clean-VM or gateway certification. Further promotion requires
captured DHCP, RA, and gateway-claim fixtures from every pinned analyzer plus
sustained CPU, memory, disk, and forwarding-survival tests on reference
hardware.
