# Recovery objectives

`schemas/recovery-objectives.yaml` is the authoritative, machine-validated RTO
and RPO registry. The authenticated `GET /api/v1/recovery-objectives` endpoint
and dashboard render this file; neither maintains a stronger independent claim.

Statuses have precise meanings:

- `verified`: the exact environment and scenario have retained automated
  evidence at or within the stated objective;
- `target`: the implementation is designed toward the value, but the exact
  timed failure matrix has not passed; and
- `not-offered`: ShakerProxy has no supported recovery contract, so RTO/RPO values
  are intentionally absent.

The current verified objective is narrow: on Ubuntu 24.04 amd64 with iptables
and a two-NIC topology, the 60-second unconfirmed-activation scenarios restore
the exact prior managed network state and reconcile within 150 seconds of the
commit. RPO zero refers to the last known-good managed configuration only. It
does not claim uninterrupted traffic or replay packets lost during recovery.

Ubuntu 26.04 safe-mode application restart is currently a ten-minute target,
not a verified objective. Routed packet-path recovery on 26.04 is separately
uncertified. Product-managed PostgreSQL and capture-artifact backup/restore are
not offered; a durable Docker volume, external export, VM snapshot, or cloud
provider snapshot is not automatically a ShakerProxy backup. Restoring an old
external snapshot can also reintroduce data deleted after that snapshot,
including data covered by newer tombstones.

To promote an objective, add timed, failure-injected evidence first, retain the
environment and component versions, then change the registry status/value. The
validator rejects missing evidence paths, duplicate IDs, targets without both
RTO and RPO, and `not-offered` entries that publish a number.
