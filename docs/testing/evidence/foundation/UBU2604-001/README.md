# UBU2604-001: Ubuntu 26.04 shared-VPS safe-runtime evidence

Recorded: 2026-09-02 UTC

The initial compatibility run exercised revision `a6df7ab`; a follow-up audit
and bounded safe-runtime retest exercised revision `8f8b999`. Both ran on
Ubuntu Server 26.04 (`resolute`), amd64, kernel `7.0.0-15`, Docker Engine
`29.7.2`, and Docker Compose `v5.5.0`. The host was a shared VPS with
pre-existing containers and port listeners. It was deliberately kept in
`SETUP_SAFE`; no ShakerProxy Netplan or firewall policy was applied and unrelated
services were not changed.

## Package and host boundary

The final Debian artifact was `shakerproxy-host_0.1.0-dev.16_amd64.deb`, SHA-256
`7a925b4613a14281cf4b30bda0c7e50bda6129c30b0487f9966d48b54a4fe62f`.
Package installation and an upgrade from the earlier test builds completed.
The upgrade run also found and fixed two real compatibility defects before the
final artifact was built:

- an exact legacy `/etc/shakerproxy/compose.env` containing only the capture group
  now migrates atomically to include the HTTPS-edge group, while unknown keys
  still fail closed; and
- `/run/lock/shakerproxy` is now provisioned both immediately and through
  `systemd-tmpfiles`, so the hardened gateway service starts after install and
  across volatile-directory recreation.

With dev.16 installed, `shakerproxy-gatewayd.service` was active, the daemon
reported capture and network-activation capabilities available, and its mode
remained `SETUP_SAFE`. `shakerproxy-app.service` correctly remained inactive
because no signed application release was installed. `shakerproxy doctor` returned
all 14 checks with overall `WARNING` due to shared-host listener/forwarding
conditions, `NORMAL` resource pressure, and permission for new captures. The
run did not start a host capture.

## Application and fault evidence

The exact source revision built and started all nine long-running development
services plus the one-shot volume initializer. The following checks passed:

- first-run administrator setup, wrong-password and missing-token rejection;
- 18 machine-validated capability records and the recovery-objective registry;
- authenticated live SSE delivery, alias/tag resolution, exact facets, saved
  view revision/import/export, and immutable query snapshots;
- PostgreSQL stop/restart fault injection, bounded spool degradation, and
  recovery drain;
- pinned Zeek 8.2.1 and Suricata 8.0.6 analysis yielding nine normalized
  events from the shared fixture;
- malformed-event quarantine and event-ID/content collision quarantine;
- one native `CLOCK_DRIFT` OPEN transition, exact-replay deduplication,
  persisted suppression after an ingestd restart, and one RESOLVED transition;
- authenticated service-port planning from the minimal gateway image using the
  bounded `/proc/net` fallback, 14-check diagnostics, connectivity-probe rate
  limiting, invalid-query rejection, analyzer broker status, and safe-mode
  capture refusal; and
- 100 concurrent setup-status requests with 100 HTTP 200 responses.

The `8f8b999` follow-up additionally ran the new documentation gate over all 65
Markdown files, revalidated all 18 capability records and four recovery
objectives, rebuilt all nine development services, and repeated authenticated
API, PostgreSQL outage/recovery, analyzer replay, and native-detection restart
tests. The fresh native sequence added exactly one `OPEN` and one `RESOLVED`
clock-drift transition; the observation between them survived an `ingestd`
restart without creating a duplicate transition.

## DNS-independent and packet-path tests

At final host verification, fixed-IP TLS to `1.1.1.1:443`, raw UDP DNS to
`1.1.1.1:53`, and raw TCP DNS to `1.1.1.1:53` all passed. An anticipated VPS
port-53 restriction was therefore not reproducible at that time. The isolated
development gateway correctly had no Internet egress because all of its
networks are marked internal.

The full Linux netlab suite passed without relying on external DNS:

- isolated IPv4 routing, NAT, emergency-bypass continuity, and root-route
  preservation;
- exact literal-IP TCP/18080 and UDP/18081 replies across the synthetic gateway;
- idempotent ShakerProxy firewall apply/rollback while preserving synthetic Docker
  and administrator rules;
- native Netplan, iptables-restore, and Kea configuration validation; and
- mitmproxy 12.2.3 explicit and transparent trusted-CA flows, untrusted-client
  and upstream rejection, scoped pass-through, non-root execution, and root-
  route preservation.

## Claim boundary

This evidence promotes only the shared-VPS `installable`/`safe-runtime` claims
recorded in `schemas/support-matrix.yaml`. It is not gateway or interception
certification. It does not cover a clean host, Docker installation, signed
application-release startup, host reboot, two-NIC activation, DHCP service,
host capture, repair, lifecycle update/rollback, or uninstall. The Ubuntu 26.04
safe-runtime RTO remains a target until timed host-reboot and process-loss
evidence is retained. No credentials, setup tokens, public addresses, or
machine identifiers are recorded here.
