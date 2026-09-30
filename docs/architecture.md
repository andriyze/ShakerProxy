# Architecture

ShakerProxy separates the privileged packet path from the replaceable application
stack.

1. `shakerproxy-gatewayd` is a narrow Linux host daemon. It owns only validated host
   inspection, guarded transactional network operations, capture lifecycle, and
   emergency bypass. It listens on a restricted Unix socket.
2. `control-api` handles authentication, configuration, audit, and normalized
   product APIs. It cannot run arbitrary host commands and has no Docker socket.
3. `web-ui` is the unified administration surface. Third-party consoles are not
   exposed as the product UI.
4. Optional protocol engines run in separately constrained Compose profiles and
   feed bounded adapters/ingestion paths.

Capability claims form a separate release-truth boundary. Strict registries in
`schemas/feature-flags.yaml`, `schemas/glossary.yaml`, and
`schemas/support-matrix.yaml` are validated together before tests and at control
API startup. The authenticated dashboard consumes the resulting bounded
`/api/v1/capabilities` representation, so visible badges cannot drift from the
repository's evidence paths and promotion gates. Platform certification is
dimensioned by OS, architecture, Docker firewall backend, topology, and feature;
safe container startup never implies gateway or interception certification. See
`docs/capabilities.md`.

All first-party privileged configuration paths share the cross-process
appliance lock documented in `docs/configuration-lock.md`. Network transactions,
the rollback watchdog, package lifecycle operations, and capture-service
start/stop cannot interleave. The durable gateway transaction phase is checked
again after lock acquisition, closing the asynchronous apply versus update
race. Read-only operations and bulk evidence deletion remain outside this lock
and retain their narrower transaction contracts.

Production management TLS is a separate host trust boundary. Package setup
creates a root-only ECDSA management authority and a server-authentication-only
leaf. Caddy receives only the leaf through read-only mounts and a dedicated
numeric supplementary group; the control API receives only a public CA copy and
bounded metadata for authenticated download. The interception authority is
provisioned into a distinct service-private path; only its public certificate
and bounded metadata are projected to the control API. The management edge
receives no interception material, and provisioning and tests reject authority
reuse. Development stays loopback HTTP and does not create ambient management
trust. See `docs/management-tls.md`.

Cases form a separate control-plane custody boundary. The service-private case
ledger holds verified references and a bounded SHA-256-chained timeline, while
the privileged host owns the authoritative per-capture hold sidecar. A
post-finalization hold is combined with the capture's immutable start-time lock
at every deletion and retention boundary. Cross-host orchestration exposes
per-capture failure as `PARTIAL`; it never infers a case-wide hold from a UI
label. See `docs/cases-and-holds.md`.

The host daemon also produces a fixed 14-check diagnostic report used by both
`shakerproxy doctor` and the authenticated dashboard. Probes are read-only, use
fixed file/command/service names and bounded output, and never open the Docker
socket. Packet-path failures are distinguished from warnings and unavailable
evidence; `UNKNOWN` contributes to a degraded overall result instead of being
reported healthy. A resource ladder combines CPU PSI, available memory, and the
managed disk reserve; critical pressure blocks new capture starts without
changing routing or management. The browser refreshes this report every 30
seconds normally and every 60 seconds under pressure, while the local CLI
remains usable when the application stack is unavailable.

Recovery capability is a separate claim surface. A machine-validated registry
distinguishes measured objectives from targets and from recovery that is not
offered. The current verified objective covers only the Ubuntu 24.04 two-NIC
unconfirmed-network rollback; application restart on Ubuntu 26.04 remains a
target, and product-managed event/capture backup and restore remain unavailable.

A separate fixed service-port plan inventories TCP/UDP 53, 443, 853, and
management TCP/8443. It distinguishes the loopback `systemd-resolved` stub from
wildcard or unrelated ownership and never rewrites host resolver state. An
administrator-triggered, rate-limited probe compares verified HTTPS dialed to a
fixed IP with a TCP/53 connect so provider restrictions remain visible.

On installed hosts, `shakerproxy-gatewayd` also owns a revisioned traffic policy.
After a confirmed IPv4 routed or single-arm plan, an authenticated preview and
reauthenticated apply can bind fixed `iptables` rules to the confirmed client
interface. Plain client UDP/TCP 53 is redirected to the unprivileged
`shakerproxy-dnsd` listener on 1053 and forwarded to literal-IP port-53 upstreams.
The development daemon omits this capability. Listener or apply failure removes
interception hooks and restores the prior runtime policy; see
[DNS forwarding and encrypted-DNS policy](dns-forwarding.md).

The optional installed-host MITM profile runs the shipped ShakerProxy addon on a
digest-pinned mitmproxy image as a fixed non-root identity. A separate public
interception CA is downloadable only through authenticated endpoints; its
private key remains in the service-private mount and never leaves the appliance.
Local and cloud-managed policies compile into interface- and device-scoped packet rules plus
a bounded read-only proxy snapshot. Only metadata events enter the local ingest
and cloud queues; bodies and PCAP remain local. Pinning failures are visible and
may create a bounded client/host retry bypass for declared mobile platforms.
Canonical device identity is promoted into the normalized envelope before
local and cloud delivery. The local event store projects only bounded TLS
outcome fields: endpoints, server name, interception state, failure reason,
recent-success evidence, platform, and probable-pinning/bypass flags. The
authenticated UI groups those outcomes per device or client IP. A successful
handshake is labeled as proof of that traffic path only; it never claims that
all apps on the device trust the CA.
Local and cloud-managed mutations share a root-owned advisory lock. A validated
cloud-managed policy claims ownership before the cloud service removes the two fixed local
interception jumps; gateway reconciliation then stops publishing the local
proxy snapshot until the cloud connector rolls back to no policy. Missing ownership means the
standalone local policy remains authoritative, while unreadable, malformed, or
symlinked ownership state removes local interception and fails open.
Emergency bypass synchronously detaches local iptables enforcement and the
cloud-policy service removes its owned nftables table, retaining the desired
policy for later restoration.

The kernel forwarding path must survive failure of the UI, database, or
analysis stack. The production-gated IPv4 path now passes through validation,
preview, syntax checks, backup, staged apply with an independent watchdog,
health checks, and explicit confirmation before entering
`ROUTED_PASSTHROUGH`. The development profile omits that activation capability
and remains in `SETUP_SAFE`. The packaged path passes clean Ubuntu confirm,
watchdog-timeout, daemon-kill, host-reboot recovery, and Docker-restart
scenarios, plus live-SSH retention/rejection and Docker-stopped local bypass;
the wider release matrix is still required before it can ship.

Bounded capture follows the same split. `shakerproxy-gatewayd` validates a typed
session request, binds it to the confirmed lab interface and policy revision,
checks quota plus a 1 GiB emergency reserve, creates root-owned provenance, and
starts only an exact allowlisted template unit. The template runs
`shakerproxy-capture-worker` as `shakerproxy-capture` with only `CAP_NET_ADMIN` and
`CAP_NET_RAW`. That worker invokes `/usr/bin/dumpcap` without a shell and may
write only the session's `artifacts/` and `runtime/` children. It monitors free
space, stops gracefully, then hashes the PCAPNG files and immutable session
record into a manifest. The privileged daemon never parses packet content. For
delivery it reads only an exact finalized manifest member in 256 KiB chunks;
callers cannot provide a host path. The control API requires fresh administrator
authentication, supports one resumable byte range, exposes the manifest digest,
and writes a durable started/completed export record before and after streaming.

The first attribution adapter remains outside that host boundary. The non-root
control API receives `/var/lib/kea` read-only, parses only the fixed Kea DHCPv4
lease schema under byte/record/field limits, and atomically persists normalized
device evidence in its private data volume. MAC and DHCP client identities drive
correlation; IPv4 addresses are validity-window observations. Conflicting
identity links stay separate and surface warnings. This JSON-backed foundation
remains separate from the implemented PostgreSQL normalized-event repository;
a measured PostgreSQL inventory migration remains future release work, and the
current store is not a claim of the complete device model.
Administrator metadata and explicit merge/split corrections are
reauthenticated, idempotent, exact-evidence operations committed atomically
with a bounded audit record; see `docs/device-inventory.md`.
The normalized-event database drain reads that inventory through a read-only
mount and resolves analyzer endpoint addresses at each event's occurrence time.
Only one-device matches receive a device ID; overlaps remain unattributed.
The PostgreSQL row also freezes the matched source/destination side, address
interval, evidence source/confidence, and confirmed interface/VLAN plan scope,
so later inventory corrections cannot silently rewrite the explanation shown
for a stored event. Legacy rows keep a null explanation instead of being
backfilled heuristically.
Hardware vendor enrichment reads only the distro-managed IEEE MA-L, MA-M, and
MA-S cache, records the matched assignment and file digest, and treats local,
missing, or duplicate-conflict results as explicit non-vendor states.

`ingestd` is the sole normalized analyzer ingress. It runs non-root without
capabilities on an internal Compose network and requires a distinct bearer
secret. Native Zeek JSON and Suricata EVE records are normalized into the same
v1 envelope used by host and future mitmproxy adapters. Source+event identity
provides durable deduplication; content conflicts and malformed records enter a
bounded quarantine. Pending records use atomic fsync+rename writes with queue
and free-space backpressure. PostgreSQL batching/acknowledgement supports both
final manifests and a bounded feed containing only rotations dumpcap has
closed. The currently written ring member is never published to analyzers.

The `observe` profile pins Zeek 8.2.1 and Suricata 8.0.6 upstream manifests.
The Suricata image also binds its first-party policy file to a strict provenance
manifest containing version, source, license, engine version, SHA-256, rule
count, and reserved SID interval. Repository tests reject hash, inventory,
duplicate-SID, and symlink drift; the image build runs Suricata's native `-T`
validation. The broker revalidates the no-follow rule and manifest files before
each offline invocation and records their identity in its durable status.
Each first-party analyzer broker scans only direct capture-session directories,
strictly decodes either the closed-rotation feed or finalized manifest, hashes
and revalidates member size and modification time through an `O_NOFOLLOW`
descriptor, and passes only a separately verified open descriptor to a fixed
engine command. Per-engine progress is atomically persisted after delivery;
deterministic ingest identities make a crash between delivery and progress
publication safe to replay. Progress retains the identities of the final ring
population, so finalization processes only retained files not already handled
and writes one manifest-bound checkpoint with cumulative totals. Feed gaps are
recorded rather than hidden. The broker starts with only `SETUID` and
`SETGID`, then the parser child switches to UID/GID 65533 and clears all
supplementary groups. The parser cannot walk the capture mount, read the
root-only token copy, or alter root-owned checkpoints. Outputs live in a
bounded no-execute tmpfs, are revalidated after parsing, and are delivered line
by line under byte/count limits. A manifest-bound checkpoint is written only
after every accepted response; failure replays safely through ingestd's
deterministic deduplication. Each broker also exposes one authenticated
checkpoint-maintenance API on the internal-only control network. Its immutable
preview binds the exact final-checkpoint and active-progress bytes plus the
manifest identity, and deletion records a mode-0600 intent before unlinking
both state files. That intent is also a replay barrier: after a crash or
successful deletion, the analyzer will not recreate either state file or
reprocess a retained PCAP for that capture. No analyzer maintenance port is
published to the host. This is rotation-latency offline analysis, not direct
interface live-sensor processing.

The same authenticated internal maintenance broker exposes a read-only bounded
health snapshot. The control API polls each engine independently and returns a
stable two-engine report even when one broker is unavailable. A worker is
healthy only while actively scanning with a heartbeat no more than two minutes
old, or after a successful scan no more than two minutes old. Clock evidence
more than five seconds in the future is stale. Suricata health includes the
validated ruleset ID, version, and SHA-256; Zeek health rejects those fields.
The browser refreshes this evidence every 30 seconds without treating a broker
failure as an authentication failure or exposing the broker's internal error.

Finalized capture artifact deletion remains inside the privileged host boundary.
The gateway validates a manifest-bound, ten-minute preview, persists intent and
a deletion receipt under the capture root, atomically renames the exact session
directory into a private quarantine, removes only that validated quarantine
path, and verifies absence before marking its backend job complete. The public
control-plane operation treats that host result as one acknowledgement rather
than as whole-system completion. It first establishes normalized-event
barriers, then requires independent Zeek and Suricata checkpoint-deletion
acknowledgements, and only then removes host artifacts. Indexes, export audit,
backups, external copies, and unresolved cross-device PCAP collateral stay
visible as retained limitations.

Capture retention begins with a side-effect-free host preview. The gateway
enumerates a bounded finalized population, validates every local manifest
footprint, sorts by finalization time and capture ID, applies age then PCAP-byte
rules, and hashes the exact selection with a ten-minute expiry. Locked, active,
and unfinalized sessions remain outside the deletion population and are
reported explicitly. A reauthenticated apply can atomically persist a new
optimistically locked policy revision and its idempotency result, bound to that
unexpired preview digest. Enabled policies wait one full cadence before their
first automatic run and can be disabled through another reviewed revision.

The manual retention executor consumes that contract without widening its
scope. Before deletion it persists the run, exact ordered candidates, and a
stable preview-bound deletion request for each capture. Each candidate delegates
to the same quarantine-and-verify deletion primitive and is checkpointed after
completion. On daemon startup, nonterminal runs replay pending requests; an
already completed deletion resolves through its durable idempotency record.
The gateway scheduler checks every 30 seconds, derives one deterministic slot
from policy revision and wall time, skips missed historical slots, and suppresses
duplicates by finding the durable run for the current slot. Pre-run failures are
persisted generically for UI visibility without exposing host paths.

The normalized-event database is PostgreSQL on the internal control network.
It publishes no host port and receives its password and ingest connection URL
through separate read-only files. `ingestd` migrates the versioned schema before
draining, writes monthly event partitions transactionally, and retains the disk
spool when the database is unavailable. Database health is visible as degraded
without making the packet-forwarding path depend on PostgreSQL.

Capture-derived ingestion has a permanent replay barrier independent of event
row deletion. `ingestd` writes a validated tombstone atomically, then purges
matching pending spool records; both intake and pending-batch reads consult the
durable marker after restart. PostgreSQL stores the same capture boundary and
serializes it with batch writes through a per-capture transaction lock. A
delayed analyzer record therefore cannot recreate data after the deletion
coordinator has established both barriers. The barrier alone does not remove
existing rows or represent a completed multi-backend deletion.

The companion deletion planner takes a bounded-lifetime observation of both
surfaces. The spool is scanned under its process lock. PostgreSQL takes the same
per-capture advisory lock as ingestion and reads under one repeatable snapshot.
The result distinguishes event rows from exclusively removable global identity
rows and binds counts, logical bytes, ingest watermark, tombstone state, and
expiry into one SHA-256 digest. Cross-store coordination rechecks this evidence
before mutation; the preview itself remains read-only.

The PostgreSQL deletion transaction is intentionally narrower than the eventual
multi-backend job. Under the same ingestion lock it requires a tombstone and an
unexpired preview, rechecks the database footprint, freezes record identities in
a transaction-local relation, deletes capture rows, removes only identity-ledger
rows without surviving references, verifies absence, and commits a minimal
receipt. Stale evidence and any count mismatch abort the entire transaction.
Receipt replay is idempotent, while a different preview digest conflicts. The
coordinator must still install and verify the spool barrier before treating this
backend receipt as one successful component of a larger deletion.

Within `ingestd`, a compare-and-set coordinator joins those two local
backends without pretending they form one transaction. It prepares PostgreSQL
against the preview first, then prepares and purges the spool under its mutex,
then executes relational deletion. A stale database footprint mutates nothing.
A stale spool footprint after database preparation leaves a durable database
barrier and untouched spool files, which is an explicit retryable partial state.
Response-loss replay resolves the existing tombstones and immutable database
receipt instead of comparing the now-empty stores with the old preview.

That local lifecycle crosses the container boundary through a dedicated
deletion client, not through database sharing. `ingestd` conditionally registers
bodyless-preview and strict-execute POST routes, each guarded by a fourth bearer
secret distinct from ingest, event-query, and saved-view credentials. Both
services receive only that scoped secret through read-only mounts; the control
API still receives no database URL or password. The client accepts only a plain
internal HTTP origin, refuses redirects, caps request/response JSON, and
revalidates cryptographic preview and verified outcome contracts. Public capture
coordination is a separate durable layer: it freezes the host, normalized-event,
Zeek-checkpoint, and Suricata-checkpoint previews into one digest. It installs
the normalized-event barriers and validates exact deletion counts first,
deletes and verifies each analyzer checkpoint second, and invokes host artifact
deletion last. Its job cannot enter `COMPLETED` without all four
acknowledgements. Event failure before any other completion is `FAILED`; a later
analyzer or host failure is `PARTIAL`, and completed backend evidence cannot be
overwritten on replay. Other data classes remain explicitly outside this
four-backend operation.

Recent normalized-event reads cross a narrower, separate trust path. `ingestd`
requires a query-only bearer secret distinct from the ingest secret and serves
at most 100 metadata records in deterministic `(occurred_at, record_id)` order.
The response excludes raw JSON payloads. The authenticated control API receives
only that query secret—not the ingest or database credentials—validates the
same fixed filters, revalidates the bounded response, and exposes it to the UI.
Friendly-name and device-tag predicates are resolved by the control plane against
one current inventory revision; only bounded, sorted immutable device IDs are
sent through the private query path and bound by PostgreSQL. Live streams freeze
that resolution at connection time. The UI follows the bounded resumable event
stream; it does not claim live packet analysis. Incoming summaries collect in a
500-row deduplicated pending buffer instead of reordering rows under inspection.
An explicit reveal merges them into a 1,000-row visible cap while retaining the
selected event and reporting browser-only eviction. A fixed-height accessible
window renders only visible rows plus overscan; raw events remain in PostgreSQL,
not in unbounded browser state.
The query credential also authorizes a fixed ingestion-status document with
queue, lag, quarantine, storage-pressure, and database-connectivity counters.
It cannot call any write adapter.

Saved traffic views are relational configuration, but the control API still has
no database URL. It uses a third distinct bearer credential against a narrow
internal PostgreSQL repository surface. That surface accepts only validated
saved-view documents and actor identities; it cannot ingest or return event
payloads. Personal visibility, shared reads, owner-only writes, optimistic
revision history, and per-owner/history bounds are enforced at this boundary.

Traffic bulk-selection intent crosses the existing query-only boundary as an
actor-bound frozen query snapshot. Ingestd persists the canonical query, frozen
alias-to-device-ID resolution, time anchor, monotonic ingestion watermark, bounded count,
expiry, and integrity hash. It returns no event payloads through this endpoint,
and post-snapshot ingestion is excluded by the stored monotonic ingestion
watermark.

Public automation uses a separate hash-only credential ledger. The control API
accepts an expiring token only on routes explicitly wrapped with one exact
scope; browser sessions remain valid on those routes, while credential,
forwarder, networking, deletion, export, trust, and retention administration
remain session-only. Optional device/case restrictions fail closed on collection
paths. Successful token use is rate-limited and appended to a bounded
SHA-256-chained audit before the handler runs.

Safe event projection sits after `ingestd` spool acceptance and deduplication.
Control API, ingestd, and a separate `forwarderd` share only a dedicated
mode-restricted forwarder volume. Ingestd retains its internal-only network;
the credential-free delivery process can read no spool, capture, inventory,
database, service-secret, or control volume. The queue schema is constructed
from an allowlist and has no raw-payload field. Only `forwarderd` receives an
outbound-only Compose network for certificate-validated HTTPS webhook and syslog TLS; its dialer
refuses private, loopback, link-local, multicast, or rebinding results. JSONL
stays inside a fixed bounded appliance directory. Queue sequence, lag, retry,
and drop state remain visible through the session-only control API.
