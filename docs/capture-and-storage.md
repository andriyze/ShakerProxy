# Capture, analysis, and storage

ShakerProxy captures traffic that traverses the confirmed lab ingress. Capture is
not decryption: encrypted payloads remain ciphertext unless a separate,
explicit interception mode succeeds.

## Automatic lab recording

Lab traffic is recorded without anyone starting a capture. While a confirmed lab
plan routes, `shakerproxy-gatewayd` keeps one capture named **Lab traffic**
running on the lab interface. It records whole packets with the same scope as a
manual capture (single-arm labs record only what devices exchange through
ShakerProxy), so Traffic, Devices and reports always have data.

- **When it runs.** It starts within seconds of a lab plan being confirmed and
  after every gatewayd restart, upgrade and reboot. Each recording lasts at most
  24 hours, then the next one starts. A new lab plan stops the old recording and
  starts one for the new scope. It stops when the lab is turned off
  (`shakerproxy network off`), rolled back, or put in emergency bypass.
- **Manual captures replace it.** One capture runs at a time, so a manual capture
  (or a test session started with `--capture`) stops the automatic recording,
  and gatewayd starts it again once the manual capture ends.
- **Disk.** Each recording is a ring of 64 files of at most 8 MiB (512 MiB). Only
  the two newest finished recordings are kept; older ones are deleted through the
  normal verified capture deletion, which leaves analyzed events in place.
  Recordings under an evidence hold are kept until the hold is released.
  Automatic recording therefore never keeps more than 1.5 GiB of PCAP. It does
  not start while CPU, memory or capture disk pressure is critical, and the
  capture worker's emergency free-space reserve still applies.
- **A reboot mid-recording.** The cut-off recording is sealed with its retained
  files and marked "interrupted", so it can be exported or deleted like any
  other capture.
- **Turning it off.** Use the switch on the Traffic or Devices page,
  `sudo shakerproxy capture auto off`, or
  `PUT /api/v1/captures/lab-recording` with `{"enabled": false}`. Stopping the
  automatic recording from the Captures page or `shakerproxy capture stop` also
  turns it off. The setting persists across restarts.
  `shakerproxy capture auto` and `shakerproxy status` show the current state; the
  pages and `GET /api/v1/system/status` (`lab_recording`) also say why nothing
  is being recorded, for example that no lab plan is confirmed.

## Rotation and finalization boundaries

The host capture worker writes rotated PCAPNG files under
`/var/lib/shakerproxy/pcap/<capture-id>/artifacts/`. While capture remains active it
publishes only ring members that dumpcap has safely closed; the currently
written member is never exposed. At completion it records an immutable manifest
containing each retained filename, byte size, modification time, and SHA-256
digest. Zeek and Suricata process closed rotations with durable per-engine
progress, then reconcile that progress against the strict final manifest so a
retained member is not replayed.

For each member, the first-party broker:

1. Rejects symlinks, traversal names, unknown manifest fields, duplicates, and
   inconsistent totals.
2. Opens with `O_NOFOLLOW`, verifies metadata and SHA-256, and retains that
   descriptor.
3. Starts only the fixed offline command for the selected pinned engine.
4. Drops the parser child to UID/GID 65533 and clears supplementary groups. The
   child receives `/proc/self/fd/3`, not a capture pathname.
5. Re-hashes the same descriptor after the engine exits, before delivering any
   output.
6. Sends bounded JSON lines to authenticated ingest adapters and writes durable
   active progress after delivery; final reconciliation writes one
   manifest-bound checkpoint only after all required responses succeed.

If analysis or ingestion stops early, unacknowledged work is retried while
deterministic event IDs make already accepted lines idempotent. Feed gaps are
recorded explicitly. A changed finalized manifest is an error and is never
silently reprocessed.

The durable spool record is established before device attribution. During the
atomic PostgreSQL drain, native Zeek origin/response or Suricata
source/destination IPv4 fields are compared with the read-only inventory at the
event timestamp. Only an unambiguous validity-window match is persisted;
address reuse and overlaps are never resolved from the current IP alone.
Invalid inventory state pauses the drain while retaining the spooled event.

## Recent-event inspection

Authenticated administrators can inspect recent committed event metadata in
the UI or `GET /api/v1/events`. Pages default to 50 records and are capped at
100. Fixed filters cover source, exact kind, capture session, and device, and a
bounded typed expression covers projected network metadata, current or retained
device names, current device tags, and observation time. Relative expressions such as
`time:last_15m` are capped at 30 days and freeze a database-time anchor across
older-page cursors and live reconnects. RFC3339 timestamps support absolute
comparisons. Opaque cursors preserve descending event-time and record-ID order. The list
contains source/parser versions, timestamps, capture/flow/device references,
and confidence, but deliberately omits the raw analyzer JSON payload.

The authenticated UI debounces and cancels bounded prefix completion requests
for current/historical aliases and current normalized tags. Alias and tag
predicates are resolved together from one inventory revision; only immutable,
sorted device IDs cross the storage boundary or enter a frozen query snapshot.

The initial page includes server-computed source, kind, protocol, and service
facets from the same database snapshot. Counts are exact through 10,000 matching
events. Larger populations are explicitly labeled as a newest-10,000 sample;
they are never described as exact or silently extrapolated. Each field exposes
at most 12 values plus an `other` count, and older cursor pages omit facets.

The control API holds a query-only token that must differ from the ingest
write token. It has no database URL or analyzer credential. `ingestd` rejects
the write token on the read endpoint and returns a bounded JSON response over
the internal network. This is a resumable metadata stream of committed
rotation/finalized analysis, not deep search, packet streaming, or
direct-interface live-sensor output.

Saved traffic views use PostgreSQL through a separate typed repository endpoint
on the same unexposed internal service. A dedicated saved-view token cannot
ingest or query event records. Personal/shared visibility, owner-only mutation,
optimistic revisions, 100-view and 100-version bounds, canonical filter
validation, and metadata-only import/export are enforced server-side.

Frozen traffic-query snapshots live alongside normalized metadata but are not
materialized row copies. A short-lived actor-bound record freezes the validated
query state, resolved immutable device IDs, relative-time anchor, deterministic
sort, and the largest committed database-assigned ingestion sequence. A
received-time/record tuple remains visible evidence, but cannot be the authority
because clocks can skew. Its SHA-256 and `event-query-v1`
policy version let later export, tagging, policy, triage, and deletion jobs bind
to the exact selection evidence. Expired rows are removed during creation; no
actor may hold more than 20 active snapshots, and a count scan stops after
100,001 candidates to report a truthful `100000+` lower bound.

The same panel polls a separate bounded status resource and shows PostgreSQL
connectivity, durable queue records/bytes, oldest pending-event lag, quarantine
records/bytes, and storage pressure. These counters remain available through
the query-only credential and do not expose raw events or write capability.

## Isolation and limits

- Capture storage is mounted read-only. The broker joins the capture-reader
  group; the parser child has that group removed and sees only one open file.
- The analyzer-only ingest token and deletion-only maintenance token are
  root-owned mode `0400`. The parser UID cannot read either token or the
  root-owned checkpoint volume.
- The parser receives a fixed engine-specific environment allowlist; broker
  secret paths and ingestion configuration are not inherited.
- Container roots are read-only; Linux capabilities are dropped except the
  broker's `SETUID`/`SETGID` transition capabilities.
- Engine output uses a no-execute 384 MiB tmpfs and an independent 256 MiB
  application limit. A capture may emit at most 64 event files and 1,000,000
  events; each native event remains within ingestd's 192 KiB payload limit.
- Engine execution is limited to 30 minutes per bounded analysis input and
  container CPU, memory, and PID ceilings. The authenticated maintenance
  listener is reachable only on the internal Compose network; no analyzer
  publishes a host port or receives the Docker socket.
- Suricata's inherited image volumes are explicitly replaced with small bounded
  tmpfs mounts. Its ten bundled rules are an auditable, provenance-bound
  first-party cleartext policy, not a comprehensive threat-intelligence feed.

Raw Zeek and Suricata output exists only in a bounded no-execute per-job tmpfs
directory and is removed after successful delivery or any isolated failure; it
is not a retained engine-log copy. Durable checkpoints can be previewed and
deleted through the broker's strict internal maintenance API. A persisted
deletion intent prevents analyzer replay before and after a crash. Both engine
acknowledgements are part of the public capture coordinator and retention
contract.
The current worker provides rotation-latency offline analysis of safely closed
ring members and final manifest reconciliation. Direct-interface live sensors,
raw-log export, per-engine seccomp/AppArmor policy, and broader malicious-PCAP
corpus coverage remain release work. Immutable start-time retention locks and
post-finalization case evidence holds are implemented at the capture/control
boundaries. The host combines them before deletion previews, deletion,
selective-PCAP impact, and automatic retention. This protects the managed
capture directory, not external exports, backups, or analyzer output; see
`docs/cases-and-holds.md` for the explicit legal-discovery boundary.

Capture finalization also streams each PCAPNG through a bounded first-party
membership inspector while calculating the artifact SHA-256. For supported
Ethernet and raw-IP interfaces it records canonical unicast MAC and IP sets,
packet counts, and link types directly in the immutable capture manifest. VLAN,
IPv4, IPv6, and Ethernet/IPv4 ARP headers are understood. The parser caps each
block at 2 MiB, captured packets at 1 MiB, interfaces at 256, and observed
identities at 4,096. Invalid PCAPNG, unsupported link types, unavailable packet
headers, or identity overflow receive distinct inexact states; partial sets are
never presented as exact. Older manifests without this optional evidence remain
readable but block exact device-scoped deletion previews.

The internal PCAP sanitizer consumes only canonical, manifest-bound MAC/IP
selection rules, with an optional half-open packet-time window. It streams a
source into a separate store-level staging directory, refuses unsupported link
types or insufficient headers, independently verifies the output membership and
SHA-256, preserves a hard-link rollback copy, atomically renames the replacement,
then commits the updated capture manifest. A durable rewrite record preserves
the original and output artifact/manifest hashes, the exact selection and its
digest, tool and version, byte and packet counts, failure code, and rewrite
lineage. The store reserves enough free capacity for a complete replacement in
addition to the capture's emergency reserve. It never edits the only path in
place.

Cancellation is checked between bounded PCAPNG blocks and is safe before the
verified replacement is installed.

Successful packet removal marks analyzer/search re-indexing as pending. The host
daemon exposes the sanitizer only as an audited privileged RPC whose request
binds the source hash, exact selection, operation ID, and tool version; there is
no standalone public action. The coordinated device-deletion workflow must
invalidate stale Zeek, Suricata, Arkime, and search references before it may
report overall completion. An interrupted nonterminal rewrite requires explicit
recovery rather than an automatic second mutation.

Removing the old directory entry is not secure erasure; SSD wear leveling,
copy-on-write filesystems, snapshots, backups, and prior exports may retain the
original bytes.

Whole-file removal uses a separate audited host operation. Before mutation it
replays the reviewed packet selection against the manifest-bound source and
requires the original hash, total packets, matched packets, and unrelated
collateral packets to agree. It atomically renames the file into rollback
staging, writes the reduced manifest, and removes the staged original only after
the manifest commit. Its durable record reports the exact collateral and leaves
index invalidation pending; completed requests replay only with identical
evidence. A manifest may intentionally contain zero files after its last shared
artifact is removed.

Analyzer checkpoint deletion barriers support a controlled re-index generation.
After a sanitizer commits its new manifest, the authenticated maintenance plane
may authorize exactly one engine/session/manifest digest against the matching
completed checkpoint-deletion receipt. The worker continues to reject an
in-flight analysis of the old manifest, reprocesses only the authorized new
manifest, and retires the active barrier only after the replacement checkpoint
is durable. Deletion and re-index receipts then move to mode-0600 history files,
so their exact operations still replay while a later rewrite can begin a new
generation. A crash after checkpoint creation is finalized on the next scan.

## Device/time shared-PCAP impact preview

`POST /api/v1/devices/{deviceID}/traffic-deletion-preview` is a read-only,
no-store dry run over a historical half-open interval of at most 30 days. It
builds canonical per-identity windows from the inventory's MAC and DHCP address
evidence; an IP address is never treated as permanent ownership. Any overlapping
claim by another device fails closed. The normalized-event side freezes an exact
query snapshot and ingestion watermark, then asks the private ingest coordinator
to bind exact event/identity rows, logical bytes, matching pending spool records,
and replay-barrier state while the host scans candidate finalized PCAPNG files
packet by packet. The public preview SHA-256 binds that complete private deletion
bundle alongside packet impact and the Zeek/Suricata checkpoint-deletion preview
for every affected capture session. It expires at the earliest database, spool,
query-snapshot, or analyzer evidence expiry.

The host evaluates at most 1,024 sessions and returns at most 512 impacted files
or blockers. Active captures, missing or changed manifests, legacy/inexact
membership, unsupported packet headers, and scan failures remain explicit
blockers. Each impacted file reports exact matched packet count, unrelated
whole-file collateral packets, original and predicted sanitized bytes, bounded
retained-identity samples and digest, retention lock, and required/available
temporary capacity. A candidate file whose exact membership cannot contain a
selected identity is not needlessly rescanned.

The response always presents the four required choices:

- `DELETE_METADATA_ONLY` retains raw packet bytes and says so; it is executable
  only against the exact database/spool bundle.
- `DELETE_DERIVED_CONTENT_ONLY` retains raw packet bytes and deletes every
  configured derived surface in this build: the exact selected normalized
  events/spool population and both analyzer checkpoint generations for each
  affected session. Body, key-log, Arkime, and OpenSearch stores are not
  configured and contribute zero managed objects rather than fake successes.
- `DELETE_WHOLE_CAPTURE_FILES` reports the exact unrelated packet collateral in
  every shared file plus full-session normalized-event collateral; it is
  executable only after those full-session database/spool previews are bound.
- `SANITIZE_AND_REWRITE_PCAP` reports matched packets, predicted reclaimed
  bytes, temporary capacity, and the re-index requirement; it is executable
  when every packet and analyzer preview is exact, unlocked, and has capacity.

`exact_impact` means that the frozen normalized-event count and packet impact
for the explicit selection rule are exact. It does not broaden incomplete
inventory evidence: `identity_evidence_covers_range` separately reports whether
known identity windows span the requested range. Time-bounded IPv6 device
address evidence is not yet indexed and is listed as a capability limitation.
The UI displays each backend blocker and never persists the sensitive preview in
browser storage. It also shows pending spool records and bytes reclaimable
immediately versus logical PostgreSQL bytes reclaimable only after maintenance;
the snapshot-only count is not treated as executable mutation evidence.

`DELETE_METADATA_ONLY` returns `execution_available: true` when its exact event
and spool evidence is eligible. It requires administrator reauthentication, the
exact device ID, and an idempotency key; its durable job installs permanent
replay barriers, purges matching pending records, deletes verified rows and
exclusive identities, and records the deferred PostgreSQL reclamation boundary.
It reports any error after invoking the private coordinator as `PARTIAL` because
a replay barrier may already exist. Retry reuses the original operation ID and
preview. Cancellation is accepted only for a persisted pending job before the
barrier phase; it fails closed after that point. Startup resumes pending/running
jobs from the mode-0600 ledger.

`DELETE_DERIVED_CONTENT_ONLY` uses the same immutable event selection, then
deletes the reviewed Zeek and Suricata checkpoints and leaves their replay
barriers in place without authorizing a re-index. The preview reports the exact
number of present checkpoints and the number of session/engine replay barriers.
Raw PCAP remains byte-for-byte unchanged, normalized events outside the frozen
selection remain, and existing exports/backups remain independent. Because the
analyzer barrier is session-wide, it also prevents a later full re-analysis of
unrelated retained packets in each affected session until an explicit future
supersession workflow exists. Each event and checkpoint acknowledgement is
persisted before the next call; retry never repeats a completed backend.

`SANITIZE_AND_REWRITE_PCAP` uses the same reauthentication, confirmation, and
immutable ledger. It installs the event replay barrier first, deletes both
reviewed analyzer checkpoints for each affected session, invokes the audited
host rewrite once per exact file, and authorizes Zeek and Suricata only for the
last committed manifest digest in that session. Each acknowledgement is
persisted before the next mutation. The job remains `RUNNING` in
`ANALYZER_REINDEXING` while either engine is rebuilding, and a 15-second
recovery loop replays only the authorization/status operation until both report
`COMPLETED`. Backend ambiguity is `PARTIAL`; retry retains every completed
acknowledgement and operation ID. Existing exports and backups remain explicit,
and SSD/COW secure erasure is not claimed.

`DELETE_WHOLE_CAPTURE_FILES` installs a permanent full-capture replay tombstone
for every affected session and deletes all normalized rows, exclusive identities,
and pending spool records in those sessions before deleting both analyzer
checkpoints and the reviewed PCAP files. This conservative boundary is explicit:
normalized events do not yet retain source-file provenance, so unrelated session
metadata is counted as collateral and removed even when its packets are in an
unselected file. Remaining unselected PCAP files are retained without searchable
metadata and are not re-indexed across the permanent tombstone. Each full-session
event outcome, analyzer barrier, and host artifact record is persisted before the
next mutation; retries reuse stable operation IDs and never repeat completed
backends.

No secure-erasure guarantee is made. Metadata-only completion explicitly retains
raw PCAP, analyzer raw logs/checkpoints, body and key-log artifacts, exports,
backups, and search indexes that are not configured in this build.

The ingest spool now provides the first execution safety primitive without
exposing a premature public mutation. A durable device/time tombstone binds the
target device, half-open interval, canonical time-bounded address evidence, and
the exact query-snapshot ID/hash to one operation and actor. Installation first
compares the reviewed matching pending-record count and bytes under the spool
lock, atomically persists mode-0600 evidence, then purges only those records.
Future intake and already-in-flight records discovered after restart are rejected
with HTTP 410 when they match. Explicit event device identity takes precedence;
only unattributed analyzer events use source/destination address evidence, which
prevents an address from overriding a different explicit device.

The hot path loads at most 1,024 strictly validated tombstones once per process,
keeps a canonical order, and projects analyzer network fields once per event.
Corrupt, unsafe, oversized, or unexpectedly named durable entries stop ingestion
rather than silently disabling replay prevention. These spool guarantees alone
are insufficient: they must be coordinated with the database deletion boundary
below before `DELETE_METADATA_ONLY` can execute.

PostgreSQL schema version 7 now supplies the equivalent durable ingestion
barrier. `normalized_event_selection_tombstones` stores the operation/actor,
device and interval, complete canonical selection JSON and digest, and frozen
query-snapshot ID/hash without a foreign key that would disappear when the
short-lived snapshot expires. The population is capped at 1,024 and exact replay
returns the first evidence; attempting to bind an operation ID to different
evidence conflicts.

Each database ingestion transaction takes a SHARE lock on that tombstone table,
loads only selections whose intervals overlap the batch, attributes every event
once, and evaluates explicit identity before projected address fallback. A
concurrent insertion is therefore linearized either before the batch (which is
rejected before both `normalized_events` and `normalized_event_identities`) or
after its commit (so a later snapshot-bound deletion must observe that row).
Schema version 8 adds that next database layer without exposing a public route.
An exact-count query snapshot is required, and its canonical query must equal
the selected device and half-open time range. The preview materializes only rows
at or below the frozen ingest watermark, rejects any matching later rows, and
binds event count/logical bytes, exclusively removable identity count/logical
bytes, maximum sequence, selection, actor, and snapshot to one SHA-256 digest.

Preparation uses a serializable transaction and the same table-lock boundary as
ingestion. It rechecks the exact footprint, installs or verifies the durable
selection tombstone, and persists the reviewed preview digest as immutable
preparation evidence. Deletion requires that preparation, repeats the drift and
footprint checks, atomically removes the selected events and only identities
left orphaned by that removal, verifies absence, and writes a durable receipt.
Exact retries return the original receipt even after the short-lived query
snapshot is gone; reuse with different preview evidence conflicts. PostgreSQL
space reclamation remains deferred to normal maintenance. The public metadata-
only and derived-content workflows coordinate this primitive with the spool.
Packet sanitization additionally requires PCAP rewrite and analyzer re-indexing.

Schema version 9 binds the database primitive to the spool as one private
operation. The combined preview contains the complete database preview plus the
exact matching pending-record count and file bytes. Its digest is carried in the
durable database tombstone and the identical mode-0600 spool tombstone, so an
operation ID cannot be replayed with a substituted pending footprint. Execution
prepares the database barrier first, installs and purges the spool barrier
second, and deletes database rows last. A retry after any boundary reuses the
same evidence, removes any delayed matching spool records behind the existing
barrier, and returns the original database receipt after completion.

The private `/v1/event-selection-deletions/preview` and `/execute` endpoints use
the deletion-only credential, strict bounded JSON, no-store responses, and typed
expired/stale/conflict/barrier errors. The validating client refuses credential-
bearing redirects and rejects inconsistent response scope or digests. These
internal endpoints do not themselves authorize a public administrator action;
the control plane must persist a reviewed job and coordinate any packet or
derived-index work before advertising an executable choice.

## Coordinated finalized capture deletion

`POST /api/v1/captures/{id}/deletion-preview` joins four authoritative backend
previews. The host preview validates the final manifest against every
current PCAP name, size, and modification time, rejects unexpected directory
entries, and counts the three bounded session metadata files. The normalized-
event half reports exact pending spool files, PostgreSQL event rows, exclusively
removable identity rows, logical row bytes, ingest watermark, and barrier state.
The Zeek and Suricata previews independently bind checkpoint presence, exact
bytes and SHA-256, analyzed manifest, input count, delivered-event count, and
output bytes. The public digest binds all four complete previews, their
overlapping validity window, the retained-data boundary, and the number of
durable capture export records. Newly generated capture and device/time
previews also bind a structured copy-boundary inventory. It reports the exact
capture-export audit count, zero managed objects for the unconfigured local
export, backup, Arkime, and OpenSearch stores, and an intentionally unknown
count for copies already delivered outside the appliance. Audit records are not
misrepresented as retained packet copies, and an unconfigured store is not
reported as a successful deletion. Older persisted schema-2 previews omit this
additive inventory but retain their original digest and execution semantics.
Active, unfinalized, or retention-locked
captures cannot produce an executable combined preview; legal-hold override is
not implemented.

Execution re-authenticates the administrator, requires the exact capture ID and
an idempotency key, and stores the full reviewed preview before mutation. The
control-plane operation is bounded to 1,024 records and reports independent
`normalized_events`, `zeek_checkpoint`, `suricata_checkpoint`, and
`host_capture_artifacts` results. It executes the normalized-event backend first
so permanent PostgreSQL and spool replay barriers exist before source PCAP
deletion. It then establishes and verifies both analyzer replay barriers. Only
after those exact acknowledgements does it ask the host to quarantine, remove,
and verify the manifest-bound capture directory. The operation can be
`COMPLETED` only when all four acknowledgements are present. An event-backend
failure before another backend completes is `FAILED`; an analyzer or host
failure after earlier completion is durably `PARTIAL`. Completed backend
evidence is immutable, and replay of a completed public idempotency key invokes
no backend again.

`POST /api/v1/capture-deletion-jobs/{jobID}/retry` reauthenticates the original
administrator and persists a bounded retry intent with its own globally unique
idempotency key before backend work resumes. A completed backend acknowledgement
is never mutated or invoked again. Replaying a completed
retry key performs no backend work, while replaying an interrupted retry key
continues the same durable intent. Only one retry may be unfinished for an
operation, and each operation is bounded to 32 retry records. On control API
startup, already-authorized `PENDING`/`RUNNING` operations and terminal jobs
whose retry receipt was interrupted are resumed automatically. Shutdown
cancellation leaves the current backend `RUNNING` for the next startup rather
than inventing a durable backend failure.

`POST /api/v1/capture-deletion-jobs/{jobID}/cancel` reauthenticates the original
administrator and records its own globally unique idempotency key. It succeeds
only while the durable job is `PENDING` and every backend remains `NOT_STARTED`;
the result is `CANCELLED` / `CANCELLED_BEFORE_BARRIER`. Once the normalized-event
backend is marked `RUNNING`, cancellation fails closed because a replay barrier
may already exist. Cancelled jobs are never recovered or retryable, and replay
of the same cancellation key performs no mutation.

Retry deliberately reuses the original immutable preview. It can recover a
transient backend outage or a response lost after an idempotent backend commit,
but it does not refresh expired or stale evidence. For a terminal
`FAILED`/`PARTIAL` job, `POST /api/v1/capture-deletion-jobs/{jobID}/supersede`
reauthenticates the original administrator and accepts only a newer, unexpired
combined preview for the same capture. The bounded durable chain preserves each
previous preview and its idempotency key. Completed irreversible backend
acknowledgements remain byte-for-byte immutable and validate against the exact
older preview that authorized them; only failed or unfinished backends return to
`NOT_STARTED` and consume the replacement evidence. A supersession cannot run
while a retry intent is unfinished and cannot revive completed or cancelled
jobs.

This remains a four-backend capture-session deletion slice, not whole-system
secure erasure. Optional external search indexes and managed backup/export
artifact stores are explicitly reported as unconfigured; capture-export audit
and external copies remain independently managed.
PCAP can contain traffic from multiple devices. Device/time preview can now
compute exact whole-file packet collateral where final membership and packet
headers are exact, but the existing capture-session deletion job still removes
the complete selected session rather than consuming those choices.
Configured optional-index deletion, legal-hold override, and managed local
backup/export deletion remain release work. Physical PostgreSQL file shrinkage
is deferred to database maintenance, and no secure-erasure claim is made for
SSDs, snapshots, or copy-on-write stores.

The normalized-event path provides the replay-prevention primitive consumed by
the public coordinator. A capture tombstone is stored durably under the spool
root before matching pending files are unlinked and separately in PostgreSQL.
New intake for the capture returns HTTP 410. Pending-batch reads remove any
record that arrives after the initial purge, so the boundary survives restart.
PostgreSQL batch writes and tombstone creation take the same per-capture
transaction lock; a batch cannot commit after a tombstone is visible. Repeated
requests preserve the first operation, actor, and timestamp. Tombstones alone
do not claim backend completion; the normalized-event receipt and control-plane
backend result provide that acknowledgement.

The read-only normalized-event deletion planner observes both replay surfaces.
Its ten-minute immutable preview lists matching pending spool records and exact
file lengths, PostgreSQL event rows, identity-ledger rows that have no reference
outside the capture, logical row bytes, the maximum ingest sequence, and each
backend's current tombstone state. The SHA-256 evidence binds every one of those
fields plus expiration. Pending-file bytes are only an estimate of immediately
reclaimable space. PostgreSQL values use `pg_column_size` and are explicitly
reported as logical bytes whose physical reclamation is deferred to database
maintenance; the preview does not promise filesystem shrinkage.

PostgreSQL can now consume that preview through an internal deletion primitive.
The operation first takes the capture ingestion lock, rejects expired evidence,
requires the permanent database tombstone, and compares every live row/byte/
watermark field with the preview. It freezes target record IDs in a transaction-
local table, deletes all matching event rows, deletes global identity rows only
when no event still references them, and verifies both event absence and the
absence of newly orphaned identities. A minimal receipt containing operation,
preview digest, counts, logical bytes, and completion time commits with the
deletion. Exact replay returns that receipt; different evidence conflicts.
Any stale count or footprint rolls the entire serializable transaction back.
This backend operation neither reclaims physical PostgreSQL files immediately
nor proves that the spool or any other backend completed deletion.

The normalized-event coordinator applies compare-and-set semantics at both
local boundaries. PostgreSQL preparation takes the ingestion lock, compares the
reviewed database footprint, and only then commits its tombstone. Spool
preparation holds the spool mutex, compares exact pending count/file bytes and
tombstone state, then atomically writes its marker before unlinking reviewed
records. Database preparation runs first so a concurrent database change cannot
cause spool deletion. If the spool changes in the narrow interval afterward,
the operation leaves the new files intact and retains the database barrier;
that partial state is safe and visible in the next preview. Replaying a completed
request bypasses mutable-footprint comparison only after its receipt and both
permanent barriers can be validated.

The local coordinator is available through two private ingestd routes: a bodyless
preview POST and a strict JSON execute POST scoped by capture ID. They exist only
when PostgreSQL lifecycle support is configured and require a deletion-only
bearer token that cannot authenticate ingest, query, or saved-view endpoints.
Responses are `no-store`; preview, request, and outcome structures are
revalidated on both sides and bounded to 32 KiB requests/64 KiB responses. The
client refuses redirects so the bearer token cannot follow a service-origin
change. Expired evidence maps to `410`, while stale evidence and completed-
different-preview conflicts map to distinct `409` codes.

The control API loads only that deletion-scoped token, never database or ingest
credentials. Its public preview and job routes combine the internal outcome with
the Unix-socket host result, persist the combined operation under control-plane
storage with mode `0600`, reject symlink/corrupt/oversized ledgers, and expose
bounded list/detail reads. The UI round-trips the immutable preview, requires
typed capture-ID confirmation plus password reauthentication, shows immediate
and maintenance-dependent space separately, warns about exports/backups, and
keeps the capture visible unless the host backend actually acknowledged removal.

The retention dry run is the safety boundary for policy and manual execution.
`POST /api/v1/capture-retention/preview` accepts bounded age and finalized-PCAP
byte limits, evaluates no more than 1,024 named sessions, and returns a
ten-minute digest over the exact ordered population and every configured
deletion backend. For each selected capture it freezes the host deletion
preview, normalized-event and exclusive-identity rows, pending ingest spool,
deferred database reclamation, and known export records. The control plane
persists that combined evidence in a bounded mode-`0600` ledger before it can
be confirmed. Age-expired unlocked
captures are selected first; the oldest remaining unlocked captures are then
selected only until the byte target is met. Active or unfinalized sessions are
reported separately, retention-locked captures are never selected, and an
unreachable byte target is explicit.

After reviewing that result, an administrator can save the rules and intended
run cadence through `PUT /api/v1/capture-retention/policy`. Apply requires fresh
password verification, an idempotency key, the expected current revision, and
the unexpired preview digest. Policy plus its bounded operation history publish
in one atomic host file, so a revision and its replay evidence cannot diverge.
Enabling waits one complete configured cadence before the first automatic run;
disabling publishes a new revision that stops future slots.

Manual cleanup now uses `POST /api/v1/capture-retention/runs`. Its strict JSON
request is bounded to 8 MiB so the full reviewed evidence can cover the declared
1,024-capture population without creating an unbounded body. It reauthenticates
the administrator, checks the current policy revision and full previously
persisted combined preview, and durably records every selected capture plus a
stable per-capture deletion request before removing anything. Normalized-event
tombstones, rows, exclusive identities, and matching spool records are handled
before host PCAP/session files. Outcomes persist after each capture as
`DELETED` or `FAILED`; the run reports `COMPLETED`, `PARTIAL`, or `FAILED` with
exact remaining host files and bytes. On restart, the control plane finds the
reviewed combined preview through the host digest already stored in the run;
it does not silently refresh event evidence after confirmation.

The control API checks enabled policies every 30 seconds while the host maps
wall time to a deterministic `(policy revision, scheduled time)` slot and
durably plans the exact selected host population. It executes only the latest
due slot, and an existing durable automatic run suppresses duplicates after
restart. For automatic runs, the control plane freezes and persists each
combined per-capture preview before its first mutation. The scheduler endpoint
reports next/last run evidence. Failures before a run can be created persist as
a generic timestamped status while the detailed cause remains only in
privileged logs; later successful checks clear that status.

Run `make analyzer-smoke` to build the pinned images and prove a deterministic
seven-packet HTTP PCAPNG produces normalized Zeek and Suricata events, a
Suricata starter-policy alert, no quarantine, durable checkpoints, and no
second-pass replay.
