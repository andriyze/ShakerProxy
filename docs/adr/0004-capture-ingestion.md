# ADR 0004: dumpcap acquisition and one normalized ingestion path

Status: acquisition, closed-rotation/finalized-capture analyzers, bounded ingestion, PostgreSQL sink, and bounded recent-event reads implemented; performance acceptance pending

Use an allowlisted `dumpcap` process for raw PCAPNG ring acquisition on lab
ingress. Zeek, Suricata, and the mitmproxy addon produce versioned events for a
single bounded `ingestd` path with disk spool, deduplication, size limits, and
quarantine. The privileged daemon never parses untrusted packet content.

The acquisition slice uses one active, typed session at a time; size/count/time
ring limits; a 1 GiB emergency reserve; root-owned immutable provenance; and a
dedicated capability-bounded worker. Completion produces SHA-256 digests for
every PCAPNG artifact and the session record. Finalized manifest members can be
exported through bounded privileged reads only: no caller path enters the host
daemon. The authenticated API adds reauthentication, resumable ranges, digest
headers, and durable interrupted/completed history; the local CLI streams to a
new mode-0600 destination and verifies SHA-256 before publishing it. It does not
claim complete inventory, direct-interface live-sensor analysis, or throughput
acceptance.

The first `ingestd` slice accepts a strict versioned envelope plus native Zeek
JSON and Suricata EVE JSON through authenticated internal-only endpoints. It
normalizes source/parser versions, derives deterministic analyzer event IDs,
deduplicates source identities, rejects conflicting reuse, and durably spools
under count/byte/free-space limits. Malformed input is represented only by a
digest and bounded prefix in quarantine.

The spool exposes deterministic, identity-bound batches and acknowledges files
only after a sink transaction succeeds. The PostgreSQL sink uses a global event
identity ledger for replay/conflict handling and monthly range partitions for
normalized event summaries. `ingestd` activates it only when a protected database
URL file is configured and retries failures with bounded exponential backoff.
Production and development Compose now isolate PostgreSQL on the internal
control network, mount generated credentials read-only, persist database and
spool data separately, and health-gate ingest startup. A repeatable failure test
proves database-down acceptance plus recovery drain.

Pinned Zeek 8.2.1 and Suricata 8.0.6 brokers consume a bounded feed of only
closed dumpcap rotations and later reconcile it with the completed manifest.
The broker validates and hashes a no-follow file descriptor before and after a
fixed offline engine command. Durable per-engine progress records monotonic
sequence gaps and recent content identities, suppresses restart replay, and
folds cumulative active counts into the manifest checkpoint. The parser child
is UID/GID 65533 with all groups
cleared; it receives that descriptor and a bounded temporary directory, but no
capture-tree, checkpoint, or root-only token access. Native JSON is delivered
only after the second hash succeeds. A durable checkpoint binds engine,
manifest digest, counts, and completion time; interruption before that point
causes safe replay through deterministic ingest deduplication. The included
Suricata rules are a narrow first-party cleartext policy, not a comprehensive
IDS feed. They are image-bound to a strict provenance manifest, validated by
both repository inventory tests and Suricata itself during image construction,
and rechecked for drift before every parser invocation. Ruleset changes ship
only in a new immutable analyzer image, so normal release rollback restores the
previous image and rules together; there is no unattended hot-update path.
Analyzer deletion previews bind both the final checkpoint and any active
progress file; the durable deletion barrier prevents either from being
republished during the finalization/deletion race.

The query surface is intentionally not a raw-log or deep-search API. A distinct
read credential exposes fixed-filter, cursor-paginated pages capped at 100
normalized event summaries, with raw payloads omitted. At database ingestion,
an allowlisted typed projection extracts only canonical source/destination IPs,
ports, protocol/service tokens, and bounded byte totals from supported Zeek and
Suricata fields. Invalid, oversized, or ambiguous values remain absent. The
control API holds only the read credential, revalidates the projection, and
serves it to an authenticated polling UI. This is a bounded precursor to the
shared typed filter AST and live stream; it is not packet streaming or a claim
of complete flow reconstruction.

Deep search, per-engine syscall profiles, and throughput acceptance remain
pending, so direct-interface live-sensor and
searchable-session claims are not made. The package now provisions fixed-ID
runtime directories, independent broker credentials, matched PostgreSQL
credentials, and the analyzer-only root-readable ingest-token copy.
