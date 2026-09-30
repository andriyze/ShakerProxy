# Appliance-wide configuration lock

ShakerProxy serializes privileged appliance configuration with one cross-process
advisory lock at `/run/lock/shakerproxy/config.lock`. The lock is **experimental**:
its implementation and contention tests exist, but the platform matrix has not
yet promoted it to a certified runtime claim.

The lock covers:

- network staging, discard, apply, confirmation, operating-mode changes, and
  independent watchdog rollback;
- application install, update, exact-version repair, application rollback, and
  uninstall;
- host capture-service start and stop; and
- the reserved DNS enforcement, restore, and signed-ruleset mutation categories
  that future implementations must acquire before changing host state.

Read-only inspection, previews, packet/event queries, exports, and data-plane
deletion do not acquire this configuration lock. Their own snapshot,
idempotency, tombstone, and backend-transaction rules remain authoritative.
Long-running PCAP rewriting or retention must never delay the independent
network rollback watchdog merely because both write ShakerProxy-owned data.

## Contract

Every acquisition supplies a bounded operation ID, category, actor, PID, and
UTC start time. While the kernel lock is held, mode-`0600` JSON metadata is
published at `/run/lock/shakerproxy/config.lock.json`. `shakerproxy status`, the
authenticated status API, and the dashboard report the current category and
start time. Operator-facing contention errors name the owning category and
operation ID but contain no arguments, credentials, network plan, or user data.

The implementation uses `flock(2)` through a no-follow regular file in a
root-owned directory. A process crash releases the kernel lock automatically.
Metadata left by a crash is explicitly reported as stale and does not block a
new owner; the next successful acquisition replaces it. Unknown categories,
unsafe paths, symbolic links, malformed metadata, duplicate ownership, and
unbounded waits fail closed.

Installer mutations fail fast when another owner exists. They acquire the lock
only after signed downloads and verification, immediately before the first
state change. Under the lock they inspect the durable gateway state and refuse
to continue through `PREPARING`, watchdog-armed, applying, health,
confirmation, rollback-required, rolling-back, or rollback-failed phases. This
closes the race between a read-only preflight and an asynchronous network apply.

The network apply goroutine holds the same lock across rollback snapshot,
syntax validation, watchdog arm, native apply, health validation, and any
immediate rollback. Confirmation is a separately locked operation. The
independent watchdog acquires the lock before restoring host state; inability
to acquire within its bounded recovery window is persisted as rollback failure,
not hidden as success.

## Boundaries

This is a coordination invariant for first-party ShakerProxy processes, not a
sandbox against root. A malicious or unrelated root process can ignore an
advisory lock. Native mutations must therefore still use typed validation,
fixed commands, rollback evidence, and exact file ownership. The lock does not
make an unsafe operation safe; it prevents otherwise safe operations from
interleaving.

A brand-new host may need to install `flock`, `jq`, or signature-verification
bootstrap packages before ShakerProxy exists and can coordinate them. Installed
ShakerProxy packages depend on `util-linux`, so repair and update paths have the
lock primitive before mutation.
