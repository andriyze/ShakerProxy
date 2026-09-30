# Device traffic deletion preview verification

This slice verifies exact shared-PCAP impact planning, bounded metadata-only and
derived-content deletion, coordinated whole-file deletion, and sanitize/rewrite
jobs.

## Automated coverage

- `go test ./internal/pcapng ./internal/capture` proves canonical per-identity
  time windows, exact packet matching, shared-file collateral, bounded identity
  samples, capacity evidence, non-overlap skipping, and explicit inexact
  membership blockers.
- `go test ./internal/gatewayprotocol ./internal/gatewayclient
  ./host/gatewayd/internal/daemon` proves the bounded Unix-socket RPC surface and
  validating client transport.
- `go test ./apps/control-api/internal/server` proves authenticated no-store
  preview, frozen normalized-event query, embedding of the validated private
  database/spool deletion bundle, exact four-choice arithmetic, scoped execution
  availability, and refusal of overlapping device ownership. It also proves
  reauthenticated exact-confirmation jobs, durable mode-0600 intent,
  initial/retry idempotency, conservative partial state, pre-barrier-only cancel,
  restart recovery, and fail-closed ledger tamper checks. Sanitize coverage binds
  and persists event barriers, two analyzer barriers, exact host rewrites, and
  both replacement-manifest re-index results without repeating completed work.
  Whole-file coverage binds full-session event/spool collateral, permanently
  blocks session replay, deletes both analyzer checkpoints and each reviewed
  artifact, and proves partial retry does not repeat completed barriers.
  Derived-content coverage proves the exact selected event/spool population and
  both analyzer checkpoint generations are deleted without a host mutation,
  while replay and retry reuse completed acknowledgements. A legacy schema-1
  preview remains valid but cannot acquire the newer execution capability.
  Fresh capture and device/time previews bind six structured copy boundaries:
  exact retained export-audit records; exact zero objects for the unconfigured
  local export, backup, Arkime, and OpenSearch stores; and an unknown external-
  copy count outside appliance control. Stored schema-2 previews without this
  additive field keep their original digest and validation behavior.
- `npm test --workspace @shakerproxy/web-ui` proves the four stable UI meanings,
  exact-versus-blocked presentation, and that eligibility alone never exposes
  execution.
- `npm run build --workspace @shakerproxy/web-ui` type-checks and bundles the
  responsive device control.

## Manual evidence review

1. Finalize a capture containing packets for the target device and at least one
   unrelated device in the same PCAPNG file.
2. Open **Devices → Preview traffic deletion impact**, choose an interval covered
   by the target's time-bounded identity evidence, and request the preview.
3. Confirm `DELETE_WHOLE_CAPTURE_FILES` reports both matched and non-zero
   collateral packets, while `SANITIZE_AND_REWRITE_PCAP` reports zero collateral
   and a smaller predicted output.
4. Confirm metadata-only and derived-content-only both state that raw packet
   bytes remain.
5. Confirm the summary shows exact pending spool records and separates bytes
   reclaimable immediately from logical database bytes reclaimable after
   maintenance.
6. Confirm all four choices say **AVAILABLE** when eligible. Confirm derived-only
   lists its analyzer barriers and checkpoint count while reporting zero PCAP
   reclaim. Confirm whole-file lists the full-session metadata rows and the
   additional collateral rows. Reauthenticate, type the exact device ID, and
   execute the intended choice.
7. For sanitize/rewrite, confirm the job remains `ANALYZER_REINDEXING` until both
   engines persist replacement checkpoints, then becomes `COMPLETED` without
   repeating the event barrier or host rewrite. For whole-file deletion, confirm
   all affected-session metadata and checkpoints are absent, the reviewed files
   are absent, and retained unselected files are labeled as having no searchable
   metadata. For derived-only, confirm selected events and both checkpoints are
   absent while the original PCAP hashes remain unchanged.
8. Repeat with a legacy manifest or active capture and confirm the named blocker
   appears instead of an exact claim.
9. Request a range outside all known identity windows and confirm the server
   refuses it; request a partially covered range and confirm the coverage warning
   remains visible.

The preview must never be interpreted as secure erasure. SSD wear leveling,
copy-on-write storage, snapshots, backups, and prior exports can retain bytes.
