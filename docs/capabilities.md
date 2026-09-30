# Capability claims and platform certification

ShakerProxy has one machine-readable source for product capability language:

- `schemas/feature-flags.yaml` owns feature status, badge text, evidence paths,
  default activation, and the gate for promotion.
- `schemas/glossary.yaml` owns shared state vocabulary and definitions.
- `schemas/support-matrix.yaml` records evidence separately for each operating
  system, architecture, Docker firewall backend, topology, and feature.

The files contain strict JSON, which is also valid YAML 1.2. This deliberately
keeps the release metadata readable without adding a YAML parser to the trusted
control-plane dependency set.

`make registry-check` rejects unknown fields, duplicate identifiers, revision
drift, unknown statuses or certification levels, hand-written badge text,
missing glossary terms, missing evidence paths, symlink evidence, and paths
that escape the repository. The same validator runs during `make verify` and
the control API refuses to start when its packaged registry is invalid.

The authenticated `GET /api/v1/capabilities` response uses `Cache-Control:
no-store`. The dashboard renders capability badges and the environment matrix
from this response; UI components do not maintain an independent list of
claims.

Recovery claims use a separate machine-readable registry because a feature can
exist without a verified recovery contract. See `schemas/recovery-objectives.yaml`
and [recovery objectives](recovery-objectives.md). `make registry-check`
validates both registries and their repository evidence paths.

## Feature status

- `supported`: the feature passed every declared release gate for its claimed
  environment.
- `experimental`: a usable gated implementation exists, but release evidence
  is incomplete or the contract may still change.
- `capture-only`: packet or bounded metadata visibility exists, without a
  stronger plaintext or decryption claim.
- `unavailable`: the current product does not expose the capability.

Feature status is product-wide and conservative. Platform certification is a
separate dimension: a feature can remain experimental while a particular
packet-path proof is `gateway-certified` in one disposable VM environment.

## Certification levels

- `not-certified`: evidence is absent or intentionally insufficient for this
  environment and feature.
- `installable`: artifact validation and installation passed, without a runtime
  or packet-path claim.
- `safe-runtime`: setup-safe services ran and retained their declared security
  boundary.
- `gateway-certified`: transactional packet-path apply, traffic, rollback, and
  recovery passed for the exact environment.
- `interception-certified`: enrolled-client interception and its trust, policy,
  bypass, and failure boundaries passed for the exact environment.

Certification is not inherited between Ubuntu releases, firewall backends,
topologies, architectures, or feature versions. Container startup alone cannot
promote an environment.

## Updating a claim

1. Add or update the automated or recorded evidence first.
2. Update all three registry revisions together.
3. Change the feature status or environment certification only to the level
   proven by that evidence.
4. Run `make registry-check` and the relevant acceptance tests.
5. Update the protocol matrix where applicable.

Evidence paths are intentionally public repository paths. They must not contain
real captures, credentials, private hostnames, public IP ownership details, or
other operator data.
