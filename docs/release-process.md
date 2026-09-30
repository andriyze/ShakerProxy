# Signed release process

ShakerProxy releases bind host code, Compose configuration, and all runtime images
to one signed manifest. The implementation is experimental until published
artifacts pass the declared clean-VM matrix.

## Trust and key custody

`packaging/release-public.pem` is the sole release trust root. Its PKIX DER
SHA-256 fingerprint is:

```text
e8c3c965ed4859f55e69af55ccb03d20d297843104b611f0a754072694dafdcb
```

The matching private RSA-3072 key must be held outside the repository. GitHub
Actions expects its base64 encoding only in the protected `release`
environment secret `SHAKERPROXY_RELEASE_SIGNING_KEY_B64`. Require reviewer approval
for that environment, restrict tag creation, and keep the secret unavailable to
pull-request workflows. Never print, upload, cache, or package the private key.

The earlier development key (fingerprint `3ff54cdd…434a`) was retired on
2026-09-30, before any release was published; nothing signed with it is
trusted.

Key rotation is a source release: commit a new public key and fingerprint,
review every pinned-fingerprint location, ship the new installer through an
already trusted channel, and document the old key's retirement. Replacing a
GitHub secret alone cannot rotate trust.

## Automated publication

`.github/workflows/release.yml` pins every third-party action to an exact commit.
It runs the complete repository verification, builds the Debian host package,
publishes six first-party linux/amd64 images to GHCR with provenance and SBOM
attestations, records registry digests, creates the signed bundle, runs its
tamper and clean-Ubuntu verification smokes, and uploads release assets. The
pinned upstream PostgreSQL digest is the seventh image.

A stable tag is `v<semver>`. A tag containing a prerelease suffix becomes a
beta release. Manual runs require an explicit version and channel. Stable
publication is not complete until an independent operator downloads every
asset from GitHub, verifies the signature and checksums, and records the
clean-VM acceptance evidence.

Required release assets are:

- `install.sh`
- `manifest.json` and `manifest.json.sig`
- `release-public.pem`
- `shakerproxy-host.deb`
- `compose-bundle.tar.zst`
- `images.json` for operator inspection

The bundle contains `bundle-files.sha256`; runtime startup rechecks every listed
file. The signed manifest declares supported Ubuntu versions, architecture,
profiles, config and database schemas, minimum resources, artifact hashes, and
the exact seven image digests.

## Local candidate build

The local signing key path below is an example and must remain ignored:

```bash
make package-smoke PACKAGE_VERSION=1.2.3-beta.1
make release-bundle-smoke \
  PACKAGE_VERSION=1.2.3-beta.1 \
  SIGNING_KEY=/secure/path/release-signing-key.pem \
  IMAGES_JSON=/secure/path/published-images.json
```

`packaging/build-push-images.sh` is intentionally push-only. It refuses a
non-GHCR repository and emits image references only after Buildx reports a
digest and registry inspection succeeds. Do not substitute mutable tags in a
manifest.

## Release acceptance and failure rules

A candidate is not stable merely because the workflow is green. Record at
least clean installs on Ubuntu 24.04 and 26.04, same-version idempotency,
repair of a deliberately corrupted bundle file, update from the prior stable
version, schema-compatible rollback, service and host reboot, uninstall with
preserved data, purge behavior, Docker restart, low-disk failure, interrupted
download, bad signature, bad artifact hash, and unavailable registry behavior.

No release may claim air-gapped support until the bundle includes verified OCI
archives. No release may claim rollback across a schema change until an
explicit backward-compatibility contract and migration evidence exist.
