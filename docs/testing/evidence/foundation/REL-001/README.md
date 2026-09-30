# REL-001: signed application lifecycle implementation evidence

Recorded: 2026-09-02 UTC

Scope: implementation-level evidence only. This does **not** claim a published
or supported release.

The evidence run covered:

- strict signed-manifest, pinned-key, immutable-image, and extracted-file
  integrity validation in the fixed-command application controller;
- rejection of an escaping current-release symlink, mutable image reference,
  unknown release metadata, and modified Compose file;
- reproducible Debian package structure and hardened systemd policy;
- signed bundle self-verification, artifact hashes, signature-tamper rejection,
  extracted-file tamper rejection, and shell syntax validation;
- installer release verification after bootstrapping its required tools in a
  clean pinned Ubuntu 24.04 container; and
- a mock-registry proof that the image publisher pushes six linux/amd64 images
  with provenance and SBOM output, inspects the published digest, and emits
  exactly seven immutable image references including PostgreSQL.

Not exercised here: a real systemd installation, GHCR publication, a GitHub
release, first application startup, same-version reinstall, corrupt-release
repair, version-to-version update, rollback, host reboot, or uninstall. Those
remain explicit release gates in `docs/release-process.md`.

Commands:

```text
go test ./internal/applifecycle ./host/app/cmd/shakerproxy-app ./host/cli/cmd/shakerproxy
make package-smoke PACKAGE_VERSION=0.1.0-dev.3
make release-bundle-smoke PACKAGE_VERSION=0.1.0-dev.3 \
  SIGNING_KEY=<ignored local key> \
  IMAGES_JSON=tests/packaging/fixtures/images.json
```

The private signing-key path and contents are deliberately excluded.

An additional Ubuntu 26.04 shared-VPS run installed and upgraded real Debian
artifacts through `0.1.0-dev.16`, verified the hardened gateway service in
`SETUP_SAFE`, and retained the absent-signed-release boundary rather than
starting an unverified application. See `../UBU2604-001/README.md`. This does
not satisfy the clean-host or complete lifecycle matrix listed above.
