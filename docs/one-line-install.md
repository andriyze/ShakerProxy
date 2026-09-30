# One-line installation trust chain

ShakerProxy's convenience installation path is designed to reduce the amount of
code executed directly from the bootstrap URL. A stable GitHub release contains
`bootstrap.sh`, the release manifest and signature, the pinned public key, the
full installer, the host Debian package, and the Compose bundle.

After a **stable release is actually published**, the convenience form is:

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://github.com/andriyze/ShakerProxy/releases/latest/download/bootstrap.sh \
  | sudo bash
```

To check the host first without changing anything, pass installer options
after `-s --`; the bootstrap forwards them to the verified installer:

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://github.com/andriyze/ShakerProxy/releases/latest/download/bootstrap.sh \
  | sudo bash -s -- --dry-run
```

The friendlier front door, [`install/index.sh`](../install/index.sh), runs
as a regular user, checks the machine, downloads the same `bootstrap.sh` to a
temporary file and runs it with sudo:

```bash
curl -fsSL https://raw.githubusercontent.com/andriyze/ShakerProxy/main/install/index.sh | sh
```

It makes no trust decisions of its own; everything below still applies. A
branded short URL may serve it through
[`install/cloudflare-worker.js`](../install/cloudflare-worker.js), which reads
`index.sh` from the latest release's tag rather than `main` and never generates
installation commands or release metadata dynamically.

## Trust sequence

`bootstrap.sh` performs this sequence before executing the larger installer:

1. Require root and a supported HTTPS GitHub release location.
2. Fetch `manifest.json`, `manifest.json.sig`, and `release-public.pem`.
3. Calculate the public key fingerprint and compare it with the fingerprint
   compiled into the bootstrap.
4. Verify the release-manifest signature.
5. Read the full installer URL and SHA-256 only from the signed manifest.
6. Require the installer URL to remain under this repository's immutable
   versioned GitHub release path.
7. Download `install.sh`.
8. Verify its SHA-256 against the signed manifest.
9. Execute the verified installer.
10. The installer independently re-verifies release identity, signed manifest,
    host package, Compose bundle, and immutable image digests before mutation.

The signed release builder and schema require installer metadata:

```json
{
  "installer": {
    "url": "https://github.com/andriyze/ShakerProxy/releases/download/v1.0.0/install.sh",
    "sha256": "..."
  }
}
```

The release workflow publishes `bootstrap.sh` together with the other release
assets. `tests/packaging/release-bundle-smoke.sh` verifies that the installer
checksum is bound into the signed manifest.

## Limitation of every curl-to-shell bootstrap

The first bootstrap bytes are trusted through the URL/TLS distribution path.
No shell script can cryptographically authenticate itself using a key contained
only inside that same potentially replaced script. Administrators requiring a
stronger first-hop trust model should download `bootstrap.sh` and the committed
release public key through separate trusted paths, review the script, verify
the expected key fingerprint, and then execute it locally.

Do not describe `curl | sudo bash` as eliminating first-hop transport trust.
The signed chain starts by pinning the release key inside the bootstrap and then
protects every larger artifact that follows.

## Safe installation state

Successful package installation does **not** make the machine a gateway. The
installer starts ShakerProxy in `SETUP_SAFE`; network forwarding, DHCP, DNS
enforcement, packet capture, and TLS interception require explicit onboarding,
preview, staged application, watchdog health checks, and confirmation.

For now, the supported routed profile is IPv4-only.
Before attaching client devices, run:

```bash
sudo /usr/libexec/shakerproxy/shakerproxy-mvp-preflight \
  --test-interface <lab-interface>
```

Do not proceed if it reports `"supported": false`. Full routed IPv6 remains a
separate release gate.
