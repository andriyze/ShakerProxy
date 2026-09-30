# Installation and release lifecycle

The signed release lifecycle is implemented and remains **experimental** until
the repository publishes a release and the complete clean-VM install, repair,
update, rollback, and uninstall matrix is recorded. The capability registry
is authoritative; source code or a passing
container smoke test is not a release claim.

## Before you start

- A dedicated Ubuntu Server 24.04 or 26.04 machine (amd64) with systemd. Other
  hosts are refused unless you pass `--developer-unsupported`.
- One network port for the uplink and one port (or Wi-Fi) for the devices
  under test.
- At least 20 GB free under `/var/lib` and 2 GB under `/opt`.
- Port 8443 free on the appliance (management HTTPS on loopback).

Docker Engine with Compose v2 is reused when present and installed from the
Ubuntu archive when missing. Snap Docker is refused.

## Quick install

After a stable GitHub release is published, run as a regular user with sudo
rights on the appliance:

```bash
curl -fsSL https://raw.githubusercontent.com/andriyze/ShakerProxy/main/install/index.sh | sh
```

[`install/index.sh`](../install/index.sh) checks the machine (Ubuntu version,
amd64, not a container, systemd), downloads the latest stable release's
`bootstrap.sh` and runs it with sudo; the bootstrap and installer verify the
signed release as described below. `SHAKERPROXY_DRY_RUN=1`, `SHAKERPROXY_VERSION` and
`SHAKERPROXY_OFFLINE_BUNDLE` are listed in [install/README.md](../install/README.md).
Run the same command again to upgrade. To review each step yourself instead,
follow the sections below.

## 1. Download and check the host (changes nothing)

After a stable GitHub release is published:

```bash
curl --proto '=https' --tlsv1.2 -fsSLO \
  https://github.com/andriyze/ShakerProxy/releases/latest/download/install.sh
sudo bash install.sh --dry-run
```

The dry run checks host support, Docker and Compose, port 8443, free disk,
missing tools, and downloads and verifies the signed release manifest into a
temporary directory. It installs nothing, changes no service, firewall, route,
DNS, DHCP, or RA setting, and writes no installer log. It exits `1` when it
finds a blocking problem. `--dry-run` cannot be combined with `--repair`,
`--rollback`, or `--uninstall`.

Before a stable release exists, the dry run is the only installer operation
that is safe to run from a source checkout:

```bash
sudo ./packaging/install.sh --dry-run --developer-unsupported
```

## 2. Install

```bash
sudo bash install.sh
```

Download, review, and then run the installer rather than piping it to root;
see [one-line install](one-line-install.md) for the bootstrap trust chain. The
installer does not trust the transport alone: it restricts downloads to this
repository, pins the ShakerProxy RSA-3072 public-key fingerprint, verifies the
release-manifest signature, and checks the Debian package and Compose-bundle
SHA-256 values before any mutation. Every runtime image is an immutable
`repository@sha256:digest` reference. The release public key is committed at
`packaging/release-public.pem`; the private key is not in the repository (see
[release process](release-process.md)).

| Option | Effect |
| --- | --- |
| `--version 1.2.3` | Install an exact signed release |
| `--channel beta --version 1.2.3-beta.1` | Beta and nightly channels need an exact version |
| `--profile core` | Management services only (`standard` adds traffic analysis; the default, `full`, also adds HTTPS decryption) |
| `--offline-bundle /media/shakerproxy-release` | Use signed assets copied to the host |
| `--no-docker-install` | Require the Docker Engine and Compose v2 already installed |
| `--http-proxy URL`, `--https-proxy URL` | Proxy for the installer's curl and apt-get downloads |
| `--developer-unsupported` | Allow an unsupported development host |

Proxies apply to the installer's own downloads. Docker image pulls use the
Docker daemon's proxy settings. `--offline-bundle` makes release verification
independent of GitHub, but the bundle does not contain image archives: the
host still needs registry access for first-time image pulls unless those exact
digests are present, so it is not an air-gapped install.

Installation never enables routing, DHCP, DNS enforcement, packet capture, or
interception. ShakerProxy starts in `SETUP_SAFE` and opens only the loopback
management listener; network changes need an explicit, previewed, watchdog-
protected, confirmed plan (see [networking](networking.md)).

## 3. First login

Management HTTPS listens on the appliance's loopback only; the installer never
opens a firewall port or an external management bind. On the appliance itself,
open `https://127.0.0.1:8443/`. From your workstation, keep an SSH tunnel open:

```bash
ssh -N -L 8443:127.0.0.1:8443 <admin>@<sensor-ip>
```

Open `https://127.0.0.1:8443/`, which matches the locally issued management
certificate ([management TLS](management-tls.md)). Create the admin account
with the one-time setup token, then remove its plaintext receipt:

```bash
sudo cat /etc/shakerproxy/setup-token
sudo rm /etc/shakerproxy/setup-token
```

Only the token's SHA-256 verifier is mounted into the control service.
Removing the receipt does not regenerate it on upgrade.

Keep the recovery codes shown at setup; they reset a forgotten password (see
[recover admin access](#recover-admin-access)).

## 4. Use the CLI

Sign the `shakerproxy` CLI in once. It creates a 90-day API token and stores it
in `~/.config/shakerproxy`, readable only by you (with `sudo`, root's token lives
in `/etc/shakerproxy/secrets` instead):

```bash
shakerproxy login
shakerproxy devices
shakerproxy status
```

`status`, `doctor`, `ports` and `capture` use the gateway daemon's socket,
which the `shakerproxy-host` group may open. The installer adds the user who ran it
through sudo to that group; the change applies at their next login, so use
`sudo` until then. Add another administrator with
`sudo usermod -aG shakerproxy-host <user>`.

Run `shakerproxy` for an overview and `shakerproxy help <command>` for examples. The
CLI exits `0` on success, `1` on failure (including `doctor` finding a failed
check), and `2` on wrong usage; add `--json` for scripts.

Network plans are normally built on the **Network** page of the web UI. To
check a plan file from the shell, use `shakerproxy config validate plan.json`
(validation only) or `shakerproxy plan plan.json` (full preview). The file format
is `schemas/network-plan/network-plan.schema.json`. Neither command changes
the host.

## Update, repair, rollback, and removal

```bash
sudo shakerproxy update
sudo shakerproxy repair
sudo shakerproxy rollback
sudo shakerproxy app status
sudo shakerproxy network off
sudo shakerproxy uninstall
sudo shakerproxy uninstall --purge-data
```

`network off` stops routing the lab and restores the host's network as it was
before the running plan was applied (the same restore the watchdog performs).
The web UI does the same with **Turn off lab network** on the Network page.
Uninstall refuses while a lab is routed, so run it first; it is also how you
start over with a different plan.

`update` downloads and verifies the latest stable release, starts it only after
Compose validation, and restores the previous symlink if startup or health
checks fail. `repair` recreates missing runtime directories and validates the
current signed release; if integrity or startup validation fails, it retrieves
that exact signed version and replaces it atomically, restoring the original
directory if the repair fails.

`rollback` swaps `current` and `previous`, validates the target, and restores
the original links on failure. It refuses rollback when the two releases
declare different config or database schema versions; ShakerProxy does not claim
reversible database migrations.

`uninstall` acquires the configuration lock and refuses to remove the host
package while routed state, an unresolved network transaction, or a degraded
network status exists. It preserves pre-existing Docker and unrelated firewall
state, and keeps `/etc/shakerproxy` and `/var/lib/shakerproxy`. `--purge-data` also
deletes those ShakerProxy-owned paths after you type `PURGE` (add `--yes` for
automation); it is not guaranteed secure erasure on SSD or copy-on-write
storage.

Releases live under `/opt/shakerproxy/releases/<version>`, with atomically
replaced `/opt/shakerproxy/current` and `/opt/shakerproxy/previous` symlinks.
`shakerproxy-app.service` validates the signed manifest, pinned key, release
metadata, exact image set, and every extracted bundle file before it invokes
fixed Docker Compose arguments with `--pull never`. Re-running the same release
is idempotent; a same-version collision with different content fails closed.
Immediately before its first mutation, the installer acquires the appliance-
wide configuration lock and rejects unresolved network transactions (see
[configuration lock](configuration-lock.md)).

## Recover admin access

A forgotten administrator password is reset in the web UI with one of the
recovery codes shown at setup (`POST /api/v1/auth/recover`). Without a code,
reset the account from the appliance:

```bash
sudo shakerproxy admin reset
```

After you type `RESET`, the control service clears the administrator and every
session and writes a new one-time setup token to
`/var/lib/shakerproxy/control-api/setup-token`; the command prints it. Complete
setup again in the web UI and run `shakerproxy login`. An admin reset does not
revoke API tokens: review them in the web UI or with `shakerproxy token list` and
revoke any you no longer trust with `shakerproxy token revoke`. See
[the threat model](threat-model.md#administrator-sessions-and-password-confirmation).

## Diagnose problems

```bash
sudo shakerproxy doctor
sudo shakerproxy logs
sudo shakerproxy logs gatewayd -f
sudo shakerproxy logs control-api
```

`doctor` returns the same bounded, read-only diagnostic report as the
dashboard. An unavailable probe is `UNKNOWN`, never silently healthy; the
command does not apply networking, restart services, or modify capture state.
See [diagnostics](diagnostics.md).

A real install, update, repair, or rollback appends its output to
`/var/log/shakerproxy/install.log`. A failed one also creates a mode-`0640`
`/var/log/shakerproxy/install-failure-<timestamp>-<pid>.tar.gz` containing only
that log and a bounded host summary (OS, kernel, interface names, Docker
versions, failed unit names, and `shakerproxy doctor`). It never collects
environment variables, configuration files, enrollment tokens, service
credentials, packet data, TLS keys, or CA private keys.

## Runtime data and credentials

The Debian post-install hook idempotently provisions every host path and
secret used by production Compose and records the numeric capture and
HTTPS-edge groups in `/etc/shakerproxy/compose.env`. Upgrading a valid legacy file
that contains only the capture group preserves it and atomically adds the edge
group; unknown keys or mismatched values fail closed. Service credentials are
independent mode-`0400` files below the root-traversable-only
`/etc/shakerproxy/secrets` directory. Token collisions, symbolic links, malformed
values, and a PostgreSQL password/URL mismatch stop package configuration
rather than rotating credentials silently. A `systemd-tmpfiles` rule creates
the volatile `/run/lock/shakerproxy` configuration-lock directory.

The package also creates the `shakerproxy-edge` group and provisions management
PKI before the application starts. `shakerproxy repair` refuses corrupt,
incomplete, or purpose-confused PKI material instead of replacing the trust
root. `shakerproxy management-ca status` and `shakerproxy management-ca export
<destination>` inspect and export the public management CA; export never
copies private material and never overwrites a destination.

## Test local DNS forwarding

DNS enforcement starts disabled. Confirm an IPv4 routed or single-arm plan in
the dashboard, then use **Local DNS forwarder** to select `ENFORCE_LOCAL`, enter
literal `IP:53` upstreams, preview the host-bound rules, and reauthenticate to
apply. Set the test client's default gateway and DNS server to ShakerProxy's
client-side IPv4 address, then verify both UDP and TCP with `dig`. Full
commands, failure behavior, and limitations are in
[DNS forwarding and encrypted-DNS policy](dns-forwarding.md).

## Current Ubuntu 26.04 evidence

The [shared-VPS safe-runtime exercise](testing/evidence/foundation/UBU2604-001/README.md)
proves package installation/upgrade, hardened daemon startup, the development
observation stack, authenticated requests, restart-safe native detections,
database fault recovery, analyzers, and isolated Linux packet-path laboratories
on Ubuntu 26.04. It is intentionally not described as a clean-host, gateway,
reboot, or interception certification. Those remain release gates.
