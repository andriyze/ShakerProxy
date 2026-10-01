# One-line installer

`index.sh` is the front door for installing ShakerProxy on an appliance:

```bash
curl -fsSL https://raw.githubusercontent.com/andriyze/ShakerProxy/main/install/index.sh | sh
```

It checks that the machine is Ubuntu Server 24.04 or 26.04 on amd64 (and not a
container), installs `curl` if needed, downloads the release's `bootstrap.sh`
and runs it with `sudo`. It makes no trust decisions itself: the bootstrap
verifies the release manifest's signature against ShakerProxy's pinned key and each
file's checksum, and the installer re-verifies the bundle before it changes
anything. Running the same command again upgrades to the latest stable release.

| Variable | Effect |
|---|---|
| `SHAKERPROXY_VERSION=1.2.3` | Install this release instead of the latest stable one |
| `SHAKERPROXY_VERSION=1.2.3-beta.1` | Install a beta release (the `-beta` suffix selects the beta channel) |
| `SHAKERPROXY_CHANNEL=beta` | Release channel, only when it differs from what the version implies |
| `SHAKERPROXY_DRY_RUN=1` | Check the machine and the signed release; change nothing |
| `SHAKERPROXY_OFFLINE_BUNDLE=/dir` | Install from a signed release copied to this machine (no internet needed for ShakerProxy files) |
| `SHAKERPROXY_GITHUB_USER`, `SHAKERPROXY_GITHUB_TOKEN` | Read access while the repository is private |

Set a variable for the shell that runs the script, for example
`curl -fsSL <url> | SHAKERPROXY_DRY_RUN=1 sh`.

## Troubleshooting

- **`curl: (6) Could not resolve host: raw.githubusercontent.com`**: the machine
  has internet access but no working DNS. Check with `resolvectl status`. A
  router can hand out a DNS server that does not answer; set working ones, for
  example `sudo nmcli con mod "<connection>" ipv4.ignore-auto-dns yes ipv4.dns
  "192.168.1.1 1.1.1.1" && sudo nmcli con up "<connection>"` (Ubuntu Desktop), or
  `nameservers: {addresses: [192.168.1.1, 1.1.1.1]}` under the interface in
  `/etc/netplan/*.yaml` followed by `sudo netplan apply` (Ubuntu Server).
- **`ShakerProxy needs at least 4096 MiB`**: give the machine more memory (a VM:
  raise its RAM, then shut it down and start it again), then rerun the command.
- **NetworkManager is running**: ShakerProxy installs on Ubuntu Desktop, but
  network plans need Ubuntu Server networking. See "NetworkManager hosts" in
  [docs/networking.md](../docs/networking.md).
- **A failed install** keeps its log in `/var/log/shakerproxy/install.log`, plus
  a diagnostic archive `/var/log/shakerproxy/install-failure-*.tar.gz` to attach
  to an issue.

## Files

- `index.sh`: the installer front door (POSIX `sh`; everything runs inside
  `main` so a truncated download does nothing).
- `cloudflare-worker.js`: optional short URL such as `https://install.<domain>`.
  It serves `index.sh` from the latest release's tag, not from `main`, so a
  merge is never an unreviewed installer deploy. Deploy it as a Worker on the
  installer hostname; it needs no secrets while the repository is public.

The stable channel is GitHub's latest (non-prerelease) release; the bootstrap
refuses a manifest whose signed `channel` is not `stable`. Publishing a release
therefore updates the installer with no extra step.

`make shell-check` lints this script together with every other shell script.
