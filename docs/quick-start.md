# Development quick start

The development stack runs the ShakerProxy web UI, control API, and an
unprivileged gateway daemon in Docker on your machine. It is setup-only: it
never routes, captures, or intercepts traffic. Guarded networking, DHCP, and
capture run on an Ubuntu appliance (see [installation](installation.md)) and
are exercised by disposable VM tests, not by `make dev`.

## Prerequisites

- Docker Engine or Docker Desktop with Compose v2
- Make, Bash, OpenSSL, and curl
- For `make verify` and the UI: Node.js 22+ with npm, python3, and ripgrep
  (`rg`)

Go is not needed on the host; Go builds and tests run in Docker and reuse the
`shakerproxy-gomod` and `shakerproxy-gocache` volumes.

## Start

```bash
make dev
```

`make dev` creates development-only secrets in the git-ignored `.local/`
directory, builds and starts the stack, waits until it answers, and prints
what to do next. While setup is pending it prints the one-time setup token;
open <http://localhost:8443>, enter the token, and create the admin account.
Development HTTP is bound to loopback only.

## Everyday commands

```bash
make                         # list every target with a description
make dev-ps                  # containers and their health
make dev-logs                # follow all logs (or: make dev-logs SERVICE=control-api)
make dev-cli ARGS=status     # run the shakerproxy CLI against the dev gateway daemon
make dev-cli ARGS=doctor
make ui-dev                  # web UI with hot reload at http://localhost:5173
make dev-down                # stop the stack, keep its data
make dev-reset               # delete dev data and start over with a new setup token
make verify                  # every check CI runs
```

`make ui-dev` serves the UI from Vite and forwards API calls to the running
development stack, so start `make dev` first.

## Observation profile

`make dev-observe` also starts bounded ingestion (`ingestd`, the forwarder
worker) and the pinned Zeek and Suricata offline analyzers. The development
capture volume starts empty; the analyzers process closed ring rotations and
finalized, manifest-bound captures placed there, and normalized events drain
into monthly PostgreSQL partitions. Useful checks while it runs:

```bash
make analyzer-smoke          # isolated PCAPNG-to-database proof
make ingest-db-smoke         # database-down spooling and automatic recovery
```

## Demo lab

`make dev-demo` loads six demo devices (a smart TV, an Android phone, an IP
camera, a Tuya smart plug, a PLC gateway and an engineer laptop) and about 90
minutes of their traffic into a running `make dev-observe` stack. It posts
Zeek, Suricata and mitmproxy events the same way the analyzers and the
interception proxy do, so Devices, Traffic, Protocols, device reports and
findings behave as they would on an appliance. All external addresses are
documentation-only ranges. Run it again to add fresh traffic; `make dev-reset`
removes it.

To try test runs and firmware comparison, start a test run for "Living room
TV" (Tests, or `shakerproxy test start tv`), run `make dev-demo-live`, and stop the
run. Start a second run, run `make dev-demo-live VARIANT=2` (the TV now
contacts a new ad partner, uses DNS over TLS and drops its plaintext firmware
check), stop it, and compare the two runs.

## Secrets and safety

Secrets stay under the mode-`0700` `.local/` directory. Files mounted into
containers are mode `0644` so the UID 999/65532 containers can read them on
native Linux; the displayed setup token stays mode `0600`. PostgreSQL runs on
an internal network and publishes no port. Production releases use HTTPS with a
generated management-only CA instead of development HTTP; see
[management TLS](management-tls.md).

Scoped API tokens and event forwarders are available in the dashboard; new
forwarders start disabled. See [integrations](integrations.md).

## Troubleshooting

- **The stack never becomes ready:** `make dev-logs SERVICE=control-api`, then
  `make dev-ps` to see which container is unhealthy.
- **Port 8443 is already in use:** stop the other service (or another checkout's
  dev stack with `make dev-down` there) and run `make dev` again.
- **Lost the admin password:** `make dev-reset` wipes development data and
  prints a new setup token.
- **`make dev-cli` cannot reach the daemon:** start the stack first; the CLI
  uses the `shakerproxy-dev_gateway-run` volume created by `make dev`.

## UI development

`make ui-dev` (or `npm run dev` in `apps/web-ui`) serves the UI with hot reload
at <http://127.0.0.1:5173> and forwards `/api` to the dev edge on
`http://127.0.0.1:8443`. The proxy presents itself as that edge (it rewrites
the Host and Origin headers) because the control API only accepts its allowed
hosts; set `SHAKERPROXY_DEV_EDGE` to use a different edge. Before sending a UI
change, run `npm run typecheck`, `npm test` and `npm run build` in
`apps/web-ui`.
