# Contributing

Keep privileged changes small, typed, auditable, and recoverable. Every claimed
network capability needs executable evidence. Do not add placeholder controls
or tests that assert mocked success for host mutations.

For the day-to-day loop, run `make` to list targets, `make dev` to start the
local stack (see [docs/quick-start.md](docs/quick-start.md)), `make ui-dev` for
the web UI with hot reload, and `make dev-cli ARGS=status` to try the `shakerproxy`
CLI against the development gateway daemon. `make test-go` runs the Go tests in
Docker with cached modules.

Before submitting a change, run `make verify`. It checks documentation links
and documented Make targets, validates the capability/recovery registries, runs
Go and UI tests, renders both Compose files, and applies the repository security
policies. Use `make docs-check` for the fast documentation-only gate.

When a capability materially changes, update its owning document,
the protocol matrix when applicable, and all three capability-registry
revisions together. Add evidence before promoting a claim. Retained evidence
must not contain credentials, captures, private hostnames, public IP ownership
details, or machine identifiers.

Run `make netlab` only on a disposable Ubuntu 24.04 or 26.04 amd64 host with
root access and Docker. The netlab is isolated, but it intentionally creates
temporary network namespaces and firewall state. Release and host-network
claims additionally require clean-VM evidence recorded in
`schemas/support-matrix.yaml`.
