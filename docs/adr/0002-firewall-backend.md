# ADR 0002: Docker coexistence through an iptables backend abstraction

Status: accepted for v1 proof; production acceptance pending

The initial Ubuntu 24.04 path will detect Docker's firewall backend and the
iptables alternative. With Docker's supported iptables backend, ShakerProxy will
own dedicated `SHAKERPROXY-*` chains loaded atomically with restore tools and attach
through documented integration points such as `DOCKER-USER`. It will never
flush unrelated rules or disable Docker rule management. Native nftables is a
separate backend gated by its own compatibility suite.

The current slice implements a fixed-command, read-only host inspector. It
records the selected iptables mode, Docker firewall backend and daemon version,
the `DOCKER-USER` integration point, UFW, and firewalld. Each preview and staged
plan is bound to that evidence. Unknown modes, Docker's native nftables backend,
missing Docker integration, invalid configuration, and active firewalld block a
future apply while still permitting a non-mutating preview.

The renderer emits only dedicated chains and fixed argument arrays. A privileged
network-namespace proof shows idempotent attachment and exact removal while
preserving synthetic Docker and administrator rules. No code applies these rules
to the host yet. Clean-VM tests with a real Docker restart remain required before
production acceptance.
