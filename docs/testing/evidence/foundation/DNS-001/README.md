# DNS-001: DNS observation, forwarding, and port-planning evidence

Recorded: 2026-09-03 UTC

Deterministic tests prove bounded DNS metadata projection from known Zeek and
Suricata schemas, rejection of unsafe text, and refusal to infer DNS from a
non-DNS event. PostgreSQL stores only the projected query/type/response/count
alongside the existing raw internal envelope, while the public recent-event
contract and inspector label it **observe only**.

The installed-host policy path is separately covered by strict authenticated
preview/apply/rollback tests, optimistic revision checks, password separation,
fixed firewall rendering, and a real DNS daemon runtime-policy test. The
isolated Linux namespace proof starts the packaged `shakerproxy-dnsd` entry point,
redirects client UDP and TCP destination port 53 to local port 1053, forwards
both requests to an authoritative test resolver, and verifies exact transaction
IDs plus returned A records.

The privileged daemon inventories only fixed service ports with `/usr/bin/ss`,
or bounded `/proc/net/{tcp,tcp6,udp,udp6}` parsing when the minimal runtime has
no `ss` binary. Tests cover IPv4 and IPv6 listeners, bounded output, owner
extraction when available, and the loopback `systemd-resolved` preservation
rule. Authenticated API tests prove that the plan is read-only and `no-store`.
The explicit connectivity endpoint accepts an empty object only, is
session-only and rate-limited, and dispatches only the fixed daemon probe.

```text
go test ./internal/ingest ./internal/dnsproxy ./host/gatewayd/internal/daemon ./apps/control-api/internal/server
sudo ./tests/netlab/dns-forwarding.sh
make registry-check
make package-smoke PACKAGE_VERSION=0.1.0-dev.9
```

The external probe performs a verified TLS `HEAD /` to `one.one.one.one` while
dialing `1.1.1.1:443` directly, then performs only a TCP connect to
`1.1.1.1:53`. It sends no DNS question and does not test UDP/53. This is
implementation evidence for provider reachability only. The namespace test is
implementation evidence for resolver and interception behavior, but it is not
clean-machine Ubuntu certification. Ubuntu 26.04 shared-VPS runtime evidence is
recorded separately in `../UBU2604-001/README.md`.
