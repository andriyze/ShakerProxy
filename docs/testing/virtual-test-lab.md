# Virtual Test Lab

Status: **experimental public-beta self-test**.

The Virtual Test Lab creates disposable Linux network namespaces on the ShakerProxy
Ubuntu host so an operator can exercise client-side networking before connecting
a physical phone or Smart TV. It is deliberately separate from the production
packet path and never claims that a synthetic Linux client certifies Android,
iOS, Wi-Fi, or Smart TV behavior.

## Safety model

The privileged host component is `/usr/libexec/shakerproxy/shakerproxy-testlabd`.
It exposes only a local Unix socket at:

```text
/var/lib/shakerproxy/control-api/testlab/testlab.sock
```

The socket is root-owned and group-readable/writable only by the control-api
runtime identity. The service has no TCP listener and no Docker socket access.
The browser can reach it only through authenticated control-api endpoints.
Running or forcing cleanup requires fresh administrator-password verification.

The service owns only names beginning with `lgtest-` and the dedicated nftables
table `inet shakerproxy-testlab`. Every run removes those objects before setup and
again on completion. The original `net.ipv4.ip_forward` value is restored after
the run.

The service does **not** modify ShakerProxy's authoritative traffic-policy document
or create fake DNS/TLS/analyzer events merely to make a self-test pass.

## Virtual topology

```text
normal client 198.18.240.10 ---\
bypass client 198.18.240.20 ----+-- lgtest-client 198.18.240.1
DNS client    198.18.240.30 ---/            |
                                             | host IPv4 forwarding
                                             |
                                  lgtest-wan 198.18.241.1
                                             |
                                   target 198.18.241.254
```

The `198.18.0.0/15` range is reserved for benchmark/testing use and is not used
as a normal Internet destination.

The target namespace is implemented by the same signed ShakerProxy binary and
provides bounded local HTTP, UDP DNS, and TLS endpoints. No third-party test
container is required.

## UI profiles

### Quick

Runs:

- namespace/bridge creation;
- independent virtual client addressing;
- routed IPv4 HTTP from a client network to the target network.

Use this immediately after install to detect basic namespace, bridge, routing,
or host-firewall conflicts.

### DNS

Runs:

- UDP DNS transaction to the deterministic target;
- a dedicated test-lab TCP/853 drop mechanic.

The TCP/853 drop is explicitly labeled a **mechanic proof**, not a ShakerProxy
DoT-policy proof. The UI returns `SKIP` for encrypted-DNS product proof until
the normal ShakerProxy traffic-policy/event path observes a real DoH/DoT/DoQ test.

### TLS

Checks whether interception prerequisites exist, but deliberately does not
force traffic into mitmproxy behind the traffic-policy owner's back.

TLS interception and probable-pinning tests remain `SKIP` unless they are
performed through the normal per-client traffic policy with real event evidence.
This prevents a self-test from claiming decryption or pinning behavior that the
actual product path did not observe.

### Full

Runs every virtual profile and additionally reports the external evidence gates
for:

- PCAP -> Zeek/Suricata -> normalized events -> Traffic search;
- MCP queries using a separately scoped token;
- TLS interception and pinned/custom-trust recovery;
- physical Android/iOS/Smart TV validation.

These remain `SKIP` until their real subsystem produces evidence.

## Combining Test Lab with a normal capture

To prove the analyzer path without synthetic events:

1. Open **Captures** and start a normal bounded capture.
2. Open **Test Lab** and run `Quick`, `DNS`, or `Full`.
3. Stop/finalize the capture.
4. Open **Traffic** and filter the resulting RFC 2544 addresses, for example:

```text
src.ip:198.18.240.10
src.ip:198.18.240.30 AND service:dns
```

5. Confirm the traffic came through the real capture/analyzer/ingest pipeline.
6. Export the filtered metadata or finalized PCAP through the existing export
   workflows.

The Test Lab service itself never inserts rows into PostgreSQL.

## PASS / FAIL / SKIP semantics

- **PASS** — the named command/protocol check really succeeded.
- **FAIL** — the named check ran and produced an unexpected result.
- **SKIP** — ShakerProxy intentionally does not have enough evidence to make that
  claim from the virtual environment.

`SKIP` is not a warning-colored PASS. It is an explicit remaining evidence gate.

## Physical beta testing remains mandatory

Before a beta build is promoted beyond internal testing, run
`docs/testing/mvp-physical-client-acceptance.md` with at least:

- Android;
- iOS/iPadOS;
- Android/Google TV;
- another representative Smart TV platform when available;
- a desktop browser control client.

The Virtual Test Lab complements those tests; it does not replace them.
