# Visibility coverage check

ShakerProxy's goal is complete visibility of every device connection. The visibility coverage
check proves it one traffic type at a time and names every gap. It is both a release test and a
button a tester can press:

- **UI:** System → *What ShakerProxy is proven to see* → **Run coverage check**
- **CLI:** `shakerproxy coverage` (last result and bypass findings), `shakerproxy coverage run --password-file FILE`
- **API:** `GET /api/v1/coverage` (session or `system:read` token), `POST /api/v1/coverage/runs` (administrator session, recent password)
- **MCP:** the read-only `visibility_coverage` tool

## What it proves

Each probe is sent once from a virtual client and must show up in stored events:

| Probe | Sent | Passes when |
|---|---|---|
| DNS via ShakerProxy | UDP 53 to the client's gateway, answered by ShakerProxy's DNS forwarder | A lookup for the run's unique name is stored |
| DNS to another resolver | UDP 53 straight to an outside resolver | The run's unique name is stored from the recording |
| DNS over TLS | TLS to TCP 853 | The connection is stored and named `dot` |
| DNS over HTTPS | HTTPS to `cloudflare-dns.com` | The connection is stored and named `doh` |
| DNS over QUIC | A QUIC Initial with ALPN `doq` to UDP 853 | The datagram is stored and named `doq` |
| HTTP | A cleartext GET with a unique path | The path is stored |
| HTTPS / TLS | A TLS handshake with a unique server name | The server name is stored |
| QUIC / HTTP/3 | A real QUIC v1 Initial with a unique server name | The server name is stored |
| TCP / UDP, unusual port | TCP 9998 / UDP 9997 | The connection is stored |
| ICMP | Two echo requests | Stored and named `icmp` |
| SSH | An SSH version exchange | Stored and named `ssh` |
| NTP | An NTP client request | Stored and named `ntp` |
| mDNS (AirPlay discovery) | A PTR query for `_airplay._tcp.local` to 224.0.0.251 | Stored and named `mdns` |
| SSDP (casting discovery) | An `M-SEARCH` to 239.255.255.250:1900 | Stored and named `ssdp` |
| IPv6 | — | Skipped: the virtual lab is IPv4-only; the routing inspection covers IPv6 |

Each result also records:

- **Event kinds:** which events showed the probe, such as `zeek.conn` or `shakerproxy.dns`.
- **Delay:** how long after sending the first event was stored.
- **What is missing:** for a failure, "not recorded" or "recorded but not identified as SSH".

Names are unique per run and live under `.coverage.shakerproxy.test`, which never resolves on the Internet. An
earlier run, or other traffic, can't make a check pass.

## How the probes travel the real path

The check never writes events itself. It only reads back what production stored.

1. **Prepare:** control-api asks the test lab (`shakerproxy-testlabd`) to build the
   [virtual test lab](virtual-test-lab.md), plus the coverage endpoints on the virtual target (SSH banner,
   NTP, TCP/UDP echo, DoH). The virtual clients' DNS for their gateway is redirected to ShakerProxy's DNS
   forwarder, and the forwarder accepts the test lab's `198.18.240.0/24` clients. The redirect lives in the test lab's
   own nftables table; one comment-tagged `INPUT` rule lets the bridge reach the forwarder.
2. **Record:** control-api starts a normal capture through gatewayd with `coverage_lab: true`. gatewayd
   records the virtual-client bridge (`lgtest-client`) instead of the lab interface, and refuses if that bridge
   does not exist. Like any manual capture, it pauses the automatic lab recording for its duration
   (about 10 seconds).
3. **Probe:** the test lab runs the probes inside the `lgtest-normal` namespace.
4. **Stop and clean up:** the capture stops and is analyzed by the real Zeek and Suricata workers. The test lab
   removes every `lgtest-` object and its rules. If cleanup never arrives, a 4-minute lease removes them.
   The configuration lock is held only while objects change, so the capture can start in between.
5. **Read back:** control-api queries the stored events with the Traffic page's own query until every probe
   passes or 150 seconds pass:

   ```text
   (capture.id:<run capture> OR (source:HOST AND src.ip:198.18.240.0/24)) AND time>=<start>
   ```

## Ways around ShakerProxy (routing inspection)

The inspection runs on every `GET /api/v1/coverage`. It judges the live configuration from gatewayd's
managed state, host inspection and DNS policy, plus the last 24 hours of recorded traffic:

| Finding | GAP when |
|---|---|
| IPv6 | Another router advertises IPv6 (a recorded ICMPv6 router advertisement from another host), or the lab interface has IPv6 that ShakerProxy did not configure, while the lab does not route IPv6 |
| Address assignment | Another DHCP server answered on the lab network, or the lab is single-arm (the network's router hands out addresses, so only devices set by hand use ShakerProxy) |
| Device-to-device traffic | Single-arm lab (devices talk directly); UNKNOWN for wired two-port labs; OK for ShakerProxy's Wi-Fi access point |
| Encrypted DNS | DoT, DoQ or known DoH is not blocked by the DNS policy |
| DNS sent to other resolvers | Plain DNS to other resolvers is not redirected to ShakerProxy |
| Local discovery | Single-arm recordings keep only routed traffic, so mDNS and SSDP are not recorded |
| Not routing | No confirmed lab routes traffic |

## Gaps found on the current test lab

These are on the Proxmox VM: a single-arm lab on 192.168.10.0/24, a home network without IPv6, and the DNS
policy observing.

The routing inspection follows from that configuration:

- **GAP, address assignment:** only devices set by hand to use 192.168.10.177 go through ShakerProxy.
- **GAP, device-to-device traffic:** AirPlay, casting and local SSH between lab devices are invisible.
- **GAP, encrypted DNS:** DoT, DoQ and DoH are allowed, so a phone using Private DNS hides its lookups.
- **GAP, DNS sent to other resolvers:** only DNS sent to the gateway is redirected.
- **GAP, local discovery:** mDNS and SSDP are not recorded in single-arm.
- **OK, IPv6:** no IPv6 router on that network.

### Probe results with the real analyzer

These results come from `tests/netlab/coverage-probes.sh` run in a privileged Linux container with
`SHAKERPROXY_COVERAGE_PCAP` set:

1. The probes travel real network namespaces through a forwarding gateway.
2. The pinned Zeek 8.2.1 image analyzes the recording with ShakerProxy's `shakerproxy.zeek` policy.
3. Each log line is normalized and projected by ingest's own `NormalizeZeekJSON` and `ProjectEvent`.
4. The coverage evaluator judges the result.

Out of scope for this run: dnsd, Suricata, PostgreSQL and the capture worker, which only the appliance run
covers.

| Result | Traffic types |
|---|---|
| PASS | DNS via ShakerProxy and to another resolver, DoT (`dot`), DoQ (`doq`), HTTP, HTTPS/TLS, QUIC, TCP and UDP on unusual ports, ICMP, SSH, NTP, mDNS (`mdns`), SSDP (`ssdp`) |
| FAIL | **DNS over HTTPS**: recorded (`zeek.conn`, `zeek.ssl`, server name `cloudflare-dns.com`) but classified `tls`. The protocol classifier names DoH only when an analyzer reports it, so DoH to a known resolver is not labelled as encrypted DNS. |
| SKIP | IPv6: the virtual lab is IPv4-only |

On the appliance, the delay column adds:

- the 10-second probe recording;
- Zeek and Suricata analysis;
- per-event delivery to ingestd.

DNS through the forwarder appears within seconds.

To run it on the appliance after installing a release that includes it:

```sh
shakerproxy coverage run --password-file ~/admin.pw
shakerproxy coverage
```

## Limitations

- **Not a phone or TV:** the probes come from Linux namespaces on the appliance. They prove what the pipeline
  records, not how a particular phone or TV behaves.
- **No device attribution:** virtual clients are not lab devices, so their events are not attributed to a device;
  `attributed` is reported, but doesn't affect the result.
- **IPv4 only:** the virtual lab has no IPv6 probes yet.
