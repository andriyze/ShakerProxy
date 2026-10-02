# DNS forwarding and encrypted-DNS policy

ShakerProxy can answer lab devices' DNS itself. That serves two purposes:

- **Force plain DNS through ShakerProxy** (`ENFORCE_LOCAL`): every lab client's
  plain DNS is answered by ShakerProxy, which forwards it to the upstream servers
  you choose, so lookups are visible and cannot silently go elsewhere.
- **Block a domain for one device**: ShakerProxy answers NXDOMAIN ("name does not
  exist") for the names you block, and their subdomains, for that device only.
  See [device-testing-quickstart.md](device-testing-quickstart.md).

Both are installed-host capabilities. They need a confirmed routed or
single-arm network plan and are absent from the safe development profile.

## Packet path

`shakerproxy-gatewayd` owns the revisioned policy and its fixed `iptables` and
`ip6tables` chains on the confirmed lab interface (wired port, Wi-Fi access
point, or the `lgbr0` bridge of both). It redirects client UDP/TCP port 53 to
the unprivileged `shakerproxy-dnsd` listener on port 1053:

- queries to ShakerProxy's own lab address (the usual DHCP-provided resolver) and
  to resolvers outside the lab are redirected;
- DNS between two lab devices is left alone, including on a bridged lab;
- for `ENFORCE_LOCAL`, the whole lab is redirected; for domain blocking, only
  the device, matched by MAC address (falling back to its current IPs); DNS
  over TLS and QUIC (port 853) is also rejected for that device so it falls
  back to plain DNS.

`shakerproxy-dnsd` listens on IPv4 and IPv6. Port 1053 is dropped on every
interface except loopback and the lab segment, in both families, and the lab
accept rule only matches queries ShakerProxy itself redirected. As a second
layer, the forwarder ignores queries from anything but loopback, private
(RFC 1918, ULA), CGNAT and link-local addresses and the lab prefixes the
gateway publishes, so a missing firewall rule cannot turn it into an open
resolver. IPv6 redirects are installed only when the lab routes IPv6 and the
gateway has confirmed the forwarder answers on `::1`.

The forwarder reads the runtime document the gateway publishes at
`/var/lib/shakerproxy/traffic/policy.json` (the same file mitmproxy reads; the
cloud connector writes its own snapshot there when it manages the policy). It uses:

- the policy's upstream servers when `ENFORCE_LOCAL` lists them;
- otherwise the host's resolver: `SHAKERPROXY_DNS_FALLBACK_UPSTREAMS` if set, else
  the nameservers in `/run/systemd/resolve/resolv.conf` or `/etc/resolv.conf`
  (the systemd-resolved stub at 127.0.0.53 is fine; the forwarder runs on the
  host). This is how per-device domain blocking and cloud-managed DNS
  redirection resolve names.

Upstreams are tried in health order. A silent upstream is hedged by the next
one after a quarter of the timeout (at most 500 ms), a failing one is replaced
immediately and tried last for 30 seconds, so one dead resolver no longer
delays every lookup by the full timeout.

## Lookups in Traffic

Every query the forwarder answers for a lab device appears in Traffic and in
the device report as a DNS lookup (kind `shakerproxy.dns`), whether or not a
capture is running: the name, record type, outcome (`NOERROR`, `NXDOMAIN`,
and so on, including names blocked for the device), and the A, AAAA and CNAME
answers with their TTLs. The device is the one that held the client address at
the time, as for captured traffic.

`shakerproxy-dnsd` writes one event file per lookup to
`/var/lib/shakerproxy/dns-events/pending`, after the answer has been sent, and
the `dns-event-forwarder` container delivers them to ingest. Recording never
delays an answer: lookups wait in a bounded queue, and when the queue or the
spool (20,000 undelivered events) is full they are dropped, counted, and
logged at most every five minutes. If the spool is missing the forwarder still
answers and logs `DNS lookups are not recorded for Traffic` once at start.
Set `SHAKERPROXY_DNS_EVENT_SPOOL=off` to stop recording.

When a capture records the same lookup through Zeek, Traffic shows the
forwarder's row and hides Zeek's copy with the other analyzer duplicates; the
device report counts each name once.

### Connections as they open

`shakerproxy-gatewayd` also reports every connection a lab device opens through
the gateway (kind `shakerproxy.conn`) within about a second, from the kernel's
connection tracking, without waiting for the packet recording to be analyzed.
It writes them to the same spool, and the same forwarder delivers them. Only
connections from the confirmed lab network to somewhere other than the gateway
are reported; lookups to the gateway are the forwarder's own rows. Ingest names
each connection from the same client's DNS answers of the previous 30 minutes
(`dns_name`), so Traffic shows `github.com · 140.82.121.4:443` at once. When the
recording's analysis of that connection arrives, its server name and size fill
in the same Traffic row instead of adding another. Set
`SHAKERPROXY_CONNECTION_EVENT_SPOOL=off` in gatewayd's environment to stop
reporting connections.

Earlier releases decoded that document with the wrong schema and answered
every query with SERVFAIL as soon as "Force plain DNS" was applied; a
cross-component test now checks that the forwarder accepts exactly what the
gateway writes.

Policy writes use optimistic revisions, the appliance-wide configuration lock,
a preview digest, and administrator confirmation. The password terminates at
`control-api` and is never sent to the privileged socket. Device controls use
the same apply path without a password because they affect one device. A
failed listener probe or policy apply removes ShakerProxy's redirects and restores
the previous runtime policy, leaving client traffic fail-open rather than
silently blackholing DNS.

## Test from a client

1. In the network planner, confirm a routed or single-arm plan.
2. In **Local DNS forwarder**, select **Force plain DNS through ShakerProxy**,
   enter one or more upstream IP endpoints such as `1.1.1.1:53`, preview the
   exact changes, and apply.
3. Point the test client's gateway and DNS server at ShakerProxy's lab address
   (DHCP from ShakerProxy does this).
4. From the client, verify both transports:

```bash
dig @SHAKERPROXY_CLIENT_IP example.com A
dig +tcp @SHAKERPROXY_CLIENT_IP example.com A
```

To test domain blocking instead, block a name for the device and look it up:

```bash
dig @SHAKERPROXY_CLIENT_IP blocked.example.com A   # status: NXDOMAIN
```

On the ShakerProxy host, inspect only the managed services and listeners:

```bash
sudo systemctl status shakerproxy-gatewayd shakerproxy-dnsd
sudo ss -lntup '( sport = :1053 )'
/usr/libexec/shakerproxy/shakerproxy-dnsd --help
```

Blocked lookups are logged by `shakerproxy-dnsd` at most once a minute per device
and name (`journalctl -u shakerproxy-dnsd`).

A VPS management tunnel by itself is not a client packet path. A remote client
must route its test traffic through ShakerProxy—for example through an explicitly
configured lab network or tunnel—before gateway or DNS interception can be
observed.

## Settings

`shakerproxy-dnsd` is configured through its environment
(`systemctl edit shakerproxy-dnsd`):

| Variable | Default | Meaning |
| --- | --- | --- |
| `SHAKERPROXY_DNS_BIND` | `:1053` | Listen address (both families). |
| `SHAKERPROXY_DNS_TIMEOUT_SECONDS` | 4 | Per-query upstream budget, 1–30. Out-of-range values are clamped and logged. |
| `SHAKERPROXY_DNS_MAX_CONCURRENT` | 256 | Concurrent queries, 16–4096. |
| `SHAKERPROXY_DNS_FALLBACK_UPSTREAMS` | host resolver | Comma-separated `IP:53` used when the policy names no upstream. |
| `SHAKERPROXY_TRAFFIC_POLICY_FILE` | `/var/lib/shakerproxy/traffic/policy.json` | Runtime document. |

## Modes and limits

- `OBSERVE` installs no client DNS enforcement rules.
- `BLOCK_KNOWN` can block selected DoT, DoQ, and catalog-known DoH/HTTP3
  endpoints; unknown resolvers, shared CDNs, relays, VPNs, ECH, and tunnels can
  remain opaque. The LOG rule for each block now precedes its REJECT, so
  blocked attempts reach the kernel log.
- `ENFORCE_LOCAL` redirects client UDP/TCP port 53 for IPv4, and for IPv6 when
  the lab routes it. It does not provide DNS caching, DNSSEC validation, or a
  per-query enforcement-outcome event.
- Domain blocking covers plain DNS and DNS over TLS/QUIC. DNS over HTTPS,
  cached answers and hard-coded IP addresses bypass it; block the device's
  internet to rule those out.
- Policy upstreams are literal unicast IP endpoints on port 53. Provider or VPS
  egress restrictions on UDP/TCP 53 can still prevent resolution.
- The current isolated namespace proof is deterministic implementation
  evidence, not clean-machine platform certification.

`tests/netlab/dns-forwarding.sh` proves that client UDP and TCP requests to an
unrelated port-53 address are redirected to the packaged DNS daemon, forwarded
to the configured test resolver, and answered correctly. Unit and API tests
cover runtime parsing of every writer's schema, blocking, upstream hedging,
fixed firewall rendering for both families, authenticated preview/apply/
rollback, device controls, revision conflicts, and password separation.
