# Traffic stream types

The live Traffic view, the events summary (`GET /api/v1/events/summary`) and
the MCP `traffic_summary` tool sort every event into one stream type. This is
the specification; three implementations follow it:

- Go: `ingest.StreamType` (`internal/ingest/stream_type.go`);
- PostgreSQL: `streamTypeSQL` in the same file, used for the summary's
  timeline and type counts;
- web UI: `streamKind` with the blocked and encrypted-DNS rules of
  `streamLine` (`apps/web-ui/src/lib/liveTraffic.ts`).

`internal/ingest/testdata/stream_types.json` lists one event per rule with its
expected type. A Go unit test, a PostgreSQL integration test and a UI test
(`tests/ui/stream-types.test.mjs`) run every case, so the three cannot drift
apart.

## Rules, in order

The first rule that matches decides.

| # | Type | Rule |
|---|---|---|
| 1 | blocked | ShakerProxy refused it: a lookup the DNS forwarder answered NXDOMAIN on purpose, or a connection the gateway rejected (`shakerproxy.blocked`) |
| 2 | wifi | An 802.11 management frame event from ShakerProxy's passive Wi-Fi monitor (HOST `wifi.*`: probe, auth, assoc, deauth, disassoc, beacon summary); see [Wi-Fi visibility](wifi-visibility.md) |
| 3 | dns | Encrypted DNS the classifier identified: app protocol `doh`, `dot` or `doq` |
| 4 | quic / tls / http / other | A connection the gateway reported as it opened (`shakerproxy.conn`): UDP to 443 or with a server name is QUIC, TCP to 443 or with a server name is TLS, TCP to 80 is HTTP, anything else is other |
| 5 | alert | A Suricata alert |
| 6 | discovery | Local discovery: destination port 5353 (mDNS), 5355 (LLMNR), 1900 (SSDP), 137/138 (NetBIOS), 67/68 (DHCP), 546/547 (DHCPv6), 3702 (WS-Discovery) or 10001 (Ubiquiti); a `zeek.dhcp` record; or the protocol classifier's `local-discovery` category or a discovery/DHCP app protocol |
| 7 | dns | A name lookup (`dns_query` set) |
| 8 | http | A web request (method or host set, or an `*.http` record) |
| 9 | quic | A QUIC record, or a UDP connection with a server name |
| 10 | tls | A connection with a server name, or a TLS handshake record |
| 11 | other | Everything else: unnamed TCP/UDP, ICMP, and other protocols |

## Analyzer duplicates

The analyzers record some traffic more than once: Suricata's flow and
application-layer records next to Zeek's, Zeek's TLS and QUIC handshakes next
to their connection record, Zeek's bookkeeping logs, and the connection
records of DNS and mDNS lookups (the lookup itself is the event). The summary
always leaves those out with the same filter the UI's "All" uses
(`EVERYTHING_QUERY`):

```text
NOT (kind:suricata.flow OR kind:suricata.dns OR kind:suricata.mdns OR kind:suricata.quic
  OR kind:suricata.tls OR kind:suricata.http OR kind:suricata.anomaly OR kind:zeek.ssl
  OR kind:zeek.quic OR kind:zeek.weird OR kind:zeek.known_services OR kind:zeek.software
  OR kind:zeek.reporter OR (kind:zeek.conn AND (dst.port:53 OR dst.port:5353 OR dst.port:5355)))
```

The UI also hides a Zeek DNS record when the DNS forwarder reported the same
lookup within five seconds; the summary does not, so a capture running next
to the forwarder can count such a lookup twice.
